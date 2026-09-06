//! Records visibility parity battery for issue #169 (C7).
//!
//! Same signed inputs through identical `SqliteNativeDwn` code on sqlite-mem
//! vs sqlite-disk. Asserts the shared visibility contract: Query and Count
//! return the same population, RecordsRead resolves through the same plan,
//! Subscribe snapshots equal Query results, tombstones route correctly, and
//! every non-initial entry carries `initialWrite`.
//!
//! Read-time record limits run through the same battery: over-limit writes
//! admit but stay invisible to Query, Count, snapshot, and Read alike.
//!
//! Covers: DWN-REC-005, DWN-AUTH-006, DWN-REC-004.

mod common;

use bytes::Bytes;
use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
use dwn_rs_core::testing::{
    bob_signer, put_limited_threads_protocol, put_notes_protocol_without_actions,
    signature_for_descriptor, signed_delete_message, signed_write_message, test_resolver,
    unsigned_count_message, unsigned_query_message, unsigned_read_message, WriteSpec,
};
use dwn_rs_core::Reply;
use serde_json::{json, Value as JsonValue};

use common::TempDb;
use dwn_rs_stores::SqliteNativeDwn;

const TENANT: &str = "did:example:alice";
const T1: &str = "2025-01-01T00:00:00.000000Z";
const T2: &str = "2025-01-01T00:00:01.000000Z";
const T3: &str = "2025-01-01T00:00:02.000000Z";
const T4: &str = "2025-01-01T00:00:03.000000Z";

struct Nodes {
    mem: SqliteNativeDwn,
    disk: SqliteNativeDwn,
    _db: TempDb,
}

async fn fresh_nodes() -> Nodes {
    let db = TempDb::new("visibility-parity");
    let mem = SqliteNativeDwn::open_in_memory(test_resolver())
        .await
        .expect("open mem node");
    let disk = SqliteNativeDwn::open_at(db.path(), test_resolver())
        .await
        .expect("open disk node");
    for node in [&mem, &disk] {
        put_notes_protocol_without_actions(TENANT, node.store()).await;
    }
    Nodes { mem, disk, _db: db }
}

async fn write(node: &SqliteNativeDwn, spec: WriteSpec, payload: Bytes) -> (i32, String) {
    let value = signed_write_message(spec).await;
    let record_id = value["recordId"].as_str().expect("recordId").to_string();
    let code = node
        .process_message_with_data(TENANT, value, Some(payload))
        .await
        .status
        .code;
    (code, record_id)
}

fn payload(version: &str) -> Bytes {
    Bytes::from(format!("visibility {version}").into_bytes())
}

fn spec(timestamp: &str, payload: &Bytes, record_id: Option<String>) -> WriteSpec {
    WriteSpec {
        data_cid: generate_dag_pb_cid_from_bytes(payload).to_string(),
        data_size: payload.len() as u64,
        published: Some(true),
        record_id,
        timestamp: timestamp.to_string(),
        // Initial writes must carry dateCreated == messageTimestamp;
        // updates override this with the initial's value (see populate).
        date_created: timestamp.to_string(),
        ..WriteSpec::new(timestamp)
    }
}

/// Two published records; recA updated once, then deleted (tombstone).
/// Returns (recA, recB).
async fn populate(node: &SqliteNativeDwn) -> (String, String) {
    let data_a1 = payload("a1");
    let (_, rec_a) = write(node, spec(T1, &data_a1, None), data_a1).await;
    let data_a2 = payload("a2");
    let mut v2spec = spec(T2, &data_a2, Some(rec_a.clone()));
    // date_created is immutable: updates keep the initial's value.
    v2spec.date_created = T1.to_string();
    let (code, _) = write(node, v2spec, data_a2).await;
    assert_eq!(code, 202);
    let data_b = payload("b1");
    let (_, rec_b) = write(node, spec(T3, &data_b, None), data_b).await;
    let delete = signed_delete_message(&rec_a, false, T4).await;
    let reply = node.dwn().process_message(TENANT, delete).await;
    assert_eq!(reply.status.code, 202, "{reply:?}");
    (rec_a, rec_b)
}

async fn query_entries(node: &SqliteNativeDwn, filter: JsonValue) -> (i32, Vec<JsonValue>) {
    let reply = node
        .dwn()
        .process_message(TENANT, unsigned_query_message(filter))
        .await;
    let Reply::RecordsQuery(query) = reply.reply else {
        panic!("expected RecordsQuery reply, got {:?}", reply.status);
    };
    let entries = query
        .entries
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| serde_json::to_value(entry).unwrap())
                .collect()
        })
        .unwrap_or_default();
    (reply.status.code, entries)
}

async fn count(node: &SqliteNativeDwn, filter: JsonValue) -> (i32, u64) {
    let reply = node
        .dwn()
        .process_message(TENANT, unsigned_count_message(filter))
        .await;
    let Reply::RecordsCount(count) = reply.reply else {
        panic!("expected RecordsCount reply, got {:?}", reply.status);
    };
    (reply.status.code, count.count.unwrap_or(0))
}

async fn read(node: &SqliteNativeDwn, message: JsonValue) -> (i32, JsonValue) {
    let reply = node.dwn().process_message(TENANT, message).await;
    let Reply::RecordsRead(read) = reply.reply else {
        panic!("expected RecordsRead reply, got {:?}", reply.status);
    };
    (
        reply.status.code,
        serde_json::to_value(&read.entry).unwrap(),
    )
}

fn published_filter() -> JsonValue {
    json!({ "published": true })
}

#[tokio::test]
async fn query_and_count_return_the_same_population() {
    // Serialize file-backed tests process-wide.
    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        populate(node).await;
    }

    let (mem_query_status, mem_entries) = query_entries(&nodes.mem, published_filter()).await;
    let (disk_query_status, disk_entries) = query_entries(&nodes.disk, published_filter()).await;
    assert_eq!((mem_query_status, disk_query_status), (200, 200));
    assert_eq!(mem_entries, disk_entries);
    assert_eq!(mem_entries.len(), 1, "deleted recA is invisible to Query");

    let (mem_count_status, mem_count) = count(&nodes.mem, published_filter()).await;
    let (disk_count_status, disk_count) = count(&nodes.disk, published_filter()).await;
    assert_eq!((mem_count_status, disk_count_status), (200, 200));
    assert_eq!(mem_count, disk_count);
    assert_eq!(mem_count, mem_entries.len() as u64);
}

#[tokio::test]
async fn read_resolves_through_the_same_plan_as_query() {
    // Serialize file-backed tests process-wide.
    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        populate(node).await;
    }

    // Top-1 read by updated date returns the latest-updated record, matching
    // the same query's entry on payload identity.
    // NB: envelope shapes differ per handler (see testing.rs helpers);
    // RecordsRead takes descriptor.filter plus descriptor.dateSort.
    let read_message = json!({
        "descriptor": {
            "interface": "Records",
            "method": "Read",
            "messageTimestamp": T4,
            "filter": { "published": true },
            "dateSort": "updatedDescending",
        },
    });
    let (mem_status, mem_entry) = read(&nodes.mem, read_message.clone()).await;
    let (disk_status, disk_entry) = read(&nodes.disk, read_message).await;
    assert_eq!((mem_status, disk_status), (200, 200));
    assert_eq!(mem_entry, disk_entry);

    let (_, entries) = query_entries(&nodes.mem, published_filter()).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(
        mem_entry["recordsWrite"]["descriptor"]["dataCid"],
        entries[0]["descriptor"]["dataCid"]
    );
    assert_eq!(
        mem_entry["encodedData"], entries[0]["encodedData"],
        "read and query expose the same payload"
    );
}

#[tokio::test]
async fn subscribe_snapshot_equals_query_at_the_same_head() {
    // Serialize file-backed tests process-wide.
    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        populate(node).await;
    }

    for node in [&nodes.mem, &nodes.disk] {
        let subscribe = json!({
            "descriptor": {
                "interface": "Records",
                "method": "Subscribe",
                "messageTimestamp": T4,
                "filter": { "published": true },
            },
        });
        let reply = node.dwn().process_message(TENANT, subscribe).await;
        assert_eq!(reply.status.code, 200, "{reply:?}");
        let Reply::RecordsSubscribe(sub) = reply.reply else {
            panic!("expected RecordsSubscribe reply");
        };
        let snapshot: Vec<JsonValue> = sub
            .entries
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| serde_json::to_value(entry).unwrap())
                    .collect()
            })
            .unwrap_or_default();
        let (_, queried) = query_entries(node, published_filter()).await;
        assert_eq!(snapshot, queried, "snapshot must equal query");
    }

    let (_, mem_entries) = query_entries(&nodes.mem, published_filter()).await;
    let (_, disk_entries) = query_entries(&nodes.disk, published_filter()).await;
    assert_eq!(mem_entries, disk_entries);
}

#[tokio::test]
async fn non_initial_entries_carry_initial_write() {
    // Serialize file-backed tests process-wide.
    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        populate(node).await;
    }

    // recB is an initial write (no initialWrite expected); recA was updated
    // then deleted, so the tombstone path is covered separately. Here assert
    // the live record's entry shape is identical across backends, then check
    // the updated-then-live case via a second record pair below.
    let (_, mem_entries) = query_entries(&nodes.mem, published_filter()).await;
    let (_, disk_entries) = query_entries(&nodes.disk, published_filter()).await;
    assert_eq!(mem_entries, disk_entries);

    // Update recB: its latest entry is no longer the initial write.
    // recB was created at T3, so its update keeps date_created == T3.
    for node in [&nodes.mem, &nodes.disk] {
        let rid = query_entries(node, published_filter())
            .await
            .1
            .first()
            .and_then(|entry| entry["recordId"].as_str().map(str::to_string))
            .expect("recB recordId");
        let data = payload("b2");
        let mut update = spec("2025-01-01T00:00:04.000000Z", &data, Some(rid));
        update.date_created = T3.to_string();
        let (code, _) = write(node, update, data).await;
        assert_eq!(code, 202);
    }

    let (_, mem_entries) = query_entries(&nodes.mem, published_filter()).await;
    let (_, disk_entries) = query_entries(&nodes.disk, published_filter()).await;
    assert_eq!(mem_entries, disk_entries);
    assert_eq!(mem_entries.len(), 1);
    assert!(
        mem_entries[0]["initialWrite"].is_object(),
        "non-initial entry must carry initialWrite"
    );
}

#[tokio::test]
async fn tombstones_are_visible_to_read_and_hidden_from_query() {
    // Serialize file-backed tests process-wide.
    let nodes = fresh_nodes().await;
    let mut rec_a = String::new();
    for node in [&nodes.mem, &nodes.disk] {
        let (a, _) = populate(node).await;
        rec_a = a;
    }

    for node in [&nodes.mem, &nodes.disk] {
        let (status, entry) = read(node, unsigned_read_message(json!({ "recordId": rec_a }))).await;
        assert_eq!(status, 404);
        assert!(
            entry["recordsDelete"].is_object(),
            "tombstone read carries recordsDelete"
        );
        assert!(
            entry["initialWrite"].is_object(),
            "tombstone read carries initialWrite"
        );
    }

    let (mem_status, mem_entry) = read(
        &nodes.mem,
        unsigned_read_message(json!({ "recordId": rec_a })),
    )
    .await;
    let (disk_status, disk_entry) = read(
        &nodes.disk,
        unsigned_read_message(json!({ "recordId": rec_a })),
    )
    .await;
    assert_eq!((mem_status, mem_entry), (disk_status, disk_entry));
}

#[tokio::test]
async fn unpublished_writes_stay_invisible_to_anonymous_query() {
    // Serialize file-backed tests process-wide.
    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        put_notes_protocol_without_actions(TENANT, node.store()).await;
        let data = payload("hidden");
        let (code, _) = write(
            node,
            WriteSpec {
                data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
                data_size: data.len() as u64,
                published: None,
                timestamp: T1.to_string(),
                date_created: T1.to_string(),
                ..WriteSpec::new(T1)
            },
            data,
        )
        .await;
        assert_eq!(code, 202);
    }

    let (_, mem_entries) = query_entries(&nodes.mem, published_filter()).await;
    let (_, disk_entries) = query_entries(&nodes.disk, published_filter()).await;
    assert_eq!(mem_entries, disk_entries);
    assert!(mem_entries.is_empty());
}

const LIMITED_PROTOCOL: &str = "http://example.com/limited";

fn limited_filter(extra: JsonValue) -> JsonValue {
    let mut filter = json!({ "protocol": LIMITED_PROTOCOL, "published": true });
    for (key, value) in extra.as_object().expect("extra filter must be an object") {
        filter[key] = value.clone();
    }
    filter
}

fn limited_post(day: &str) -> (WriteSpec, Bytes) {
    let timestamp = format!("2025-01-{day}T00:00:00.000000Z");
    let data = payload(&format!("post-{day}"));
    (
        WriteSpec {
            protocol: LIMITED_PROTOCOL.to_string(),
            protocol_path: "post".to_string(),
            data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
            data_size: data.len() as u64,
            published: Some(true),
            timestamp: timestamp.clone(),
            date_created: timestamp.clone(),
            ..WriteSpec::new(&timestamp)
        },
        data,
    )
}

/// Three root posts under a max-2 limit: Query, Count, snapshot, and Read
/// agree that only the two oldest are visible, identically on both backends.
#[tokio::test]
async fn record_limit_root_bounds_all_read_surfaces() {
    let nodes = fresh_nodes().await;
    let mut posts = Vec::new();
    for node in [&nodes.mem, &nodes.disk] {
        put_limited_threads_protocol(TENANT, node.store()).await;
        let mut ids = Vec::new();
        for day in ["01", "02", "03"] {
            let (spec, data) = limited_post(day);
            let (code, record_id) = write(node, spec, data).await;
            assert_eq!(code, 202, "over-limit writes still admit");
            ids.push(record_id);
        }
        posts.push(ids);
    }

    let scope = || limited_filter(json!({ "protocolPath": "post" }));
    for (node, ids) in [&nodes.mem, &nodes.disk].into_iter().zip(posts) {
        let (status, entries) = query_entries(node, scope()).await;
        assert_eq!(status, 200);
        let mut visible: Vec<String> = entries
            .iter()
            .filter_map(|entry| entry["recordId"].as_str().map(str::to_string))
            .collect();
        visible.sort();
        let mut expected = vec![ids[0].clone(), ids[1].clone()];
        expected.sort();
        assert_eq!(visible, expected);

        let (count_status, count) = count(node, scope()).await;
        assert_eq!(count_status, 200);
        assert_eq!(count, 2);

        let subscribe = json!({
            "descriptor": {
                "interface": "Records",
                "method": "Subscribe",
                "messageTimestamp": T4,
                "filter": limited_filter(json!({ "protocolPath": "post" })),
            },
        });
        let reply = node.dwn().process_message(TENANT, subscribe).await;
        assert_eq!(reply.status.code, 200, "{reply:?}");
        let Reply::RecordsSubscribe(sub) = reply.reply else {
            panic!("expected RecordsSubscribe reply");
        };
        let snapshot: Vec<JsonValue> = sub
            .entries
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| serde_json::to_value(entry).unwrap())
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(snapshot, entries, "snapshot must equal query under policy");

        let (hidden_status, _) =
            read(node, unsigned_read_message(json!({ "recordId": ids[2] }))).await;
        assert_eq!(hidden_status, 404, "non-occupant read is a bare 404");
        let (read_status, _) =
            read(node, unsigned_read_message(json!({ "recordId": ids[0] }))).await;
        assert_eq!(read_status, 200, "occupant read succeeds");
    }

    let (_, mem_entries) = query_entries(&nodes.mem, scope()).await;
    let (_, disk_entries) = query_entries(&nodes.disk, scope()).await;
    assert_eq!(mem_entries, disk_entries);
}

/// One message per direct parent under a max-1 nested limit.
#[tokio::test]
async fn record_limit_nested_groups_bound_query_and_count() {
    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        put_limited_threads_protocol(TENANT, node.store()).await;

        let thread_data = payload("thread");
        let (code, thread_id) = write(
            node,
            WriteSpec {
                protocol: LIMITED_PROTOCOL.to_string(),
                protocol_path: "thread".to_string(),
                data_cid: generate_dag_pb_cid_from_bytes(&thread_data).to_string(),
                data_size: thread_data.len() as u64,
                published: Some(true),
                timestamp: T1.to_string(),
                date_created: T1.to_string(),
                ..WriteSpec::new(T1)
            },
            thread_data,
        )
        .await;
        assert_eq!(code, 202);

        for day in ["02", "03"] {
            let timestamp = format!("2025-01-{day}T00:00:00.000000Z");
            let data = payload(&format!("message-{day}"));
            let (code, _) = write(
                node,
                WriteSpec {
                    protocol: LIMITED_PROTOCOL.to_string(),
                    protocol_path: "thread/message".to_string(),
                    parent_id: Some(thread_id.clone()),
                    // Root records carry their record ID as context.
                    parent_context_id: Some(thread_id.clone()),
                    data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
                    data_size: data.len() as u64,
                    published: Some(true),
                    timestamp: timestamp.clone(),
                    date_created: timestamp.clone(),
                    ..WriteSpec::new(&timestamp)
                },
                data,
            )
            .await;
            assert_eq!(code, 202, "over-limit nested writes still admit");
        }

        let filter = limited_filter(json!({
            "protocolPath": "thread/message",
            "parentId": thread_id,
        }));
        let (status, entries) = query_entries(node, filter.clone()).await;
        assert_eq!(status, 200);
        assert_eq!(entries.len(), 1, "one occupant per direct parent");
        let (count_status, count) = count(node, filter).await;
        assert_eq!(count_status, 200);
        assert_eq!(count, 1);
    }
}

/// `published:false` with a published sort is a 400 on Query and Read.
#[tokio::test]
async fn published_false_with_published_sort_is_rejected() {
    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        populate(node).await;

        let query = json!({
            "descriptor": {
                "interface": "Records",
                "method": "Query",
                "messageTimestamp": T4,
                "filter": { "published": false },
                "dateSort": "publishedAscending",
            },
        });
        let reply = node.dwn().process_message(TENANT, query).await;
        assert_eq!(reply.status.code, 400);

        let read_message = json!({
            "descriptor": {
                "interface": "Records",
                "method": "Read",
                "messageTimestamp": T4,
                "filter": { "published": false },
                "dateSort": "publishedAscending",
            },
        });
        let (status, _) = read(node, read_message).await;
        assert_eq!(status, 400);
    }
}

/// A squash purges older siblings: occupancy recomputes from the accepted
/// state transition and no purged record leaks back into the population.
#[tokio::test]
async fn record_limit_squash_recomputes_from_current_state() {
    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        put_limited_threads_protocol(TENANT, node.store()).await;
        for day in ["01", "02"] {
            let (spec, data) = limited_post(day);
            let (code, _) = write(node, spec, data).await;
            assert_eq!(code, 202);
        }

        let squash_data = payload("post-squash");
        let (code, squash_id) = write(
            node,
            WriteSpec {
                protocol: LIMITED_PROTOCOL.to_string(),
                protocol_path: "post".to_string(),
                data_cid: generate_dag_pb_cid_from_bytes(&squash_data).to_string(),
                data_size: squash_data.len() as u64,
                published: Some(true),
                timestamp: "2025-01-04T00:00:00.000000Z".to_string(),
                date_created: "2025-01-04T00:00:00.000000Z".to_string(),
                squash: Some(true),
                ..WriteSpec::new("2025-01-04T00:00:00.000000Z")
            },
            squash_data,
        )
        .await;
        assert_eq!(code, 202, "squash write must admit");

        let scope = || limited_filter(json!({ "protocolPath": "post" }));
        let (status, entries) = query_entries(node, scope()).await;
        assert_eq!(status, 200);
        let visible: Vec<String> = entries
            .iter()
            .filter_map(|entry| entry["recordId"].as_str().map(str::to_string))
            .collect();
        assert_eq!(visible, vec![squash_id]);

        let (count_status, count) = count(node, scope()).await;
        assert_eq!(count_status, 200);
        assert_eq!(count, 1);
    }

    let scope = || limited_filter(json!({ "protocolPath": "post" }));
    let (_, mem_entries) = query_entries(&nodes.mem, scope()).await;
    let (_, disk_entries) = query_entries(&nodes.disk, scope()).await;
    assert_eq!(mem_entries, disk_entries);
}

/// A broad anonymous read whose top-1 is a non-occupant returns 404: checks
/// apply to the top-1 selection, matching upstream check-after-top-1 order.
#[tokio::test]
async fn broad_read_with_non_occupant_top1_returns_404() {
    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        put_limited_threads_protocol(TENANT, node.store()).await;
        for day in ["01", "02", "03"] {
            let (spec, data) = limited_post(day);
            let (code, _) = write(node, spec, data).await;
            assert_eq!(code, 202);
        }

        let read_message = json!({
            "descriptor": {
                "interface": "Records",
                "method": "Read",
                "messageTimestamp": T4,
                "filter": limited_filter(json!({ "protocolPath": "post" })),
                "dateSort": "updatedDescending",
            },
        });
        let (status, _) = read(node, read_message).await;
        assert_eq!(status, 404, "non-occupant top-1 is invisible");
    }
}

/// A broad signed read whose top-1 the requester cannot see returns 401.
#[tokio::test]
async fn broad_read_with_unauthorized_top1_returns_401() {
    use dwn_rs_core::cid::generate_cid_from_json;

    let nodes = fresh_nodes().await;
    for node in [&nodes.mem, &nodes.disk] {
        let hidden_data = payload("hidden-newest");
        let (code, _) = write(
            node,
            WriteSpec {
                data_cid: generate_dag_pb_cid_from_bytes(&hidden_data).to_string(),
                data_size: hidden_data.len() as u64,
                published: None,
                timestamp: T3.to_string(),
                date_created: T3.to_string(),
                ..WriteSpec::new(T3)
            },
            hidden_data,
        )
        .await;
        assert_eq!(code, 202);
        let visible_data = payload("visible-older");
        let (code, _) = write(
            node,
            WriteSpec {
                data_cid: generate_dag_pb_cid_from_bytes(&visible_data).to_string(),
                data_size: visible_data.len() as u64,
                published: Some(true),
                timestamp: T1.to_string(),
                date_created: T1.to_string(),
                ..WriteSpec::new(T1)
            },
            visible_data,
        )
        .await;
        assert_eq!(code, 202);

        let descriptor = json!({
            "interface": "Records",
            "method": "Read",
            "messageTimestamp": T4,
            "filter": { "dataFormat": "text/plain" },
            "dateSort": "updatedDescending",
        });
        let descriptor_cid = generate_cid_from_json(&descriptor).expect("descriptor CID");
        let signature = signature_for_descriptor(
            &descriptor,
            json!({ "descriptorCid": descriptor_cid.to_string() }),
            bob_signer(),
        )
        .await;
        let request = json!({
            "descriptor": descriptor,
            "authorization": { "signature": signature },
        });
        let (status, _) = read(node, request).await;
        assert_eq!(status, 401, "unauthorized top-1 is rejected");
    }
}
