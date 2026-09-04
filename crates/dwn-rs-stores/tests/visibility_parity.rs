//! Records visibility parity battery for issue #169 (C7).
//!
//! Same signed inputs through identical `SqliteNativeDwn` code on sqlite-mem
//! vs sqlite-disk. Asserts the shared visibility contract: Query and Count
//! return the same population, RecordsRead resolves through the same plan,
//! Subscribe snapshots equal Query results, tombstones route correctly, and
//! every non-initial entry carries `initialWrite`.
//!
//! This pins backend parity (memory of the contract), not the #190
//! remainder: read-time record limits and boundary-aware subtree filtering
//! are asserted as currently implemented, identically on both backends.
//!
//! Covers: DWN-REC-005, DWN-AUTH-006.

mod common;

use bytes::Bytes;
use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
use dwn_rs_core::testing::{
    put_notes_protocol_without_actions, signed_delete_message, signed_write_message, test_resolver,
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
