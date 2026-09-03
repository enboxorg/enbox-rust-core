//! Backend-neutral conformance tests for the durable replication feed.
//!
//! Backend test modules call [`run`] with an async factory. The suite deliberately
//! uses only the public [`MessageStore`] and [`ReplicationFeedReader`] contracts.

use std::{collections::BTreeMap, future::Future};

use serde_json::json;

use super::{
    replication_feed_reader::{build_token, cid_contribution, xor_in_place, Fingerprint},
    EventLogReadOptions, KeyValues, LatestStateMutation, LatestStateTransition, MessageStore,
    ProgressGapReason, ReplicationFeedReader,
};
use crate::{
    descriptors::{DeleteDescriptor, Protocols, Records},
    errors::{EventLogError, MessageReplicationError, MessageStoreError, StoreError},
    fields::WriteFields,
    filters::{Filter, FilterKey, Filters},
    permissions::PERMISSIONS_PROTOCOL_URI,
    Descriptor, Fields, Message, ProgressToken, Value,
};

const TENANT: &str = "did:example:alice";
const OTHER_TENANT: &str = "did:example:bob";

/// Runs the complete durable-feed contract against stores returned by `factory`.
///
/// The factory is invoked once per scenario and may perform backend-specific
/// allocation, such as creating a temporary database. The returned store is
/// opened by the harness.
pub async fn run<S, F, Fut>(factory: F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    empty_feed(&factory).await;
    paging_resume_limits_and_filters(&factory).await;
    deletion_holes(&factory).await;
    duplicate_and_data_completion_updates(&factory).await;
    atomic_latest_state_transitions(&factory).await;
    clear_and_epochs(&factory).await;
    progress_gaps(&factory).await;
    eligible_message_types(&factory).await;
    fingerprints(&factory).await;
    perm_fingerprint_domain(&factory).await;
    multi_tenant_isolation(&factory).await;
    malformed_cursor_rejected(&factory).await;
    token_too_old_unreachable_without_retention(&factory).await;
    log_bounds_shape(&factory).await;
}

async fn atomic_latest_state_transitions<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    // Covers: DWN-REC-006
    let store = new_store(factory).await;
    let retained = delete_message("retained", "2025-01-01T00:00:00Z");
    let displaced = delete_message("displaced", "2025-01-01T00:00:01Z");
    let winner = delete_message("winner", "2025-01-01T00:00:02Z");
    let retained_cid = cid(&retained);
    let displaced_cid = cid(&displaced);
    let winner_cid = cid(&winner);

    store
        .put(
            TENANT,
            retained.clone(),
            indexes(None, None, "retained-old"),
        )
        .await
        .expect("seed retained message");
    store
        .put(TENANT, displaced, indexes(None, None, "displaced"))
        .await
        .expect("seed displaced message");

    let result = store
        .commit_latest_state(
            TENANT,
            LatestStateTransition {
                put: LatestStateMutation {
                    message: winner.clone(),
                    indexes: indexes(None, None, "winner"),
                },
                retains: vec![LatestStateMutation {
                    message: retained.clone(),
                    indexes: indexes(None, None, "retained-new"),
                }],
                deletes: vec![displaced_cid.clone()],
            },
        )
        .await
        .expect("atomic latest-state transition");

    assert_eq!(
        result
            .position
            .as_ref()
            .map(|token| token.position.as_str()),
        Some("3")
    );
    assert_eq!(
        result
            .position
            .as_ref()
            .and_then(|token| token.message_cid.as_deref()),
        Some(winner_cid.as_str())
    );
    assert!(store.get(TENANT, &retained_cid).await.unwrap().is_some());
    assert_eq!(store.get(TENANT, &displaced_cid).await.unwrap(), None);
    assert!(store.get(TENANT, &winner_cid).await.unwrap().is_some());

    let page = store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("read transitioned feed");
    assert_eq!(
        page.events
            .iter()
            .map(|event| (event.seq.as_str(), event.message_cid.as_deref()))
            .collect::<Vec<_>>(),
        [
            ("1", Some(retained_cid.as_str())),
            ("3", Some(winner_cid.as_str()))
        ]
    );
    assert_eq!(markers(&page), ["retained-new", "winner"]);

    // Covers: DWN-REC-003
    // Covers: DWN-REC-006
    let rollback_store = new_store(factory).await;
    let existing = delete_message("existing", "2025-02-01T00:00:00Z");
    let existing_cid = cid(&existing);
    rollback_store
        .put(
            TENANT,
            existing.clone(),
            indexes(Some("protocol-a"), None, "existing"),
        )
        .await
        .expect("seed rollback store");
    let rejected = delete_message("rejected", "2025-02-01T00:00:01Z");
    let rejected_cid = cid(&rejected);
    let error = rollback_store
        .commit_latest_state(
            TENANT,
            LatestStateTransition {
                put: LatestStateMutation {
                    message: rejected,
                    indexes: indexes(None, None, "rejected"),
                },
                retains: vec![LatestStateMutation {
                    message: existing.clone(),
                    indexes: indexes(Some("protocol-b"), None, "invalid-reindex"),
                }],
                deletes: vec![],
            },
        )
        .await
        .expect_err("fingerprint scope mutation must roll back");
    assert!(matches!(
        error,
        MessageStoreError::StoreError(StoreError::ReplicationError(
            MessageReplicationError::FingerprintScopesMismatch
        ))
    ));
    assert_eq!(
        rollback_store.get(TENANT, &rejected_cid).await.unwrap(),
        None
    );
    assert!(rollback_store
        .get(TENANT, &existing_cid)
        .await
        .unwrap()
        .is_some());
    let page = rollback_store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("read rolled-back feed");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].seq, "1");
    assert_eq!(markers(&page), ["existing"]);

    let invalid_store = new_store(factory).await;
    let put = delete_message("overlap", "2025-03-01T00:00:00Z");
    let put_cid = cid(&put);
    invalid_store
        .commit_latest_state(
            TENANT,
            LatestStateTransition {
                put: LatestStateMutation {
                    message: put,
                    indexes: indexes(None, None, "overlap"),
                },
                retains: vec![],
                deletes: vec![put_cid.clone()],
            },
        )
        .await
        .expect_err("put/delete overlap must be rejected");
    assert_eq!(invalid_store.get(TENANT, &put_cid).await.unwrap(), None);
    assert!(invalid_store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("read invalid transition store")
        .events
        .is_empty());

    let candidate = delete_message("candidate", "2025-03-01T00:00:01Z");
    let candidate_cid = cid(&candidate);
    let missing = delete_message("missing", "2025-03-01T00:00:00Z");
    invalid_store
        .commit_latest_state(
            TENANT,
            LatestStateTransition {
                put: LatestStateMutation {
                    message: candidate,
                    indexes: indexes(None, None, "candidate"),
                },
                retains: vec![LatestStateMutation {
                    message: missing,
                    indexes: indexes(None, None, "missing"),
                }],
                deletes: vec![],
            },
        )
        .await
        .expect_err("missing retain must roll back");
    assert_eq!(
        invalid_store.get(TENANT, &candidate_cid).await.unwrap(),
        None
    );
}

async fn new_store<S, F, Fut>(factory: &F) -> S
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = factory().await;
    store.open().await.expect("conformance store must open");
    store
}

fn delete_message(record_id: &str, timestamp: &str) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Records(Box::new(Records::Delete(Box::new(DeleteDescriptor {
            message_timestamp: timestamp.parse().expect("valid fixture timestamp"),
            record_id: record_id.to_string(),
            prune: false,
        })))),
        fields: Fields::Authorization(Default::default()),
    }
}

fn write_message(encoded_data: Option<&str>) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Records(Box::new(Records::Write(Default::default()))),
        fields: Fields::Write(WriteFields {
            encoded_data: encoded_data.map(str::to_string),
            ..Default::default()
        }),
    }
}

fn non_feed_message(timestamp: &str) -> Message<Descriptor> {
    serde_json::from_value(json!({
        "descriptor": {
            "interface": "Messages",
            "method": "Query",
            "messageTimestamp": timestamp,
        },
        "authorization": { "signature": {} },
    }))
    .expect("valid non-feed fixture")
}

fn cid(message: &Message<Descriptor>) -> String {
    message.cid().expect("fixture must have a CID").to_string()
}

fn indexes(protocol: Option<&str>, schema: Option<&str>, marker: &str) -> KeyValues {
    let mut indexes = KeyValues::new();
    indexes.insert("marker".to_string(), Value::String(marker.to_string()));
    if let Some(protocol) = protocol {
        indexes.insert("protocol".to_string(), Value::String(protocol.to_string()));
    }
    if let Some(schema) = schema {
        indexes.insert("schema".to_string(), Value::String(schema.to_string()));
    }
    indexes
}

fn equal(key: &str, value: &str) -> (FilterKey, Filter<Value>) {
    (
        FilterKey::Index(key.to_string()),
        Filter::Equal(Value::String(value.to_string())),
    )
}

fn markers(result: &super::EventLogReadResult) -> Vec<&str> {
    result
        .events
        .iter()
        .map(|entry| match entry.indexes.get("marker") {
            Some(Value::String(marker)) => marker.as_str(),
            other => panic!("event marker must be a string, got {other:?}"),
        })
        .collect()
}

fn assert_gap(error: EventLogError, expected: ProgressGapReason) {
    let EventLogError::ProgressGap(gap) = error else {
        panic!("expected progress gap, got {error:?}");
    };
    assert_eq!(gap.reason, expected);
}

async fn empty_feed<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    let epoch = store.epoch().await.expect("epoch");
    assert!(!epoch.is_empty());
    assert_eq!(store.log_bounds(TENANT).await.expect("bounds"), None);

    let page = store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("empty read");
    assert!(page.events.is_empty());
    assert!(page.drained);
    assert_eq!(page.cursor, Some(build_token(TENANT, &epoch, 0, None)));
}

async fn paging_resume_limits_and_filters<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    for (position, (protocol, schema)) in [("p1", "s1"), ("p1", "s2"), ("p2", "s2")]
        .into_iter()
        .enumerate()
    {
        let marker = format!("m{}", position + 1);
        store
            .put(
                TENANT,
                delete_message(&marker, &format!("2025-01-01T00:00:0{position}Z")),
                indexes(Some(protocol), Some(schema), &marker),
            )
            .await
            .expect("feed put");
    }

    let first = store
        .log_read(
            TENANT,
            EventLogReadOptions {
                limit: Some(2),
                ..Default::default()
            },
        )
        .await
        .expect("first page");
    assert_eq!(markers(&first), ["m1", "m2"]);
    assert!(!first.drained);
    assert_eq!(first.cursor.as_ref().expect("cursor").position, "2");

    let resumed = store
        .log_read(
            TENANT,
            EventLogReadOptions {
                cursor: first.cursor,
                ..Default::default()
            },
        )
        .await
        .expect("exclusive resume");
    assert_eq!(markers(&resumed), ["m3"]);
    assert!(resumed.drained);

    let epoch = store.epoch().await.expect("epoch");
    let anchor = build_token(TENANT, &epoch, 0, None);
    let zero = store
        .log_read(
            TENANT,
            EventLogReadOptions {
                cursor: Some(anchor.clone()),
                limit: Some(0),
                filters: None,
            },
        )
        .await
        .expect("zero-limit read");
    assert!(zero.events.is_empty());
    assert_eq!(zero.cursor, Some(anchor));
    assert!(!zero.drained);

    let filters = Filters::from(vec![
        BTreeMap::from([equal("protocol", "p1"), equal("schema", "s1")]),
        BTreeMap::from([equal("protocol", "p2"), equal("schema", "s2")]),
    ]);
    let filtered = store
        .log_read(
            TENANT,
            EventLogReadOptions {
                filters: Some(filters),
                ..Default::default()
            },
        )
        .await
        .expect("OR/AND filtered read");
    assert_eq!(markers(&filtered), ["m1", "m3"]);
    assert!(filtered.drained);
    assert_eq!(filtered.cursor.as_ref().expect("cursor").position, "3");
    assert_eq!(
        filtered.cursor.as_ref().expect("cursor").message_cid,
        filtered.events.last().expect("last event").message_cid
    );

    let high_water = store
        .log_read(
            TENANT,
            EventLogReadOptions {
                filters: Some(Filters::from(BTreeMap::from([equal("marker", "m2")]))),
                ..Default::default()
            },
        )
        .await
        .expect("filtered high-water read");
    assert_eq!(markers(&high_water), ["m2"]);
    assert!(high_water.drained);
    assert_eq!(high_water.cursor.as_ref().expect("cursor").position, "3");
    assert_eq!(high_water.cursor.expect("cursor").message_cid, None);
}

async fn deletion_holes<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    let messages = [
        delete_message("one", "2025-01-01T00:00:00Z"),
        delete_message("two", "2025-01-01T00:00:01Z"),
        delete_message("three", "2025-01-01T00:00:02Z"),
    ];
    let cids = messages.iter().map(cid).collect::<Vec<_>>();
    for (index, message) in messages.into_iter().enumerate() {
        store
            .put(TENANT, message, indexes(None, None, &format!("m{index}")))
            .await
            .expect("feed put");
    }

    store.delete(TENANT, &cids[1]).await.expect("delete hole");
    let page = store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("read across hole");
    assert_eq!(
        page.events
            .iter()
            .map(|entry| entry.seq.as_str())
            .collect::<Vec<_>>(),
        ["1", "3"]
    );

    store.delete(TENANT, &cids[2]).await.expect("delete head");
    let (_, latest) = store
        .log_bounds(TENANT)
        .await
        .expect("bounds")
        .expect("non-empty position history");
    assert_eq!(latest.position, "3");
    assert_eq!(latest.message_cid, None);
}

async fn duplicate_and_data_completion_updates<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    let duplicate = delete_message("duplicate", "2025-01-01T00:00:00Z");
    store
        .put(TENANT, duplicate.clone(), indexes(None, None, "old"))
        .await
        .expect("initial put");
    store
        .put(TENANT, duplicate, indexes(None, None, "updated"))
        .await
        .expect("duplicate put");
    let page = store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("duplicate read");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].seq, "1");
    assert_eq!(markers(&page), ["updated"]);

    let without_data = write_message(None);
    let with_data = write_message(Some("dGVzdA=="));
    assert_eq!(cid(&without_data), cid(&with_data));
    let write_cid = cid(&without_data);
    store
        .put(TENANT, without_data, indexes(None, None, "write"))
        .await
        .expect("write metadata put");
    store
        .put(TENANT, with_data.clone(), indexes(None, None, "write"))
        .await
        .expect("data completion put");

    let completed = store
        .log_read(
            TENANT,
            EventLogReadOptions {
                cursor: Some(page.cursor.expect("duplicate cursor")),
                ..Default::default()
            },
        )
        .await
        .expect("completed data read");
    assert_eq!(completed.events.len(), 1);
    assert_eq!(completed.events[0].seq, "2");
    assert_eq!(
        completed.events[0].encoded_data.as_deref(),
        Some("dGVzdA==")
    );
    assert_eq!(
        store.get(TENANT, &write_cid).await.expect("get"),
        Some(with_data)
    );
}

async fn clear_and_epochs<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    store
        .put(
            TENANT,
            delete_message("before-clear", "2025-01-01T00:00:00Z"),
            indexes(None, None, "before"),
        )
        .await
        .expect("put");
    let old_epoch = store.epoch().await.expect("old epoch");
    let old_cursor = store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("read")
        .cursor
        .expect("cursor");

    store.clear().await.expect("clear");
    let new_epoch = store.epoch().await.expect("new epoch");
    assert!(!new_epoch.is_empty());
    assert_ne!(new_epoch, old_epoch);
    assert_gap(
        store
            .log_read(
                TENANT,
                EventLogReadOptions {
                    cursor: Some(old_cursor),
                    ..Default::default()
                },
            )
            .await
            .expect_err("old epoch must be rejected"),
        ProgressGapReason::EpochMismatch,
    );

    store
        .put(
            TENANT,
            delete_message("after-clear", "2025-01-01T00:00:01Z"),
            indexes(None, None, "after"),
        )
        .await
        .expect("post-clear put");
    let restarted = store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("post-clear read");
    assert_eq!(restarted.events[0].seq, "1");
}

async fn progress_gaps<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    let message = delete_message("gap", "2025-01-01T00:00:00Z");
    let message_cid = cid(&message);
    store
        .put(TENANT, message, indexes(None, None, "gap"))
        .await
        .expect("put");
    let epoch = store.epoch().await.expect("epoch");

    let cases = [
        (
            ProgressToken {
                stream_id: "wrong-stream".to_string(),
                epoch: epoch.clone(),
                position: "0".to_string(),
                message_cid: None,
            },
            ProgressGapReason::StreamMismatch,
        ),
        (
            build_token(TENANT, &epoch, 2, None),
            ProgressGapReason::TokenTooNew,
        ),
        (
            build_token(TENANT, &epoch, 1, Some("wrong-cid")),
            ProgressGapReason::MessageMismatch,
        ),
    ];

    for (cursor, reason) in cases {
        assert_gap(
            store
                .log_read(
                    TENANT,
                    EventLogReadOptions {
                        cursor: Some(cursor),
                        ..Default::default()
                    },
                )
                .await
                .expect_err("invalid cursor must fail"),
            reason,
        );
    }

    let valid = build_token(TENANT, &epoch, 1, Some(&message_cid));
    assert!(
        store
            .log_read(
                TENANT,
                EventLogReadOptions {
                    cursor: Some(valid),
                    ..Default::default()
                },
            )
            .await
            .expect("valid cursor")
            .drained
    );
}

async fn eligible_message_types<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    let eligible = [
        write_message(None),
        delete_message("eligible-delete", "2025-01-01T00:00:00Z"),
        Message {
            descriptor: Descriptor::Protocols(Box::new(Protocols::Configure(Default::default()))),
            fields: Fields::Authorization(Default::default()),
        },
    ];
    for (index, message) in eligible.into_iter().enumerate() {
        store
            .put(TENANT, message, indexes(None, None, &format!("e{index}")))
            .await
            .expect("eligible put");
    }
    store
        .put(
            TENANT,
            non_feed_message("2025-01-01T00:00:01Z"),
            indexes(None, None, "not-eligible"),
        )
        .await
        .expect("non-feed put");

    let page = store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("eligibility read");
    assert_eq!(markers(&page), ["e0", "e1", "e2"]);
    assert_eq!(page.cursor.expect("cursor").position, "3");
}

async fn fingerprints<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    let first = delete_message("fp-one", "2025-01-01T00:00:00Z");
    let second = delete_message("fp-two", "2025-01-01T00:00:01Z");
    let first_cid = cid(&first);
    let second_cid = cid(&second);

    let zero = store
        .fingerprint(TENANT, &["".to_string()])
        .await
        .expect("zero fingerprint");
    assert_eq!(zero, Fingerprint::default());
    assert_eq!(zero.to_string(), "0".repeat(64));

    store
        .put(TENANT, first, indexes(Some("a"), None, "one"))
        .await
        .expect("first put");
    store
        .put(TENANT, second, indexes(Some("b"), None, "two"))
        .await
        .expect("second put");

    let mut expected_global = cid_contribution(&first_cid);
    xor_in_place(&mut expected_global, &cid_contribution(&second_cid));
    assert_eq!(
        store
            .fingerprint(TENANT, &["".to_string()])
            .await
            .expect("global fingerprint"),
        expected_global
    );
    assert_eq!(
        store
            .fingerprint(TENANT, &["protocol:a".to_string()])
            .await
            .expect("scoped fingerprint"),
        cid_contribution(&first_cid)
    );

    let normalized = store
        .fingerprint(
            TENANT,
            &[
                "protocol:a".to_string(),
                "".to_string(),
                "protocol:a".to_string(),
            ],
        )
        .await
        .expect("normalized fingerprint");
    let reordered = store
        .fingerprint(TENANT, &["".to_string(), "protocol:a".to_string()])
        .await
        .expect("reordered fingerprint");
    assert_eq!(normalized, reordered);
    assert_eq!(normalized.to_string().len(), 64);
    assert!(normalized
        .to_string()
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));

    store.delete(TENANT, &first_cid).await.expect("delete");
    assert_eq!(
        store
            .fingerprint(TENANT, &["protocol:a".to_string()])
            .await
            .expect("fingerprint after delete"),
        Fingerprint::default()
    );
}

#[tokio::test]
async fn memory_message_store_conforms_to_replication_feed_contract() {
    run(|| async { super::memory::MemoryMessageStore::default() }).await;
}

async fn perm_fingerprint_domain<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    let target = "https://example.com/protocol/notes";
    let message = delete_message("perm-grant", "2025-01-01T00:00:00Z");
    let message_cid = cid(&message);
    let mut permission_indexes = indexes(Some(PERMISSIONS_PROTOCOL_URI), None, "perm");
    permission_indexes.insert(
        "tag.protocol".to_string(),
        Value::String(target.to_string()),
    );
    store
        .put(TENANT, message, permission_indexes)
        .await
        .expect("feed put");

    let expected = cid_contribution(&message_cid);
    for scope in [
        "".to_string(),
        format!("protocol:{PERMISSIONS_PROTOCOL_URI}"),
        format!("perm:{target}"),
    ] {
        assert_eq!(
            store
                .fingerprint(TENANT, std::slice::from_ref(&scope))
                .await
                .expect("perm fingerprint"),
            expected,
            "scope {scope} must carry the contribution"
        );
    }
    assert_eq!(
        store
            .fingerprint(TENANT, &["perm:https://example.com/other".to_string()])
            .await
            .expect("unrelated perm fingerprint"),
        Fingerprint::default()
    );
}

async fn multi_tenant_isolation<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    let message = delete_message("tenant-one", "2025-01-01T00:00:00Z");
    let message_cid = cid(&message);
    store
        .put(TENANT, message, indexes(None, None, "t1"))
        .await
        .expect("feed put");

    let epoch = store.epoch().await.expect("epoch");
    let other = store
        .log_read(OTHER_TENANT, EventLogReadOptions::default())
        .await
        .expect("other-tenant read");
    assert!(other.events.is_empty());
    assert!(other.drained);
    assert_eq!(
        other.cursor,
        Some(build_token(OTHER_TENANT, &epoch, 0, None))
    );
    assert_eq!(
        store
            .log_bounds(OTHER_TENANT)
            .await
            .expect("other-tenant bounds"),
        None
    );

    let alice_cursor = build_token(TENANT, &epoch, 1, Some(&message_cid));
    assert_gap(
        store
            .log_read(
                OTHER_TENANT,
                EventLogReadOptions {
                    cursor: Some(alice_cursor),
                    ..Default::default()
                },
            )
            .await
            .expect_err("cross-tenant cursor must fail"),
        ProgressGapReason::StreamMismatch,
    );
}

async fn malformed_cursor_rejected<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    store
        .put(
            TENANT,
            delete_message("malformed", "2025-01-01T00:00:00Z"),
            indexes(None, None, "m"),
        )
        .await
        .expect("feed put");
    let epoch = store.epoch().await.expect("epoch");

    for position in ["", "00", "01", "-1", " 1", "18446744073709551616"] {
        let error = store
            .log_read(
                TENANT,
                EventLogReadOptions {
                    cursor: Some(ProgressToken {
                        position: position.to_string(),
                        ..build_token(TENANT, &epoch, 0, None)
                    }),
                    ..Default::default()
                },
            )
            .await
            .expect_err("malformed position must fail");
        let EventLogError::InvalidProgressToken(value) = error else {
            panic!("expected InvalidProgressToken, got {error:?}");
        };
        assert_eq!(value, position);
    }
}

async fn token_too_old_unreachable_without_retention<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    // Neither backend implements retention trimming (`oldest_replayable` is
    // hardcoded 0 with a `// todo: retention policy`), so TokenTooOld is
    // unreachable. Pin the zero anchor as valid so a future retention change
    // must update this test deliberately rather than silently.
    let store = new_store(factory).await;
    store
        .put(
            TENANT,
            delete_message("retention", "2025-01-01T00:00:00Z"),
            indexes(None, None, "m"),
        )
        .await
        .expect("feed put");
    let epoch = store.epoch().await.expect("epoch");

    let page = store
        .log_read(
            TENANT,
            EventLogReadOptions {
                cursor: Some(build_token(TENANT, &epoch, 0, None)),
                ..Default::default()
            },
        )
        .await
        .expect("zero anchor stays valid");
    assert_eq!(page.events.len(), 1);
    assert!(page.drained);
}

async fn log_bounds_shape<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    assert_eq!(store.log_bounds(TENANT).await.expect("empty bounds"), None);

    let second = delete_message("bounds-two", "2025-01-01T00:00:01Z");
    let second_cid = cid(&second);
    for (index, message) in [delete_message("bounds-one", "2025-01-01T00:00:00Z"), second]
        .into_iter()
        .enumerate()
    {
        store
            .put(TENANT, message, indexes(None, None, &format!("b{index}")))
            .await
            .expect("feed put");
    }

    let epoch = store.epoch().await.expect("epoch");
    let (oldest, latest) = store
        .log_bounds(TENANT)
        .await
        .expect("bounds")
        .expect("non-empty bounds");
    assert_eq!(oldest, build_token(TENANT, &epoch, 0, None));
    assert_eq!(latest, build_token(TENANT, &epoch, 2, Some(&second_cid)));
}
