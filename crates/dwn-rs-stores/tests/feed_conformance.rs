//! Durable feed wire-contract battery for issue #169.
//!
//! The eight-scenario shared suite in `replication_feed_conformance::run`
//! already covers memory (core) and sqlite-mem (sqlite unit test). C2 adds:
//! - the same suite on sqlite-disk (real file, fresh handle per scenario),
//! - new cases absent from the shared suite, run on all three backends
//!   (memory × sqlite-mem × sqlite-disk): `perm:` fingerprint domain,
//!   multi-tenant isolation, malformed-cursor rejection, the
//!   TokenTooOld-unreachable pin, and `log_bounds` shape.
//!
//! `cidsOnly` is a MessagesQuery handler projection, not a feed property — it
//! belongs to C7 visibility, not here.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dwn_rs_core::descriptors::{DeleteDescriptor, Records};
use dwn_rs_core::errors::EventLogError;
use dwn_rs_core::permissions::PERMISSIONS_PROTOCOL_URI;
use dwn_rs_core::stores::memory::MemoryMessageStore;
use dwn_rs_core::stores::replication_feed_conformance;
use dwn_rs_core::stores::replication_feed_reader::{build_token, cid_contribution, Fingerprint};
use dwn_rs_core::stores::wake::WakePublishHandler;
use dwn_rs_core::stores::{
    EventLogReadOptions, KeyValues, MessageStore, ProgressGapReason, ReplicationFeedReader,
};
use dwn_rs_core::{Descriptor, Fields, Message, ProgressToken, Value};

use common::TempDb;
use dwn_rs_stores::SqliteStore;

const TENANT: &str = "did:example:alice";
const OTHER_TENANT: &str = "did:example:bob";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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

fn cid(message: &Message<Descriptor>) -> String {
    message
        .message_cid()
        .expect("fixture must have a CID")
        .to_string()
}

fn indexes(protocol: Option<&str>, tag_protocol: Option<&str>, marker: &str) -> KeyValues {
    let mut out = KeyValues::new();
    out.insert("marker".to_string(), Value::String(marker.to_string()));
    if let Some(protocol) = protocol {
        out.insert("protocol".to_string(), Value::String(protocol.to_string()));
    }
    if let Some(tagged) = tag_protocol {
        out.insert(
            "tag.protocol".to_string(),
            Value::String(tagged.to_string()),
        );
    }
    out
}

fn assert_gap(error: EventLogError, expected: ProgressGapReason) {
    let EventLogError::ProgressGap(gap) = error else {
        panic!("expected progress gap, got {error:?}");
    };
    assert_eq!(gap.reason, expected);
}

// ---------------------------------------------------------------------------
// Full shared suite on sqlite-disk (memory + sqlite-mem covered elsewhere)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn feed_contract_sqlite_disk() {
    let dir = tempfile::tempdir().expect("battery tempdir");
    let seq = AtomicU64::new(0);
    replication_feed_conformance::run(|| async {
        let n = seq.fetch_add(1, Ordering::Relaxed);
        SqliteStore::new(
            dir.path().join(format!("feed-{n}.sqlite")),
            WakePublishHandler::new(Arc::new(())),
        )
    })
    .await;
}

// ---------------------------------------------------------------------------
// New cases (generic over backend)
// ---------------------------------------------------------------------------

async fn case_perm_fingerprint_domain<S>(store: &S)
where
    S: MessageStore + ReplicationFeedReader,
{
    let target = "https://example.com/protocol/notes";
    let msg = delete_message("perm-grant", "2025-01-01T00:00:00Z");
    let msg_cid = cid(&msg);
    let msg_indexes = indexes(Some(PERMISSIONS_PROTOCOL_URI), Some(target), "perm");

    MessageStore::put(store, TENANT, msg, msg_indexes)
        .await
        .expect("feed put");

    let expected = cid_contribution(&msg_cid);
    assert_eq!(
        store
            .fingerprint(TENANT, &["".to_string()])
            .await
            .expect("global fingerprint"),
        expected
    );
    assert_eq!(
        store
            .fingerprint(TENANT, &[format!("protocol:{PERMISSIONS_PROTOCOL_URI}")])
            .await
            .expect("protocol fingerprint"),
        expected
    );
    assert_eq!(
        store
            .fingerprint(TENANT, &[format!("perm:{target}")])
            .await
            .expect("perm fingerprint"),
        expected
    );
    // An unrelated perm domain stays zero.
    assert_eq!(
        store
            .fingerprint(TENANT, &["perm:https://example.com/other".to_string()])
            .await
            .expect("unrelated perm fingerprint"),
        Fingerprint::default()
    );
}

async fn case_multi_tenant_isolation<S>(store: &S)
where
    S: MessageStore + ReplicationFeedReader,
{
    let msg = delete_message("tenant-one", "2025-01-01T00:00:00Z");
    let msg_cid = cid(&msg);
    MessageStore::put(store, TENANT, msg, indexes(None, None, "t1"))
        .await
        .expect("feed put");

    // Other tenant sees an empty, drained feed at the zero anchor.
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

    // Alice's cursor is meaningless on Bob's stream.
    let alice_cursor = build_token(TENANT, &epoch, 1, Some(&msg_cid));
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

async fn case_malformed_cursor_rejected<S>(store: &S)
where
    S: MessageStore + ReplicationFeedReader,
{
    let msg = delete_message("malformed", "2025-01-01T00:00:00Z");
    MessageStore::put(store, TENANT, msg, indexes(None, None, "m"))
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

async fn case_token_too_old_unreachable_without_retention<S>(store: &S)
where
    S: MessageStore + ReplicationFeedReader,
{
    // Neither backend implements retention trimming (`oldest_replayable` is
    // hardcoded 0 with a `// todo: retention policy`), so TokenTooOld is
    // unreachable. Pin the zero anchor as valid so a future retention change
    // must update this test deliberately rather than silently.
    let msg = delete_message("retention", "2025-01-01T00:00:00Z");
    MessageStore::put(store, TENANT, msg, indexes(None, None, "m"))
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

async fn case_log_bounds_shape<S>(store: &S)
where
    S: MessageStore + ReplicationFeedReader,
{
    assert_eq!(store.log_bounds(TENANT).await.expect("empty bounds"), None);

    let first = delete_message("bounds-one", "2025-01-01T00:00:00Z");
    let second = delete_message("bounds-two", "2025-01-01T00:00:01Z");
    let second_cid = cid(&second);
    for (index, msg) in [first, second].into_iter().enumerate() {
        MessageStore::put(
            store,
            TENANT,
            msg,
            indexes(None, None, &format!("b{index}")),
        )
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

// ---------------------------------------------------------------------------
// Backend wiring: memory × sqlite-mem × sqlite-disk
// ---------------------------------------------------------------------------

macro_rules! feed_battery {
    ($mem:ident, $sqlite_mem:ident, $sqlite_disk:ident, $case:ident) => {
        #[tokio::test]
        async fn $mem() {
            let mut store = MemoryMessageStore::default();
            MessageStore::open(&mut store).await.unwrap();
            $case(&store).await;
        }

        #[tokio::test]
        async fn $sqlite_mem() {
            let store = common::open_sqlite_mem().await;
            $case(&store).await;
        }

        #[tokio::test]
        async fn $sqlite_disk() {
            let db = TempDb::new(stringify!($sqlite_disk));
            let store = common::open_sqlite_disk(&db).await;
            $case(&store).await;
        }
    };
}

feed_battery!(
    perm_fingerprint_domain_memory,
    perm_fingerprint_domain_sqlite_mem,
    perm_fingerprint_domain_sqlite_disk,
    case_perm_fingerprint_domain
);
feed_battery!(
    multi_tenant_isolation_memory,
    multi_tenant_isolation_sqlite_mem,
    multi_tenant_isolation_sqlite_disk,
    case_multi_tenant_isolation
);
feed_battery!(
    malformed_cursor_rejected_memory,
    malformed_cursor_rejected_sqlite_mem,
    malformed_cursor_rejected_sqlite_disk,
    case_malformed_cursor_rejected
);
feed_battery!(
    token_too_old_unreachable_memory,
    token_too_old_unreachable_sqlite_mem,
    token_too_old_unreachable_sqlite_disk,
    case_token_too_old_unreachable_without_retention
);
feed_battery!(
    log_bounds_shape_memory,
    log_bounds_shape_sqlite_mem,
    log_bounds_shape_sqlite_disk,
    case_log_bounds_shape
);
