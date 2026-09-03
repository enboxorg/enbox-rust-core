//! True file-backed reopen tests for issue #169.
//!
//! Unlike the earlier same-handle "reopen" tests, every test here closes and
//! drops its store (or node) and reopens the same file with a **fresh**
//! handle, proving real-disk durability: epochs, bounds, positions, cursors,
//! fingerprints, ledger checkpoints, and node state.
//!
//! Covers: DWN-REC-006 (no split-brain across restart), DWN-SYNC-001/005
//! (resume from durable cursors/checkpoints).

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::Utc;
use dwn_rs_core::auth::{ed25519_jwk, StaticPublicKeyResolver};
use dwn_rs_core::descriptors::{DeleteDescriptor, Records};
use dwn_rs_core::stores::replication_feed_reader::Fingerprint;
use dwn_rs_core::stores::wake::WakePublishHandler;
use dwn_rs_core::stores::{
    EventLogReadOptions, KeyValues, MessageStore, ReplicationFeedReader, ResumableTaskStore,
    StateIndex,
};
use dwn_rs_core::sync::ledger::SyncLedger;
use dwn_rs_core::sync::{SyncCheckpoint, SyncDirection};
use dwn_rs_core::{Descriptor, Fields, Message, Value};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use common::TempDb;
use dwn_rs_stores::{
    SqliteNativeDwn, SqliteResumableTaskStore, SqliteStateIndex, SqliteStore, SqliteSyncLedger,
};

const TENANT: &str = "did:example:alice";
const OTHER_TENANT: &str = "did:example:bob";
const PROTOCOL_NOTES: &str = "https://example.com/protocol/notes";
const PROTOCOL_TASKS: &str = "https://example.com/protocol/tasks";

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

fn indexes(protocol: Option<&str>, marker: &str) -> KeyValues {
    let mut out = KeyValues::new();
    out.insert("marker".to_string(), Value::String(marker.to_string()));
    if let Some(protocol) = protocol {
        out.insert("protocol".to_string(), Value::String(protocol.to_string()));
    }
    out
}

fn noop_waker() -> WakePublishHandler {
    WakePublishHandler::new(Arc::new(()))
}

async fn full_read(store: &SqliteStore, tenant: &str) -> Vec<(String, String)> {
    store
        .log_read(tenant, EventLogReadOptions::default())
        .await
        .expect("feed read")
        .events
        .into_iter()
        .map(|entry| (entry.seq, entry.message_cid.expect("feed entry has a CID")))
        .collect()
}

fn test_resolver() -> StaticPublicKeyResolver {
    StaticPublicKeyResolver::new(BTreeMap::from([(
        "did:example:alice#key1".to_string(),
        ed25519_jwk(
            "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            None,
            Some("did:example:alice#key1"),
        )
        .unwrap(),
    )]))
}

#[tokio::test]
async fn message_feed_multi_tenant_state_survives_fresh_reopen() {
    let db = TempDb::new("message-feed-multi-tenant");
    let alice = [
        delete_message("a1", "2025-01-01T00:00:00Z"),
        delete_message("a2", "2025-01-01T00:00:01Z"),
        delete_message("a3", "2025-01-01T00:00:02Z"),
    ];
    let bob = [
        delete_message("b1", "2025-01-01T00:00:00Z"),
        delete_message("b2", "2025-01-01T00:00:01Z"),
    ];

    let (epoch, alice_bounds, bob_bounds, alice_feed, bob_feed, alice_fp, cursor) = {
        let mut store = SqliteStore::new(db.path(), noop_waker());
        MessageStore::open(&mut store).await.unwrap();
        for (index, msg) in alice.iter().enumerate() {
            let protocol = if index < 2 {
                PROTOCOL_NOTES
            } else {
                PROTOCOL_TASKS
            };
            MessageStore::put(
                &store,
                TENANT,
                msg.clone(),
                indexes(Some(protocol), &format!("a{index}")),
            )
            .await
            .expect("alice put");
        }
        for (index, msg) in bob.iter().enumerate() {
            MessageStore::put(
                &store,
                OTHER_TENANT,
                msg.clone(),
                indexes(Some(PROTOCOL_NOTES), &format!("b{index}")),
            )
            .await
            .expect("bob put");
        }
        let epoch = store.epoch().await.expect("epoch");
        let alice_bounds = store.log_bounds(TENANT).await.expect("alice bounds");
        let bob_bounds = store.log_bounds(OTHER_TENANT).await.expect("bob bounds");
        let alice_feed = full_read(&store, TENANT).await;
        let bob_feed = full_read(&store, OTHER_TENANT).await;
        let alice_fp = store
            .fingerprint(TENANT, &["".to_string()])
            .await
            .expect("global fingerprint");
        let cursor = store
            .log_read(TENANT, EventLogReadOptions::default())
            .await
            .expect("cursor read")
            .cursor;
        MessageStore::close(&mut store).await;
        (
            epoch,
            alice_bounds,
            bob_bounds,
            alice_feed,
            bob_feed,
            alice_fp,
            cursor,
        )
    };
    let mut reopened = SqliteStore::new(db.path(), noop_waker());
    MessageStore::open(&mut reopened).await.unwrap();

    assert_eq!(reopened.epoch().await.expect("epoch"), epoch);
    assert_eq!(
        reopened.log_bounds(TENANT).await.expect("alice bounds"),
        alice_bounds
    );
    assert_eq!(
        reopened.log_bounds(OTHER_TENANT).await.expect("bob bounds"),
        bob_bounds
    );
    assert_eq!(full_read(&reopened, TENANT).await, alice_feed);
    assert_eq!(full_read(&reopened, OTHER_TENANT).await, bob_feed);
    assert_eq!(
        reopened
            .fingerprint(TENANT, &["".to_string()])
            .await
            .expect("global fingerprint"),
        alice_fp
    );
    assert_ne!(alice_fp, Fingerprint::default());

    // The pre-restart cursor still resumes to a drained, empty page.
    let resumed = reopened
        .log_read(
            TENANT,
            EventLogReadOptions {
                cursor,
                ..Default::default()
            },
        )
        .await
        .expect("resume after reopen");
    assert!(resumed.events.is_empty());
    assert!(resumed.drained);
}

/// Fresh handles on the same file keep working after this point because the
/// `TempDb` guard in each test outlives them.

#[tokio::test]
async fn delete_holes_survive_fresh_reopen() {
    let db = TempDb::new("delete-holes");
    let messages = [
        delete_message("one", "2025-01-01T00:00:00Z"),
        delete_message("two", "2025-01-01T00:00:01Z"),
        delete_message("three", "2025-01-01T00:00:02Z"),
    ];
    let cids: Vec<String> = messages.iter().map(cid).collect();

    {
        let mut store = SqliteStore::new(db.path(), noop_waker());
        MessageStore::open(&mut store).await.unwrap();
        for (index, msg) in messages.into_iter().enumerate() {
            MessageStore::put(&store, TENANT, msg, indexes(None, &format!("m{index}")))
                .await
                .expect("feed put");
        }
        store.delete(TENANT, &cids[1]).await.expect("delete hole");
        store.delete(TENANT, &cids[2]).await.expect("delete head");
        MessageStore::close(&mut store).await;
    }

    let mut reopened = SqliteStore::new(db.path(), noop_waker());
    MessageStore::open(&mut reopened).await.unwrap();

    let page = reopened
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("read across holes");
    assert_eq!(
        page.events
            .iter()
            .map(|entry| entry.seq.as_str())
            .collect::<Vec<_>>(),
        ["1"]
    );
    let (_, latest) = reopened
        .log_bounds(TENANT)
        .await
        .expect("bounds")
        .expect("non-empty history");
    assert_eq!(latest.position, "3");
    assert_eq!(latest.message_cid, None);
}

#[tokio::test]
async fn sync_ledger_checkpoints_survive_true_db_reopen() {
    let db = TempDb::new("sync-ledger-true-reopen");
    let cursor = {
        let mut store = SqliteStore::new(db.path(), noop_waker());
        MessageStore::open(&mut store).await.unwrap();
        let msg = delete_message("ledger", "2025-01-01T00:00:00Z");
        MessageStore::put(&store, TENANT, msg, indexes(None, "ledger"))
            .await
            .expect("feed put");
        let cursor = store
            .log_read(TENANT, EventLogReadOptions::default())
            .await
            .expect("feed read")
            .cursor
            .expect("cursor");

        let ledger = SqliteSyncLedger::new(&store);
        ledger
            .upsert_checkpoint(&SyncCheckpoint {
                key: format!("{TENANT}|https://peer.example|full|pull"),
                tenant: TENANT.to_string(),
                remote: "https://peer.example".to_string(),
                scope_id: "full".to_string(),
                direction: SyncDirection::Pull,
                local_root: Some("local-root".to_string()),
                remote_root: Some("remote-root".to_string()),
                pending_pull_prefixes: Vec::new(),
                pending_push_prefixes: Vec::new(),
                pull_cursor: Some(cursor.clone()),
                push_cursor: None,
                records_pulled: 7,
                records_pushed: 0,
                bytes_downloaded: 128,
                bytes_uploaded: 0,
                last_error: None,
                updated_at: Utc::now(),
            })
            .await
            .expect("upsert checkpoint");
        MessageStore::close(&mut store).await;
        cursor
    };

    // Fresh handle on the same file: the checkpoint must still be there.
    let fresh = SqliteStore::new(db.path(), noop_waker());
    let ledger = SqliteSyncLedger::new(&fresh);
    let loaded = ledger.load().await.expect("reload ledger");
    let checkpoint = loaded
        .checkpoints
        .values()
        .next()
        .expect("checkpoint survives reopen");
    assert_eq!(checkpoint.tenant, TENANT);
    assert_eq!(checkpoint.records_pulled, 7);
    assert_eq!(checkpoint.pull_cursor.as_ref(), Some(&cursor));
}

#[tokio::test]
async fn native_node_open_at_resumes_from_disk() {
    let dir = tempfile::tempdir().expect("battery tempdir");
    let path = dir.path().join("node.sqlite");

    let epoch = {
        let node = SqliteNativeDwn::open_at(&path, test_resolver())
            .await
            .expect("node opens at path");
        let msg = delete_message("node-one", "2025-01-01T00:00:00Z");
        let msg_cid = cid(&msg);
        MessageStore::put(
            node.store(),
            TENANT,
            msg,
            indexes(Some(PROTOCOL_NOTES), "n1"),
        )
        .await
        .expect("node put");
        let epoch = node.store().epoch().await.expect("node epoch");
        assert!(MessageStore::get(node.store(), TENANT, &msg_cid)
            .await
            .expect("node get")
            .is_some());
        epoch
    };

    let node = SqliteNativeDwn::open_at(&path, test_resolver())
        .await
        .expect("node reopens at path");
    assert_eq!(node.store().epoch().await.expect("epoch"), epoch);
    let page = node
        .store()
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("feed read after node reopen");
    assert_eq!(page.events.len(), 1);
    assert!(page.drained);
}

#[tokio::test]
async fn legacy_v1_database_migrates_forward_on_open() {
    let db = TempDb::new("legacy-v1-migrate");
    {
        let connection = Connection::open(db.path()).expect("raw open");
        connection
            .execute_batch(include_str!("../src/sqlite/migrations/sql/V1__initial.sql"))
            .expect("apply V1 baseline");
    }

    let mut store = SqliteStore::new(db.path(), noop_waker());
    MessageStore::open(&mut store).await.unwrap();

    // The store migrated forward: the durable feed works and has an epoch.
    assert!(!store.epoch().await.expect("epoch").is_empty());
    let msg = delete_message("post-migration", "2025-01-01T00:00:00Z");
    let msg_cid = cid(&msg);
    MessageStore::put(&store, TENANT, msg, indexes(None, "migrated"))
        .await
        .expect("put after migration");
    // `get` rehydrates stored fields rather than echoing the fixture shape
    // (field normalization changes the CID), so assert presence, not equality.
    assert!(MessageStore::get(&store, TENANT, &msg_cid)
        .await
        .expect("get after migration")
        .is_some());
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SampleTask {
    action: String,
}

#[tokio::test]
async fn aux_stores_multi_row_state_survives_fresh_reopen() {
    let db = TempDb::new("aux-multi-row");
    let task_a = SampleTask {
        action: "prune".to_string(),
    };
    let task_b = SampleTask {
        action: "squash".to_string(),
    };

    let (root_before, task_ids) = {
        let store = SqliteStore::new(db.path(), noop_waker());
        let mut state_index = SqliteStateIndex::new(&store);
        state_index.open().await.unwrap();
        for (cid, ts) in [
            ("bafyreiaaa", "2025-01-01T00:00:00.000000Z"),
            ("bafyreiaab", "2025-01-01T00:00:01.000000Z"),
            ("bafyreiaac", "2025-01-01T00:00:02.000000Z"),
        ] {
            state_index
                .insert(
                    TENANT,
                    cid,
                    BTreeMap::from([(
                        "messageTimestamp".to_string(),
                        Value::String(ts.to_string()),
                    )]),
                )
                .await
                .unwrap();
        }
        let root_before = state_index.get_root(TENANT).await.unwrap();
        state_index.close().await;

        let mut task_store = SqliteResumableTaskStore::new(&store);
        ResumableTaskStore::open(&mut task_store).await.unwrap();
        let a = task_store.register(task_a.clone(), 120).await.unwrap();
        let b = task_store.register(task_b.clone(), 120).await.unwrap();
        ResumableTaskStore::close(&mut task_store).await;
        (root_before, (a.id, b.id))
    };

    // Fresh handles on the same file.
    let fresh = SqliteStore::new(db.path(), noop_waker());
    let mut state_index = SqliteStateIndex::new(&fresh);
    state_index.open().await.unwrap();
    assert_eq!(state_index.get_root(TENANT).await.unwrap(), root_before);

    let mut task_store = SqliteResumableTaskStore::new(&fresh);
    ResumableTaskStore::open(&mut task_store).await.unwrap();
    assert_eq!(
        task_store
            .read::<SampleTask>(&task_ids.0)
            .await
            .unwrap()
            .expect("task a")
            .task,
        task_a
    );
    assert_eq!(
        task_store
            .read::<SampleTask>(&task_ids.1)
            .await
            .unwrap()
            .expect("task b")
            .task,
        task_b
    );
}
