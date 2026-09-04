//! Store-level atomicity grid for issue #169 (C6a).
//!
//! Proves the crash invariant at the layer Rust implements atomically: one
//! SQLite transaction commits the message row together with its feed
//! entry/position/head/fingerprint. After any restart — clean `close` or a
//! kill-style drop without close — there must be no split-brain:
//! `get(cid).is_some()` ⟺ the feed contains `cid`.
//!
//! Handler-level delete-wins convergence belongs to C6b.
//!
//! Covers: DWN-REC-006, DWN-SYNC-001.

mod common;

use std::collections::BTreeSet;

use dwn_rs_core::stores::memory::MemoryMessageStore;
use dwn_rs_core::stores::replication_feed_reader::Fingerprint;
use dwn_rs_core::stores::{
    EventLogReadOptions, MessageStore, ProgressGapReason, ReplicationFeedReader,
};
use dwn_rs_core::{Descriptor, Message};

use common::fixtures::{delete_message, feed_indexes, full_read, message_cid};
use common::{TempDb, TENANT};
use dwn_rs_stores::SqliteStore;

/// How the pre-restart handle goes away.
#[derive(Clone, Copy)]
enum Shutdown {
    Close,
    Drop,
}

impl Shutdown {
    async fn shutdown(self, store: &mut SqliteStore) {
        match self {
            Shutdown::Close => MessageStore::close(store).await,
            // Kill-style: drop without closing; recovery must still hold on
            // fresh open.
            Shutdown::Drop => {}
        }
    }
}

/// Mixed op log with puts, a duplicate, and deletes.
struct OpLog {
    messages: Vec<Message<Descriptor>>,
    cids: Vec<String>,
}

fn op_log() -> OpLog {
    let messages = vec![
        delete_message("op-1", "2025-01-01T00:00:00Z"),
        delete_message("op-2", "2025-01-01T00:00:01Z"),
        delete_message("op-3", "2025-01-01T00:00:02Z"),
        delete_message("op-4", "2025-01-01T00:00:03Z"),
    ];
    let cids = messages.iter().map(message_cid).collect();
    OpLog { messages, cids }
}

async fn apply_op_log(store: &SqliteStore, log: &OpLog) {
    for (index, msg) in log.messages.iter().enumerate() {
        MessageStore::put(
            store,
            TENANT,
            msg.clone(),
            feed_indexes(None, None, &format!("op{index}")),
        )
        .await
        .expect("feed put");
    }
    // Duplicate re-put of op-1 (idempotent, no new position).
    MessageStore::put(
        store,
        TENANT,
        log.messages[0].clone(),
        feed_indexes(None, None, "op0-dup"),
    )
    .await
    .expect("duplicate put");
    // Delete the hole (op-2) and the head (op-4).
    store.delete(TENANT, &log.cids[1]).await.expect("delete");
    store.delete(TENANT, &log.cids[3]).await.expect("delete");
}

/// Reference observable state: presence set, feed seqs, global fingerprint.
struct FeedSnapshot {
    present: BTreeSet<String>,
    feed: Vec<(String, String)>,
    fingerprint: Fingerprint,
    epoch: String,
}

async fn snapshot<S>(store: &S, cids: &[String]) -> FeedSnapshot
where
    S: MessageStore + ReplicationFeedReader,
{
    let mut present = BTreeSet::new();
    for cid in cids {
        if store.get(TENANT, cid).await.expect("get").is_some() {
            present.insert(cid.clone());
        }
    }
    FeedSnapshot {
        present,
        feed: full_read(store, TENANT).await,
        fingerprint: store
            .fingerprint(TENANT, &["".to_string()])
            .await
            .expect("fingerprint"),
        epoch: store.epoch().await.expect("epoch"),
    }
}

async fn assert_no_split_brain<S>(store: &S, cids: &[String])
where
    S: MessageStore + ReplicationFeedReader,
{
    let feed_cids: BTreeSet<String> = full_read(store, TENANT)
        .await
        .into_iter()
        .map(|(_, cid)| cid)
        .collect();
    for cid in cids {
        let stored = store.get(TENANT, cid).await.expect("get").is_some();
        assert_eq!(
            stored,
            feed_cids.contains(cid),
            "split-brain for {cid}: stored={stored}"
        );
    }
}

#[tokio::test]
async fn puts_survive_drop_without_close() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("puts-drop-no-close");
    let log = op_log();
    let epoch = {
        let mut store = SqliteStore::new(db.path(), common::noop_waker());
        MessageStore::open(&mut store).await.unwrap();
        apply_op_log(&store, &log).await;
        let epoch = store.epoch().await.expect("epoch");
        Shutdown::Drop.shutdown(&mut store).await;
        epoch
    };

    let mut reopened = SqliteStore::new(db.path(), common::noop_waker());
    MessageStore::open(&mut reopened).await.unwrap();
    assert_eq!(reopened.epoch().await.expect("epoch"), epoch);
    assert_no_split_brain(&reopened, &log.cids).await;
    assert_eq!(
        full_read(&reopened, TENANT)
            .await
            .into_iter()
            .map(|(seq, _)| seq)
            .collect::<Vec<_>>(),
        ["1", "3"]
    );
}

#[tokio::test]
async fn atomic_grid_close_vs_drop_matches_uninterrupted_run() {
    // Serialize file-backed tests process-wide.
    for shutdown in [Shutdown::Close, Shutdown::Drop] {
        // Reference: same op log on memory, no restart.
        let mut reference = MemoryMessageStore::default();
        MessageStore::open(&mut reference).await.unwrap();
        for (index, msg) in op_log().messages.iter().enumerate() {
            MessageStore::put(
                &reference,
                TENANT,
                msg.clone(),
                feed_indexes(None, None, &format!("op{index}")),
            )
            .await
            .expect("reference put");
        }
        reference
            .delete(TENANT, &op_log().cids[1])
            .await
            .expect("reference delete");
        reference
            .delete(TENANT, &op_log().cids[3])
            .await
            .expect("reference delete");
        let log = op_log();
        let expected = snapshot(&reference, &log.cids).await;

        // Durable run with a restart in the shutdown mode under test.
        let db = TempDb::new("atomic-grid");
        let (epoch, bounds) = {
            let mut store = SqliteStore::new(db.path(), common::noop_waker());
            MessageStore::open(&mut store).await.unwrap();
            apply_op_log(&store, &log).await;
            let epoch = store.epoch().await.expect("epoch");
            let bounds = store.log_bounds(TENANT).await.expect("bounds");
            shutdown.shutdown(&mut store).await;
            (epoch, bounds)
        };
        let mut reopened = SqliteStore::new(db.path(), common::noop_waker());
        MessageStore::open(&mut reopened).await.unwrap();
        let actual = snapshot(&reopened, &log.cids).await;

        assert_eq!(actual.present, expected.present);
        assert_eq!(actual.feed, expected.feed);
        assert_eq!(actual.fingerprint, expected.fingerprint);
        assert_eq!(actual.epoch, epoch);
        assert_eq!(reopened.log_bounds(TENANT).await.expect("bounds"), bounds);
        assert_no_split_brain(&reopened, &log.cids).await;
    }
}

#[tokio::test]
async fn mid_sequence_restart_converges_with_uninterrupted_run() {
    // Serialize file-backed tests process-wide.
    let log = op_log();

    // Uninterrupted reference on memory.
    let mut reference = MemoryMessageStore::default();
    MessageStore::open(&mut reference).await.unwrap();
    for (index, msg) in log.messages.iter().enumerate() {
        MessageStore::put(
            &reference,
            TENANT,
            msg.clone(),
            feed_indexes(None, None, &format!("op{index}")),
        )
        .await
        .expect("reference put");
    }
    reference
        .delete(TENANT, &log.cids[1])
        .await
        .expect("reference delete");
    reference
        .delete(TENANT, &log.cids[3])
        .await
        .expect("reference delete");
    let expected = snapshot(&reference, &log.cids).await;

    // Durable run: restart (drop, no close) between puts and deletes.
    let db = TempDb::new("mid-sequence-restart");
    {
        let mut store = SqliteStore::new(db.path(), common::noop_waker());
        MessageStore::open(&mut store).await.unwrap();
        for (index, msg) in log.messages.iter().enumerate() {
            MessageStore::put(
                &store,
                TENANT,
                msg.clone(),
                feed_indexes(None, None, &format!("op{index}")),
            )
            .await
            .expect("put before restart");
        }
        // No close: kill-style interrupt mid-sequence.
    }
    let mut reopened = SqliteStore::new(db.path(), common::noop_waker());
    MessageStore::open(&mut reopened).await.unwrap();
    MessageStore::put(
        &reopened,
        TENANT,
        log.messages[0].clone(),
        feed_indexes(None, None, "op0-dup"),
    )
    .await
    .expect("duplicate put after restart");
    reopened
        .delete(TENANT, &log.cids[1])
        .await
        .expect("delete after restart");
    reopened
        .delete(TENANT, &log.cids[3])
        .await
        .expect("delete after restart");

    let actual = snapshot(&reopened, &log.cids).await;
    assert_eq!(actual.present, expected.present);
    assert_eq!(actual.feed, expected.feed);
    assert_eq!(actual.fingerprint, expected.fingerprint);
    assert_no_split_brain(&reopened, &log.cids).await;
}

#[tokio::test]
async fn clear_then_drop_without_close_reopens_clean() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("clear-drop-reopen");
    let old_cursor = {
        let mut store = SqliteStore::new(db.path(), common::noop_waker());
        MessageStore::open(&mut store).await.unwrap();
        let msg = delete_message("clear-me", "2025-01-01T00:00:00Z");
        MessageStore::put(&store, TENANT, msg, feed_indexes(None, None, "c"))
            .await
            .expect("put");
        let cursor = store
            .log_read(TENANT, EventLogReadOptions::default())
            .await
            .expect("read")
            .cursor
            .expect("cursor");
        store.clear().await.expect("clear");
        cursor
    };

    let mut reopened = SqliteStore::new(db.path(), common::noop_waker());
    MessageStore::open(&mut reopened).await.unwrap();
    let page = reopened
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("read after clear+drop");
    assert!(page.events.is_empty());
    assert!(page.drained);

    // Pre-clear cursor belongs to a rotated epoch.
    let error = reopened
        .log_read(
            TENANT,
            EventLogReadOptions {
                cursor: Some(old_cursor),
                ..Default::default()
            },
        )
        .await
        .expect_err("old epoch must be rejected");
    let dwn_rs_core::errors::EventLogError::ProgressGap(gap) = error else {
        panic!("expected progress gap, got {error:?}");
    };
    assert_eq!(gap.reason, ProgressGapReason::EpochMismatch);
}
