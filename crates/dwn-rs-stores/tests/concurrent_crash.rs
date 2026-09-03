//! SQLite runners for the shared concurrency battery plus WAL-unclean
//! recovery (issue #169).
//!
//! The four pressure cases live once in
//! `dwn_rs_core::stores::concurrent_conformance` and run here on sqlite-mem
//! and sqlite-disk. Losing the WAL after an unclean shutdown is
//! SQLite-specific and stays in this file.
//!
//! Covers: DWN-REC-006 (no split-brain), DWN-SYNC-001 (resume without
//! omission/duplication).

mod common;

use std::collections::BTreeSet;

use dwn_rs_core::stores::concurrent_conformance::run_concurrent;
use dwn_rs_core::stores::{MessageStore, ReplicationFeedReader};
use dwn_rs_core::{Descriptor, Message};
use dwn_rs_stores::SqliteStore;

use common::fixtures::{delete_message, feed_indexes, full_read, message_cid};
use common::{TempDb, TENANT};

#[tokio::test]
async fn sqlite_mem_conforms_to_concurrency_contract() {
    run_concurrent(|| async { SqliteStore::in_memory(None) }).await;
}

#[tokio::test]
async fn sqlite_disk_conforms_to_concurrency_contract() {
    let dir = tempfile::tempdir().expect("battery tempdir");
    let seq = std::sync::atomic::AtomicU64::new(0);
    run_concurrent(|| async {
        let n = seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SqliteStore::new(
            dir.path().join(format!("concurrent-{n}.sqlite")),
            common::noop_waker(),
        )
    })
    .await;
}

fn messages(n: usize) -> Vec<Message<Descriptor>> {
    (0..n)
        .map(|index| {
            delete_message(
                &format!("concurrent-{index}"),
                "2025-01-01T00:00:00.000000Z",
            )
        })
        .collect()
}

#[tokio::test]
async fn wal_deleted_after_unclean_drop_still_reopens() {
    let db = TempDb::new("wal-deleted");
    {
        let mut store = SqliteStore::new(db.path(), common::noop_waker());
        MessageStore::open(&mut store).await.unwrap();
        for (index, message) in messages(4).into_iter().enumerate() {
            MessageStore::put(
                &store,
                TENANT,
                message,
                feed_indexes(None, None, &format!("w{index}")),
            )
            .await
            .expect("seed put");
        }
        // No close: kill-style shutdown with a possibly uncheckpointed WAL.
    }

    // Simulate crash loss of write-ahead frames; recovery must stay structural.
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = db.path().as_os_str().to_owned();
        sidecar.push(suffix);
        let _ = std::fs::remove_file(std::path::Path::new(&sidecar));
    }

    let mut reopened = SqliteStore::new(db.path(), common::noop_waker());
    MessageStore::open(&mut reopened)
        .await
        .expect("reopen after WAL loss succeeds");
    assert!(
        !reopened.epoch().await.expect("epoch").is_empty(),
        "epoch metadata survives WAL loss"
    );
    // Reads must work; row presence depends on what checkpointed, so only
    // structural correspondence is asserted.
    let feed_cids: BTreeSet<String> = full_read(&reopened, TENANT)
        .await
        .into_iter()
        .map(|(_, cid)| cid)
        .collect();
    for index in 0..4 {
        let cid = message_cid(&delete_message(
            &format!("concurrent-{index}"),
            "2025-01-01T00:00:00.000000Z",
        ));
        let stored = reopened.get(TENANT, &cid).await.expect("get").is_some();
        assert_eq!(
            stored,
            feed_cids.contains(&cid),
            "split-brain for {cid} after WAL loss"
        );
    }
}
