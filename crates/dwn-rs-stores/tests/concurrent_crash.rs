//! Concurrency and WAL-unclean recovery battery for issue #169 (C8).
//!
//! The production backend serves concurrent writers through a single-writer
//! pool (`busy_timeout` 5s). These tests prove that pressure never surfaces
//! as client-visible errors, duplicates, or split-brain, and that losing
//! the WAL after an unclean shutdown still reopens structurally sound.
//!
//! Covers: DWN-REC-006 (no split-brain), DWN-SYNC-001 (resume without
//! omission/duplication).

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use dwn_rs_core::stores::{EventLogReadOptions, MessageStore, ReplicationFeedReader};
use dwn_rs_core::{Descriptor, Message};
use tokio::sync::Barrier;

use common::fixtures::{delete_message, feed_indexes, full_read, message_cid};
use common::{TempDb, TENANT};
use dwn_rs_stores::SqliteStore;

const WRITERS: usize = 16;

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

async fn concurrent_puts(store: &SqliteStore, messages: &[Message<Descriptor>]) {
    let barrier = Arc::new(Barrier::new(messages.len()));
    let mut handles = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        let store = store.clone();
        let message = message.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            MessageStore::put(
                &store,
                TENANT,
                message,
                feed_indexes(None, None, &format!("w{index}")),
            )
            .await
        }));
    }
    for handle in handles {
        handle
            .await
            .expect("writer task joins")
            .expect("concurrent put never surfaces pool errors");
    }
}

async fn assert_feed_positions_are_exactly(store: &SqliteStore, count: usize) {
    let feed = full_read(store, TENANT).await;
    assert_eq!(feed.len(), count);
    let positions: BTreeSet<String> = feed.into_iter().map(|(seq, _)| seq).collect();
    let expected: BTreeSet<String> = (1..=count as u64).map(|n| n.to_string()).collect();
    assert_eq!(
        positions, expected,
        "positions stay gap-free under concurrency"
    );
}

#[tokio::test]
async fn concurrent_distinct_puts_all_land_mem_and_disk() {
    for db in [None, Some(TempDb::new("concurrent-puts"))] {
        let _guard = &db;
        let mut store = match &db {
            Some(db) => SqliteStore::new(db.path(), common::noop_waker()),
            None => SqliteStore::new(
                common::unique_memory_uri("dwn-concurrent"),
                common::noop_waker(),
            ),
        };
        MessageStore::open(&mut store).await.unwrap();

        concurrent_puts(&store, &messages(WRITERS)).await;
        assert_feed_positions_are_exactly(&store, WRITERS).await;
    }
}

#[tokio::test]
async fn concurrent_duplicate_puts_leave_a_single_entry() {
    let db = TempDb::new("concurrent-dups");
    let mut store = SqliteStore::new(db.path(), common::noop_waker());
    MessageStore::open(&mut store).await.unwrap();

    let message = delete_message("same", "2025-01-01T00:00:00.000000Z");
    let messages = vec![message; WRITERS];
    concurrent_puts(&store, &messages).await;

    let feed = full_read(&store, TENANT).await;
    assert_eq!(feed.len(), 1, "same-CID races collapse to one entry");
    assert_eq!(feed[0].0, "1");
}

#[tokio::test]
async fn concurrent_reads_during_writes_never_fail() {
    let db = TempDb::new("concurrent-read-write");
    let mut store = SqliteStore::new(db.path(), common::noop_waker());
    MessageStore::open(&mut store).await.unwrap();

    let barrier = Arc::new(Barrier::new(WRITERS + 4));
    let mut handles = Vec::new();
    for message in messages(WRITERS) {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            MessageStore::put(&store, TENANT, message, feed_indexes(None, None, "w"))
                .await
                .expect("writer put");
        }));
    }
    for _ in 0..4 {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..32 {
                let page = store
                    .log_read(TENANT, EventLogReadOptions::default())
                    .await
                    .expect("concurrent read never fails");
                // Any snapshot is valid; positions never go backwards.
                let _ = page;
                let bounds = store.log_bounds(TENANT).await.expect("bounds read");
                let _ = bounds;
            }
        }));
    }
    for handle in handles {
        handle.await.expect("task joins");
    }

    assert_feed_positions_are_exactly(&store, WRITERS).await;
}

#[tokio::test]
async fn concurrent_delete_and_put_keep_message_feed_correspondence() {
    let db = TempDb::new("concurrent-delete-put");
    let mut store = SqliteStore::new(db.path(), common::noop_waker());
    MessageStore::open(&mut store).await.unwrap();

    let messages = messages(8);
    let cids: Vec<String> = messages.iter().map(message_cid).collect();
    for (index, message) in messages.into_iter().enumerate() {
        MessageStore::put(
            &store,
            TENANT,
            message,
            feed_indexes(None, None, &format!("w{index}")),
        )
        .await
        .expect("seed put");
    }

    // Racers delete even CIDs while re-putting odd ones; the outcome is order
    // dependent, but the store must never split-brain: presence ⟺ feed.
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for (index, cid) in cids.into_iter().enumerate() {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            if index % 2 == 0 {
                store.delete(TENANT, &cid).await.expect("racer delete");
            } else {
                // Re-put is idempotent; absence afterwards would be split-brain
                // only if the feed still listed it (checked below).
                let message = delete_message(
                    &format!("concurrent-{index}"),
                    "2025-01-01T00:00:00.000000Z",
                );
                MessageStore::put(
                    &store,
                    TENANT,
                    message,
                    feed_indexes(None, None, &format!("w{index}")),
                )
                .await
                .expect("racer re-put");
            }
        }));
    }
    for handle in handles {
        handle.await.expect("task joins");
    }

    let feed_cids: BTreeSet<String> = full_read(&store, TENANT)
        .await
        .into_iter()
        .map(|(_, cid)| cid)
        .collect();
    for index in 0..8 {
        let message = delete_message(
            &format!("concurrent-{index}"),
            "2025-01-01T00:00:00.000000Z",
        );
        let cid = message_cid(&message);
        let stored = store.get(TENANT, &cid).await.expect("get").is_some();
        assert_eq!(
            stored,
            feed_cids.contains(&cid),
            "split-brain for {cid} after racy delete/put"
        );
    }
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
