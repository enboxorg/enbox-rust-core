//! Backend-neutral concurrency battery (issue #169).
//!
//! The production backend serves concurrent writers through a single-writer
//! pool with a busy timeout. These cases prove pressure never surfaces as
//! client-visible errors, duplicates, or split-brain, on any backend. WAL
//! loss and file-handle recovery stay SQLite-specific in `dwn-rs-stores`.
//!
//! Covers: DWN-REC-006 (no split-brain), DWN-SYNC-001 (resume without
//! omission/duplication).

use std::{collections::BTreeSet, future::Future, sync::Arc};

use tokio::sync::Barrier;

use super::replication_feed_reader::ReplicationFeedReader;
use super::{EventLogReadOptions, KeyValues, MessageStore};
use crate::descriptors::{DeleteDescriptor, Records};
use crate::{Descriptor, Fields, Message, Value};

/// Runs the concurrency battery against stores built by `factory`.
///
/// The factory is invoked once per scenario; concurrent tasks share clones
/// of the returned handle. `concurrency` sizes the writer/reader pools.
pub async fn run_concurrent<S, F, Fut>(factory: F)
where
    S: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    distinct_puts_all_land(&factory).await;
    duplicate_puts_collapse(&factory).await;
    reads_during_writes_never_fail(&factory).await;
    delete_put_keeps_correspondence(&factory).await;
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

const TENANT: &str = "did:example:alice";
const WRITERS: usize = 16;

fn message(index: usize) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Records(Box::new(Records::Delete(Box::new(DeleteDescriptor {
            message_timestamp: "2025-01-01T00:00:00.000000Z".parse().expect("timestamp"),
            record_id: format!("concurrent-{index}"),
            prune: false,
        })))),
        fields: Fields::Authorization(Default::default()),
    }
}

fn indexes(marker: &str) -> KeyValues {
    let mut out = KeyValues::new();
    out.insert("marker".to_string(), Value::String(marker.to_string()));
    out
}

fn message_cid(message: &Message<Descriptor>) -> String {
    crate::cid::generate_message_cid_from_json(
        &serde_json::to_value(message).expect("message JSON"),
    )
    .expect("message CID")
    .to_string()
}

async fn feed_cids<S>(store: &S) -> BTreeSet<String>
where
    S: ReplicationFeedReader,
{
    store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("feed read")
        .events
        .into_iter()
        .filter_map(|entry| entry.message_cid)
        .collect()
}

async fn assert_no_split_brain<S>(store: &S, cids: &[String])
where
    S: MessageStore + ReplicationFeedReader,
{
    let feed = feed_cids(store).await;
    for cid in cids {
        let stored = store.get(TENANT, cid).await.expect("get").is_some();
        assert_eq!(
            stored,
            feed.contains(cid),
            "split-brain for {cid} under concurrency"
        );
    }
}

async fn concurrent_puts<S>(store: &S, messages: Vec<Message<Descriptor>>)
where
    S: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
{
    let barrier = Arc::new(Barrier::new(messages.len()));
    let mut handles = Vec::new();
    for (index, message) in messages.into_iter().enumerate() {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            MessageStore::put(&store, TENANT, message, indexes(&format!("w{index}"))).await
        }));
    }
    for handle in handles {
        handle
            .await
            .expect("writer task joins")
            .expect("concurrent put never surfaces pool errors");
    }
}

async fn positions_are_exactly<S>(store: &S, count: usize)
where
    S: ReplicationFeedReader,
{
    let page = store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .expect("feed read");
    assert_eq!(page.events.len(), count);
    let positions: BTreeSet<String> = page.events.into_iter().map(|entry| entry.seq).collect();
    let expected: BTreeSet<String> = (1..=count as u64).map(|n| n.to_string()).collect();
    assert_eq!(positions, expected, "positions stay gap-free");
}

async fn distinct_puts_all_land<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    concurrent_puts(&store, (0..WRITERS).map(message).collect()).await;
    positions_are_exactly(&store, WRITERS).await;
}

async fn duplicate_puts_collapse<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    concurrent_puts(&store, vec![message(0); WRITERS]).await;
    positions_are_exactly(&store, 1).await;
}

async fn reads_during_writes_never_fail<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    let barrier = Arc::new(Barrier::new(WRITERS + 4));
    let mut handles = Vec::new();
    for index in 0..WRITERS {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            MessageStore::put(&store, TENANT, message(index), indexes("w"))
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
                store
                    .log_read(TENANT, EventLogReadOptions::default())
                    .await
                    .expect("concurrent read never fails");
                store
                    .log_bounds(TENANT)
                    .await
                    .expect("concurrent bounds never fail");
            }
        }));
    }
    for handle in handles {
        handle.await.expect("task joins");
    }
    positions_are_exactly(&store, WRITERS).await;
}

async fn delete_put_keeps_correspondence<S, F, Fut>(factory: &F)
where
    S: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_store(factory).await;
    // Racers delete even CIDs while re-putting odd ones over disjoint keys;
    // the outcome is deterministic but lock pressure is real.
    let cids: Vec<String> = (0..8).map(|index| message_cid(&message(index))).collect();
    for index in 0..8 {
        MessageStore::put(&store, TENANT, message(index), indexes("seed"))
            .await
            .expect("seed put");
    }
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for (index, cid) in cids.iter().enumerate() {
        let store = store.clone();
        let barrier = barrier.clone();
        let cid = cid.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            if index % 2 == 0 {
                // Seed first: the delete targets a missing row unless the
                // seeder below already ran; correspondence holds either way.
                store.delete(TENANT, &cid).await.expect("racer delete");
            } else {
                MessageStore::put(&store, TENANT, message(index), indexes("w"))
                    .await
                    .expect("racer put");
            }
        }));
    }
    for handle in handles {
        handle.await.expect("task joins");
    }
    assert_no_split_brain(&store, &cids).await;
}

#[tokio::test]
async fn memory_conforms_to_concurrency_contract() {
    run_concurrent(|| async { super::memory::MemoryMessageStore::default() }).await;
}
