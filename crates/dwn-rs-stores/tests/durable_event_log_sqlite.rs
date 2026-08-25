//! Feed-backed subscriptions over the SQLite replication feed.
//!
//! Bundle composition (one shared bus per assembly, handler registration) lands
//! in #230; this covers the store pairing the adapter depends on.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dwn_rs_core::descriptors::{DeleteDescriptor, Records};
use dwn_rs_core::stores::durable_event_log::{DurableEventLog, DurableEventLogConfig};
use dwn_rs_core::stores::wake::{InProcessWakeBus, WakePublishHandler};
use dwn_rs_core::stores::{
    EventLog, EventLogSubscribeOptions, KeyValues, MessageStore, SubscriptionListener,
    SubscriptionMessage,
};
use dwn_rs_core::{Descriptor, Fields, Message, Value};
use tokio::sync::mpsc;
use tokio::time::timeout;

use dwn_rs_stores::SqliteStore;

const TENANT: &str = "did:example:alice";
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);

static DATABASE_ID: AtomicU64 = AtomicU64::new(0);

fn memory_uri() -> String {
    format!(
        "file:dwn-durable-{}-{}?mode=memory&cache=shared",
        std::process::id(),
        DATABASE_ID.fetch_add(1, Ordering::Relaxed)
    )
}

/// Builds a SQLite store whose commits publish wakes onto `bus`.
async fn harness(bus: &InProcessWakeBus) -> SqliteStore {
    let mut store = SqliteStore::new(memory_uri(), WakePublishHandler::new(Arc::new(bus.clone())));
    MessageStore::open(&mut store)
        .await
        .expect("sqlite store must open");
    store
}

fn recorder() -> (
    SubscriptionListener,
    mpsc::UnboundedReceiver<SubscriptionMessage>,
) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let listener: SubscriptionListener = Box::new(move |message| {
        let _ = sender.send(message);
    });

    (listener, receiver)
}

async fn next(receiver: &mut mpsc::UnboundedReceiver<SubscriptionMessage>) -> SubscriptionMessage {
    timeout(RECEIVE_TIMEOUT, receiver.recv())
        .await
        .expect("timed out waiting for a subscription message")
        .expect("subscription listener was dropped")
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

fn indexes(marker: &str) -> KeyValues {
    let mut indexes = KeyValues::new();
    indexes.insert("marker".to_string(), Value::String(marker.to_string()));
    indexes.insert(
        "messageTimestamp".to_string(),
        Value::String("2025-01-01T00:00:00.000000Z".to_string()),
    );
    indexes
}

async fn commit(store: &SqliteStore, marker: &str, timestamp: &str) {
    store
        .put(TENANT, delete_message(marker, timestamp), indexes(marker))
        .await
        .expect("feed put");
}

fn test_config() -> DurableEventLogConfig {
    DurableEventLogConfig {
        idle_redrain_interval: None,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_committed_message_reaches_a_live_subscription() {
    let bus = InProcessWakeBus::new();
    let store = harness(&bus).await;
    let log = DurableEventLog::new(store.clone(), bus.clone(), None, Some(test_config()));

    let (listener, mut received) = recorder();
    let _subscription = log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    commit(&store, "m1", "2025-01-01T00:00:00.000000Z").await;

    match next(&mut received).await {
        SubscriptionMessage::Event { seq, cursor, .. } => {
            assert_eq!(seq.as_deref(), Some("1"));
            assert_eq!(cursor.position, "1");
            assert!(cursor.message_cid.is_some());
        }
        other => panic!("expected an event, got {other:?}"),
    }
}

#[tokio::test]
async fn a_resumed_subscription_replays_then_follows_the_feed() {
    let bus = InProcessWakeBus::new();
    let store = harness(&bus).await;
    let log = DurableEventLog::new(store.clone(), bus.clone(), None, Some(test_config()));

    commit(&store, "m1", "2025-01-01T00:00:00.000000Z").await;
    commit(&store, "m2", "2025-01-01T00:00:01.000000Z").await;

    let bounds = log
        .get_replay_bounds(TENANT)
        .await
        .expect("bounds")
        .expect("two committed messages");

    let (listener, mut received) = recorder();
    let _subscription = log
        .subscribe(
            TENANT,
            "sub-1",
            listener,
            Some(EventLogSubscribeOptions {
                cursor: Some(bounds.oldest.clone()),
                filters: None,
            }),
        )
        .await
        .expect("cursor subscribe");

    for position in ["1", "2"] {
        match next(&mut received).await {
            SubscriptionMessage::Event { seq, .. } => assert_eq!(seq.as_deref(), Some(position)),
            other => panic!("expected an event, got {other:?}"),
        }
    }

    match next(&mut received).await {
        SubscriptionMessage::Eose { cursor } => assert_eq!(cursor, bounds.latest),
        other => panic!("expected EOSE, got {other:?}"),
    }

    // Rows committed after the frozen head arrive through the live drain.
    commit(&store, "m3", "2025-01-01T00:00:02.000000Z").await;

    match next(&mut received).await {
        SubscriptionMessage::Event { seq, .. } => assert_eq!(seq.as_deref(), Some("3")),
        other => panic!("expected an event, got {other:?}"),
    }
}
