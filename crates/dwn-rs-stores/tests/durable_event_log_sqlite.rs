//! Feed-backed subscriptions over the SQLite replication feed.
//!
//! Bundle composition (one shared bus per assembly, handler registration) lands
//! in #230; this covers the store pairing the adapter depends on.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dwn_rs_core::descriptors::{DeleteDescriptor, Records};
use dwn_rs_core::errors::EventLogError;
use dwn_rs_core::stores::durable_event_log::{DurableEventLog, DurableEventLogConfig};
use dwn_rs_core::stores::wake::{InProcessWakeBus, WakePublishHandler};
use dwn_rs_core::stores::{
    EventLog, EventLogReadOptions, EventLogSubscribeOptions, KeyValues, MessageStore,
    ProgressGapCode, ProgressGapReason, SubscriptionListener, SubscriptionMessage,
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

#[tokio::test]
async fn replay_positions_epoch_and_bounds_survive_a_restart() {
    let bus = InProcessWakeBus::new();
    let database_path = std::env::temp_dir().join(format!(
        "dwn-feed-restart-{}-{}.sqlite",
        std::process::id(),
        ulid::Ulid::new()
    ));

    let oldest_before;
    let latest_before;
    {
        let mut store = SqliteStore::new(
            &database_path,
            WakePublishHandler::new(Arc::new(bus.clone())),
        );
        MessageStore::open(&mut store)
            .await
            .expect("sqlite store must open");
        let log = DurableEventLog::new(store.clone(), bus.clone(), None, Some(test_config()));

        commit(&store, "m1", "2025-01-01T00:00:00.000000Z").await;
        commit(&store, "m2", "2025-01-01T00:00:01.000000Z").await;

        let bounds = log
            .get_replay_bounds(TENANT)
            .await
            .expect("bounds")
            .expect("two committed messages");
        oldest_before = bounds.oldest.clone();
        latest_before = bounds.latest;
    }

    // Reopen the same database through a fresh adapter and continue from the
    // pre-restart cursor.
    {
        let mut store = SqliteStore::new(
            &database_path,
            WakePublishHandler::new(Arc::new(bus.clone())),
        );
        MessageStore::open(&mut store)
            .await
            .expect("sqlite reopen must open");
        let log = DurableEventLog::new(store.clone(), bus.clone(), None, Some(test_config()));

        let bounds = log
            .get_replay_bounds(TENANT)
            .await
            .expect("bounds after reopen")
            .expect("committed rows survive the restart");
        assert_eq!(bounds.oldest.stream_id, oldest_before.stream_id);
        assert_eq!(bounds.oldest.epoch, oldest_before.epoch);
        assert_eq!(bounds.oldest.position, oldest_before.position);
        assert_eq!(bounds.oldest.message_cid, oldest_before.message_cid);
        assert_eq!(bounds.latest.position, latest_before.position);
        assert_eq!(bounds.latest.message_cid, latest_before.message_cid);

        let (listener, mut received) = recorder();
        let _subscription = log
            .subscribe(
                TENANT,
                "sub-1",
                listener,
                Some(EventLogSubscribeOptions {
                    cursor: Some(oldest_before),
                    filters: None,
                }),
            )
            .await
            .expect("cursor subscribe after restart");

        for position in ["1", "2"] {
            match next(&mut received).await {
                SubscriptionMessage::Event { seq, .. } => {
                    assert_eq!(seq.as_deref(), Some(position))
                }
                other => panic!("expected an event, got {other:?}"),
            }
        }
        match next(&mut received).await {
            SubscriptionMessage::Eose { cursor } => assert_eq!(cursor, latest_before),
            other => panic!("expected EOSE, got {other:?}"),
        }

        MessageStore::close(&mut store).await;
    }

    let _ = std::fs::remove_file(database_path);
}

#[tokio::test]
async fn a_cursor_from_a_cleared_feed_is_a_structured_progress_gap() {
    let bus = InProcessWakeBus::new();
    let store = harness(&bus).await;
    let log = DurableEventLog::new(store.clone(), bus, None, Some(test_config()));

    commit(&store, "m1", "2025-01-01T00:00:00.000000Z").await;
    let stale = log
        .read(TENANT, None)
        .await
        .expect("initial read")
        .cursor
        .expect("anchor cursor");

    // Clearing rotates the feed epoch, so the old token can never resume.
    MessageStore::clear(&store).await.expect("clear");

    let error = log
        .read(
            TENANT,
            Some(EventLogReadOptions {
                cursor: Some(stale),
                ..Default::default()
            }),
        )
        .await
        .expect_err("stale epoch must not resume");

    let EventLogError::ProgressGap(gap) = error else {
        panic!("expected a progress gap, got {error:?}");
    };
    assert_eq!(gap.reason, ProgressGapReason::EpochMismatch);
    assert_eq!(gap.code, ProgressGapCode::ProgressGap);
}

#[tokio::test]
async fn an_empty_store_reads_as_drained_at_the_position_zero_anchor() {
    let bus = InProcessWakeBus::new();
    let store = harness(&bus).await;
    let log = DurableEventLog::new(store, bus, None, Some(test_config()));

    let read = log.read(TENANT, None).await.expect("empty read");
    assert!(read.events.is_empty());
    assert!(read.drained);
    let cursor = read.cursor.expect("authoritative anchor cursor");
    assert_eq!(cursor.position, "0");
}
