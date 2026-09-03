//! Feed-backed subscriptions over the SQLite replication feed.
//!
//! The backend-neutral live battery runs here against sqlite-mem and
//! sqlite-disk through [`run_live_suite`]; the tests below keep the
//! SQLite-specific coverage (restart bounds, clear gap, empty anchor).

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dwn_rs_core::errors::EventLogError;
use dwn_rs_core::stores::durable_event_log::live_suite::{
    run_live_suite, LiveOptions, LivePair, LiveResolver,
};
use dwn_rs_core::stores::durable_event_log::{DurableEventLog, DurableEventLogConfig};
use dwn_rs_core::stores::wake::{InProcessWakeBus, WakePublishHandler};
use dwn_rs_core::stores::write_resolver::{InitialWriteResolver, MessageStoreInitialWriteResolver};
use dwn_rs_core::stores::{
    EventLog, EventLogReadOptions, EventLogSubscribeOptions, MessageStore, ProgressGapCode,
    ProgressGapReason, SubscriptionListener, SubscriptionMessage,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

use common::fixtures::{delete_message, feed_indexes};
use common::{noop_waker, TempDb, TENANT};
use dwn_rs_stores::SqliteStore;

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds a SQLite store whose commits publish wakes onto `bus`.
async fn harness(bus: &InProcessWakeBus) -> SqliteStore {
    let mut store = SqliteStore::new(
        common::unique_memory_uri("dwn-durable"),
        WakePublishHandler::new(Arc::new(bus.clone())),
    );
    MessageStore::open(&mut store)
        .await
        .expect("sqlite store must open");
    store
}

/// Live pair over one SQLite database file (or shared-cache URI): `quiet`
/// shares state but publishes no wakes, modelling a lost wake for the idle
/// poll to recover.
async fn sqlite_live_pair(options: LiveOptions, path: PathBuf) -> LivePair<SqliteStore> {
    let bus = InProcessWakeBus::new();
    let mut store = SqliteStore::new(&path, WakePublishHandler::new(Arc::new(bus.clone())));
    MessageStore::open(&mut store)
        .await
        .expect("sqlite store must open");
    let mut quiet = SqliteStore::new(&path, noop_waker());
    MessageStore::open(&mut quiet)
        .await
        .expect("quiet handle must open");

    let resolver: Option<Arc<dyn InitialWriteResolver>> = match options.resolver {
        LiveResolver::None => None,
        LiveResolver::MessageStore => Some(Arc::new(MessageStoreInitialWriteResolver::new(
            Arc::new(store.clone()),
        ))),
    };
    let log = DurableEventLog::new(
        store.clone(),
        bus.clone(),
        resolver,
        Some(DurableEventLogConfig {
            idle_redrain_interval: options.idle_redrain_interval,
            ..Default::default()
        }),
    );

    LivePair {
        log,
        bus,
        store,
        quiet,
    }
}

#[tokio::test]
async fn sqlite_mem_conforms_to_live_durable_event_log_contract() {
    run_live_suite(|options| async move {
        sqlite_live_pair(
            options,
            PathBuf::from(common::unique_memory_uri("dwn-live")),
        )
        .await
    })
    .await;
}

#[tokio::test]
async fn sqlite_disk_conforms_to_live_durable_event_log_contract() {
    let _guard = tempfile::tempdir().expect("battery tempdir");
    let seq = AtomicU64::new(0);
    let dir = _guard.path().to_path_buf();
    run_live_suite(|options| {
        let n = seq.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("live-{n}.sqlite"));
        async move { sqlite_live_pair(options, path).await }
    })
    .await;
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

async fn commit(store: &SqliteStore, marker: &str, timestamp: &str) {
    store
        .put(
            TENANT,
            delete_message(marker, timestamp),
            feed_indexes(None, None, marker),
        )
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
    let db = TempDb::new("dwn-feed-restart");
    let database_path = db.path().to_path_buf();

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
