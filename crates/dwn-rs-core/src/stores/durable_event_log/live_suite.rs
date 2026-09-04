//! Backend-neutral live battery for [`DurableEventLog`](super::DurableEventLog).
//!
//! The scripted suite in `tests/` drives the adapter with impossible feed
//! states and stays store-independent by design. The cases here exercise the
//! real commit -> wake -> drain path, so they run against every backend
//! through [`run_live_suite`]: memory in core, SQLite in `dwn-rs-stores`.
//! Backends only supply a [`LivePair`]; all assertions use the public
//! [`EventLog`](crate::stores::EventLog) contract.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::descriptors::{DeleteDescriptor, Protocols, Records};
use crate::errors::EventLogError;
use crate::fields::WriteFields;
use crate::filters::{Filter, FilterKey};
use crate::stores::durable_event_log::{DurableEventLog, DurableEventLogConfig};
use crate::stores::memory::MemoryMessageStore;
use crate::stores::wake::{InProcessWakeBus, Wake, WakePublisher};
use crate::stores::write_resolver::{InitialWriteResolver, MessageStoreInitialWriteResolver};
use crate::stores::{
    EventLog, Filters, KeyValues, MessageEvent, MessageStore, ReplicationFeedReader,
    SubscriptionErrorCode, SubscriptionListener, SubscriptionMessage,
};
use crate::{Descriptor, Fields, Message, ProgressToken, Value};

pub const TENANT: &str = "did:example:alice";
pub const OTHER_TENANT: &str = "did:example:bob";

/// Upper bound on any harness wait. Exceeding it is a test failure, not a retry.
pub const HARNESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Window used when asserting that nothing further is delivered.
pub const QUIET_WINDOW: Duration = Duration::from_millis(50);

pub fn delete_message(record_id: &str, timestamp: &str) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Records(Box::new(Records::Delete(Box::new(DeleteDescriptor {
            message_timestamp: timestamp.parse().expect("valid fixture timestamp"),
            record_id: record_id.to_string(),
            prune: false,
        })))),
        fields: Fields::Authorization(Default::default()),
    }
}

pub fn write_message(encoded_data: Option<&str>) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Records(Box::new(Records::Write(Default::default()))),
        fields: Fields::Write(WriteFields {
            encoded_data: encoded_data.map(str::to_string),
            ..Default::default()
        }),
    }
}

/// `ProtocolsConfigure` fixture, the third message type carried by the feed.
pub fn configure_message() -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Protocols(Box::new(Protocols::Configure(Default::default()))),
        fields: Fields::Authorization(Default::default()),
    }
}

/// Builds indexes from string pairs, the common case for feed rows.
pub fn indexes(pairs: &[(&str, &str)]) -> KeyValues {
    let mut indexes = KeyValues::new();
    for (key, value) in pairs {
        indexes.insert((*key).to_string(), Value::String((*value).to_string()));
    }
    indexes
}

/// Single-index equality filter, the common subscription filter shape.
pub fn index_filters(key: &str, value: &str) -> Filters {
    Filters::from([[(
        FilterKey::Index(key.to_string()),
        Filter::Equal(Value::String(value.to_string())),
    )]])
}

/// Config used by live tests: no idle polling unless a case asks for it.
pub fn test_config() -> DurableEventLogConfig {
    DurableEventLogConfig {
        idle_redrain_interval: None,
        ..Default::default()
    }
}

/// One delivered `SubscriptionMessage::Event`, flattened for assertions.
#[derive(Debug, Clone, PartialEq)]
pub struct DeliveredEvent {
    pub cursor: ProgressToken,
    pub event: MessageEvent<Descriptor>,
    pub seq: Option<String>,
    pub message_cid: Option<String>,
    pub is_latest_base_state: Option<bool>,
    pub protocol: Option<String>,
    pub encoded_data: Option<String>,
}

/// Receiving half of a [`SubscriptionListener`] built by [`recorder`].
pub struct Recorder {
    receiver: mpsc::UnboundedReceiver<SubscriptionMessage>,
}

/// Creates a listener and the recorder that observes what it was called with.
pub fn recorder() -> (SubscriptionListener, Recorder) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let listener: SubscriptionListener = Box::new(move |message| {
        let _ = sender.send(message);
    });

    (listener, Recorder { receiver })
}

/// Creates a listener that runs `hook` before recording each message.
///
/// Used for close-from-inside-the-listener coverage.
pub fn recorder_with_hook<F>(hook: F) -> (SubscriptionListener, Recorder)
where
    F: Fn(&SubscriptionMessage) + Send + Sync + 'static,
{
    let (sender, receiver) = mpsc::unbounded_channel();
    let listener: SubscriptionListener = Box::new(move |message| {
        hook(&message);
        let _ = sender.send(message);
    });

    (listener, Recorder { receiver })
}

impl Recorder {
    pub async fn next_message(&mut self) -> SubscriptionMessage {
        timeout(HARNESS_TIMEOUT, self.receiver.recv())
            .await
            .expect("timed out waiting for a subscription message")
            .expect("subscription listener was dropped")
    }

    pub fn try_next(&mut self) -> Option<SubscriptionMessage> {
        self.receiver.try_recv().ok()
    }

    pub async fn expect_event(&mut self) -> DeliveredEvent {
        match self.next_message().await {
            SubscriptionMessage::Event {
                cursor,
                event,
                seq,
                message_cid,
                is_latest_base_state,
                protocol,
                encoded_data,
            } => DeliveredEvent {
                cursor,
                event: *event,
                seq,
                message_cid,
                is_latest_base_state,
                protocol,
                encoded_data,
            },
            other => panic!("expected an event, got {other:?}"),
        }
    }

    pub async fn expect_events(&mut self, count: usize) -> Vec<DeliveredEvent> {
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            events.push(self.expect_event().await);
        }
        events
    }

    pub async fn expect_eose(&mut self) -> ProgressToken {
        match self.next_message().await {
            SubscriptionMessage::Eose { cursor } => cursor,
            other => panic!("expected EOSE, got {other:?}"),
        }
    }

    pub async fn expect_error(&mut self) -> (ProgressToken, crate::stores::SubscriptionError) {
        match self.next_message().await {
            SubscriptionMessage::Error { cursor, error } => (cursor, error),
            other => panic!("expected a terminal error, got {other:?}"),
        }
    }

    /// Asserts nothing is delivered within `window`.
    ///
    /// A dropped listener counts as quiet: a cleaned-up subscription releases it.
    pub async fn expect_quiet(&mut self, window: Duration) {
        if let Ok(Some(message)) = timeout(window, self.receiver.recv()).await {
            panic!("expected no further messages, got {message:?}");
        }
    }

    /// Positions (`seq`) of every event delivered so far, drained without waiting.
    pub fn drain_event_positions(&mut self) -> Vec<String> {
        let mut positions = Vec::new();
        while let Some(message) = self.try_next() {
            match message {
                SubscriptionMessage::Event { seq, .. } => {
                    positions.push(seq.expect("delivered events carry seq"));
                }
                other => panic!("expected only events, got {other:?}"),
            }
        }
        positions
    }
}

/// Yields enough times for wake-bus tasks queued on this runtime to run.
pub async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// Publishes a wake directly, bypassing the store, to model a duplicate or stale hint.
pub fn publish_wake(bus: &InProcessWakeBus, tenant: &str, position: u64) {
    bus.publish(Wake {
        tenant: tenant.to_string(),
        position,
    })
    .expect("in-process wake publish");
}

// ---------------------------------------------------------------------------
// Backend-neutral live battery
// ---------------------------------------------------------------------------

/// How a live pair resolves initial writes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LiveResolver {
    /// No resolver: events carry no `initialWrite`.
    None,
    /// Resolve through the pair's own message store (production wiring).
    MessageStore,
}

/// Per-case options for [`run_live_suite`] factories.
#[derive(Clone, Copy, Debug)]
pub struct LiveOptions {
    pub resolver: LiveResolver,
    pub idle_redrain_interval: Option<Duration>,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            resolver: LiveResolver::None,
            idle_redrain_interval: None,
        }
    }
}

/// A log wired to a live store plus a quiet handle sharing the same state.
///
/// `quiet` publishes no wakes, modelling a lost wake (case
/// `dropped_wake_recovered_by_idle_poll`) without touching the log's bus.
pub struct LivePair<M>
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
{
    pub log: DurableEventLog<M, InProcessWakeBus>,
    pub bus: InProcessWakeBus,
    pub store: M,
    pub quiet: M,
}

/// In-core pair over [`MemoryMessageStore`]; clones share state.
pub async fn memory_live_pair(options: LiveOptions) -> LivePair<MemoryMessageStore> {
    let bus = InProcessWakeBus::new();
    let mut store = MemoryMessageStore::default().with_waker_publisher(bus.clone());
    store.open().await.expect("memory message store must open");
    let quiet = store.clone().with_waker_publisher(());

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

/// Runs the live battery against stores built by `factory`.
///
/// Each scenario gets a fresh pair. Factories receive per-scenario
/// [`LiveOptions`]: most cases run with defaults, the initial-write case
/// asks for [`LiveResolver::MessageStore`], and the polling case sets an
/// idle interval.
pub async fn run_live_suite<M, F, Fut>(factory: F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    live_delivers_committed_events(&factory).await;
    duplicate_wakes_do_not_duplicate_delivery(&factory).await;
    wake_ahead_of_feed_delivers_nothing(&factory).await;
    delete_carries_write_it_deletes(&factory).await;
    writes_deletes_configures_reach_subscribers(&factory).await;
    paged_replay_delivers_exactly_once_with_single_eose(&factory).await;
    filtered_subscribe_delivers_only_matching(&factory).await;
    live_progress_gap_closes_subscription(&factory).await;
    close_releases_subscription(&factory).await;
    delete_without_resolver_has_no_initial_write(&factory).await;
    dropped_wake_recovered_by_idle_poll(&factory).await;
}

async fn fresh_pair<M, F, Fut>(factory: &F, options: LiveOptions) -> LivePair<M>
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    factory(options).await
}

async fn commit<M>(pair: &LivePair<M>, tenant: &str, message: Message<Descriptor>, marker: &str)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
{
    pair.store
        .put(tenant, message, indexes(&[("marker", marker)]))
        .await
        .expect("feed put");
}

async fn commit_delete<M>(pair: &LivePair<M>, tenant: &str, marker: &str, timestamp: &str)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
{
    commit(pair, tenant, delete_message(marker, timestamp), marker).await;
}

async fn live_delivers_committed_events<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(factory, LiveOptions::default()).await;

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(
            TENANT,
            "sub-1",
            listener,
            Some(crate::stores::EventLogSubscribeOptions::default()),
        )
        .await
        .expect("no-cursor subscribe");

    commit_delete(&pair, TENANT, "m1", "2025-01-01T00:00:00.000000Z").await;

    let delivered = recorder.expect_event().await;
    assert_eq!(delivered.seq.as_deref(), Some("1"));
    assert_eq!(delivered.cursor.position, "1");
    assert!(
        delivered.message_cid.is_some(),
        "feed rows carry their message CID"
    );

    recorder.expect_quiet(QUIET_WINDOW).await;
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn duplicate_wakes_do_not_duplicate_delivery<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(factory, LiveOptions::default()).await;

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    for index in 0..3 {
        commit_delete(
            &pair,
            TENANT,
            &format!("m{index}"),
            "2025-01-01T00:00:00.000000Z",
        )
        .await;
        // Spurious repeats of a hint the store already published.
        publish_wake(&pair.bus, TENANT, 1);
        publish_wake(&pair.bus, TENANT, 99);
    }

    let delivered = recorder.expect_events(3).await;
    let positions: Vec<_> = delivered
        .iter()
        .map(|event| event.seq.clone().expect("seq"))
        .collect();
    assert_eq!(
        positions,
        vec!["1".to_string(), "2".to_string(), "3".to_string()]
    );
    recorder.expect_quiet(QUIET_WINDOW).await;
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn wake_ahead_of_feed_delivers_nothing<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(factory, LiveOptions::default()).await;

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    // A hint is never proof an event exists; the feed stays authoritative.
    publish_wake(&pair.bus, TENANT, 42);

    recorder.expect_quiet(QUIET_WINDOW).await;
    assert!(recorder.try_next().is_none());
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn delete_carries_write_it_deletes<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(
        factory,
        LiveOptions {
            resolver: LiveResolver::MessageStore,
            ..Default::default()
        },
    )
    .await;

    let mut write_indexes = KeyValues::new();
    write_indexes.insert("entryId".to_string(), Value::String("record-1".to_string()));
    // Message stores index the timestamp; the resolver's query sorts on it.
    write_indexes.insert(
        "messageTimestamp".to_string(),
        Value::String("2025-01-01T00:00:00.000000Z".to_string()),
    );
    pair.store
        .put(TENANT, write_message(Some("aGVsbG8")), write_indexes)
        .await
        .expect("write put");

    // Subscribing after the write means only the delete is delivered.
    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    commit_delete(&pair, TENANT, "record-1", "2025-01-01T00:00:00.000000Z").await;

    let delivered = recorder.expect_event().await;
    assert_eq!(delivered.seq.as_deref(), Some("2"));
    assert!(
        delivered.event.initial_write.is_some(),
        "a delete resolves the RecordsWrite it removes"
    );
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn writes_deletes_configures_reach_subscribers<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(factory, LiveOptions::default()).await;

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    commit(&pair, TENANT, write_message(Some("aGVsbG8")), "write").await;
    commit_delete(&pair, TENANT, "record-1", "2025-01-01T00:00:00.000000Z").await;
    commit(&pair, TENANT, configure_message(), "configure").await;

    let delivered = recorder.expect_events(3).await;
    let positions: Vec<_> = delivered
        .iter()
        .map(|event| event.seq.clone().expect("seq"))
        .collect();
    assert_eq!(
        positions,
        vec!["1".to_string(), "2".to_string(), "3".to_string()]
    );
    recorder.expect_quiet(QUIET_WINDOW).await;
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn paged_replay_delivers_exactly_once_with_single_eose<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(factory, LiveOptions::default()).await;

    for index in 0..10 {
        commit_delete(
            &pair,
            TENANT,
            &format!("m{index}"),
            "2025-01-01T00:00:00.000000Z",
        )
        .await;
    }
    // A wake racing the replay must not duplicate or split it. No-cursor
    // subscriptions never send EOSE, so subscribe from the oldest bound to
    // get replay-then-EOSE semantics.
    let (oldest, _) = pair
        .store
        .log_bounds(TENANT)
        .await
        .expect("bounds")
        .expect("non-empty feed");
    publish_wake(&pair.bus, TENANT, 10);

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(
            TENANT,
            "sub-1",
            listener,
            Some(crate::stores::EventLogSubscribeOptions {
                cursor: Some(oldest),
                filters: None,
            }),
        )
        .await
        .expect("cursor subscribe");

    let delivered = recorder.expect_events(10).await;
    let positions: Vec<_> = delivered
        .iter()
        .map(|event| event.seq.clone().expect("seq"))
        .collect();
    assert_eq!(
        positions,
        (1..=10)
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
    );
    let eose = recorder.expect_eose().await;
    assert_eq!(eose.position, "10");
    recorder.expect_quiet(QUIET_WINDOW).await;
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn filtered_subscribe_delivers_only_matching<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(factory, LiveOptions::default()).await;

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(
            TENANT,
            "sub-1",
            listener,
            Some(crate::stores::EventLogSubscribeOptions {
                cursor: None,
                filters: Some(index_filters("marker", "keep")),
            }),
        )
        .await
        .expect("filtered subscribe");

    commit_delete(&pair, TENANT, "keep", "2025-01-01T00:00:00.000000Z").await;
    commit_delete(&pair, TENANT, "drop", "2025-01-01T00:00:01.000000Z").await;
    commit_delete(&pair, TENANT, "keep", "2025-01-01T00:00:02.000000Z").await;

    let delivered = recorder.expect_events(2).await;
    assert_eq!(delivered[0].seq.as_deref(), Some("1"));
    assert_eq!(delivered[1].seq.as_deref(), Some("3"));
    recorder.expect_quiet(QUIET_WINDOW).await;
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn live_progress_gap_closes_subscription<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(factory, LiveOptions::default()).await;

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    commit_delete(&pair, TENANT, "m1", "2025-01-01T00:00:00.000000Z").await;
    recorder.expect_event().await;

    // Rotating the epoch under a live subscription ends it terminally.
    pair.store.clear().await.expect("clear feed");
    publish_wake(&pair.bus, TENANT, 99);

    let (_, error) = recorder.expect_error().await;
    assert_eq!(error.code, SubscriptionErrorCode::ProgressGap);
    recorder.expect_quiet(QUIET_WINDOW).await;
    assert!(recorder.try_next().is_none());
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn close_releases_subscription<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(factory, LiveOptions::default()).await;

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    commit_delete(&pair, TENANT, "m1", "2025-01-01T00:00:00.000000Z").await;
    recorder.expect_event().await;

    pair.log.close().await;
    commit_delete(&pair, TENANT, "m2", "2025-01-01T00:00:01.000000Z").await;
    publish_wake(&pair.bus, TENANT, 2);
    recorder.expect_quiet(QUIET_WINDOW).await;

    // Subscribing after close is a terminal error, not a hang.
    let (post_close_listener, _) = crate::stores::durable_event_log::live_suite::recorder();
    assert!(matches!(
        pair.log
            .subscribe(TENANT, "sub-2", post_close_listener, None)
            .await,
        Err(EventLogError::Closed)
    ));
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn delete_without_resolver_has_no_initial_write<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(factory, LiveOptions::default()).await;

    let mut write_indexes = KeyValues::new();
    write_indexes.insert("entryId".to_string(), Value::String("record-1".to_string()));
    write_indexes.insert(
        "messageTimestamp".to_string(),
        Value::String("2025-01-01T00:00:00.000000Z".to_string()),
    );
    pair.store
        .put(TENANT, write_message(Some("aGVsbG8")), write_indexes)
        .await
        .expect("write put");

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    commit_delete(&pair, TENANT, "record-1", "2025-01-01T00:00:00.000000Z").await;

    // No resolver: the delete still delivers, without an initial write.
    let delivered = recorder.expect_event().await;
    assert_eq!(delivered.seq.as_deref(), Some("2"));
    assert!(delivered.event.initial_write.is_none());
    pair.store.close().await;
    pair.quiet.close().await;
}

async fn dropped_wake_recovered_by_idle_poll<M, F, Fut>(factory: &F)
where
    M: MessageStore + ReplicationFeedReader + Clone + Send + Sync + 'static,
    F: Fn(LiveOptions) -> Fut,
    Fut: Future<Output = LivePair<M>>,
{
    let mut pair = fresh_pair(
        factory,
        LiveOptions {
            idle_redrain_interval: Some(Duration::from_millis(50)),
            ..Default::default()
        },
    )
    .await;

    let (listener, mut recorder) = recorder();
    let _subscription = pair
        .log
        .subscribe(TENANT, "sub-1", listener, None)
        .await
        .expect("no-cursor subscribe");

    // The quiet handle shares state but publishes no wakes: the commit is
    // invisible until the idle poll redrains.
    pair.quiet
        .put(
            TENANT,
            delete_message("lost-wake", "2025-01-01T00:00:00.000000Z"),
            indexes(&[("marker", "lost-wake")]),
        )
        .await
        .expect("quiet put");

    let delivered = recorder.expect_event().await;
    assert_eq!(delivered.seq.as_deref(), Some("1"));
    pair.store.close().await;
    pair.quiet.close().await;
}
