//! Shared harness for [`DurableEventLog`] tests.
//!
//! Two harnesses cover different halves of the adapter's contract:
//!
//! * [`live_harness`] pairs a [`MemoryMessageStore`] with an [`InProcessWakeBus`]
//!   so tests exercise the real commit -> wake -> drain path.
//! * [`scripted_harness`] drives the adapter with a [`ScriptedReader`], which can
//!   produce feed responses a real store never would: a missing scan cursor, a
//!   mid-drain progress gap, a transient failure, or a read held open while the
//!   subscription closes.
//!
//! Waits are bounded by [`HARNESS_TIMEOUT`]; a timeout means the adapter stopped
//! making progress and the test fails rather than hangs.

// Later commits in this series consume the rest of the harness surface.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::timeout;

use crate::descriptors::{DeleteDescriptor, Protocols, Records, RecordsWriteDescriptor};
use crate::errors::{EventLogError, StoreError};
use crate::fields::WriteFields;
use crate::filters::{Filter, FilterKey};
use crate::stores::durable_event_log::{DurableEventLog, DurableEventLogConfig, ErrorFn};
use crate::stores::memory::MemoryMessageStore;
use crate::stores::replication_feed_reader::{build_token, Fingerprint, ReplicationBounds};
use crate::stores::wake::{InProcessWakeBus, Wake, WakePublisher};
use crate::stores::write_resolver::{InitialWriteResolver, MessageStoreInitialWriteResolver};
use crate::stores::{
    EventLogEntry, EventLogReadOptions, EventLogReadResult, KeyValues, MessageStore,
    ProgressGapCode, ProgressGapInfo, ProgressGapReason, ReplicationFeedReader, SubscriptionError,
    SubscriptionListener, SubscriptionMessage,
};
use crate::{Descriptor, Fields, Filters, Message, MessageEvent, ProgressToken, Value};

pub(crate) const TENANT: &str = "did:example:alice";
pub(crate) const OTHER_TENANT: &str = "did:example:bob";
pub(crate) const EPOCH: &str = "01JBQ0TESTEPOCH000000000000";

/// Upper bound on any harness wait. Exceeding it is a test failure, not a retry.
pub(crate) const HARNESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Window used when asserting that nothing further is delivered.
pub(crate) const QUIET_WINDOW: Duration = Duration::from_millis(50);

// -------------------------------------------------------------------------
// Token, message, and page fixtures
// -------------------------------------------------------------------------

/// Progress token for [`TENANT`] in the harness epoch.
pub(crate) fn token(position: u64, message_cid: Option<&str>) -> ProgressToken {
    build_token(TENANT, EPOCH, position, message_cid)
}

/// Progress token for an arbitrary tenant and epoch.
pub(crate) fn tenant_token(
    tenant: &str,
    epoch: &str,
    position: u64,
    message_cid: Option<&str>,
) -> ProgressToken {
    build_token(tenant, epoch, position, message_cid)
}

pub(crate) fn delete_message(record_id: &str, timestamp: &str) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Records(Box::new(Records::Delete(Box::new(DeleteDescriptor {
            message_timestamp: timestamp.parse().expect("valid fixture timestamp"),
            record_id: record_id.to_string(),
            prune: false,
        })))),
        fields: Fields::Authorization(Default::default()),
    }
}

pub(crate) fn write_message(encoded_data: Option<&str>) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Records(Box::new(Records::Write(Default::default()))),
        fields: Fields::Write(WriteFields {
            encoded_data: encoded_data.map(str::to_string),
            ..Default::default()
        }),
    }
}

/// Builds indexes from string pairs, the common case for feed rows.
pub(crate) fn indexes(pairs: &[(&str, &str)]) -> KeyValues {
    let mut indexes = KeyValues::new();
    for (key, value) in pairs {
        indexes.insert((*key).to_string(), Value::String((*value).to_string()));
    }
    indexes
}

/// `ProtocolsConfigure` fixture, the third message type carried by the feed.
pub(crate) fn configure_message() -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Protocols(Box::new(Protocols::Configure(Default::default()))),
        fields: Fields::Authorization(Default::default()),
    }
}

/// Stand-in for the `RecordsWrite` a resolver attaches to an update or delete.
pub(crate) fn initial_write_message() -> Message<RecordsWriteDescriptor> {
    Message {
        descriptor: Default::default(),
        fields: WriteFields::default(),
    }
}

/// Single-index equality filter, the common subscription filter shape.
pub(crate) fn index_filters(key: &str, value: &str) -> Filters {
    Filters::from([[(
        FilterKey::Index(key.to_string()),
        Filter::Equal(Value::String(value.to_string())),
    )]])
}

/// Feed entry at `position` carrying a `RecordsWrite` and no indexes.
pub(crate) fn entry(position: u64, message_cid: &str) -> EventLogEntry {
    entry_with_message(position, message_cid, write_message(None))
}

pub(crate) fn entry_with_message(
    position: u64,
    message_cid: &str,
    message: Message<Descriptor>,
) -> EventLogEntry {
    EventLogEntry {
        seq: position.to_string(),
        event: MessageEvent {
            message,
            initial_write: None,
        },
        indexes: KeyValues::new(),
        message_cid: Some(message_cid.to_string()),
        encoded_data: None,
    }
}

pub(crate) fn page(
    events: Vec<EventLogEntry>,
    cursor: ProgressToken,
    drained: bool,
) -> EventLogReadResult {
    EventLogReadResult {
        events,
        cursor: Some(cursor),
        drained,
    }
}

pub(crate) fn empty_page(cursor: ProgressToken, drained: bool) -> EventLogReadResult {
    page(Vec::new(), cursor, drained)
}

/// Page missing its scan cursor, which the adapter must reject as an internal error.
pub(crate) fn page_without_cursor(events: Vec<EventLogEntry>, drained: bool) -> EventLogReadResult {
    EventLogReadResult {
        events,
        cursor: None,
        drained,
    }
}

/// Structured progress gap, as a feed reader would return one.
pub(crate) fn progress_gap_error(
    requested: ProgressToken,
    latest_available: ProgressToken,
    reason: ProgressGapReason,
) -> EventLogError {
    EventLogError::ProgressGap(Box::new(ProgressGapInfo {
        requested,
        oldest_available: token(0, None),
        latest_available,
        reason,
        code: ProgressGapCode::ProgressGap,
    }))
}

/// Transient read failure that must not close a subscription.
pub(crate) fn transient_error(detail: &str) -> EventLogError {
    EventLogError::StoreError(StoreError::InternalException(detail.to_string()))
}

// -------------------------------------------------------------------------
// Scripted feed reader
// -------------------------------------------------------------------------

/// Produces an [`EventLogError`] on demand, since errors are not [`Clone`].
pub(crate) type ErrorFactory = Arc<dyn Fn() -> EventLogError + Send + Sync>;

pub(crate) fn error_factory<F>(factory: F) -> ErrorFactory
where
    F: Fn() -> EventLogError + Send + Sync + 'static,
{
    Arc::new(factory)
}

enum ScriptedOutcome {
    Page(EventLogReadResult),
    Error(ErrorFactory),
}

struct ScriptedResponse {
    outcome: ScriptedOutcome,
    entered: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

/// Controls one scripted read that the reader holds open.
///
/// [`ReadGate::entered`] resolves once the adapter is inside that read, and
/// [`ReadGate::release`] lets it return. Together they make "close while a read
/// is in flight" deterministic.
pub(crate) struct ReadGate {
    entered: Option<oneshot::Receiver<()>>,
    release: Option<oneshot::Sender<()>>,
}

impl ReadGate {
    /// Waits until the adapter has entered the gated read.
    pub(crate) async fn entered(&mut self) {
        let entered = self
            .entered
            .take()
            .expect("read gate entry awaited more than once");
        timeout(HARNESS_TIMEOUT, entered)
            .await
            .expect("timed out waiting for the gated read to start")
            .expect("scripted reader dropped before entering the gated read");
    }

    /// Lets the gated read return its scripted outcome.
    pub(crate) fn release(&mut self) {
        let release = self
            .release
            .take()
            .expect("read gate released more than once");
        let _ = release.send(());
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RecordedRead {
    pub(crate) tenant: String,
    pub(crate) cursor: Option<ProgressToken>,
    pub(crate) limit: Option<u64>,
    pub(crate) filters: Option<Filters>,
}

#[derive(Default)]
struct ScriptedReaderInner {
    epoch: Mutex<String>,
    bounds: Mutex<Option<ReplicationBounds>>,
    bounds_error: Mutex<Option<ErrorFactory>>,
    /// Scan position used for the default page returned once the script runs out.
    default_position: Mutex<u64>,
    responses: Mutex<VecDeque<ScriptedResponse>>,
    zero_limit_responses: Mutex<VecDeque<ScriptedResponse>>,
    reads: Mutex<Vec<RecordedRead>>,
    bounds_calls: Mutex<Vec<String>>,
    progress: Notify,
}

/// Feed reader whose responses are scripted per read.
///
/// Queued responses are consumed in order. Once the script is exhausted the
/// reader returns an empty drained page anchored at
/// [`ScriptedReader::set_default_position`], so incidental reads (cursor
/// validation, empty-feed anchors, a final drain pass) never panic. Assertions
/// are made against [`ScriptedReader::reads`] and delivered messages instead.
///
/// Reads with `limit: Some(0)` — cursor validation and empty-feed anchor
/// capture — draw from their own script ([`ScriptedReader::push_zero_limit_page`],
/// [`ScriptedReader::push_zero_limit_error`]) so tests script paging without
/// counting the opening reads that interleave with it.
#[derive(Clone, Default)]
pub(crate) struct ScriptedReader {
    inner: Arc<ScriptedReaderInner>,
}

impl ScriptedReader {
    pub(crate) fn new() -> Self {
        let reader = Self::default();
        *reader.inner.epoch.lock().expect("epoch lock") = EPOCH.to_string();
        reader
    }

    pub(crate) fn with_epoch(epoch: &str) -> Self {
        let reader = Self::default();
        *reader.inner.epoch.lock().expect("epoch lock") = epoch.to_string();
        reader
    }

    /// Sets the bounds returned by `log_bounds`. `None` models an empty feed.
    pub(crate) fn set_bounds(&self, bounds: Option<ReplicationBounds>) {
        *self.inner.bounds.lock().expect("bounds lock") = bounds;
    }

    /// Fails the next `log_bounds` call.
    pub(crate) fn fail_next_bounds(&self, factory: ErrorFactory) {
        *self.inner.bounds_error.lock().expect("bounds error lock") = Some(factory);
    }

    /// Scan position used by the default page returned after the script is exhausted.
    pub(crate) fn set_default_position(&self, position: u64) {
        *self
            .inner
            .default_position
            .lock()
            .expect("default position lock") = position;
    }

    pub(crate) fn push_page(&self, result: EventLogReadResult) {
        self.push(ScriptedResponse {
            outcome: ScriptedOutcome::Page(result),
            entered: None,
            release: None,
        });
    }

    pub(crate) fn push_pages<I>(&self, results: I)
    where
        I: IntoIterator<Item = EventLogReadResult>,
    {
        for result in results {
            self.push_page(result);
        }
    }

    pub(crate) fn push_error(&self, factory: ErrorFactory) {
        self.push(ScriptedResponse {
            outcome: ScriptedOutcome::Error(factory),
            entered: None,
            release: None,
        });
    }

    /// Queues a response for the next `limit: Some(0)` read.
    pub(crate) fn push_zero_limit_page(&self, result: EventLogReadResult) {
        self.push_zero_limit(ScriptedResponse {
            outcome: ScriptedOutcome::Page(result),
            entered: None,
            release: None,
        });
    }

    /// Fails the next `limit: Some(0)` read, as cursor validation would.
    pub(crate) fn push_zero_limit_error(&self, factory: ErrorFactory) {
        self.push_zero_limit(ScriptedResponse {
            outcome: ScriptedOutcome::Error(factory),
            entered: None,
            release: None,
        });
    }

    /// Queues a page the harness can hold open; see [`ReadGate`].
    pub(crate) fn push_gated_page(&self, result: EventLogReadResult) -> ReadGate {
        self.push_gated(ScriptedOutcome::Page(result))
    }

    /// Holds the next `limit: Some(0)` read open, freezing a subscription mid-install.
    pub(crate) fn push_gated_zero_limit_page(&self, result: EventLogReadResult) -> ReadGate {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        self.push_zero_limit(ScriptedResponse {
            outcome: ScriptedOutcome::Page(result),
            entered: Some(entered_tx),
            release: Some(release_rx),
        });

        ReadGate {
            entered: Some(entered_rx),
            release: Some(release_tx),
        }
    }

    /// Queues an error the harness can hold open; see [`ReadGate`].
    pub(crate) fn push_gated_error(&self, factory: ErrorFactory) -> ReadGate {
        self.push_gated(ScriptedOutcome::Error(factory))
    }

    fn push_gated(&self, outcome: ScriptedOutcome) -> ReadGate {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        self.push(ScriptedResponse {
            outcome,
            entered: Some(entered_tx),
            release: Some(release_rx),
        });

        ReadGate {
            entered: Some(entered_rx),
            release: Some(release_tx),
        }
    }

    fn push(&self, response: ScriptedResponse) {
        self.inner
            .responses
            .lock()
            .expect("responses lock")
            .push_back(response);
    }

    fn push_zero_limit(&self, response: ScriptedResponse) {
        self.inner
            .zero_limit_responses
            .lock()
            .expect("zero-limit responses lock")
            .push_back(response);
    }

    /// Reads that actually scanned the feed, excluding validation and anchor reads.
    pub(crate) fn paging_reads(&self) -> Vec<RecordedRead> {
        self.reads()
            .into_iter()
            .filter(|read| read.limit != Some(0))
            .collect()
    }

    /// Every read the adapter has issued, in order.
    pub(crate) fn reads(&self) -> Vec<RecordedRead> {
        self.inner.reads.lock().expect("reads lock").clone()
    }

    pub(crate) fn read_count(&self) -> usize {
        self.inner.reads.lock().expect("reads lock").len()
    }

    /// Tenants passed to `log_bounds`, in order.
    pub(crate) fn bounds_calls(&self) -> Vec<String> {
        self.inner
            .bounds_calls
            .lock()
            .expect("bounds calls lock")
            .clone()
    }

    /// Waits until at least `count` reads have been recorded.
    pub(crate) async fn await_reads(&self, count: usize) -> Vec<RecordedRead> {
        timeout(HARNESS_TIMEOUT, async {
            loop {
                let progress = self.inner.progress.notified();
                if self.read_count() >= count {
                    return self.reads();
                }
                progress.await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "timed out waiting for {count} reads; recorded {}",
                self.read_count()
            )
        })
    }

    /// Asserts no further read arrives within `window`.
    pub(crate) async fn expect_no_read_within(&self, window: Duration) {
        let before = self.read_count();
        let waited = timeout(window, async {
            loop {
                let progress = self.inner.progress.notified();
                if self.read_count() > before {
                    return self.read_count();
                }
                progress.await;
            }
        })
        .await;

        if let Ok(after) = waited {
            panic!("expected no further reads, but read count went from {before} to {after}");
        }
    }

    fn record(&self, tenant: &str, options: &EventLogReadOptions) {
        self.inner
            .reads
            .lock()
            .expect("reads lock")
            .push(RecordedRead {
                tenant: tenant.to_string(),
                cursor: options.cursor.clone(),
                limit: options.limit,
                filters: options.filters.clone(),
            });
        self.inner.progress.notify_waiters();
    }

    fn default_page(&self) -> EventLogReadResult {
        let position = *self
            .inner
            .default_position
            .lock()
            .expect("default position lock");
        let epoch = self.inner.epoch.lock().expect("epoch lock").clone();
        empty_page(build_token(TENANT, &epoch, position, None), true)
    }
}

impl ReplicationFeedReader for ScriptedReader {
    async fn log_read(
        &self,
        tenant: &str,
        options: EventLogReadOptions,
    ) -> Result<EventLogReadResult, EventLogError> {
        self.record(tenant, &options);

        let response = if options.limit == Some(0) {
            self.inner
                .zero_limit_responses
                .lock()
                .expect("zero-limit responses lock")
                .pop_front()
        } else {
            self.inner
                .responses
                .lock()
                .expect("responses lock")
                .pop_front()
        };

        let Some(response) = response else {
            return Ok(self.default_page());
        };

        if let Some(entered) = response.entered {
            let _ = entered.send(());
        }

        if let Some(release) = response.release {
            let _ = release.await;
        }

        match response.outcome {
            ScriptedOutcome::Page(result) => Ok(result),
            ScriptedOutcome::Error(factory) => Err(factory()),
        }
    }

    async fn log_bounds(&self, tenant: &str) -> Result<Option<ReplicationBounds>, EventLogError> {
        self.inner
            .bounds_calls
            .lock()
            .expect("bounds calls lock")
            .push(tenant.to_string());

        let failure = self
            .inner
            .bounds_error
            .lock()
            .expect("bounds error lock")
            .take();
        if let Some(failure) = failure {
            return Err(failure());
        }

        Ok(self.inner.bounds.lock().expect("bounds lock").clone())
    }

    async fn fingerprint(
        &self,
        _tenant: &str,
        _scopes: &[String],
    ) -> Result<Fingerprint, EventLogError> {
        Ok(Fingerprint::default())
    }

    async fn epoch(&self) -> Result<String, EventLogError> {
        Ok(self.inner.epoch.lock().expect("epoch lock").clone())
    }
}

// -------------------------------------------------------------------------
// Listener recording
// -------------------------------------------------------------------------

/// One delivered `SubscriptionMessage::Event`, flattened for assertions.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DeliveredEvent {
    pub(crate) cursor: ProgressToken,
    pub(crate) event: MessageEvent<Descriptor>,
    pub(crate) seq: Option<String>,
    pub(crate) message_cid: Option<String>,
    pub(crate) is_latest_base_state: Option<bool>,
    pub(crate) protocol: Option<String>,
    pub(crate) encoded_data: Option<String>,
}

/// Receiving half of a [`SubscriptionListener`] built by [`recorder`].
pub(crate) struct Recorder {
    receiver: mpsc::UnboundedReceiver<SubscriptionMessage>,
}

/// Creates a listener and the recorder that observes what it was called with.
pub(crate) fn recorder() -> (SubscriptionListener, Recorder) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let listener: SubscriptionListener = Box::new(move |message| {
        let _ = sender.send(message);
    });

    (listener, Recorder { receiver })
}

/// Creates a listener that runs `hook` before recording each message.
///
/// Used for close-from-inside-the-listener coverage.
pub(crate) fn recorder_with_hook<F>(hook: F) -> (SubscriptionListener, Recorder)
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
    pub(crate) async fn next_message(&mut self) -> SubscriptionMessage {
        timeout(HARNESS_TIMEOUT, self.receiver.recv())
            .await
            .expect("timed out waiting for a subscription message")
            .expect("subscription listener was dropped")
    }

    pub(crate) fn try_next(&mut self) -> Option<SubscriptionMessage> {
        self.receiver.try_recv().ok()
    }

    pub(crate) async fn expect_event(&mut self) -> DeliveredEvent {
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

    pub(crate) async fn expect_events(&mut self, count: usize) -> Vec<DeliveredEvent> {
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            events.push(self.expect_event().await);
        }
        events
    }

    pub(crate) async fn expect_eose(&mut self) -> ProgressToken {
        match self.next_message().await {
            SubscriptionMessage::Eose { cursor } => cursor,
            other => panic!("expected EOSE, got {other:?}"),
        }
    }

    pub(crate) async fn expect_error(&mut self) -> (ProgressToken, SubscriptionError) {
        match self.next_message().await {
            SubscriptionMessage::Error { cursor, error } => (cursor, error),
            other => panic!("expected a terminal error, got {other:?}"),
        }
    }

    /// Asserts nothing is delivered within `window`.
    ///
    /// A dropped listener counts as quiet: a cleaned-up subscription releases it.
    pub(crate) async fn expect_quiet(&mut self, window: Duration) {
        if let Ok(Some(message)) = timeout(window, self.receiver.recv()).await {
            panic!("expected no further messages, got {message:?}");
        }
    }

    /// Positions (`seq`) of every event delivered so far, drained without waiting.
    pub(crate) fn drain_event_positions(&mut self) -> Vec<String> {
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

// -------------------------------------------------------------------------
// Initial-write resolution
// -------------------------------------------------------------------------

#[derive(Default)]
struct StubResolverInner {
    initial_write: Option<Message<RecordsWriteDescriptor>>,
    failures: Mutex<usize>,
    calls: Mutex<usize>,
}

/// Resolver stand-in: answers with a fixed initial write, or fails on demand.
#[derive(Clone, Default)]
pub(crate) struct StubResolver {
    inner: Arc<StubResolverInner>,
}

impl StubResolver {
    /// Resolver that attaches `initial_write` to every event it is asked about.
    pub(crate) fn resolving(initial_write: Message<RecordsWriteDescriptor>) -> Self {
        Self {
            inner: Arc::new(StubResolverInner {
                initial_write: Some(initial_write),
                ..Default::default()
            }),
        }
    }

    /// Fails the next `count` resolutions, then resolves normally again.
    pub(crate) fn fail_next(&self, count: usize) {
        *self.inner.failures.lock().expect("failures lock") = count;
    }

    pub(crate) fn calls(&self) -> usize {
        *self.inner.calls.lock().expect("calls lock")
    }

    pub(crate) fn shared(&self) -> Arc<dyn InitialWriteResolver> {
        Arc::new(self.clone())
    }
}

impl InitialWriteResolver for StubResolver {
    fn resolve_initial_write<'a>(
        &'a self,
        _tenant: &'a str,
        _event: &'a Message<Descriptor>,
    ) -> crate::stores::write_resolver::InitialWriteFuture<'a> {
        *self.inner.calls.lock().expect("calls lock") += 1;

        let failing = {
            let mut failures = self.inner.failures.lock().expect("failures lock");
            let failing = *failures > 0;
            *failures = failures.saturating_sub(1);
            failing
        };
        let initial_write = self.inner.initial_write.clone();

        Box::pin(async move {
            if failing {
                return Err(transient_error("initial-write resolution failed"));
            }
            Ok(initial_write)
        })
    }
}

// -------------------------------------------------------------------------
// Background error sink
// -------------------------------------------------------------------------

/// Captures background drain errors reported through [`DurableEventLogConfig::on_error`].
#[derive(Clone, Default)]
pub(crate) struct ErrorSink {
    errors: Arc<Mutex<Vec<String>>>,
    progress: Arc<Notify>,
}

impl ErrorSink {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn sink(&self) -> ErrorFn {
        let errors = Arc::clone(&self.errors);
        let progress = Arc::clone(&self.progress);
        Arc::new(move |error: &EventLogError| {
            errors
                .lock()
                .expect("error sink lock")
                .push(error.to_string());
            progress.notify_waiters();
        })
    }

    pub(crate) fn errors(&self) -> Vec<String> {
        self.errors.lock().expect("error sink lock").clone()
    }

    /// Waits until at least `count` background errors have been reported.
    pub(crate) async fn await_errors(&self, count: usize) -> Vec<String> {
        timeout(HARNESS_TIMEOUT, async {
            loop {
                let progress = self.progress.notified();
                if self.errors().len() >= count {
                    return self.errors();
                }
                progress.await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "timed out waiting for {count} background errors; recorded {:?}",
                self.errors()
            )
        })
    }
}

// -------------------------------------------------------------------------
// Adapter harnesses
// -------------------------------------------------------------------------

/// Config used by tests: no idle polling unless a test asks for it.
pub(crate) fn test_config() -> DurableEventLogConfig {
    DurableEventLogConfig {
        idle_redrain_interval: None,
        ..Default::default()
    }
}

/// Adapter over a [`ScriptedReader`], for feed responses a real store cannot produce.
pub(crate) struct ScriptedHarness {
    pub(crate) reader: ScriptedReader,
    pub(crate) bus: InProcessWakeBus,
    pub(crate) log: DurableEventLog<ScriptedReader, InProcessWakeBus>,
}

pub(crate) struct ScriptedHarnessBuilder {
    reader: ScriptedReader,
    bus: InProcessWakeBus,
    config: DurableEventLogConfig,
    resolver: Option<Arc<dyn InitialWriteResolver>>,
}

pub(crate) fn scripted_harness() -> ScriptedHarnessBuilder {
    ScriptedHarnessBuilder {
        reader: ScriptedReader::new(),
        bus: InProcessWakeBus::new(),
        config: test_config(),
        resolver: None,
    }
}

impl ScriptedHarnessBuilder {
    pub(crate) fn reader(mut self, reader: ScriptedReader) -> Self {
        self.reader = reader;
        self
    }

    pub(crate) fn bus(mut self, bus: InProcessWakeBus) -> Self {
        self.bus = bus;
        self
    }

    pub(crate) fn config(mut self, config: DurableEventLogConfig) -> Self {
        self.config = config;
        self
    }

    pub(crate) fn resolver(mut self, resolver: Arc<dyn InitialWriteResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub(crate) fn build(self) -> ScriptedHarness {
        let log = DurableEventLog::new(
            self.reader.clone(),
            self.bus.clone(),
            self.resolver,
            Some(self.config),
        );

        ScriptedHarness {
            reader: self.reader,
            bus: self.bus,
            log,
        }
    }
}

impl ScriptedHarness {
    /// Publishes a best-effort wake, as the message store would after a commit.
    pub(crate) fn publish_wake(&self, tenant: &str, position: u64) {
        publish_wake(&self.bus, tenant, position);
    }
}

/// Adapter over [`MemoryMessageStore`], exercising the real commit -> wake -> drain path.
pub(crate) struct LiveHarness {
    pub(crate) store: MemoryMessageStore,
    pub(crate) bus: InProcessWakeBus,
    pub(crate) log: DurableEventLog<MemoryMessageStore, InProcessWakeBus>,
}

pub(crate) struct LiveHarnessBuilder {
    bus: InProcessWakeBus,
    config: DurableEventLogConfig,
    resolver: Option<Arc<dyn InitialWriteResolver>>,
    message_store_resolver: bool,
}

pub(crate) fn live_harness() -> LiveHarnessBuilder {
    LiveHarnessBuilder {
        bus: InProcessWakeBus::new(),
        config: test_config(),
        resolver: None,
        message_store_resolver: false,
    }
}

impl LiveHarnessBuilder {
    pub(crate) fn bus(mut self, bus: InProcessWakeBus) -> Self {
        self.bus = bus;
        self
    }

    pub(crate) fn config(mut self, config: DurableEventLogConfig) -> Self {
        self.config = config;
        self
    }

    pub(crate) fn resolver(mut self, resolver: Arc<dyn InitialWriteResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Resolves initial writes through the harness's own message store.
    pub(crate) fn with_message_store_resolver(mut self) -> Self {
        self.message_store_resolver = true;
        self
    }

    pub(crate) async fn build(self) -> LiveHarness {
        // The publisher clone goes to the store and the subscriber clone to the
        // adapter, so wakes follow the same path as a native assembly.
        let mut store = MemoryMessageStore::default().with_waker_publisher(self.bus.clone());
        store.open().await.expect("memory message store must open");

        let resolver = match (self.resolver, self.message_store_resolver) {
            (Some(resolver), _) => Some(resolver),
            (None, true) => Some(Arc::new(MessageStoreInitialWriteResolver::new(Arc::new(
                store.clone(),
            ))) as Arc<dyn InitialWriteResolver>),
            (None, false) => None,
        };

        let log =
            DurableEventLog::new(store.clone(), self.bus.clone(), resolver, Some(self.config));

        LiveHarness {
            store,
            bus: self.bus,
            log,
        }
    }
}

impl LiveHarness {
    /// Commits a feed message, which publishes a wake after the commit.
    pub(crate) async fn commit(&self, tenant: &str, message: Message<Descriptor>, index: &str) {
        self.store
            .put(tenant, message, indexes(&[("marker", index)]))
            .await
            .expect("feed put");
    }

    /// Publishes a wake directly, modelling a duplicate or stale hint.
    pub(crate) fn publish_wake(&self, tenant: &str, position: u64) {
        publish_wake(&self.bus, tenant, position);
    }

    /// Commits a message with explicit indexes.
    pub(crate) async fn store_put(
        &self,
        tenant: &str,
        message: Message<Descriptor>,
        indexes: KeyValues,
    ) {
        self.store
            .put(tenant, message, indexes)
            .await
            .expect("feed put");
    }

    /// Commits a `RecordsDelete` distinguished by `marker`.
    pub(crate) async fn commit_delete(&self, tenant: &str, marker: &str, timestamp: &str) {
        self.commit(tenant, delete_message(marker, timestamp), marker)
            .await;
    }
}

/// Yields enough times for wake-bus tasks queued on this runtime to run.
///
/// Wake delivery is asynchronous, so a test that must observe a wake taking
/// effect before it proceeds parks here rather than sleeping.
pub(crate) async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// Publishes a wake directly, bypassing the store, to model a duplicate or stale hint.
pub(crate) fn publish_wake(bus: &InProcessWakeBus, tenant: &str, position: u64) {
    bus.publish(Wake {
        tenant: tenant.to_string(),
        position,
    })
    .expect("in-process wake publish");
}
