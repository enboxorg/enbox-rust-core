//! Shared harness for [`DurableEventLog`] tests.
//!
//! Live commit -> wake -> drain coverage lives in the backend-neutral
//! [`live_suite`](super::super::live_suite), run against memory here and
//! SQLite in `dwn-rs-stores`.
//!
//! * [`scripted_harness`] drives the adapter with a [`ScriptedReader`], which can
//!   produce feed responses a real store never would: a missing scan cursor, a
//!   mid-drain progress gap, a transient failure, or a read held open while the
//!   subscription closes.
//!
//! Waits are bounded by [`HARNESS_TIMEOUT`]; a timeout means the adapter stopped
//! making progress and the test fails rather than hangs.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{oneshot, Notify};
use tokio::time::timeout;

use crate::descriptors::RecordsWriteDescriptor;
use crate::errors::{EventLogError, StoreError};
use crate::fields::WriteFields;
use crate::stores::durable_event_log::{DurableEventLog, DurableEventLogConfig, ErrorFn};
use crate::stores::replication_feed_reader::{build_token, Fingerprint, ReplicationBounds};
use crate::stores::wake::InProcessWakeBus;
use crate::stores::write_resolver::InitialWriteResolver;
use crate::stores::{
    EventLogEntry, EventLogReadOptions, EventLogReadResult, KeyValues, ProgressGapCode,
    ProgressGapInfo, ProgressGapReason, ReplicationFeedReader,
};
use crate::{Descriptor, Filters, Message, MessageEvent, ProgressToken};

pub(crate) const EPOCH: &str = "01JBQ0TESTEPOCH000000000000";

pub(crate) use super::super::live_suite::{
    index_filters, publish_wake, recorder, recorder_with_hook, settle, test_config, write_message,
    HARNESS_TIMEOUT, OTHER_TENANT, QUIET_WINDOW, TENANT,
};

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

pub(crate) fn initial_write_message() -> Message<RecordsWriteDescriptor> {
    Message {
        descriptor: Default::default(),
        fields: WriteFields::default(),
    }
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
/// reader returns an empty drained page, so incidental reads (cursor
/// validation, empty-feed anchors, a final drain pass) never panic. Assertions
/// are made against [`ScriptedReader::reads`] and delivered messages instead.
///
/// Reads with `limit: Some(0)` — cursor validation and empty-feed anchor
/// capture — draw from their own script ([`ScriptedReader::push_zero_limit_error`])
/// so tests script paging without counting the opening reads that interleave
/// with it.
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

    /// Sets the bounds returned by `log_bounds`. `None` models an empty feed.
    pub(crate) fn set_bounds(&self, bounds: Option<ReplicationBounds>) {
        *self.inner.bounds.lock().expect("bounds lock") = bounds;
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
