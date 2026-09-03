//! Read-only [`EventLog`] adapter for the durable replication feed.
//!
//! [`DurableEventLog`] presents a [`ReplicationFeedReader`] through the event-log
//! API used by subscription handlers. Durable feed rows remain owned by the
//! message store; the adapter reads committed rows and uses a [`WakeSubscriber`]
//! only to learn when a tenant's feed may need to be drained again.
//!
//! Wake delivery is best effort and does not establish progress. Implementations
//! must resume from progress tokens returned by the durable feed and tolerate
//! coalesced, duplicated, or dropped wakes.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::errors::{EventLogError, StoreError};
use crate::stores::replication_feed_reader::{parse_feed_position, ReplicationBounds};
use crate::stores::wake::{
    InProcessWakeBus, WakePublishHandler, WakeSubscriptionHandle, WakeSubscriptionListener,
};
use crate::stores::write_resolver::{InitialWriteResolver, MessageStoreInitialWriteResolver};
use crate::stores::{
    wake::WakeSubscriber, EventLog, EventLogReadOptions, EventLogReadResult, EventLogReplayBounds,
    EventLogSubscribeOptions, EventLogTrimBound, EventSubscription, KeyValues,
    ReplicationFeedReader, SubscriptionErrorCode, SubscriptionListener,
};
use crate::stores::{
    EventLogEntry, MessageStore, ProgressGapCode, ProgressGapInfo, ProgressGapReason,
    SubscriptionError, SubscriptionMessage,
};
use crate::{Descriptor, Filters, MessageEvent, ProgressToken, Value};

#[cfg(test)]
mod tests;

/// Backend-neutral live battery, run against memory here and SQLite in
/// `dwn-rs-stores`. Available to downstream crates via `test-utils`.
#[cfg(any(test, feature = "test-utils"))]
pub mod live_suite;

const DEFAULT_DRAIN_READ_LIMIT: u64 = 100;

/// Read-only event log backed by a durable replication-feed reader.
///
/// This adapter does not own a second event history. In particular, it must not
/// allocate feed positions, persist event rows, trim feed history, or publish
/// events independently of the message store. Its `emit` and `trim` operations
/// therefore return an unsupported-operation error while those legacy methods
/// remain part of [`EventLog`].
///
/// `R` provides authoritative ordered reads and progress validation. `S`
/// supplies best-effort tenant wake notifications used to trigger live drains.
/// The two dependencies must refer to the same underlying message-feed domain.
pub struct DurableEventLog<R, S>
where
    R: ReplicationFeedReader,
    S: WakeSubscriber,
{
    /// Authoritative source of committed replication-feed entries and cursors.
    inner: Arc<DurableEventLogInner<R>>,

    /// Consumer of best-effort wake hints for newly committed feed entries.
    subscriber: S,
}

impl<R, S> Clone for DurableEventLog<R, S>
where
    R: ReplicationFeedReader,
    S: WakeSubscriber + Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            subscriber: self.subscriber.clone(),
        }
    }
}

impl<M> DurableEventLog<M, InProcessWakeBus>
where
    M: ReplicationFeedReader + MessageStore + Clone + Send + Sync + 'static,
{
    pub fn paired_message_store<E>(
        make_reader: impl FnOnce(WakePublishHandler) -> Result<M, E>,
        config: Option<DurableEventLogConfig>,
    ) -> Result<(Self, M), E> {
        let wake = InProcessWakeBus::new();
        let publisher = WakePublishHandler::new(Arc::new(wake.clone()));
        let reader = make_reader(publisher)?;

        let shared = Arc::new(reader.clone());
        let resolver: Arc<dyn InitialWriteResolver> =
            Arc::new(MessageStoreInitialWriteResolver::new(shared.clone()));

        Ok((
            Self::with_parts(shared, wake, Some(resolver), config),
            reader,
        ))
    }
}

/// IdleRedrainTask is a background task that periodically re-drains all subscriptions that have
/// requested a redrain. This is used to ensure that subscriptions that have been idle for a long
/// time are still able to receive new events. The task is spawned when the DurableEventLog
/// is created and is cancelled when the DurableEventLog is dropped. The task is only spawned if the
/// idle_redrain_interval is set to Some(Duration) in the DurableEventLogConfig. If
/// idle_redrain_interval is set to None, the task is not spawned and the subscriptions will only be
/// redrained when a wake is received. If idle_redrain_interval is set to Some(Duration::ZERO), the task
/// is not spawned and the subscriptions will be redrained immediately after a wake is received. This
/// is useful for testing and debugging, but should not be used in production.
struct IdleRedrainTask {
    cancel: oneshot::Sender<()>,
    handle: JoinHandle<()>,
}

impl IdleRedrainTask {
    fn spawn<R>(period: Duration, inner: &Arc<DurableEventLogInner<R>>) -> Self
    where
        R: ReplicationFeedReader + Send + Sync + 'static,
    {
        debug_assert!(
            period > Duration::ZERO,
            "idle_redrain_interval must be greater than zero"
        );

        let weak = Arc::downgrade(inner);
        let (cancel, mut cancelled) = oneshot::channel();

        let handle = tokio::spawn(async move {
            let start = Instant::now() + period;
            let mut ticker = tokio::time::interval_at(start, period);

            loop {
                tokio::select! {
                    biased;

                    _ = &mut cancelled => {
                        return;
                    }

                    _ = ticker.tick() => {
                        let Some(inner) = weak.upgrade() else {
                            return;
                        };

                        DurableEventLogInner::redrain_all(&inner).await;
                        }
                }
            }
        });

        Self { cancel, handle }
    }

    async fn shutdown(self) {
        let _ = self.cancel.send(());
        if let Err(err) = self.handle.await {
            tracing::error!("IdleRedrainTask failed to join: {:?}", err);
        }
    }
}

impl<R, S> DurableEventLog<R, S>
where
    R: ReplicationFeedReader + Send + Sync + 'static,
    S: WakeSubscriber,
{
    /// Create a new durable event log adapter.
    pub fn new(
        reader: R,
        subscriber: S,
        initial_write_resolver: Option<Arc<dyn InitialWriteResolver>>,
        config: Option<DurableEventLogConfig>,
    ) -> Self {
        Self::with_parts(Arc::new(reader), subscriber, initial_write_resolver, config)
    }

    fn with_parts(
        reader: Arc<R>,
        subscriber: S,
        initial_write_resolver: Option<Arc<dyn InitialWriteResolver>>,
        config: Option<DurableEventLogConfig>,
    ) -> Self {
        let mut config = config.unwrap_or_default();
        if config.idle_redrain_interval == Some(Duration::ZERO) {
            config.idle_redrain_interval = None;
        }
        config.read_limit = config.read_limit.max(1);

        let inner = Arc::new(DurableEventLogInner {
            reader,
            initial_write_resolver,
            subscriptions: RwLock::new(BTreeMap::new()),
            install_locks: Mutex::new(BTreeMap::new()),
            config: config.clone(),
            closed: AtomicBool::new(false),
            idle_redrain_task: StdMutex::new(None),
            installation_gate: RwLock::new(()),
        });

        if let Some(period) = config.idle_redrain_interval {
            let task = IdleRedrainTask::spawn(period, &inner);
            *inner
                .idle_redrain_task
                .lock()
                .expect("mutex for inner redrain failed") = Some(task);
        }

        Self { subscriber, inner }
    }
}

pub type ErrorFn = Arc<dyn Fn(&EventLogError) + Send + Sync>;

/// Configuration for [`DurableEventLog`].
#[derive(Clone)]
pub struct DurableEventLogConfig {
    // Maximum number of feed rows returned per-drain. Default 100; values
    // are claimed to at least 1.
    pub read_limit: u64,

    // Idle re-drain interval bounding dropped-wake latency. None disables
    // polling. Default 30s.
    pub idle_redrain_interval: Option<Duration>,

    // Sink for background drain errors. Defaults to logs via `tracing`.
    pub on_error: Option<ErrorFn>,
}

impl Default for DurableEventLogConfig {
    fn default() -> Self {
        Self {
            read_limit: DEFAULT_DRAIN_READ_LIMIT,
            idle_redrain_interval: Some(Duration::from_secs(30)),
            on_error: None,
        }
    }
}

struct DurableEventLogInner<R> {
    reader: Arc<R>,
    initial_write_resolver: Option<Arc<dyn InitialWriteResolver>>,
    subscriptions: RwLock<BTreeMap<String, Arc<SubscriptionState>>>,
    install_locks: Mutex<BTreeMap<String, Weak<Mutex<()>>>>,
    config: DurableEventLogConfig,
    closed: AtomicBool,
    // Background task for periodic idle re-drain. None if disabled.
    idle_redrain_task: StdMutex<Option<IdleRedrainTask>>,

    // coordinate subscription installation and cleanup to avoid installing
    // a subscription while another task is cleaning it up.
    installation_gate: RwLock<()>,
}

pub struct SubscriptionState {
    id: String,
    tenant: String,
    listener: SubscriptionListener,
    filters: Option<Filters>,
    mutable: Mutex<SubscriptionStateMutable>,
    delivery_gate: Mutex<()>,
}

struct SubscriptionStateMutable {
    cursor: Option<ProgressToken>,
    phase: SubscriptionPhase,
    draining: bool,
    redrain_requested: bool,
    terminal_error_sent: bool,
    wake_handle: Option<Box<dyn WakeSubscriptionHandle>>,
    drain_task: Option<JoinHandle<()>>,
}

#[derive(Debug, PartialEq, Eq)]
enum SubscriptionPhase {
    Replay,
    Live,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
enum ReplayOutcome {
    ReachedFrozenHead,
    NoCursorFollow,
    Closed,
}

impl<R, S> EventLog for DurableEventLog<R, S>
where
    R: ReplicationFeedReader + Send + Sync + 'static,
    S: WakeSubscriber,
{
    async fn open(&mut self) -> Result<(), EventLogError> {
        Ok(())
    }

    async fn close(&mut self) -> () {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }

        let task = {
            self.inner
                .idle_redrain_task
                .lock()
                .expect("idle redrain mutex failed")
                .take()
        };
        if let Some(task) = task {
            task.shutdown().await;
        }

        // wait for installation and cleanup to finish before we start cleaning up subscriptions
        drop(self.inner.installation_gate.write().await);

        let subscriptions = {
            self.inner
                .subscriptions
                .read()
                .await
                .values()
                .cloned()
                .collect::<Vec<_>>()
        };

        for subscription in subscriptions {
            if let Err(err) = DurableEventLogInner::cleanup_subscription(
                &self.inner,
                &subscription,
                CleanupOrigin::External,
            )
            .await
            {
                self.inner.report_background_error(&subscription, &err);
            }
        }
    }

    async fn emit(
        &self,
        _tenant: &str,
        _event: MessageEvent<Descriptor>,
        _indexes: KeyValues,
        _message_cid: &str,
    ) -> Result<Option<ProgressToken>, EventLogError> {
        Err(EventLogError::UnsupportedReadOption("emit".to_string()))
    }

    async fn read(
        &self,
        tenant: &str,
        options: Option<EventLogReadOptions>,
    ) -> Result<EventLogReadResult, EventLogError> {
        let options = options.unwrap_or_default();
        self.inner.reader.log_read(tenant, options).await
    }

    async fn subscribe(
        &self,
        tenant: &str,
        id: &str,
        listener: SubscriptionListener,
        options: Option<EventLogSubscribeOptions>,
    ) -> Result<EventSubscription, EventLogError> {
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(EventLogError::Closed);
        }

        let cursor = self
            .validate_resume_cursor(tenant, options.as_ref())
            .await?;

        let subscription = self
            .install_subscription(tenant, id, listener, cursor.clone(), options.as_ref())
            .await?;

        let bounds = match self.inner.reader.log_bounds(tenant).await {
            Ok(bounds) => bounds,
            Err(error) => {
                self.cleanup_subscription(&subscription).await?;
                return Err(error);
            }
        };

        let frozen_cursor = match self.frozen_cursor(bounds, cursor.clone(), tenant).await {
            Ok(frozen_cursor) => frozen_cursor,
            Err(error) => {
                self.cleanup_subscription(&subscription).await?;
                return Err(error);
            }
        };

        let event_sub = match cursor {
            Some(requested) => {
                let outcome = DurableEventLogInner::replay_to_frozen(
                    &self.inner,
                    Arc::clone(&subscription),
                    requested,
                    frozen_cursor.clone(),
                )
                .await;

                match outcome {
                    Ok(ReplayOutcome::ReachedFrozenHead) => Ok((
                        ReplayOutcome::ReachedFrozenHead,
                        DurableEventLogInner::make_subscription(
                            Arc::clone(&self.inner),
                            Arc::clone(&subscription),
                        ),
                    )),
                    Ok(ReplayOutcome::Closed) => Ok((
                        ReplayOutcome::Closed,
                        DurableEventLogInner::make_subscription(
                            Arc::clone(&self.inner),
                            Arc::clone(&subscription),
                        ),
                    )),
                    Ok(_) => {
                        self.cleanup_subscription(&subscription).await?;
                        Err(EventLogError::StoreError(StoreError::InternalException(
                            "subscription phase changed unexpectedly during replay".to_string(),
                        )))
                    }
                    Err(error) => {
                        self.cleanup_subscription(&subscription).await?;
                        Err(error)
                    }
                }
            }
            None => {
                let should_start = {
                    let mut mutable = subscription.mutable.lock().await;
                    mutable.cursor = Some(frozen_cursor.clone());

                    if mutable.phase == SubscriptionPhase::Closed {
                        return Ok(DurableEventLogInner::make_subscription(
                            Arc::clone(&self.inner),
                            Arc::clone(&subscription),
                        ));
                    }

                    mutable.phase = SubscriptionPhase::Live;
                    mutable.redrain_requested
                };
                let inner = Arc::clone(&self.inner);
                let state = Arc::clone(&subscription);
                if should_start {
                    DurableEventLogInner::try_start_drain(&inner, state).await;
                }

                Ok((
                    ReplayOutcome::NoCursorFollow,
                    DurableEventLogInner::make_subscription(
                        Arc::clone(&self.inner),
                        Arc::clone(&subscription),
                    ),
                ))
            }
        };

        match event_sub {
            Ok((outcome, sub)) => match outcome {
                ReplayOutcome::ReachedFrozenHead => {
                    let _delivery_guard = subscription.delivery_gate.lock().await;

                    let mut mutable = subscription.mutable.lock().await;
                    if mutable.phase == SubscriptionPhase::Closed {
                        return Ok(sub);
                    }

                    if mutable.phase != SubscriptionPhase::Replay {
                        drop(mutable);
                        self.cleanup_subscription(&subscription).await?;
                        return Err(EventLogError::StoreError(StoreError::InternalException(
                            "subscription phase changed unexpectedly during replay".to_string(),
                        )));
                    }

                    mutable.cursor = Some(frozen_cursor.clone());
                    drop(mutable);

                    (subscription.listener)(SubscriptionMessage::Eose {
                        cursor: frozen_cursor.clone(),
                    });

                    let mut mutable = subscription.mutable.lock().await;
                    if mutable.phase == SubscriptionPhase::Closed {
                        return Ok(sub);
                    }

                    if mutable.phase != SubscriptionPhase::Replay {
                        drop(mutable);
                        drop(_delivery_guard);
                        self.cleanup_subscription(&subscription).await?;
                        return Err(EventLogError::StoreError(StoreError::InternalException(
                            "subscription phase changed unexpectedly during replay".to_string(),
                        )));
                    }

                    mutable.cursor = Some(frozen_cursor.clone());
                    mutable.phase = SubscriptionPhase::Live;
                    let should_start = mutable.redrain_requested;
                    drop(mutable);

                    if should_start {
                        let inner = Arc::clone(&self.inner);
                        let state = Arc::clone(&subscription);
                        DurableEventLogInner::try_start_drain(&inner, state).await;
                    }

                    Ok(sub)
                }
                ReplayOutcome::NoCursorFollow => Ok(sub),
                ReplayOutcome::Closed => Ok(sub),
            },
            Err(error) => Err(error),
        }
    }

    async fn get_replay_bounds(
        &self,
        tenant: &str,
    ) -> Result<Option<EventLogReplayBounds>, EventLogError> {
        Ok(self
            .inner
            .reader
            .log_bounds(tenant)
            .await?
            .map(|(lower, upper)| EventLogReplayBounds {
                oldest: lower,
                latest: upper,
            }))
    }

    async fn trim(
        &self,
        _tenant: &str,
        _older_than: EventLogTrimBound,
    ) -> Result<(), EventLogError> {
        Err(EventLogError::UnsupportedReadOption("trim".to_string()))
    }
}

impl<R, S> DurableEventLog<R, S>
where
    R: ReplicationFeedReader + Send + Sync + 'static,
    S: WakeSubscriber,
{
    fn wake_handler(&self, sub_state: Weak<SubscriptionState>) -> WakeSubscriptionListener {
        let inner = Arc::downgrade(&self.inner);
        Box::new(move |wake| {
            let sub_state = sub_state.clone();
            let inner = inner.clone();
            Box::pin(async move {
                let (Some(inner), Some(subscription)) =
                    (Weak::upgrade(&inner), Weak::upgrade(&sub_state))
                else {
                    return;
                };
                if wake.tenant != subscription.tenant {
                    return;
                }

                DurableEventLogInner::request_drain(&inner, subscription).await;
            })
        })
    }

    async fn cleanup_subscription(
        &self,
        subscription: &Arc<SubscriptionState>,
    ) -> Result<(), EventLogError> {
        DurableEventLogInner::cleanup_subscription(
            &self.inner,
            subscription,
            CleanupOrigin::External,
        )
        .await
    }

    async fn frozen_cursor(
        &self,
        bounds: Option<(ProgressToken, ProgressToken)>,
        cursor: Option<ProgressToken>,
        tenant: &str,
    ) -> Result<ProgressToken, EventLogError> {
        let frozen_cursor = match &bounds {
            Some((_, latest)) => latest.clone(),
            None => {
                let anchor = self
                    .inner
                    .reader
                    .log_read(
                        tenant,
                        EventLogReadOptions {
                            cursor: None,
                            limit: Some(0),
                            filters: None,
                        },
                    )
                    .await;
                match anchor {
                    Ok(result) => match result.cursor {
                        Some(anchor) => anchor,
                        None => {
                            return Err(EventLogError::StoreError(StoreError::InternalException(
                                "feed reader returned no empty-feed anchor".to_string(),
                            )));
                        }
                    },
                    Err(error) => {
                        return Err(error);
                    }
                }
            }
        };

        let frozen_position = match parse_feed_position(&frozen_cursor.position) {
            Ok(frozen_position) => frozen_position,
            Err(err) => {
                return Err(EventLogError::InvalidProgressToken(format!(
                    "invalid frozen cursor position: {err}"
                )));
            }
        };

        if let Some(cursor) = &cursor {
            let cursor_position = match parse_feed_position(&cursor.position) {
                Ok(cursor_position) => cursor_position,
                Err(err) => {
                    return Err(EventLogError::InvalidProgressToken(format!(
                        "invalid cursor position: {err}"
                    )));
                }
            };

            if cursor.epoch != frozen_cursor.epoch {
                let gap = progress_gap(
                    cursor.clone(),
                    ProgressGapCode::ProgressGap,
                    frozen_cursor,
                    bounds,
                    ProgressGapReason::EpochMismatch,
                );
                return Err(gap);
            }

            if cursor.stream_id != frozen_cursor.stream_id {
                let gap = progress_gap(
                    cursor.clone(),
                    ProgressGapCode::ProgressGap,
                    frozen_cursor,
                    bounds,
                    ProgressGapReason::StreamMismatch,
                );
                return Err(gap);
            }

            if cursor_position > frozen_position {
                let gap = progress_gap(
                    cursor.clone(),
                    ProgressGapCode::ProgressGap,
                    frozen_cursor,
                    bounds,
                    ProgressGapReason::TokenTooNew,
                );
                return Err(gap);
            }
        }

        Ok(frozen_cursor)
    }

    async fn install_lock(&self, id: &str) -> Arc<Mutex<()>> {
        let mut install_locks = self.inner.install_locks.lock().await;
        if let Some(lock) = install_locks.get(id).and_then(Weak::upgrade) {
            return lock;
        }

        let new_lock = Arc::new(Mutex::new(()));
        install_locks.insert(id.to_string(), Arc::downgrade(&new_lock));
        new_lock
    }

    async fn validate_resume_cursor(
        &self,
        tenant: &str,
        options: Option<&EventLogSubscribeOptions>,
    ) -> Result<Option<ProgressToken>, EventLogError> {
        let cursor = options.as_ref().and_then(|o| o.cursor.clone());

        if let Some(cursor) = &cursor {
            self.inner
                .reader
                .log_read(
                    tenant,
                    EventLogReadOptions {
                        cursor: Some(cursor.clone()),
                        filters: options.as_ref().and_then(|o| o.filters.clone()),
                        limit: Some(0),
                    },
                )
                .await?;
        };

        Ok(cursor)
    }

    async fn install_subscription(
        &self,
        tenant: &str,
        id: &str,
        listener: SubscriptionListener,
        cursor: Option<ProgressToken>,
        options: Option<&EventLogSubscribeOptions>,
    ) -> Result<Arc<SubscriptionState>, EventLogError> {
        let _install_guard = self.inner.installation_gate.write().await;

        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(EventLogError::Closed);
        }

        let install_lock = self.install_lock(id).await;
        let _id_guard = install_lock.lock().await;

        let subscription = Arc::new(SubscriptionState {
            id: id.to_string(),
            tenant: tenant.to_string(),
            listener,
            filters: options.as_ref().and_then(|o| o.filters.clone()),
            delivery_gate: Mutex::new(()),
            mutable: Mutex::new(SubscriptionStateMutable {
                cursor: cursor.clone(),
                phase: SubscriptionPhase::Replay,
                draining: false,
                redrain_requested: false,
                terminal_error_sent: false,
                wake_handle: None,
                drain_task: None,
            }),
        });

        let removed = {
            let mut subscriptions = self.inner.subscriptions.write().await;
            subscriptions.remove(id)
        };
        if let Some(removed) = removed {
            self.cleanup_subscription(&removed).await?;
        };

        {
            let mut subscriptions = self.inner.subscriptions.write().await;
            let replaced = subscriptions.insert(id.to_string(), subscription.clone());
            debug_assert!(replaced.is_none(), "subscription replaced unexpectedly");
        }

        let handler = self.wake_handler(Arc::downgrade(&subscription));
        let wake_handle = self.subscriber.subscribe(tenant, handler).await;
        let wake_handle = {
            let mut mutable = subscription.mutable.lock().await;

            if mutable.phase == SubscriptionPhase::Closed {
                Some(wake_handle)
            } else {
                mutable.wake_handle = Some(wake_handle);
                None
            }
        };

        if let Some(wake_handle) = wake_handle {
            wake_handle.close().await;
        }

        if Self::closed(&subscription).await {
            self.cleanup_subscription(&subscription).await?;
        }

        Ok(subscription)
    }

    async fn closed(subscription: &Arc<SubscriptionState>) -> bool {
        DurableEventLogInner::<R>::closed(subscription).await
    }
}

impl<R> DurableEventLogInner<R>
where
    R: ReplicationFeedReader + Send + Sync + 'static,
{
    async fn redrain_all(inner: &Arc<Self>) {
        let subscriptions = inner
            .subscriptions
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();

        for subscription in subscriptions {
            DurableEventLogInner::request_drain(inner, subscription).await;
        }
    }

    async fn replay_to_frozen(
        inner: &Arc<Self>,
        subscription: Arc<SubscriptionState>,
        requested: ProgressToken,
        frozen: ProgressToken,
    ) -> Result<ReplayOutcome, EventLogError> {
        let mut read_cursor = requested.clone();
        let mut read_position = parse_feed_position(&requested.position)?;
        let frozen_position = parse_feed_position(&frozen.position)?;

        if read_position > frozen_position {
            return Err(EventLogError::StoreError(StoreError::InternalException(
                "validated replay cursor is ahead of the frozen cursor".to_string(),
            )));
        }

        if read_position == frozen_position {
            return Ok(ReplayOutcome::ReachedFrozenHead);
        };

        loop {
            if Self::closed(&subscription).await {
                return Ok(ReplayOutcome::Closed);
            }

            let results = inner
                .reader
                .log_read(
                    &subscription.tenant,
                    EventLogReadOptions {
                        cursor: Some(read_cursor.clone()),
                        limit: Some(inner.config.read_limit),
                        filters: subscription.filters.clone(),
                    },
                )
                .await?;

            if Self::closed(&subscription).await {
                return Ok(ReplayOutcome::Closed);
            }

            let scan_cursor = results.cursor.ok_or_else(|| {
                EventLogError::StoreError(StoreError::InternalException(
                    "feed reader returned no replay scan cursor".to_string(),
                ))
            })?;

            if scan_cursor.stream_id != frozen.stream_id {
                return Err(EventLogError::StoreError(StoreError::InternalException(
                    "replay scan cursor stream does not match frozen cursor".to_string(),
                )));
            }

            if scan_cursor.epoch != frozen.epoch {
                return Err(EventLogError::StoreError(StoreError::InternalException(
                    "replay scan cursor epoch does not match frozen cursor".to_string(),
                )));
            }

            let scan_position = parse_feed_position(&scan_cursor.position)?;
            if scan_position < frozen_position && scan_position <= read_position {
                return Err(EventLogError::StoreError(StoreError::InternalException(
                    "replay scan cursor did not advance toward frozen cursor".to_string(),
                )));
            }

            let mut last_entry_position = read_position;
            for entry in results.events {
                if Self::closed(&subscription).await {
                    return Ok(ReplayOutcome::Closed);
                }
                let entry_position = parse_feed_position(&entry.seq)?;
                if entry_position <= last_entry_position {
                    return Err(EventLogError::StoreError(StoreError::InternalException(
                        "replay entries are not in strictly increasing position order".to_string(),
                    )));
                }
                last_entry_position = entry_position;

                if entry_position > frozen_position {
                    break;
                }

                let entry_cursor =
                    Self::deliver_entry(inner, &subscription, entry, &scan_cursor).await?;
                let mut mutable = subscription.mutable.lock().await;
                match mutable.phase {
                    SubscriptionPhase::Replay => mutable.cursor = Some(entry_cursor),
                    SubscriptionPhase::Closed => return Ok(ReplayOutcome::Closed),
                    SubscriptionPhase::Live => {
                        return Err(EventLogError::StoreError(StoreError::InternalException(
                            "subscription became live during replay".to_string(),
                        )));
                    }
                }
            }

            if scan_position >= frozen_position {
                return Ok(ReplayOutcome::ReachedFrozenHead);
            }

            {
                let mut mutable = subscription.mutable.lock().await;
                match mutable.phase {
                    SubscriptionPhase::Replay => {
                        mutable.cursor = Some(scan_cursor.clone());
                    }
                    SubscriptionPhase::Closed => return Ok(ReplayOutcome::Closed),
                    SubscriptionPhase::Live => {
                        return Err(EventLogError::StoreError(StoreError::InternalException(
                            "subscription became live during replay".to_string(),
                        )));
                    }
                }
            }

            read_position = scan_position;
            read_cursor = scan_cursor;
        }
    }

    async fn request_drain(inner: &Arc<Self>, subscription: Arc<SubscriptionState>) {
        let should_try_start = {
            let mut mutable = subscription.mutable.lock().await;
            if mutable.phase == SubscriptionPhase::Closed || mutable.terminal_error_sent {
                return;
            }

            mutable.redrain_requested = true;
            mutable.phase == SubscriptionPhase::Live
        };

        if should_try_start {
            Self::try_start_drain(inner, subscription).await;
        }
    }

    async fn try_start_drain(inner: &Arc<Self>, subscription: Arc<SubscriptionState>) {
        let mut mutable = subscription.mutable.lock().await;
        if mutable.phase != SubscriptionPhase::Live
            || mutable.draining
            || mutable.terminal_error_sent
        {
            return;
        }

        mutable.draining = true;
        mutable.redrain_requested = false;
        let cursor = mutable.cursor.clone();
        let inner = Arc::clone(inner);
        let task_subscription = Arc::clone(&subscription);
        let task = tokio::spawn(async move {
            Self::run_drain(inner, task_subscription, cursor).await;
        });
        mutable.drain_task = Some(task);
    }

    async fn run_drain(
        inner: Arc<Self>,
        subscription: Arc<SubscriptionState>,
        mut cursor: Option<ProgressToken>,
    ) {
        // Taking this lock first ensures the claiming caller stores our
        // JoinHandle before this task can finish and clear it. Do not clear a
        // redrain here: a wake may have re-armed it after the drain was claimed.
        drop(subscription.mutable.lock().await);

        loop {
            match Self::drain_once(&inner, &subscription, &mut cursor).await {
                Ok(()) => {}
                Err(EventLogError::ProgressGap(gap)) => {
                    if let Err(error) = Self::handle_progress_gap(&inner, &subscription, *gap).await
                    {
                        inner.report_background_error(&subscription, &error);
                    };

                    break;
                }
                Err(error) => {
                    inner.report_background_error(&subscription, &error);

                    let mut mutable = subscription.mutable.lock().await;
                    if mutable.phase == SubscriptionPhase::Live
                        && std::mem::take(&mut mutable.redrain_requested)
                    {
                        cursor = mutable.cursor.clone();
                        drop(mutable);
                        continue;
                    }

                    mutable.draining = false;
                    mutable.drain_task = None;
                    return;
                }
            }

            let mut mutable = subscription.mutable.lock().await;
            if mutable.phase == SubscriptionPhase::Live
                && std::mem::take(&mut mutable.redrain_requested)
            {
                cursor = mutable.cursor.clone();
                drop(mutable);
                continue;
            }

            mutable.draining = false;
            mutable.drain_task = None;
            return;
        }

        let mut mutable = subscription.mutable.lock().await;
        mutable.draining = false;
        mutable.drain_task = None;
    }

    async fn drain_once(
        inner: &Arc<Self>,
        subscription: &Arc<SubscriptionState>,
        cursor: &mut Option<ProgressToken>,
    ) -> Result<(), EventLogError> {
        loop {
            if Self::closed(subscription).await {
                return Ok(());
            }

            let results = inner
                .reader
                .log_read(
                    &subscription.tenant,
                    EventLogReadOptions {
                        cursor: cursor.clone(),
                        limit: Some(inner.config.read_limit),
                        filters: subscription.filters.clone(),
                    },
                )
                .await?;
            let scan_cursor = results.cursor.ok_or_else(|| {
                EventLogError::StoreError(StoreError::InternalException(
                    "feed reader returned no live-drain scan cursor".to_string(),
                ))
            })?;

            for entry in results.events {
                if Self::closed(subscription).await {
                    return Ok(());
                }

                let entry_cursor =
                    Self::deliver_entry(inner, subscription, entry, &scan_cursor).await?;
                let mut mutable = subscription.mutable.lock().await;
                if mutable.phase == SubscriptionPhase::Closed {
                    return Ok(());
                }
                mutable.cursor = Some(entry_cursor);
            }

            {
                let mut mutable = subscription.mutable.lock().await;
                if mutable.phase == SubscriptionPhase::Closed {
                    return Ok(());
                }
                mutable.cursor = Some(scan_cursor.clone());
            }
            *cursor = Some(scan_cursor);

            if results.drained {
                return Ok(());
            }
        }
    }

    async fn deliver_entry(
        inner: &Arc<Self>,
        subscription: &Arc<SubscriptionState>,
        mut entry: EventLogEntry,
        page_cursor: &ProgressToken,
    ) -> Result<ProgressToken, EventLogError> {
        parse_feed_position(&entry.seq)?;

        if Self::closed(subscription).await {
            return Ok(page_cursor.clone());
        }

        let cursor = ProgressToken {
            stream_id: page_cursor.stream_id.clone(),
            epoch: page_cursor.epoch.clone(),
            position: entry.seq.clone(),
            message_cid: entry.message_cid.clone(),
        };

        if let Some(resolver) = &inner.initial_write_resolver {
            entry.event.initial_write = resolver
                .resolve_initial_write(&subscription.tenant, &entry.event.message)
                .await?
        }

        let _delivery_guard = subscription.delivery_gate.lock().await;

        if Self::closed(subscription).await {
            return Ok(cursor);
        }

        (subscription.listener)(SubscriptionMessage::Event {
            event: Box::new(entry.event),
            seq: Some(entry.seq.clone()),
            cursor: cursor.clone(),
            message_cid: entry.message_cid.clone(),
            is_latest_base_state: entry
                .indexes
                .get("isLatestBaseState")
                .map(|value| match value {
                    Value::Bool(value) => *value,
                    Value::String(value) => value == "true",
                    _ => false,
                }),
            protocol: entry.indexes.get("protocol").and_then(|value| match value {
                Value::String(value) => Some(value.clone()),
                _ => None,
            }),
            encoded_data: entry.encoded_data,
        });

        Ok(cursor)
    }

    async fn handle_progress_gap(
        inner: &Arc<Self>,
        subscription: &Arc<SubscriptionState>,
        gap: ProgressGapInfo,
    ) -> Result<(), EventLogError> {
        let _delivery_guard = subscription.delivery_gate.lock().await;

        let should_send = {
            let mut mutable = subscription.mutable.lock().await;
            if mutable.phase == SubscriptionPhase::Closed || mutable.terminal_error_sent {
                false
            } else {
                mutable.terminal_error_sent = true;
                true
            }
        };

        if should_send {
            let cursor = gap.requested.clone();
            let error = SubscriptionError {
                code: SubscriptionErrorCode::ProgressGap,
                detail: format!(
                    "progress gap: requested={:?}, latest_available={:?}, oldest_available={:?}, reason={:?}",
                    gap.requested, gap.latest_available, gap.oldest_available, gap.reason
                ),
            };

            (subscription.listener)(SubscriptionMessage::Error { cursor, error });
        }

        drop(_delivery_guard);

        Self::cleanup_subscription(inner, subscription, CleanupOrigin::DrainTask).await
    }

    async fn closed(subscription: &Arc<SubscriptionState>) -> bool {
        subscription.mutable.lock().await.phase == SubscriptionPhase::Closed
    }

    fn make_subscription(
        inner: Arc<Self>,
        subscription: Arc<SubscriptionState>,
    ) -> EventSubscription {
        let subscription_id = subscription.id.clone();

        EventSubscription {
            id: subscription_id,
            close: Arc::new(move || {
                let inner = Arc::clone(&inner);
                let subscription = Arc::clone(&subscription);
                Box::pin(async move {
                    Self::cleanup_subscription(&inner, &subscription, CleanupOrigin::External).await
                })
            }),
        }
    }

    async fn cleanup_subscription(
        inner: &Arc<Self>,
        subscription: &Arc<SubscriptionState>,
        origin: CleanupOrigin,
    ) -> Result<(), EventLogError> {
        let (wake_handle, drain_task) = {
            let mut mutable = subscription.mutable.lock().await;
            mutable.phase = SubscriptionPhase::Closed;
            mutable.redrain_requested = false;

            let drain_task = match origin {
                CleanupOrigin::External => mutable.drain_task.take(),
                CleanupOrigin::DrainTask => None,
            };

            (mutable.wake_handle.take(), drain_task)
        };

        {
            let mut subscriptions = inner.subscriptions.write().await;
            if subscriptions
                .get(&subscription.id)
                .is_some_and(|current| Arc::ptr_eq(current, subscription))
            {
                subscriptions.remove(&subscription.id);
            }
        }

        if let Some(wake_handle) = wake_handle {
            wake_handle.close().await;
        }

        // wait for any in-progress listeners, then drop the lock so that any in-progress
        // drain can finish
        drop(subscription.delivery_gate.lock().await);

        if let Some(drain_task) = drain_task {
            drain_task.await.map_err(|err| {
                EventLogError::StoreError(StoreError::InternalException(format!(
                    "drain task join failed: {err}"
                )))
            })?;
        }

        Ok(())
    }

    fn report_background_error(&self, subscription: &SubscriptionState, error: &EventLogError) {
        if let Some(on_error) = &self.config.on_error {
            on_error(error);
        } else {
            tracing::error!(
                %error,
                subscription_id = %subscription.id,
                tenant = %subscription.tenant,
                "durable event-log background error"
            );
        }
    }
}

enum CleanupOrigin {
    DrainTask,
    External,
}

fn progress_gap(
    requested: ProgressToken,
    code: ProgressGapCode,
    latest_available: ProgressToken,
    bounds: Option<ReplicationBounds>,
    reason: ProgressGapReason,
) -> EventLogError {
    let oldest_available = bounds
        .as_ref()
        .map(|(oldest, _)| oldest.clone())
        .unwrap_or_else(|| latest_available.clone());

    EventLogError::ProgressGap(Box::new(ProgressGapInfo {
        requested,
        code,
        latest_available,
        oldest_available,
        reason,
    }))
}
