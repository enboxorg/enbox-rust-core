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
use std::sync::{Arc, Weak};

use tokio::sync::{Mutex, RwLock};

use crate::errors::{EventLogError, StoreError};
use crate::stores::replication_feed_reader::{parse_feed_position, ReplicationBounds};
use crate::stores::wake::{WakeSubscriptionHandle, WakeSubscriptionListener};
use crate::stores::{
    wake::WakeSubscriber, EventLog, EventLogReadOptions, EventLogReadResult, EventLogReplayBounds,
    EventLogSubscribeOptions, EventLogTrimBound, EventSubscription, KeyValues,
    ReplicationFeedReader, SubscriptionListener,
};
use crate::stores::{ProgressGapCode, ProgressGapInfo, ProgressGapReason};
use crate::{Descriptor, Filters, MessageEvent, ProgressToken};

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

impl<R, S> DurableEventLog<R, S>
where
    R: ReplicationFeedReader,
    S: WakeSubscriber,
{
    /// Create a new durable event log adapter.
    pub fn new(reader: R, subscriber: S) -> Self {
        Self {
            subscriber,
            inner: Arc::new(DurableEventLogInner {
                reader: Arc::new(reader),
                subscriptions: RwLock::new(BTreeMap::new()),
                install_locks: Mutex::new(BTreeMap::new()),
            }),
        }
    }
}

struct DurableEventLogInner<R> {
    reader: Arc<R>,
    subscriptions: RwLock<BTreeMap<String, Arc<SubscriptionState>>>,
    install_locks: Mutex<BTreeMap<String, Weak<Mutex<()>>>>,
}

pub struct SubscriptionState {
    id: String,
    tenant: String,
    listener: SubscriptionListener,
    filters: Option<Filters>,
    mutable: Mutex<SubscriptionStateMutable>,
}

struct SubscriptionStateMutable {
    cursor: Option<ProgressToken>,
    phase: SubscriptionPhase,
    draining: bool,
    redrain_requested: bool,
    terminal_error_sent: bool,
    wake_handle: Option<Box<dyn WakeSubscriptionHandle>>,
}

#[derive(Debug, PartialEq, Eq)]
enum SubscriptionPhase {
    Replay,
    Live,
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
        self.inner.subscriptions.write().await.clear();
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
        }

        let subscription = Arc::new(SubscriptionState {
            id: id.to_string(),
            tenant: tenant.to_string(),
            listener,
            filters: options.as_ref().and_then(|o| o.filters.clone()),
            mutable: Mutex::new(SubscriptionStateMutable {
                cursor: cursor.clone(),
                phase: SubscriptionPhase::Replay,
                draining: false,
                redrain_requested: false,
                terminal_error_sent: false,
                wake_handle: None,
            }),
        });

        let install_lock = self.install_lock(id).await;
        let _install_guard = install_lock.lock().await;

        let removed = {
            let mut subscriptions = self.inner.subscriptions.write().await;
            subscriptions.remove(id)
        };
        if let Some(removed) = removed {
            self.cleanup_subscription(&removed).await;
        };

        {
            let mut subscriptions = self.inner.subscriptions.write().await;
            let replaced = subscriptions.insert(id.to_string(), subscription.clone());
            debug_assert!(replaced.is_none(), "subscription replaced unexpectedly");
        }

        let handler = self.wake_handler(Arc::downgrade(&subscription));
        let wake_handle = self.subscriber.subscribe(tenant, handler).await;
        subscription.mutable.lock().await.wake_handle = Some(wake_handle);

        let bounds = match self.inner.reader.log_bounds(tenant).await {
            Ok(bounds) => bounds,
            Err(error) => {
                self.cleanup_subscription(&subscription).await;
                return Err(error);
            }
        };

        let frozen_cursor = match self.frozen_cursor(bounds, cursor.clone(), tenant).await {
            Ok(frozen_cursor) => frozen_cursor,
            Err(error) => {
                self.cleanup_subscription(&subscription).await;
                return Err(error);
            }
        };

        todo!()
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
        let sub_state = sub_state.clone();
        Box::new(move |wake| {
            let sub_state = sub_state.clone();
            Box::pin(async move {
                let subscription = Weak::upgrade(&sub_state);
                if subscription.is_none() {
                    return;
                }
                let subscription = subscription.unwrap();
                if wake.tenant != subscription.tenant {
                    return;
                }

                let mut mutable = subscription.mutable.lock().await;
                if mutable.phase == SubscriptionPhase::Closed {
                    return;
                }
                mutable.redrain_requested = true;
                drop(mutable);
            })
        })
    }

    async fn cleanup_subscription(&self, subscription: &Arc<SubscriptionState>) {
        let wake_handle = {
            let mut mutable = subscription.mutable.lock().await;
            mutable.phase = SubscriptionPhase::Closed;
            mutable.wake_handle.take()
        };

        {
            let mut subscriptions = self.inner.subscriptions.write().await;
            let is_current = subscriptions
                .get(&subscription.id)
                .is_some_and(|current| Arc::ptr_eq(current, subscription));
            if is_current {
                subscriptions.remove(&subscription.id);
            }
        }

        if let Some(wake_handle) = wake_handle {
            wake_handle.close().await;
        }
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
