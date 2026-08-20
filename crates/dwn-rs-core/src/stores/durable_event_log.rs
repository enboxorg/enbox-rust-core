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

use crate::errors::EventLogError;
use crate::stores::{
    wake::WakeSubscriber, EventLog, EventLogReadOptions, EventLogReadResult, EventLogReplayBounds,
    EventLogSubscribeOptions, EventLogTrimBound, EventSubscription, KeyValues,
    ReplicationFeedReader, SubscriptionListener,
};
use crate::{Descriptor, MessageEvent, ProgressToken};

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
#[derive(Debug)]
pub struct DurableEventLog<R, S>
where
    R: ReplicationFeedReader + Default,
    S: WakeSubscriber + Default,
{
    /// Authoritative source of committed replication-feed entries and cursors.
    pub reader: R,

    /// Consumer of best-effort wake hints for newly committed feed entries.
    pub subscriber: S,
}

impl<R, S> Default for DurableEventLog<R, S>
where
    R: ReplicationFeedReader + Default,
    S: WakeSubscriber + Default,
{
    fn default() -> Self {
        Self {
            reader: R::default(),
            subscriber: S::default(),
        }
    }
}

impl<R, S> EventLog for DurableEventLog<R, S>
where
    R: ReplicationFeedReader + Default + Send + Sync,
    S: WakeSubscriber + Default,
{
    async fn open(&mut self) -> Result<(), EventLogError> {
        Ok(())
    }

    async fn close(&mut self) -> () {
        self.subscriber.clear().await;
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
        self.reader.log_read(tenant, options).await
    }

    async fn subscribe(
        &self,
        tenant: &str,
        id: &str,
        listener: SubscriptionListener,
        options: Option<EventLogSubscribeOptions>,
    ) -> Result<EventSubscription, EventLogError> {
        todo!()
    }

    async fn get_replay_bounds(
        &self,
        tenant: &str,
    ) -> Result<Option<EventLogReplayBounds>, EventLogError> {
        Ok(self
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
