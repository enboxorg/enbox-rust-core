use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use k256::sha2::{Digest, Sha256};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::cid::generate_cid_from_json;
use crate::errors::{EventLogError, ResumableTaskStoreError, StoreError};
use crate::events::MessageEvent;
use crate::filters::Filters;
use crate::stores::{
    EnboxEventLog, EnboxManagedResumableTask, EnboxResumableTaskStore, EventLogEntry,
    EventLogReadOptions, EventLogReadResult, EventLogReplayBounds, EventLogSubscribeOptions,
    EventLogTrimBound, EventSubscription, EventSubscriptionClose, KeyValues, ProgressGapInfo,
    ProgressGapReason, ProgressToken, SubscriptionListener, SubscriptionMessage,
};
use crate::{Descriptor, Value};

const DEFAULT_MAX_EVENTS_PER_TENANT: usize = 10_000;
const GRABBED_TASK_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone)]
/// In-memory `EventLog` for development, tests, and the `MobileCore` /
/// `DesktopLocalNode` reference flows. Process-local; not durable. Wire a
/// real backend (SQLite, SurrealDB, etc.) for production deployments.
pub struct MemoryEventLog {
    inner: Arc<RwLock<EventLogInner>>,
    epoch: String,
    max_events_per_tenant: usize,
}

#[derive(Default)]
struct EventLogInner {
    is_open: bool,
    tenant_logs: BTreeMap<String, BTreeMap<u64, StoredEvent>>,
    tenant_seqs: BTreeMap<String, u64>,
    subscriptions: BTreeMap<(String, String), StoredSubscription>,
}

#[derive(Debug, Clone)]
struct StoredEvent {
    event: MessageEvent<Descriptor>,
    indexes: KeyValues,
    message_cid: String,
}

#[derive(Clone)]
struct StoredSubscription {
    listener: SharedSubscriptionListener,
    filters: Option<Filters>,
}

type SharedSubscriptionListener = Arc<SubscriptionListener>;

impl Default for MemoryEventLog {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(EventLogInner::default())),
            epoch: ulid::Ulid::new().to_string(),
            max_events_per_tenant: DEFAULT_MAX_EVENTS_PER_TENANT,
        }
    }
}

impl MemoryEventLog {
    pub fn new(max_events_per_tenant: usize) -> Self {
        Self {
            max_events_per_tenant,
            ..Self::default()
        }
    }
}

impl EnboxEventLog for MemoryEventLog {
    fn open(&mut self) -> impl Future<Output = Result<(), EventLogError>> + Send {
        let inner = self.inner.clone();
        async move {
            inner.write().map_err(event_lock_error)?.is_open = true;
            Ok(())
        }
    }

    fn close(&mut self) -> impl Future<Output = ()> + Send {
        let inner = self.inner.clone();
        async move {
            if let Ok(mut inner) = inner.write() {
                inner.is_open = false;
                inner.tenant_logs.clear();
                inner.tenant_seqs.clear();
                inner.subscriptions.clear();
            }
        }
    }

    fn emit(
        &self,
        tenant: &str,
        event: MessageEvent<Descriptor>,
        indexes: KeyValues,
        message_cid: &str,
    ) -> impl Future<Output = Result<Option<ProgressToken>, EventLogError>> + Send {
        let inner = self.inner.clone();
        let epoch = self.epoch.clone();
        let max_events_per_tenant = self.max_events_per_tenant;
        let tenant = tenant.to_string();
        let message_cid = message_cid.to_string();
        async move {
            let mut deliveries = Vec::new();
            let token;

            {
                let mut inner = inner.write().map_err(event_lock_error)?;
                if !inner.is_open {
                    return Ok(None);
                }

                let seq = inner.tenant_seqs.get(&tenant).copied().unwrap_or_default() + 1;
                inner.tenant_seqs.insert(tenant.clone(), seq);
                let log = inner.tenant_logs.entry(tenant.clone()).or_default();
                log.insert(
                    seq,
                    StoredEvent {
                        event: event.clone(),
                        indexes: indexes.clone(),
                        message_cid: message_cid.clone(),
                    },
                );

                while log.len() > max_events_per_tenant {
                    if let Some(oldest) = log.keys().next().copied() {
                        log.remove(&oldest);
                    }
                }

                token = build_token(&tenant, &epoch, seq, &message_cid);

                for ((subscription_tenant, _), subscription) in &inner.subscriptions {
                    if subscription_tenant == &tenant
                        && matches_filters(&indexes, subscription.filters.as_ref())
                    {
                        deliveries.push(subscription.listener.clone());
                    }
                }
            }

            for listener in deliveries {
                listener(SubscriptionMessage::Event {
                    cursor: token.clone(),
                    event: Box::new(event.clone()),
                });
            }

            Ok(Some(token))
        }
    }

    fn read(
        &self,
        tenant: &str,
        options: Option<EventLogReadOptions>,
    ) -> impl Future<Output = Result<EventLogReadResult, EventLogError>> + Send {
        let inner = self.inner.clone();
        let epoch = self.epoch.clone();
        let tenant = tenant.to_string();
        async move {
            let options = options.unwrap_or_default();
            let cursor_seq = match &options.cursor {
                Some(cursor) => Some(validate_cursor(&inner, &tenant, &epoch, cursor)?),
                None => None,
            };
            let limit = options.limit.unwrap_or(u64::MAX) as usize;
            let inner = inner.read().map_err(event_lock_error)?;

            let mut events = Vec::new();
            if let Some(log) = inner.tenant_logs.get(&tenant) {
                for (seq, entry) in log {
                    if cursor_seq.is_some_and(|cursor_seq| *seq <= cursor_seq) {
                        continue;
                    }
                    if !matches_filters(&entry.indexes, options.filters.as_ref()) {
                        continue;
                    }

                    events.push(EventLogEntry {
                        seq: *seq,
                        event: entry.event.clone(),
                        indexes: entry.indexes.clone(),
                        message_cid: Some(entry.message_cid.clone()),
                    });
                    if events.len() >= limit {
                        break;
                    }
                }
            }

            let cursor = events.last().map_or(options.cursor, |entry| {
                Some(build_token(
                    &tenant,
                    &epoch,
                    entry.seq,
                    entry.message_cid.as_deref().unwrap_or_default(),
                ))
            });
            Ok(EventLogReadResult { events, cursor })
        }
    }

    fn subscribe(
        &self,
        tenant: &str,
        id: &str,
        listener: SubscriptionListener,
        options: Option<EventLogSubscribeOptions>,
    ) -> impl Future<Output = Result<EventSubscription, EventLogError>> + Send {
        let inner = self.inner.clone();
        let epoch = self.epoch.clone();
        let tenant = tenant.to_string();
        let id = id.to_string();
        async move {
            let options = options.unwrap_or_default();
            if let Some(cursor) = &options.cursor {
                validate_cursor(&inner, &tenant, &epoch, cursor)?;
            }

            let listener: SharedSubscriptionListener = Arc::new(listener);
            let subscription = StoredSubscription {
                listener: listener.clone(),
                filters: options.filters.clone(),
            };
            inner
                .write()
                .map_err(event_lock_error)?
                .subscriptions
                .insert((tenant.clone(), id.clone()), subscription);

            if let Some(cursor) = options.cursor.clone() {
                let read_result = read_events(
                    &inner,
                    &tenant,
                    &epoch,
                    Some(cursor.clone()),
                    None,
                    options.filters.as_ref(),
                )?;
                let eose_cursor = read_result.cursor.clone().unwrap_or(cursor);
                for entry in read_result.events {
                    listener(SubscriptionMessage::Event {
                        cursor: build_token(
                            &tenant,
                            &epoch,
                            entry.seq,
                            entry.message_cid.as_deref().unwrap_or_default(),
                        ),
                        event: Box::new(entry.event),
                    });
                }
                listener(SubscriptionMessage::Eose {
                    cursor: eose_cursor,
                });
            }

            Ok(EventSubscription {
                id: id.clone(),
                close: subscription_close(inner, tenant, id),
            })
        }
    }

    fn get_replay_bounds(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Option<EventLogReplayBounds>, EventLogError>> + Send {
        let inner = self.inner.clone();
        let epoch = self.epoch.clone();
        let tenant = tenant.to_string();
        async move {
            let inner = inner.read().map_err(event_lock_error)?;
            let Some(log) = inner.tenant_logs.get(&tenant) else {
                return Ok(None);
            };
            let Some((oldest_seq, oldest_entry)) = log.first_key_value() else {
                return Ok(None);
            };
            let Some((latest_seq, latest_entry)) = log.last_key_value() else {
                return Ok(None);
            };
            Ok(Some(EventLogReplayBounds {
                oldest: build_token(&tenant, &epoch, *oldest_seq, &oldest_entry.message_cid),
                latest: build_token(&tenant, &epoch, *latest_seq, &latest_entry.message_cid),
            }))
        }
    }

    fn trim(
        &self,
        tenant: &str,
        older_than: EventLogTrimBound,
    ) -> impl Future<Output = Result<(), EventLogError>> + Send {
        let inner = self.inner.clone();
        let tenant = tenant.to_string();
        async move {
            let mut inner = inner.write().map_err(event_lock_error)?;
            let Some(log) = inner.tenant_logs.get_mut(&tenant) else {
                return Ok(());
            };

            match older_than {
                EventLogTrimBound::Sequence(sequence) => {
                    log.retain(|seq, _| *seq >= sequence);
                }
                EventLogTrimBound::Timestamp(timestamp) => {
                    log.retain(|_, entry| match entry.indexes.get("messageTimestamp") {
                        Some(Value::String(message_timestamp)) => message_timestamp >= &timestamp,
                        _ => true,
                    });
                }
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Default)]
/// In-memory `ResumableTaskStore` for development and tests. Tasks are
/// lost on restart. Wire a durable backend (SQLite or equivalent) for
/// production.
pub struct MemoryResumableTaskStore {
    tasks: Arc<RwLock<BTreeMap<String, StoredTask>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredTask {
    id: String,
    task: JsonValue,
    timeout: u64,
    retry_count: u64,
}

impl EnboxResumableTaskStore for MemoryResumableTaskStore {
    async fn open(&mut self) -> Result<(), ResumableTaskStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    fn register<T: Serialize + Send + Sync + DeserializeOwned + Debug + 'static>(
        &self,
        task: T,
        timeout_in_seconds: u64,
    ) -> impl Future<Output = Result<EnboxManagedResumableTask<T>, ResumableTaskStoreError>> + Send
    {
        let tasks = self.tasks.clone();
        async move {
            let task_json = serde_json::to_value(&task).map_err(task_store_error)?;
            let id = generate_cid_from_json(&task_json)
                .map_err(task_store_error)?
                .to_string();
            let timeout = now_millis() + timeout_in_seconds.saturating_mul(1000);

            let stored = StoredTask {
                id: id.clone(),
                task: task_json,
                timeout,
                retry_count: 0,
            };
            let mut tasks = tasks.write().map_err(task_lock_error)?;
            if tasks.contains_key(&id) {
                return Err(ResumableTaskStoreError::StoreError(
                    StoreError::InternalException("ResumableTaskAlreadyExists".to_string()),
                ));
            }
            tasks.insert(id.clone(), stored);
            Ok(EnboxManagedResumableTask {
                id,
                task,
                timeout,
                retry_count: 0,
            })
        }
    }

    fn grab<T: Serialize + Send + Sync + DeserializeOwned + Debug + Unpin>(
        &self,
        count: u64,
    ) -> impl Future<Output = Result<Vec<EnboxManagedResumableTask<T>>, ResumableTaskStoreError>> + Send
    {
        let tasks = self.tasks.clone();
        async move {
            let now = now_millis();
            let mut tasks = tasks.write().map_err(task_lock_error)?;
            let expired = tasks
                .iter()
                .filter_map(|(id, task)| (now >= task.timeout).then_some(id.clone()))
                .take(count as usize)
                .collect::<Vec<_>>();

            let mut grabbed = Vec::new();
            for id in expired {
                let task = tasks.get_mut(&id).expect("expired task must exist");
                task.timeout = now + GRABBED_TASK_TIMEOUT_SECONDS * 1000;
                task.retry_count += 1;
                grabbed.push(enbox_task(task)?);
            }
            Ok(grabbed)
        }
    }

    fn read<T: Serialize + Send + Sync + DeserializeOwned + Debug>(
        &self,
        task_id: &str,
    ) -> impl Future<Output = Result<Option<EnboxManagedResumableTask<T>>, ResumableTaskStoreError>> + Send
    {
        let tasks = self.tasks.clone();
        let task_id = task_id.to_string();
        async move {
            let tasks = tasks.read().map_err(task_lock_error)?;
            tasks.get(&task_id).map(enbox_task).transpose()
        }
    }

    fn extend(
        &self,
        task_id: &str,
        timeout_in_seconds: u64,
    ) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send {
        let tasks = self.tasks.clone();
        let task_id = task_id.to_string();
        async move {
            if let Some(task) = tasks.write().map_err(task_lock_error)?.get_mut(&task_id) {
                task.timeout = now_millis() + timeout_in_seconds.saturating_mul(1000);
            }
            Ok(())
        }
    }

    fn delete(
        &self,
        task_id: &str,
    ) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send {
        let tasks = self.tasks.clone();
        let task_id = task_id.to_string();
        async move {
            tasks.write().map_err(task_lock_error)?.remove(&task_id);
            Ok(())
        }
    }

    fn clear(&self) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send {
        let tasks = self.tasks.clone();
        async move {
            tasks.write().map_err(task_lock_error)?.clear();
            Ok(())
        }
    }
}

fn read_events(
    inner: &Arc<RwLock<EventLogInner>>,
    tenant: &str,
    epoch: &str,
    cursor: Option<ProgressToken>,
    limit: Option<u64>,
    filters: Option<&Filters>,
) -> Result<EventLogReadResult, EventLogError> {
    let cursor_seq = match &cursor {
        Some(cursor) => Some(validate_cursor(inner, tenant, epoch, cursor)?),
        None => None,
    };
    let max = limit.unwrap_or(u64::MAX) as usize;
    let inner = inner.read().map_err(event_lock_error)?;
    let mut events = Vec::new();

    if let Some(log) = inner.tenant_logs.get(tenant) {
        for (seq, entry) in log {
            if cursor_seq.is_some_and(|cursor_seq| *seq <= cursor_seq) {
                continue;
            }
            if !matches_filters(&entry.indexes, filters) {
                continue;
            }
            events.push(EventLogEntry {
                seq: *seq,
                event: entry.event.clone(),
                indexes: entry.indexes.clone(),
                message_cid: Some(entry.message_cid.clone()),
            });
            if events.len() >= max {
                break;
            }
        }
    }

    let cursor = events.last().map_or(cursor, |entry| {
        Some(build_token(
            tenant,
            epoch,
            entry.seq,
            entry.message_cid.as_deref().unwrap_or_default(),
        ))
    });
    Ok(EventLogReadResult { events, cursor })
}

fn validate_cursor(
    inner: &Arc<RwLock<EventLogInner>>,
    tenant: &str,
    epoch: &str,
    cursor: &ProgressToken,
) -> Result<u64, EventLogError> {
    if cursor.stream_id != stream_id(tenant) {
        return Err(progress_gap(
            inner,
            tenant,
            epoch,
            cursor,
            ProgressGapReason::StreamMismatch,
        ));
    }
    if cursor.epoch != epoch {
        return Err(progress_gap(
            inner,
            tenant,
            epoch,
            cursor,
            ProgressGapReason::EpochMismatch,
        ));
    }
    let seq = cursor
        .position
        .parse::<u64>()
        .map_err(|_| invalid_cursor_position(&cursor.position))?;

    let inner = inner.read().map_err(event_lock_error)?;
    if let Some(log) = inner.tenant_logs.get(tenant) {
        if let Some(oldest) = log.keys().next() {
            if seq < oldest.saturating_sub(1) {
                return Err(progress_gap_from_log(
                    tenant,
                    epoch,
                    cursor,
                    ProgressGapReason::TokenTooOld,
                    Some(log),
                ));
            }
        }
    }
    Ok(seq)
}

fn build_token(tenant: &str, epoch: &str, seq: u64, message_cid: &str) -> ProgressToken {
    ProgressToken {
        stream_id: stream_id(tenant),
        epoch: epoch.to_string(),
        position: seq.to_string(),
        message_cid: message_cid.to_string(),
    }
}

fn stream_id(tenant: &str) -> String {
    let digest = Sha256::digest(tenant.as_bytes());
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn subscription_close(
    inner: Arc<RwLock<EventLogInner>>,
    tenant: String,
    id: String,
) -> EventSubscriptionClose {
    Box::new(move || {
        let inner = inner.clone();
        let tenant = tenant.clone();
        let id = id.clone();
        Box::pin(async move {
            inner
                .write()
                .map_err(event_lock_error)?
                .subscriptions
                .remove(&(tenant, id));
            Ok(())
        })
    })
}

use crate::filters::matching::matches_filters;

fn enbox_task<T>(task: &StoredTask) -> Result<EnboxManagedResumableTask<T>, ResumableTaskStoreError>
where
    T: DeserializeOwned + Serialize + Send + Sync + Debug,
{
    Ok(EnboxManagedResumableTask {
        id: task.id.clone(),
        task: serde_json::from_value(task.task.clone()).map_err(task_store_error)?,
        timeout: task.timeout,
        retry_count: task.retry_count,
    })
}

fn now_millis() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

fn progress_gap(
    inner: &Arc<RwLock<EventLogInner>>,
    tenant: &str,
    epoch: &str,
    requested: &ProgressToken,
    reason: ProgressGapReason,
) -> EventLogError {
    let Ok(inner) = inner.read() else {
        return event_lock_error(());
    };
    progress_gap_from_log(
        tenant,
        epoch,
        requested,
        reason,
        inner.tenant_logs.get(tenant),
    )
}

fn progress_gap_from_log(
    tenant: &str,
    epoch: &str,
    requested: &ProgressToken,
    reason: ProgressGapReason,
    log: Option<&BTreeMap<u64, StoredEvent>>,
) -> EventLogError {
    let (oldest_available, latest_available) = log
        .and_then(|log| {
            let (oldest_seq, oldest_entry) = log.first_key_value()?;
            let (latest_seq, latest_entry) = log.last_key_value()?;
            Some((
                build_token(tenant, epoch, *oldest_seq, &oldest_entry.message_cid),
                build_token(tenant, epoch, *latest_seq, &latest_entry.message_cid),
            ))
        })
        .unwrap_or_else(|| (requested.clone(), requested.clone()));

    EventLogError::ProgressGap(Box::new(ProgressGapInfo {
        requested: requested.clone(),
        oldest_available,
        latest_available,
        reason,
    }))
}

fn invalid_cursor_position(position: &str) -> EventLogError {
    EventLogError::StoreError(StoreError::InternalException(format!(
        "invalid cursor position: {position}"
    )))
}

fn event_lock_error<T>(_: T) -> EventLogError {
    EventLogError::StoreError(StoreError::InternalException(
        "EventLog lock poisoned".to_string(),
    ))
}

fn task_lock_error<T>(_: T) -> ResumableTaskStoreError {
    ResumableTaskStoreError::StoreError(StoreError::InternalException(
        "ResumableTaskStore lock poisoned".to_string(),
    ))
}

fn task_store_error(error: impl std::error::Error) -> ResumableTaskStoreError {
    ResumableTaskStoreError::StoreError(StoreError::InternalException(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    #[tokio::test]
    async fn event_log_reads_replays_and_trims() {
        let mut log = MemoryEventLog::new(2);
        log.open().await.unwrap();
        let message = serde_json::from_value(json!({
            "descriptor": {
                "interface": "Messages",
                "method": "Query",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z"
            },
            "authorization": { "signature": {} }
        }))
        .unwrap();
        let event = MessageEvent {
            message,
            initial_write: None,
        };
        let mut indexes = KeyValues::default();
        indexes.insert(
            "messageTimestamp".to_string(),
            Value::String("2025-01-01T00:00:00Z".to_string()),
        );

        let first = log
            .emit("did:example:alice", event.clone(), indexes.clone(), "cid-1")
            .await
            .unwrap()
            .unwrap();
        let second = log
            .emit("did:example:alice", event.clone(), indexes.clone(), "cid-2")
            .await
            .unwrap()
            .unwrap();
        let read = log
            .read(
                "did:example:alice",
                Some(EventLogReadOptions {
                    cursor: Some(first.clone()),
                    limit: None,
                    filters: None,
                }),
            )
            .await
            .unwrap();
        assert_eq!(read.events.len(), 1);
        assert_eq!(read.cursor.unwrap().message_cid, "cid-2");

        let delivered = Arc::new(Mutex::new(Vec::new()));
        let delivered_listener = delivered.clone();
        let subscription = log
            .subscribe(
                "did:example:alice",
                "sub-1",
                Box::new(move |message| delivered_listener.lock().unwrap().push(message)),
                Some(EventLogSubscribeOptions {
                    cursor: Some(second),
                    filters: None,
                }),
            )
            .await
            .unwrap();
        assert!(matches!(
            delivered.lock().unwrap().last(),
            Some(SubscriptionMessage::Eose { .. })
        ));
        (subscription.close)().await.unwrap();

        log.emit("did:example:alice", event.clone(), indexes.clone(), "cid-3")
            .await
            .unwrap()
            .unwrap();
        let fourth = log
            .emit("did:example:alice", event, indexes, "cid-4")
            .await
            .unwrap()
            .unwrap();
        let gap = log
            .read(
                "did:example:alice",
                Some(EventLogReadOptions {
                    cursor: Some(first),
                    limit: None,
                    filters: None,
                }),
            )
            .await
            .unwrap_err();
        let EventLogError::ProgressGap(gap) = gap else {
            panic!("expected progress gap");
        };
        assert_eq!(gap.reason, ProgressGapReason::TokenTooOld);
        assert_eq!(gap.oldest_available.message_cid, "cid-3");
        assert_eq!(gap.latest_available, fourth);

        log.trim("did:example:alice", EventLogTrimBound::Sequence(5))
            .await
            .unwrap();
        assert!(log
            .get_replay_bounds("did:example:alice")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn resumable_tasks_are_grabbed_exclusively() {
        let mut store = MemoryResumableTaskStore::default();
        store.open().await.unwrap();
        let registered = store
            .register(json!({ "task": "squash" }), 0)
            .await
            .unwrap();

        let first_grab = store.grab::<JsonValue>(1).await.unwrap();
        assert_eq!(first_grab.len(), 1);
        assert_eq!(first_grab[0].id, registered.id);
        assert_eq!(first_grab[0].retry_count, 1);

        let second_grab = store.grab::<JsonValue>(1).await.unwrap();
        assert!(second_grab.is_empty());

        store.delete(&registered.id).await.unwrap();
        assert!(store
            .read::<JsonValue>(&registered.id)
            .await
            .unwrap()
            .is_none());
    }
}
