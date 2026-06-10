use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use k256::sha2::{Digest, Sha256};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::cid::generate_cid_from_json;
use crate::descriptors::MessageDescriptor;
use crate::errors::{EventLogError, MessageStoreError, ResumableTaskStoreError, StoreError};
use crate::events::MessageEvent;
use crate::fields::MessageFields;
use crate::filters::Filters;
use crate::stores::{
    EventLog, EventLogEntry, EventLogReadOptions, EventLogReadResult, EventLogReplayBounds,
    EventLogSubscribeOptions, EventLogTrimBound, EventSubscription, EventSubscriptionClose,
    KeyValues, ManagedResumableTask, MessageQueryResult, MessageStore, ProgressGapInfo,
    ProgressGapReason, ProgressToken, ResumableTaskStore, SubscriptionListener,
    SubscriptionMessage,
};
use crate::{compare_values, Cursor, Descriptor, Message, MessageSort, SortDirection, Value};

const DEFAULT_MAX_EVENTS_PER_TENANT: usize = 10_000;
const GRABBED_TASK_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone, Debug)]
struct MessageRow {
    tenant: String,
    cid: String,
    message: Message<Descriptor>,
    indexes: KeyValues,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryMessageStore {
    messages: Arc<RwLock<Vec<MessageRow>>>,
}

impl MessageStore for MemoryMessageStore {
    async fn open(&mut self) -> Result<(), MessageStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    async fn put<D>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: KeyValues,
    ) -> Result<(), MessageStoreError>
    where
        D: MessageDescriptor + Serialize + Send,
    {
        let value = serde_json::to_value(&message)?;
        let message: Message<Descriptor> = serde_json::from_value(value)?;
        let mut canonical = message.clone();
        canonical.fields.encoded_data();
        let cid = canonical.cid()?.to_string();

        let mut rows = self.messages.write().expect("MessageStore lock poisoned");
        rows.retain(|row| !(row.tenant == tenant && row.cid == cid));
        rows.push(MessageRow {
            tenant: tenant.to_string(),
            cid,
            message,
            indexes,
        });

        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        cid: &str,
    ) -> Result<Option<Message<Descriptor>>, MessageStoreError> {
        let rows = self.messages.read().expect("MessageStore lock poisoned");
        Ok(rows
            .iter()
            .find(|row| row.tenant == tenant && row.cid == cid)
            .map(|row| row.message.clone()))
    }

    async fn delete(&self, tenant: &str, cid: &str) -> Result<(), MessageStoreError> {
        self.messages
            .write()
            .expect("MessageStore lock poisoned")
            .retain(|row| !(row.tenant == tenant && row.cid == cid));
        Ok(())
    }

    async fn clear(&self) -> Result<(), MessageStoreError> {
        self.messages
            .write()
            .expect("MessageStore lock poisoned")
            .clear();
        Ok(())
    }

    async fn query(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<crate::MessageSort>,
        pagination: Option<crate::Pagination>,
    ) -> Result<crate::stores::MessageQueryResult, MessageStoreError> {
        if matches!(pagination.as_ref().and_then(|p| p.limit), Some(0)) {
            return Ok(MessageQueryResult {
                messages: Vec::new(),
                cursor: None,
            });
        }

        let (property, direction) = sort_property(sort.unwrap_or_default());

        let mut rows: Vec<MessageRow> = {
            let g = self.messages.read().expect("MessageStore lock poisoned");
            g.iter()
                .filter(|row| row.tenant == tenant && matches_filters(&row.indexes, Some(&filters)))
                .cloned()
                .collect()
        };

        rows.retain(|row| row.indexes.contains_key(property));

        rows.sort_by(|a, b| {
            let ord = compare_indexes(a.indexes.get(property), b.indexes.get(property))
                .then_with(|| a.cid.cmp(&b.cid));
            apply_dir(ord, direction)
        });

        let start = match pagination.as_ref().and_then(|p| p.cursor.as_ref()) {
            Some(cursor) => cursor_start(&rows, property, direction, cursor),
            None => 0,
        };
        let mut page: Vec<MessageRow> = rows.into_iter().skip(start).collect();

        let cursor = match pagination.and_then(|p| p.limit) {
            Some(limit) if (page.len() as u64) > limit => {
                page.truncate(limit as usize);
                let last = page
                    .last()
                    .expect("page must have at least one entry after truncation");
                Some(Cursor {
                    cursor: last
                        .cid
                        .parse()
                        .map_err(MessageStoreError::CidEncodeError)?,
                    value: last.indexes.get(property).cloned(),
                })
            }
            _ => None,
        };

        Ok(MessageQueryResult {
            messages: page.into_iter().map(|row| row.message).collect(),
            cursor,
        })
    }

    async fn count(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<crate::MessageSort>,
    ) -> Result<u64, MessageStoreError> {
        let property = Some(sort_property(sort.unwrap_or_default()).0);
        let guard = self.messages.read().expect("MessageStore lock poisoned");

        Ok(guard
            .iter()
            .filter(|row| {
                row.tenant == tenant
                    && matches_filters(&row.indexes, Some(&filters))
                    && property.is_none_or(|prop| row.indexes.contains_key(prop))
            })
            .count() as u64)
    }
}

fn sort_property(sort: MessageSort) -> (&'static str, SortDirection) {
    match sort {
        MessageSort::DateCreated(d) => ("dateCreated", d),
        MessageSort::DatePublished(d) => ("datePublished", d),
        MessageSort::Timestamp(d) => ("messageTimestamp", d),
    }
}

fn compare_indexes(a: Option<&Value>, b: Option<&Value>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => compare_values(a, b).unwrap_or(Ordering::Equal),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

fn cursor_start(
    rows: &[MessageRow],
    property: &str,
    direction: SortDirection,
    c: &Cursor,
) -> usize {
    let cursor_cid = c.cursor.to_string();
    rows.iter()
        .position(|r| {
            let val = compare_indexes(r.indexes.get(property), c.value.as_ref());
            apply_dir(val.then_with(|| r.cid.cmp(&cursor_cid)), direction) == Ordering::Greater
        })
        .unwrap_or(rows.len())
}

fn apply_dir(o: Ordering, d: SortDirection) -> Ordering {
    match d {
        SortDirection::Ascending => o,
        SortDirection::Descending => o.reverse(),
    }
}

#[derive(Clone)]
/// In-memory `EventLog` for development, tests, and the `MobileCore` /
/// `DesktopLocalNode` reference flows. Process-local; not durable. Wire a
/// real backend (SQLite, etc.) for production deployments.
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

    /// Creates an event log with a stable epoch for durable backends.
    pub fn with_epoch(epoch: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(EventLogInner::default())),
            epoch: epoch.into(),
            max_events_per_tenant: DEFAULT_MAX_EVENTS_PER_TENANT,
        }
    }

    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// Restores persisted events for a tenant without notifying subscribers.
    pub fn restore_tenant(
        &self,
        tenant: &str,
        next_seq: u64,
        events: Vec<(u64, MessageEvent<Descriptor>, KeyValues, String)>,
    ) -> Result<(), EventLogError> {
        let mut inner = self.inner.write().map_err(event_lock_error)?;
        let log = inner.tenant_logs.entry(tenant.to_string()).or_default();
        for (seq, event, indexes, message_cid) in events {
            log.insert(
                seq,
                StoredEvent {
                    event,
                    indexes,
                    message_cid,
                },
            );
        }
        inner.tenant_seqs.insert(tenant.to_string(), next_seq);
        Ok(())
    }
}

impl EventLog for MemoryEventLog {
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

impl MemoryResumableTaskStore {
    /// Restores a persisted task without re-registering (for durable backends).
    pub fn restore(
        &self,
        id: String,
        task: JsonValue,
        timeout: u64,
        retry_count: u64,
    ) -> Result<(), ResumableTaskStoreError> {
        let mut tasks = self.tasks.write().map_err(task_lock_error)?;
        tasks.insert(
            id.clone(),
            StoredTask {
                id,
                task,
                timeout,
                retry_count,
            },
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredTask {
    id: String,
    task: JsonValue,
    timeout: u64,
    retry_count: u64,
}

impl ResumableTaskStore for MemoryResumableTaskStore {
    async fn open(&mut self) -> Result<(), ResumableTaskStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    fn register<T: Serialize + Send + Sync + DeserializeOwned + Debug + 'static>(
        &self,
        task: T,
        timeout_in_seconds: u64,
    ) -> impl Future<Output = Result<ManagedResumableTask<T>, ResumableTaskStoreError>> + Send {
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
            Ok(ManagedResumableTask {
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
    ) -> impl Future<Output = Result<Vec<ManagedResumableTask<T>>, ResumableTaskStoreError>> + Send
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
    ) -> impl Future<Output = Result<Option<ManagedResumableTask<T>>, ResumableTaskStoreError>> + Send
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

fn enbox_task<T>(task: &StoredTask) -> Result<ManagedResumableTask<T>, ResumableTaskStoreError>
where
    T: DeserializeOwned + Serialize + Send + Sync + Debug,
{
    Ok(ManagedResumableTask {
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
    use crate::filters::{Filter, FilterKey};
    use crate::Pagination;
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

    // Distinct `descriptor.messageTimestamp` yields a distinct CID (so rows don't
    // collapse on upsert); the index `messageTimestamp` is supplied separately, so
    // tests can hold the sort value constant while CIDs differ.
    fn msg(descriptor_ts: &str) -> Message<Descriptor> {
        serde_json::from_value(json!({
            "descriptor": {
                "interface": "Messages",
                "method": "Query",
                "messageTimestamp": descriptor_ts,
            },
            "authorization": { "signature": {} },
        }))
        .expect("valid message")
    }

    fn idx(timestamp: &str, protocol: Option<&str>) -> KeyValues {
        let mut indexes = KeyValues::default();
        indexes.insert(
            "messageTimestamp".to_string(),
            Value::String(timestamp.to_string()),
        );
        if let Some(protocol) = protocol {
            indexes.insert("protocol".to_string(), Value::String(protocol.to_string()));
        }
        indexes
    }

    #[tokio::test]
    async fn message_store_put_get_delete_and_upsert() {
        let store = MemoryMessageStore::default();
        let message = msg("2025-01-01T00:00:00.000001Z");
        let cid = message.cid().unwrap().to_string();

        store
            .put(
                "did:alice",
                message.clone(),
                idx("2025-01-01T00:00:01Z", None),
            )
            .await
            .unwrap();
        assert_eq!(
            store.get("did:alice", &cid).await.unwrap(),
            Some(message.clone())
        );

        // re-putting the same message (same CID) upserts rather than duplicating
        store
            .put(
                "did:alice",
                message.clone(),
                idx("2025-01-01T00:00:01Z", None),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .count("did:alice", Filters::default(), None)
                .await
                .unwrap(),
            1
        );

        // tenant isolation
        assert_eq!(store.get("did:bob", &cid).await.unwrap(), None);

        store.delete("did:alice", &cid).await.unwrap();
        assert_eq!(store.get("did:alice", &cid).await.unwrap(), None);
    }

    #[tokio::test]
    async fn message_store_filters_sorts_and_counts() {
        let store = MemoryMessageStore::default();
        let m1 = msg("2025-01-01T00:00:00.000001Z");
        let m2 = msg("2025-01-01T00:00:00.000002Z");
        let m3 = msg("2025-01-01T00:00:00.000003Z");
        store
            .put("t", m1.clone(), idx("2025-01-01T00:00:01Z", Some("notes")))
            .await
            .unwrap();
        store
            .put("t", m2.clone(), idx("2025-01-01T00:00:02Z", Some("notes")))
            .await
            .unwrap();
        store
            .put("t", m3.clone(), idx("2025-01-01T00:00:03Z", Some("tasks")))
            .await
            .unwrap();

        let notes = Filters::from([[(
            FilterKey::Index("protocol".to_string()),
            Filter::Equal(Value::String("notes".to_string())),
        )]]);

        assert_eq!(store.count("t", notes.clone(), None).await.unwrap(), 2);

        let desc = store
            .query(
                "t",
                notes.clone(),
                Some(MessageSort::Timestamp(SortDirection::Descending)),
                None,
            )
            .await
            .unwrap();
        assert_eq!(desc.messages, vec![m2.clone(), m1.clone()]); // notes only, newest first
        assert!(desc.cursor.is_none());

        let asc = store
            .query(
                "t",
                notes,
                Some(MessageSort::Timestamp(SortDirection::Ascending)),
                None,
            )
            .await
            .unwrap();
        assert_eq!(asc.messages, vec![m1, m2]);
    }

    #[tokio::test]
    async fn message_store_paginates_with_cursor() {
        let store = MemoryMessageStore::default();
        let m1 = msg("2025-01-01T00:00:00.000001Z");
        let m2 = msg("2025-01-01T00:00:00.000002Z");
        let m3 = msg("2025-01-01T00:00:00.000003Z");
        store
            .put("t", m1.clone(), idx("2025-01-01T00:00:01Z", None))
            .await
            .unwrap();
        store
            .put("t", m2.clone(), idx("2025-01-01T00:00:02Z", None))
            .await
            .unwrap();
        store
            .put("t", m3.clone(), idx("2025-01-01T00:00:03Z", None))
            .await
            .unwrap();

        let sort = Some(MessageSort::Timestamp(SortDirection::Ascending));

        let p1 = store
            .query(
                "t",
                Filters::default(),
                sort,
                Some(Pagination::with_limit(1)),
            )
            .await
            .unwrap();
        assert_eq!(p1.messages, vec![m1]);
        assert!(p1.cursor.is_some());

        let p2 = store
            .query(
                "t",
                Filters::default(),
                sort,
                Some(Pagination::new(p1.cursor, Some(1))),
            )
            .await
            .unwrap();
        assert_eq!(p2.messages, vec![m2]);
        assert!(p2.cursor.is_some());

        let p3 = store
            .query(
                "t",
                Filters::default(),
                sort,
                Some(Pagination::new(p2.cursor, Some(1))),
            )
            .await
            .unwrap();
        assert_eq!(p3.messages, vec![m3]);
        assert!(p3.cursor.is_none()); // last page, no overflow
    }

    #[tokio::test]
    async fn message_store_cursor_breaks_ties_on_identical_sort_value() {
        let store = MemoryMessageStore::default();
        // distinct CIDs, identical index sort value -> exercises the cid tiebreak
        let a = msg("2025-01-01T00:00:00.000001Z");
        let b = msg("2025-01-01T00:00:00.000002Z");
        store
            .put("t", a.clone(), idx("2025-01-01T00:00:05Z", None))
            .await
            .unwrap();
        store
            .put("t", b.clone(), idx("2025-01-01T00:00:05Z", None))
            .await
            .unwrap();

        let sort = Some(MessageSort::Timestamp(SortDirection::Ascending));
        let p1 = store
            .query(
                "t",
                Filters::default(),
                sort,
                Some(Pagination::with_limit(1)),
            )
            .await
            .unwrap();
        assert_eq!(p1.messages.len(), 1);
        let p2 = store
            .query(
                "t",
                Filters::default(),
                sort,
                Some(Pagination::new(p1.cursor.clone(), Some(1))),
            )
            .await
            .unwrap();
        assert_eq!(p2.messages.len(), 1);

        // no row dropped or duplicated across the tie: the two pages are distinct and cover {a, b}
        assert_ne!(p1.messages[0], p2.messages[0]);
        let page = [p1.messages[0].clone(), p2.messages[0].clone()];
        assert!(page.contains(&a) && page.contains(&b));
    }

    #[tokio::test]
    async fn message_store_query_limit_zero_is_empty() {
        let store = MemoryMessageStore::default();
        store
            .put(
                "t",
                msg("2025-01-01T00:00:00.000001Z"),
                idx("2025-01-01T00:00:01Z", None),
            )
            .await
            .unwrap();
        let result = store
            .query(
                "t",
                Filters::default(),
                None,
                Some(Pagination::with_limit(0)),
            )
            .await
            .unwrap();
        assert!(result.messages.is_empty());
        assert!(result.cursor.is_none());
    }
}
