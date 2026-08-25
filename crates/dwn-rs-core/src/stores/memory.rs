use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, RwLock};

use crate::cid::generate_cid_from_json;
use crate::descriptors::records::write_tag_protocol;
use crate::descriptors::MessageDescriptor;
use crate::errors::{
    EventLogError, MessageReplicationError, MessageStoreError, ResumableTaskStoreError, StoreError,
};
use crate::events::MessageEvent;
use crate::fields::MessageFields;
use crate::filters::Filters;
use crate::matching::has_valid_subtree_filters;
use crate::stores::replication_feed_reader::{
    build_token, derive_stream_id, fingerprint_scopes, fold_cid_into_domain, is_feed_message,
    normalize_scopes, parse_feed_position, scopes_unchanged, validate_feed_cursor, xor_in_place,
    FeedCursorState, Fingerprint,
};
use crate::stores::wake::{Wake, WakePublishHandler, WakePublisher};
use crate::stores::{
    EventLog, EventLogEntry, EventLogReadOptions, EventLogReadResult, EventLogReplayBounds,
    EventLogSubscribeOptions, EventLogTrimBound, EventSubscription, EventSubscriptionClose,
    KeyValues, ManagedResumableTask, MessageQueryResult, MessageStore, ProgressGapCode,
    ProgressGapInfo, ProgressGapReason, ProgressToken, ReplicationFeedReader, ResumableTaskStore,
    SubscriptionListener, SubscriptionMessage,
};
use crate::{
    compare_values, Cursor, Descriptor, FilterError, Message, MessageSort, SortDirection, Value,
};
use chrono::Utc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value as JsonValue;

const DEFAULT_MAX_EVENTS_PER_TENANT: usize = 10_000;
const GRABBED_TASK_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone, Debug)]
struct MessageRow {
    cid: String,
    message: Message<Descriptor>,
    indexes: KeyValues,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct MemoryFeedEntry {
    fingerprint_scopes: Vec<String>,
    indexes: KeyValues,
    message_cid: String,
}

#[derive(Clone, Default)]
struct MemoryMessageState {
    epoch: String,
    // (tenants, message_cid) => message row
    messages: BTreeMap<(String, String), MessageRow>,
    // (tenant) => latest seq
    heads: BTreeMap<String, u64>,
    // (tenant, seq) => feed entry
    entries: BTreeMap<(String, u64), MemoryFeedEntry>,
    // (tenant, cid) => position
    positions_by_cid: BTreeMap<(String, String), u64>,
    // (tenant, domain) => fingerprint
    fingerprints: BTreeMap<(String, String), Fingerprint>,
}

impl MemoryMessageState {
    fn clear(&mut self) {
        self.epoch = ulid::Ulid::new().to_string();
        self.messages.clear();
        self.heads.clear();
        self.entries.clear();
        self.positions_by_cid.clear();
        self.fingerprints.clear();
    }
}

#[derive(Clone, Default)]
pub struct MemoryMessageStore {
    state: Arc<RwLock<MemoryMessageState>>,
    waker_publisher: WakePublishHandler,
}

impl MemoryMessageStore {
    pub fn with_waker_publisher(mut self, waker_publisher: impl WakePublisher + 'static) -> Self {
        self.waker_publisher = WakePublishHandler::new(Arc::new(waker_publisher));
        self
    }

    fn log_bounds_from_state(
        &self,
        tenant: &str,
        state: &MemoryMessageState,
    ) -> Result<Option<(ProgressToken, ProgressToken)>, EventLogError> {
        let head = state.heads.get(tenant).copied().unwrap_or(0);
        if head == 0 {
            return Ok(None);
        }

        let oldest = build_token(tenant, &state.epoch, 0, None);

        let latest_entry = state.entries.get(&(tenant.to_string(), head));

        let latest = match latest_entry {
            Some(entry) => build_token(tenant, &state.epoch, head, Some(&entry.message_cid)),
            None => build_token(tenant, &state.epoch, head, None),
        };

        Ok(Some((oldest, latest)))
    }
}

impl MessageStore for MemoryMessageStore {
    async fn open(&mut self) -> Result<(), MessageStoreError> {
        self.state
            .write()
            .map_err(message_lock_error)
            .map(|mut state| {
                state.epoch.is_empty().then(|| {
                    state.epoch = ulid::Ulid::new().to_string();
                });
            })
            .map_err(message_lock_error)?;

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
        Message<Descriptor>: From<Message<D>>,
    {
        let message: Message<Descriptor> = message.into();
        let mut canonical = message.clone();
        canonical.fields.encoded_data();
        let cid = canonical.cid()?.to_string();

        let wake = {
            let mut state = self.state.write().map_err(message_lock_error)?;

            let msg_key = (tenant.to_string(), cid.clone());
            let msg_row = MessageRow {
                cid: cid.clone(),
                message: message.clone(),
                indexes: indexes.clone(),
            };

            if !is_feed_message(&canonical) {
                state.messages.insert(msg_key, msg_row);
                None
            } else {
                let msg_scopes = fingerprint_scopes(write_tag_protocol(&message), &indexes);

                match state.positions_by_cid.get(&msg_key).copied() {
                    Some(position) => {
                        let entry = state
                            .entries
                            .get(&(tenant.to_string(), position))
                            .ok_or_else(|| {
                                MessageStoreError::StoreError(StoreError::InternalException(
                                    "feed entry missing for existing feed position".to_string(),
                                ))
                            })?;

                        if !scopes_unchanged(&entry.fingerprint_scopes, &msg_scopes) {
                            return Err(MessageStoreError::StoreError(
                                StoreError::ReplicationError(
                                    MessageReplicationError::FingerprintScopesMismatch,
                                ),
                            ));
                        }

                        state.messages.insert(msg_key, msg_row);
                        state
                            .entries
                            .get_mut(&(tenant.to_string(), position))
                            .expect("in-memory feed positions are generated canonically")
                            .indexes = indexes;

                        None
                    }
                    None => {
                        let next_position = state
                            .heads
                            .get(tenant)
                            .copied()
                            .unwrap_or(0)
                            .checked_add(1)
                            .ok_or(MessageStoreError::StoreError(StoreError::ReplicationError(
                                MessageReplicationError::FeedPositionOverflow,
                            )))?;

                        state.messages.insert(msg_key, msg_row);

                        state.entries.insert(
                            (tenant.to_string(), next_position),
                            MemoryFeedEntry {
                                fingerprint_scopes: msg_scopes.clone(),
                                indexes,
                                message_cid: cid.clone(),
                            },
                        );

                        state
                            .positions_by_cid
                            .insert((tenant.to_string(), cid.clone()), next_position);

                        state.heads.insert(tenant.to_string(), next_position);

                        fold_cid_into_domain(&mut state.fingerprints, tenant, &cid, &msg_scopes);

                        Some(Wake {
                            tenant: tenant.to_string(),
                            position: next_position,
                        })
                    }
                }
            }
        };

        if let Some(wake) = wake {
            let _ = self.waker_publisher.publish(wake);
        }

        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        cid: &str,
    ) -> Result<Option<Message<Descriptor>>, MessageStoreError> {
        let state = self.state.read().map_err(message_lock_error)?;
        Ok(state
            .messages
            .iter()
            .find(|((row_tenant, row_cid), _)| row_tenant == tenant && row_cid == cid)
            .map(|((_, _), row)| row.message.clone()))
    }

    async fn delete(&self, tenant: &str, cid: &str) -> Result<(), MessageStoreError> {
        let mut state = self.state.write().map_err(message_lock_error)?;
        let key = (tenant.to_string(), cid.to_string());

        let feed = match state.positions_by_cid.get(&key).copied() {
            Some(position) => {
                let entry = state
                    .entries
                    .get(&(tenant.to_string(), position))
                    .ok_or_else(|| {
                        MessageStoreError::StoreError(StoreError::InternalException(
                            "feed entry missing for existing feed position".to_string(),
                        ))
                    })?;

                if entry.message_cid != cid {
                    return Err(MessageStoreError::StoreError(
                        StoreError::InternalException(
                            "feed entry message CID mismatch for existing feed position"
                                .to_string(),
                        ),
                    ));
                }

                Some((
                    position,
                    entry.fingerprint_scopes.clone(),
                    entry.message_cid.clone(),
                ))
            }
            None => None,
        };

        state.messages.remove(&key);
        if let Some((position, scopes, stored_cid)) = feed {
            state.entries.remove(&(tenant.to_string(), position));
            state.positions_by_cid.remove(&key);
            fold_cid_into_domain(&mut state.fingerprints, tenant, &stored_cid, &scopes);
        }

        Ok(())
    }

    async fn clear(&self) -> Result<(), MessageStoreError> {
        let mut state = self.state.write().map_err(message_lock_error)?;

        state.clear();
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
            let g = self.state.read().map_err(message_lock_error)?;
            g.messages
                .iter()
                .filter(|((row_tenant, _), row)| {
                    row_tenant == tenant && matches_filters(&row.indexes, Some(&filters))
                })
                .map(|((_, _), row)| row)
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
                let last = page.last().ok_or_else(|| {
                    MessageStoreError::StoreError(StoreError::InternalException(
                        "page must have at least one entry after truncation".to_string(),
                    ))
                })?;
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
        let guard = self.state.read().map_err(message_lock_error)?;

        Ok(guard
            .messages
            .iter()
            .filter(|((row_tenant, _), row)| {
                row_tenant == tenant
                    && matches_filters(&row.indexes, Some(&filters))
                    && property.is_none_or(|prop| row.indexes.contains_key(prop))
            })
            .count() as u64)
    }
}

impl ReplicationFeedReader for MemoryMessageStore {
    async fn log_read(
        &self,
        tenant: &str,
        options: EventLogReadOptions,
    ) -> Result<EventLogReadResult, EventLogError> {
        if let Some(filters) = &options.filters {
            if !has_valid_subtree_filters(filters) {
                return Err(EventLogError::FilterError(FilterError::UnparseableFilter(
                    "invalid subtree filter".to_string(),
                )));
            }
        }

        let state = self.state.read().map_err(event_lock_error)?;

        let head = state.heads.get(tenant).copied().unwrap_or(0);
        if let Some(cursor) = &options.cursor {
            let bounds = self.log_bounds_from_state(tenant, &state)?;
            let zero_cursor = build_token(tenant, &state.epoch, 0, None);
            let zero_bounds = (zero_cursor.clone(), zero_cursor.clone());
            let message_cid_at_position = state
                .entries
                .get(&(
                    tenant.to_string(),
                    parse_feed_position(&cursor.position).unwrap_or(0),
                ))
                .map(|entry| entry.message_cid.as_str());

            validate_feed_cursor(
                cursor,
                FeedCursorState {
                    expected_stream_id: derive_stream_id(tenant).as_str(),
                    expected_epoch: state.epoch.clone().as_str(),
                    head,
                    oldest_replayable: 0, // todo: retention policy
                    message_cid_at_position,
                    bounds: match bounds {
                        Some(ref bounds) => Some(bounds),
                        None => Some(&zero_bounds),
                    },
                },
            )?;
        }

        if head == 0 {
            return Ok(EventLogReadResult {
                events: Vec::new(),
                cursor: Some(
                    options
                        .cursor
                        .unwrap_or(build_token(tenant, &state.epoch, 0, None)),
                ),
                drained: true,
            });
        }

        let start_position = options
            .cursor
            .as_ref()
            .and_then(|c| parse_feed_position(&c.position).ok())
            .unwrap_or(0);

        let max_events = options.limit.unwrap_or(u64::MAX) as usize;
        if max_events == 0 {
            return Ok(EventLogReadResult {
                events: Vec::new(),
                cursor: match options.cursor {
                    Some(cursor) => Some(cursor),
                    None => Some(build_token(tenant, &state.epoch, start_position, None)),
                },
                drained: start_position >= head,
            });
        }

        if start_position == head {
            return Ok(EventLogReadResult {
                events: Vec::new(),
                cursor: Some(build_token(tenant, &state.epoch, start_position, None)),
                drained: true,
            });
        }

        if start_position > head {
            return Ok(EventLogReadResult {
                events: Vec::new(),
                cursor: options.cursor,
                drained: true,
            });
        }

        let mut events: Vec<EventLogEntry> = Vec::new();
        let mut last_position_scanned = start_position;

        for position in start_position + 1..=head {
            last_position_scanned = position;

            let entry_key = (tenant.to_string(), position);
            if let Some(entry) = state.entries.get(&entry_key) {
                if !matches_filters(&entry.indexes, options.filters.as_ref()) {
                    continue;
                }

                let msg_key = (tenant.to_string(), entry.message_cid.clone());

                match state.messages.get(&msg_key) {
                    Some(row) => {
                        let mut msg = row.message.clone();
                        let encoded_data = match msg.fields.encoded_data() {
                            Some(Value::String(encoded)) => Some(encoded.clone()),
                            Some(Value::Null) | None => None,
                            Some(_) => {
                                return Err(EventLogError::StoreError(
                                    StoreError::ReplicationError(
                                        MessageReplicationError::InvalidEncodedData,
                                    ),
                                ))
                            }
                        };

                        if row.cid != entry.message_cid {
                            return Err(EventLogError::StoreError(StoreError::ReplicationError(
                                MessageReplicationError::CidsMismatch {
                                    expected: entry.message_cid.clone(),
                                    actual: row.cid.clone(),
                                },
                            )));
                        }

                        if row
                            .message
                            .message_cid()
                            .map_err(|err| {
                                EventLogError::StoreError(StoreError::InternalException(format!(
                                    "failed to compute message CID: {err}"
                                )))
                            })?
                            .to_string()
                            != entry.message_cid
                        {
                            return Err(EventLogError::StoreError(StoreError::InternalException(
                                "message CID mismatch for feed entry".to_string(),
                            )));
                        }

                        events.push(EventLogEntry {
                            seq: position.to_string(),
                            event: MessageEvent {
                                message: msg,
                                initial_write: None,
                            },
                            indexes: entry.indexes.clone(),
                            message_cid: Some(row.cid.clone()),
                            encoded_data,
                        });
                    }

                    None => {
                        return Err(EventLogError::StoreError(StoreError::ReplicationError(
                            MessageReplicationError::MissingMessage {
                                message_cid: entry.message_cid.clone(),
                            },
                        )))
                    }
                };

                if events.len() >= max_events {
                    break;
                }
            }
        }

        Ok(EventLogReadResult {
            events: events.clone(),
            cursor: Some(build_token(
                tenant,
                &state.epoch,
                last_position_scanned,
                if last_position_scanned
                    == events
                        .last()
                        .map_or(0, |entry| parse_feed_position(&entry.seq).unwrap_or(0))
                {
                    events.last().and_then(|entry| entry.message_cid.as_deref())
                } else {
                    None
                },
            )),
            drained: last_position_scanned >= head,
        })
    }

    async fn log_bounds(
        &self,
        tenant: &str,
    ) -> Result<Option<super::replication_feed_reader::ReplicationBounds>, EventLogError> {
        let state = self.state.read().map_err(event_lock_error)?;
        self.log_bounds_from_state(tenant, &state)
    }

    async fn fingerprint(
        &self,
        tenant: &str,
        scopes: &[String],
    ) -> Result<Fingerprint, EventLogError> {
        let mut fingerprint = Fingerprint::default();
        let normal_scopes = normalize_scopes(scopes);

        let state = self.state.read().map_err(event_lock_error)?;
        for scope in normal_scopes {
            let key = (tenant.to_string(), scope.clone());
            if let Some(fp) = state.fingerprints.get(&key) {
                xor_in_place(&mut fingerprint, fp);
            }
        }

        Ok(fingerprint)
    }

    async fn epoch(&self) -> Result<String, EventLogError> {
        let state = self.state.read().map_err(event_lock_error)?;
        Ok(state.epoch.clone())
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

                token = build_token(&tenant, &epoch, seq, Some(&message_cid));

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
                    seq: Some(token.position.clone()),
                    message_cid: token.message_cid.clone(),
                    is_latest_base_state: None,
                    protocol: None,
                    encoded_data: None,
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
            let mut drained = true;

            if let Some(log) = inner.tenant_logs.get(&tenant) {
                for (seq, entry) in log {
                    if cursor_seq.is_some_and(|cursor_seq| *seq <= cursor_seq) {
                        continue;
                    }
                    if !matches_filters(&entry.indexes, options.filters.as_ref()) {
                        continue;
                    }

                    events.push(EventLogEntry {
                        seq: seq.to_string(),
                        event: entry.event.clone(),
                        indexes: entry.indexes.clone(),
                        message_cid: Some(entry.message_cid.clone()),
                        encoded_data: None,
                    });
                    if events.len() >= limit {
                        drained = false;
                        break;
                    }
                }
            }

            let cursor = events.last().map_or(options.cursor, |entry| {
                Some(build_token(
                    &tenant,
                    &epoch,
                    parse_feed_position(&entry.seq)
                        .expect("in-memory event positions are generated canonically"),
                    entry.message_cid.as_deref(),
                ))
            });

            Ok(EventLogReadResult {
                events,
                cursor,
                drained,
            })
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
                            parse_feed_position(&entry.seq)
                                .expect("in-memory event positions are generated canonically"),
                            entry.message_cid.as_deref(),
                        ),
                        event: Box::new(entry.event),
                        seq: Some(entry.seq),
                        message_cid: entry.message_cid,
                        is_latest_base_state: None,
                        protocol: None,
                        encoded_data: None,
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
                oldest: build_token(
                    &tenant,
                    &epoch,
                    *oldest_seq,
                    Some(&oldest_entry.message_cid),
                ),
                latest: build_token(
                    &tenant,
                    &epoch,
                    *latest_seq,
                    Some(&latest_entry.message_cid),
                ),
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
    let mut drained = true;

    if let Some(log) = inner.tenant_logs.get(tenant) {
        for (seq, entry) in log {
            if cursor_seq.is_some_and(|cursor_seq| *seq <= cursor_seq) {
                continue;
            }
            if !matches_filters(&entry.indexes, filters) {
                continue;
            }
            events.push(EventLogEntry {
                seq: seq.to_string(),
                event: entry.event.clone(),
                indexes: entry.indexes.clone(),
                message_cid: Some(entry.message_cid.clone()),
                encoded_data: None,
            });
            if events.len() >= max {
                drained = false;
                break;
            }
        }
    }

    let cursor = events.last().map_or(cursor, |entry| {
        Some(build_token(
            tenant,
            epoch,
            parse_feed_position(&entry.seq)
                .expect("in-memory event positions are generated canonically"),
            entry.message_cid.as_deref(),
        ))
    });
    Ok(EventLogReadResult {
        events,
        cursor,
        drained,
    })
}

fn validate_cursor(
    inner: &Arc<RwLock<EventLogInner>>,
    tenant: &str,
    epoch: &str,
    cursor: &ProgressToken,
) -> Result<u64, EventLogError> {
    if cursor.stream_id != derive_stream_id(tenant) {
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
    let seq = parse_feed_position(&cursor.position)
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
                build_token(tenant, epoch, *oldest_seq, Some(&oldest_entry.message_cid)),
                build_token(tenant, epoch, *latest_seq, Some(&latest_entry.message_cid)),
            ))
        })
        .unwrap_or_else(|| (requested.clone(), requested.clone()));

    EventLogError::ProgressGap(Box::new(ProgressGapInfo {
        requested: requested.clone(),
        oldest_available,
        latest_available,
        reason,
        code: ProgressGapCode::ProgressGap,
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

fn message_lock_error<T>(_: T) -> MessageStoreError {
    MessageStoreError::StoreError(StoreError::InternalException(
        "MessageStore lock poisoned".to_string(),
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
    use crate::descriptors::{DeleteDescriptor, Records};
    use crate::fields::WriteFields;
    use crate::filters::{Filter, FilterKey};
    use crate::stores::replication_feed_reader::{cid_contribution, xor_in_place};
    use crate::stores::wake::{WakeError, WakePublisher};
    use crate::{Fields, Pagination};
    use serde_json::json;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct RecordingWakePublisher {
        wakes: Arc<Mutex<Vec<(String, u64)>>>,
        fail: bool,
    }

    impl RecordingWakePublisher {
        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::default()
            }
        }

        fn recorded(&self) -> Vec<(String, u64)> {
            self.wakes.lock().unwrap().clone()
        }
    }

    impl WakePublisher for RecordingWakePublisher {
        fn publish(&self, wake: Wake) -> Result<(), WakeError> {
            self.wakes
                .lock()
                .unwrap()
                .push((wake.tenant, wake.position));
            if self.fail {
                Err(WakeError::PublishError("test failure".to_string()))
            } else {
                Ok(())
            }
        }
    }

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
        assert_eq!(read.cursor.unwrap().message_cid.as_deref(), Some("cid-2"));

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
        assert_eq!(gap.oldest_available.message_cid.as_deref(), Some("cid-3"));
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

    fn feed_msg(record_id: &str, descriptor_ts: &str) -> Message<Descriptor> {
        Message {
            descriptor: Descriptor::Records(Box::new(Records::Delete(Box::new(
                DeleteDescriptor {
                    message_timestamp: descriptor_ts.parse().unwrap(),
                    record_id: record_id.to_string(),
                    prune: false,
                },
            )))),
            fields: Fields::Authorization(Default::default()),
        }
    }

    fn feed_write_msg(encoded_data: Option<&str>) -> Message<Descriptor> {
        Message {
            descriptor: Descriptor::Records(Box::new(Records::Write(Default::default()))),
            fields: Fields::Write(WriteFields {
                encoded_data: encoded_data.map(str::to_string),
                ..Default::default()
            }),
        }
    }

    fn stored_cid(message: &Message<Descriptor>) -> String {
        message.message_cid().unwrap().to_string()
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

    fn protocol_filter(protocol: &str) -> Filters {
        Filters::from([[(
            FilterKey::Index("protocol".to_string()),
            Filter::Equal(Value::String(protocol.to_string())),
        )]])
    }

    #[tokio::test]
    async fn feed_put_assigns_monotonic_positions_and_publishes_after_commit() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let first = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let second = feed_msg("record-2", "2025-01-01T00:00:01Z");
        let first_cid = stored_cid(&first);
        let second_cid = stored_cid(&second);

        store
            .put("did:alice", first, idx("2025-01-01T00:00:00Z", Some("p")))
            .await
            .unwrap();
        store
            .put("did:alice", second, idx("2025-01-01T00:00:01Z", Some("p")))
            .await
            .unwrap();

        let state = store.state.read().unwrap();
        assert_eq!(state.heads.get("did:alice"), Some(&2));
        assert_eq!(
            state
                .positions_by_cid
                .get(&("did:alice".to_string(), first_cid.clone())),
            Some(&1)
        );
        assert_eq!(
            state
                .positions_by_cid
                .get(&("did:alice".to_string(), second_cid.clone())),
            Some(&2)
        );
        assert_eq!(
            state
                .entries
                .get(&("did:alice".to_string(), 1))
                .map(|entry| &entry.message_cid),
            Some(&first_cid)
        );
        assert_eq!(
            state
                .entries
                .get(&("did:alice".to_string(), 2))
                .map(|entry| &entry.message_cid),
            Some(&second_cid)
        );
        assert_eq!(
            state
                .fingerprints
                .get(&("did:alice".to_string(), "".to_string())),
            Some(&{
                let mut expected = cid_contribution(&first_cid);
                xor_in_place(&mut expected, &cid_contribution(&second_cid));
                expected
            })
        );
        drop(state);

        assert_eq!(
            publisher.recorded(),
            vec![("did:alice".to_string(), 1), ("did:alice".to_string(), 2)]
        );
    }

    #[tokio::test]
    async fn duplicate_feed_put_updates_indexes_without_moving_or_waking() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let message = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let cid = stored_cid(&message);
        let original_indexes = idx("2025-01-01T00:00:00Z", Some("p"));
        let updated_indexes = idx("2025-01-01T00:00:01Z", Some("p"));

        store
            .put("did:alice", message.clone(), original_indexes)
            .await
            .unwrap();
        let fingerprint = store.state.read().unwrap().fingerprints.clone();

        store
            .put("did:alice", message, updated_indexes.clone())
            .await
            .unwrap();

        let state = store.state.read().unwrap();
        assert_eq!(state.heads.get("did:alice"), Some(&1));
        assert_eq!(
            state.positions_by_cid.get(&("did:alice".to_string(), cid)),
            Some(&1)
        );
        assert_eq!(
            state
                .entries
                .get(&("did:alice".to_string(), 1))
                .map(|entry| &entry.indexes),
            Some(&updated_indexes)
        );
        assert_eq!(state.fingerprints, fingerprint);
        drop(state);
        assert_eq!(publisher.recorded(), vec![("did:alice".to_string(), 1)]);
    }

    #[tokio::test]
    async fn data_completion_replaces_message_without_changing_feed_identity() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let incomplete = feed_write_msg(None);
        let complete = feed_write_msg(Some("dGVzdA=="));
        let cid = stored_cid(&incomplete);
        assert_eq!(stored_cid(&complete), cid);
        let indexes = idx("2025-01-01T00:00:00Z", Some("p"));

        store
            .put("did:alice", incomplete, indexes.clone())
            .await
            .unwrap();
        store
            .put("did:alice", complete.clone(), indexes)
            .await
            .unwrap();

        let state = store.state.read().unwrap();
        assert_eq!(state.heads.get("did:alice"), Some(&1));
        assert_eq!(
            state
                .positions_by_cid
                .get(&("did:alice".to_string(), cid.clone())),
            Some(&1)
        );
        assert_eq!(
            state
                .messages
                .get(&("did:alice".to_string(), cid))
                .map(|row| &row.message),
            Some(&complete)
        );
        drop(state);
        assert_eq!(publisher.recorded(), vec![("did:alice".to_string(), 1)]);
    }

    #[tokio::test]
    async fn non_feed_put_does_not_allocate_position_or_publish_wake() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let message = msg("2025-01-01T00:00:00Z");
        let cid = stored_cid(&message);

        store
            .put("did:alice", message, idx("2025-01-01T00:00:00Z", None))
            .await
            .unwrap();

        let state = store.state.read().unwrap();
        assert!(state.messages.contains_key(&("did:alice".to_string(), cid)));
        assert!(state.heads.is_empty());
        assert!(state.entries.is_empty());
        assert!(state.positions_by_cid.is_empty());
        assert!(state.fingerprints.is_empty());
        drop(state);
        assert!(publisher.recorded().is_empty());
    }

    #[tokio::test]
    async fn wake_failure_does_not_roll_back_committed_feed_put() {
        let publisher = RecordingWakePublisher::failing();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let message = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let cid = stored_cid(&message);

        store
            .put("did:alice", message, idx("2025-01-01T00:00:00Z", None))
            .await
            .unwrap();

        let state = store.state.read().unwrap();
        assert!(state
            .messages
            .contains_key(&("did:alice".to_string(), cid.clone())));
        assert_eq!(
            state.positions_by_cid.get(&("did:alice".to_string(), cid)),
            Some(&1)
        );
        drop(state);
        assert_eq!(publisher.recorded(), vec![("did:alice".to_string(), 1)]);
    }

    #[tokio::test]
    async fn scope_mismatch_fails_without_mutating_existing_feed_state() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let original = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let cid = stored_cid(&original);
        let original_indexes = idx("2025-01-01T00:00:00Z", Some("p1"));

        store
            .put("did:alice", original.clone(), original_indexes.clone())
            .await
            .unwrap();
        let original_fingerprints = store.state.read().unwrap().fingerprints.clone();

        let error = store
            .put(
                "did:alice",
                original.clone(),
                idx("2025-01-01T00:00:01Z", Some("p2")),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("fingerprint scopes mismatch"));

        let state = store.state.read().unwrap();
        let key = ("did:alice".to_string(), cid);
        assert_eq!(
            state.messages.get(&key).map(|row| &row.message),
            Some(&original)
        );
        assert_eq!(
            state.messages.get(&key).map(|row| &row.indexes),
            Some(&original_indexes)
        );
        assert_eq!(
            state
                .entries
                .get(&("did:alice".to_string(), 1))
                .map(|entry| &entry.indexes),
            Some(&original_indexes)
        );
        assert_eq!(state.heads.get("did:alice"), Some(&1));
        assert_eq!(state.fingerprints, original_fingerprints);
        drop(state);
        assert_eq!(publisher.recorded(), vec![("did:alice".to_string(), 1)]);
    }

    #[tokio::test]
    async fn missing_feed_entry_fails_without_mutating_message_row_or_waking() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let original = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let cid = stored_cid(&original);
        let original_indexes = idx("2025-01-01T00:00:00Z", Some("p"));

        store
            .put("did:alice", original.clone(), original_indexes.clone())
            .await
            .unwrap();
        store
            .state
            .write()
            .unwrap()
            .entries
            .remove(&("did:alice".to_string(), 1));

        let error = store
            .put(
                "did:alice",
                original.clone(),
                idx("2025-01-01T00:00:01Z", Some("p")),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("feed entry missing"));

        let state = store.state.read().unwrap();
        let key = ("did:alice".to_string(), cid);
        assert_eq!(
            state.messages.get(&key).map(|row| &row.message),
            Some(&original)
        );
        assert_eq!(
            state.messages.get(&key).map(|row| &row.indexes),
            Some(&original_indexes)
        );
        drop(state);
        assert_eq!(publisher.recorded(), vec![("did:alice".to_string(), 1)]);
    }

    #[tokio::test]
    async fn delete_removes_feed_state_and_reverses_fingerprints_without_reusing_head() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let first = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let second = feed_msg("record-2", "2025-01-01T00:00:01Z");
        let first_cid = stored_cid(&first);
        let second_cid = stored_cid(&second);
        let indexes = idx("2025-01-01T00:00:00Z", Some("p"));

        store
            .put("did:alice", first, indexes.clone())
            .await
            .unwrap();
        store.put("did:alice", second, indexes).await.unwrap();
        let wakes_before_delete = publisher.recorded();

        store.delete("did:alice", &first_cid).await.unwrap();

        let state = store.state.read().unwrap();
        let first_key = ("did:alice".to_string(), first_cid);
        assert!(!state.messages.contains_key(&first_key));
        assert!(!state.positions_by_cid.contains_key(&first_key));
        assert!(!state.entries.contains_key(&("did:alice".to_string(), 1)));
        assert_eq!(state.heads.get("did:alice"), Some(&2));
        assert_eq!(
            state
                .entries
                .get(&("did:alice".to_string(), 2))
                .map(|entry| entry.message_cid.as_str()),
            Some(second_cid.as_str())
        );
        let second_contribution = cid_contribution(&second_cid);
        assert_eq!(
            state
                .fingerprints
                .get(&("did:alice".to_string(), "".to_string())),
            Some(&second_contribution)
        );
        assert_eq!(
            state
                .fingerprints
                .get(&("did:alice".to_string(), "protocol:p".to_string())),
            Some(&second_contribution)
        );
        drop(state);
        assert_eq!(publisher.recorded(), wakes_before_delete);
    }

    #[tokio::test]
    async fn deleting_non_feed_or_unknown_message_does_not_change_feed_or_wake() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let feed = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let non_feed = msg("2025-01-01T00:00:01Z");
        let non_feed_cid = stored_cid(&non_feed);

        store
            .put("did:alice", feed, idx("2025-01-01T00:00:00Z", None))
            .await
            .unwrap();
        store
            .put("did:alice", non_feed, idx("2025-01-01T00:00:01Z", None))
            .await
            .unwrap();
        let feed_state_before = {
            let state = store.state.read().unwrap();
            (
                state.heads.clone(),
                state.entries.clone(),
                state.positions_by_cid.clone(),
                state.fingerprints.clone(),
            )
        };
        let wakes_before = publisher.recorded();

        store.delete("did:alice", &non_feed_cid).await.unwrap();
        store.delete("did:alice", "unknown-cid").await.unwrap();

        let state = store.state.read().unwrap();
        assert!(!state
            .messages
            .contains_key(&("did:alice".to_string(), non_feed_cid)));
        assert_eq!(state.heads, feed_state_before.0);
        assert_eq!(state.entries, feed_state_before.1);
        assert_eq!(state.positions_by_cid, feed_state_before.2);
        assert_eq!(state.fingerprints, feed_state_before.3);
        drop(state);
        assert_eq!(publisher.recorded(), wakes_before);
    }

    #[tokio::test]
    async fn delete_missing_feed_entry_fails_without_mutating_state() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let message = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let cid = stored_cid(&message);
        let indexes = idx("2025-01-01T00:00:00Z", Some("p"));

        store
            .put("did:alice", message.clone(), indexes.clone())
            .await
            .unwrap();
        store
            .state
            .write()
            .unwrap()
            .entries
            .remove(&("did:alice".to_string(), 1));
        let fingerprints_before = store.state.read().unwrap().fingerprints.clone();
        let wakes_before = publisher.recorded();

        let error = store.delete("did:alice", &cid).await.unwrap_err();
        assert!(error.to_string().contains("feed entry missing"));

        let state = store.state.read().unwrap();
        let key = ("did:alice".to_string(), cid);
        assert_eq!(
            state.messages.get(&key).map(|row| &row.message),
            Some(&message)
        );
        assert_eq!(
            state.messages.get(&key).map(|row| &row.indexes),
            Some(&indexes)
        );
        assert_eq!(state.positions_by_cid.get(&key), Some(&1));
        assert_eq!(state.heads.get("did:alice"), Some(&1));
        assert_eq!(state.fingerprints, fingerprints_before);
        drop(state);
        assert_eq!(publisher.recorded(), wakes_before);
    }

    #[tokio::test]
    async fn delete_feed_cid_mismatch_fails_without_mutating_state() {
        let publisher = RecordingWakePublisher::default();
        let store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        let message = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let cid = stored_cid(&message);
        let indexes = idx("2025-01-01T00:00:00Z", Some("p"));

        store
            .put("did:alice", message.clone(), indexes.clone())
            .await
            .unwrap();
        store
            .state
            .write()
            .unwrap()
            .entries
            .get_mut(&("did:alice".to_string(), 1))
            .unwrap()
            .message_cid = "wrong-cid".to_string();
        let fingerprints_before = store.state.read().unwrap().fingerprints.clone();
        let wakes_before = publisher.recorded();

        let error = store.delete("did:alice", &cid).await.unwrap_err();
        assert!(error.to_string().contains("message CID mismatch"));

        let state = store.state.read().unwrap();
        let key = ("did:alice".to_string(), cid);
        assert_eq!(
            state.messages.get(&key).map(|row| &row.message),
            Some(&message)
        );
        assert_eq!(
            state.messages.get(&key).map(|row| &row.indexes),
            Some(&indexes)
        );
        assert_eq!(state.positions_by_cid.get(&key), Some(&1));
        assert!(state.entries.contains_key(&("did:alice".to_string(), 1)));
        assert_eq!(state.heads.get("did:alice"), Some(&1));
        assert_eq!(state.fingerprints, fingerprints_before);
        drop(state);
        assert_eq!(publisher.recorded(), wakes_before);
    }

    #[tokio::test]
    async fn clear_rotates_epoch_and_removes_all_message_and_feed_state_without_waking() {
        let publisher = RecordingWakePublisher::default();
        let mut store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
        store.open().await.unwrap();
        let feed = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let feed_cid = stored_cid(&feed);
        let non_feed = msg("2025-01-01T00:00:01Z");

        store
            .put(
                "did:alice",
                feed.clone(),
                idx("2025-01-01T00:00:00Z", Some("p")),
            )
            .await
            .unwrap();
        store
            .put("did:alice", non_feed, idx("2025-01-01T00:00:01Z", None))
            .await
            .unwrap();
        let epoch_before = store.state.read().unwrap().epoch.clone();
        let wakes_before = publisher.recorded();

        store.clear().await.unwrap();

        {
            let state = store.state.read().unwrap();
            assert!(!state.epoch.is_empty());
            assert_ne!(state.epoch, epoch_before);
            assert!(state.messages.is_empty());
            assert!(state.heads.is_empty());
            assert!(state.entries.is_empty());
            assert!(state.positions_by_cid.is_empty());
            assert!(state.fingerprints.is_empty());
        }
        assert_eq!(publisher.recorded(), wakes_before);

        store
            .put("did:alice", feed, idx("2025-01-01T00:00:02Z", Some("p")))
            .await
            .unwrap();
        let state = store.state.read().unwrap();
        assert_eq!(state.heads.get("did:alice"), Some(&1));
        assert_eq!(
            state
                .positions_by_cid
                .get(&("did:alice".to_string(), feed_cid)),
            Some(&1)
        );
        drop(state);
        assert_eq!(
            publisher.recorded(),
            vec![("did:alice".to_string(), 1), ("did:alice".to_string(), 1)]
        );
    }

    #[tokio::test]
    async fn replication_feed_empty_bounds_and_cursor_validation() {
        let mut store = MemoryMessageStore::default();
        store.open().await.unwrap();
        let epoch = ReplicationFeedReader::epoch(&store).await.unwrap();

        assert!(store.log_bounds("did:alice").await.unwrap().is_none());

        let empty = store
            .log_read("did:alice", EventLogReadOptions::default())
            .await
            .unwrap();
        assert!(empty.events.is_empty());
        assert!(empty.drained);
        assert_eq!(
            empty.cursor,
            Some(build_token("did:alice", &epoch, 0, None))
        );

        let error = store
            .log_read(
                "did:alice",
                EventLogReadOptions {
                    cursor: Some(build_token("did:alice", &epoch, 1, None)),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        let EventLogError::ProgressGap(gap) = error else {
            panic!("expected progress gap");
        };
        assert_eq!(gap.reason, ProgressGapReason::TokenTooNew);
    }

    #[tokio::test]
    async fn replication_feed_limit_counts_matches_and_drains_to_high_water() {
        let mut store = MemoryMessageStore::default();
        store.open().await.unwrap();
        for (record, timestamp, protocol) in [
            ("record-1", "2025-01-01T00:00:00Z", "other"),
            ("record-2", "2025-01-01T00:00:01Z", "wanted"),
            ("record-3", "2025-01-01T00:00:02Z", "other"),
        ] {
            store
                .put(
                    "did:alice",
                    feed_msg(record, timestamp),
                    idx(timestamp, Some(protocol)),
                )
                .await
                .unwrap();
        }

        let limited = store
            .log_read(
                "did:alice",
                EventLogReadOptions {
                    limit: Some(1),
                    filters: Some(protocol_filter("wanted")),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(limited.events.len(), 1);
        assert_eq!(limited.events[0].seq, "2");
        assert!(!limited.drained);
        let limited_cursor = limited.cursor.unwrap();
        assert_eq!(limited_cursor.position, "2");
        assert_eq!(
            limited_cursor.message_cid.as_deref(),
            limited.events[0].message_cid.as_deref()
        );

        let drained = store
            .log_read(
                "did:alice",
                EventLogReadOptions {
                    filters: Some(protocol_filter("wanted")),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(drained.events.len(), 1);
        assert!(drained.drained);
        assert_eq!(drained.cursor.as_ref().unwrap().position, "3");
        assert_eq!(drained.cursor.unwrap().message_cid, None);
    }

    #[tokio::test]
    async fn replication_feed_limit_zero_validates_without_advancing_and_at_head_is_drained() {
        let mut store = MemoryMessageStore::default();
        store.open().await.unwrap();
        store
            .put(
                "did:alice",
                feed_msg("record-1", "2025-01-01T00:00:00Z"),
                idx("2025-01-01T00:00:00Z", None),
            )
            .await
            .unwrap();
        let epoch = ReplicationFeedReader::epoch(&store).await.unwrap();
        let anchor = build_token("did:alice", &epoch, 0, None);

        let zero_limit = store
            .log_read(
                "did:alice",
                EventLogReadOptions {
                    cursor: Some(anchor.clone()),
                    limit: Some(0),
                    filters: None,
                },
            )
            .await
            .unwrap();
        assert!(zero_limit.events.is_empty());
        assert_eq!(zero_limit.cursor, Some(anchor));
        assert!(!zero_limit.drained);

        let invalid = store
            .log_read(
                "did:alice",
                EventLogReadOptions {
                    cursor: Some(build_token("did:alice", &epoch, 2, None)),
                    limit: Some(0),
                    filters: None,
                },
            )
            .await
            .unwrap_err();
        let EventLogError::ProgressGap(gap) = invalid else {
            panic!("expected progress gap");
        };
        assert_eq!(gap.reason, ProgressGapReason::TokenTooNew);

        let head_cursor = store
            .log_read("did:alice", EventLogReadOptions::default())
            .await
            .unwrap()
            .cursor
            .unwrap();
        assert_eq!(head_cursor.position, "1");
        assert!(head_cursor.message_cid.is_some());
        let at_head = store
            .log_read(
                "did:alice",
                EventLogReadOptions {
                    cursor: Some(head_cursor),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(at_head.events.is_empty());
        assert!(at_head.drained);
        assert_eq!(at_head.cursor.as_ref().unwrap().position, "1");
        assert_eq!(at_head.cursor.unwrap().message_cid, None);
    }

    #[tokio::test]
    async fn replication_feed_skips_deleted_positions_and_preserves_deleted_head() {
        let mut store = MemoryMessageStore::default();
        store.open().await.unwrap();
        let messages = [
            feed_msg("record-1", "2025-01-01T00:00:00Z"),
            feed_msg("record-2", "2025-01-01T00:00:01Z"),
            feed_msg("record-3", "2025-01-01T00:00:02Z"),
        ];
        let cids = messages.iter().map(stored_cid).collect::<Vec<_>>();
        for (position, message) in messages.into_iter().enumerate() {
            store
                .put(
                    "did:alice",
                    message,
                    idx(&format!("2025-01-01T00:00:0{position}Z"), None),
                )
                .await
                .unwrap();
        }

        store.delete("did:alice", &cids[1]).await.unwrap();
        let through_hole = store
            .log_read("did:alice", EventLogReadOptions::default())
            .await
            .unwrap();
        assert_eq!(
            through_hole
                .events
                .iter()
                .map(|event| event.seq.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "3"]
        );
        assert!(through_hole.drained);

        store.delete("did:alice", &cids[2]).await.unwrap();
        let (_, latest) = store.log_bounds("did:alice").await.unwrap().unwrap();
        assert_eq!(latest.position, "3");
        assert_eq!(latest.message_cid, None);

        let epoch = ReplicationFeedReader::epoch(&store).await.unwrap();
        let after_position_one = store
            .log_read(
                "did:alice",
                EventLogReadOptions {
                    cursor: Some(build_token("did:alice", &epoch, 1, Some(&cids[0]))),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(after_position_one.events.is_empty());
        assert!(after_position_one.drained);
        assert_eq!(after_position_one.cursor.as_ref().unwrap().position, "3");
        assert_eq!(after_position_one.cursor.unwrap().message_cid, None);
    }

    #[tokio::test]
    async fn replication_feed_detaches_inline_data_without_mutating_storage() {
        let mut store = MemoryMessageStore::default();
        store.open().await.unwrap();
        let message = feed_write_msg(Some("dGVzdA=="));
        let cid = stored_cid(&message);
        store
            .put(
                "did:alice",
                message.clone(),
                idx("2025-01-01T00:00:00Z", None),
            )
            .await
            .unwrap();

        let read = store
            .log_read("did:alice", EventLogReadOptions::default())
            .await
            .unwrap();
        assert_eq!(read.events[0].encoded_data.as_deref(), Some("dGVzdA=="));
        assert!(matches!(
            &read.events[0].event.message.fields,
            Fields::Write(WriteFields {
                encoded_data: None,
                ..
            })
        ));
        assert_eq!(store.get("did:alice", &cid).await.unwrap(), Some(message));
    }

    #[tokio::test]
    async fn replication_feed_rejects_corrupt_message_rows() {
        let mut missing_store = MemoryMessageStore::default();
        missing_store.open().await.unwrap();
        let message = feed_msg("record-1", "2025-01-01T00:00:00Z");
        let cid = stored_cid(&message);
        missing_store
            .put("did:alice", message, idx("2025-01-01T00:00:00Z", None))
            .await
            .unwrap();
        missing_store
            .state
            .write()
            .unwrap()
            .messages
            .remove(&("did:alice".to_string(), cid));
        let missing_error = missing_store
            .log_read("did:alice", EventLogReadOptions::default())
            .await
            .unwrap_err();
        assert!(missing_error
            .to_string()
            .contains("without corresponding message"));

        let mut mismatch_store = MemoryMessageStore::default();
        mismatch_store.open().await.unwrap();
        let message = feed_msg("record-2", "2025-01-01T00:00:01Z");
        let cid = stored_cid(&message);
        mismatch_store
            .put("did:alice", message, idx("2025-01-01T00:00:01Z", None))
            .await
            .unwrap();
        mismatch_store
            .state
            .write()
            .unwrap()
            .messages
            .get_mut(&("did:alice".to_string(), cid))
            .unwrap()
            .cid = "wrong-cid".to_string();
        let mismatch_error = mismatch_store
            .log_read("did:alice", EventLogReadOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(
            mismatch_error,
            EventLogError::StoreError(StoreError::ReplicationError(
                MessageReplicationError::CidsMismatch { ref actual, .. }
            )) if actual == "wrong-cid"
        ));
    }

    #[tokio::test]
    async fn replication_feed_normalizes_fingerprint_scopes() {
        let mut store = MemoryMessageStore::default();
        store.open().await.unwrap();
        store
            .put(
                "did:alice",
                feed_msg("record-1", "2025-01-01T00:00:00Z"),
                idx("2025-01-01T00:00:00Z", Some("a")),
            )
            .await
            .unwrap();

        let ordered = store
            .fingerprint("did:alice", &["".to_string(), "protocol:a".to_string()])
            .await
            .unwrap();
        let reordered = store
            .fingerprint("did:alice", &["protocol:a".to_string(), "".to_string()])
            .await
            .unwrap();
        let duplicated = store
            .fingerprint(
                "did:alice",
                &[
                    "".to_string(),
                    "protocol:a".to_string(),
                    "protocol:a".to_string(),
                ],
            )
            .await
            .unwrap();
        assert_eq!(ordered, reordered);
        assert_eq!(ordered, duplicated);
        assert_ne!(
            ordered,
            store
                .fingerprint("did:alice", &["".to_string()])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn replication_feed_epoch_is_shared_and_clear_invalidates_cursors() {
        let mut store = MemoryMessageStore::default();
        store.open().await.unwrap();
        let clone = store.clone();
        let epoch = ReplicationFeedReader::epoch(&store).await.unwrap();
        assert_eq!(ReplicationFeedReader::epoch(&clone).await.unwrap(), epoch);

        store
            .put(
                "did:alice",
                feed_msg("record-1", "2025-01-01T00:00:00Z"),
                idx("2025-01-01T00:00:00Z", None),
            )
            .await
            .unwrap();
        let cursor = store
            .log_read("did:alice", EventLogReadOptions::default())
            .await
            .unwrap()
            .cursor
            .unwrap();

        store.clear().await.unwrap();
        let new_epoch = ReplicationFeedReader::epoch(&store).await.unwrap();
        assert_ne!(new_epoch, epoch);
        assert_eq!(
            ReplicationFeedReader::epoch(&clone).await.unwrap(),
            new_epoch
        );
        let error = clone
            .log_read(
                "did:alice",
                EventLogReadOptions {
                    cursor: Some(cursor),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        let EventLogError::ProgressGap(gap) = error else {
            panic!("expected progress gap");
        };
        assert_eq!(gap.reason, ProgressGapReason::EpochMismatch);
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
