use std::{fmt::Debug, future::Future, pin::Pin};

use bytes::Bytes;
use futures_util::Stream;
use ipld_core::cid::Cid;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ulid::Ulid;

use crate::events::MessageEvent;
use crate::{
    descriptors::MessageDescriptor,
    errors::{
        DataStoreError, EventLogError, MessageStoreError, ResumableTaskStoreError, StoreError,
    },
    filters::filter_key::Filters,
    Cursor, QueryReturn,
};
use crate::{Descriptor, MapValue, Message, MessageSort, Pagination};

/// Legacy `MessageStore` trait inherited from upstream `dwn-rs`. Only the
/// SurrealDB backend (`crates/dwn-rs-stores/src/surrealdb/*`) implements it.
/// New code should target [`MessageStore`] (formerly `EnboxMessageStore`).
pub trait LegacyMessageStore: Default {
    fn open(&mut self) -> impl Future<Output = Result<(), MessageStoreError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()>;

    fn put<D: MessageDescriptor + Serialize + Send + 'static>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: MapValue,
        tags: MapValue,
    ) -> impl Future<Output = Result<Cid, MessageStoreError>> + Send;

    fn get<D: MessageDescriptor + DeserializeOwned + Send + 'static>(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<Message<D>, MessageStoreError>> + Send
    where
        Message<D>: DeserializeOwned;

    fn query<D: MessageDescriptor + DeserializeOwned + Send + 'static>(
        &self,
        tenant: &str,
        filter: Filters,
        sort: Option<MessageSort>,
        pagination: Option<Pagination>,
    ) -> impl Future<Output = Result<QueryReturn<Message<D>>, MessageStoreError>> + Send
    where
        Message<D>: DeserializeOwned;

    fn delete(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send;

    fn clear(&self) -> impl Future<Output = Result<(), MessageStoreError>> + Send;
}

/// Legacy `DataStore` trait inherited from upstream `dwn-rs`. See
/// [`LegacyMessageStore`].
pub trait LegacyDataStore: Default {
    fn open(&mut self) -> impl Future<Output = Result<(), DataStoreError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()> + Send;

    fn put<T: Stream<Item = Bytes> + Send + Unpin>(
        &self,
        tenant: &str,
        record_id: &str,
        cid: &str,
        value: T,
    ) -> impl Future<Output = Result<PutDataResults, DataStoreError>> + Send;

    fn get(
        &self,
        tenant: &str,
        record_id: &str,
        cid: &str,
    ) -> impl Future<Output = Result<GetDataResults, DataStoreError>> + Send;

    fn delete(
        &self,
        tenant: &str,
        record_id: &str,
        cid: &str,
    ) -> impl Future<Output = Result<(), DataStoreError>> + Send;

    fn clear(&self) -> impl Future<Output = Result<(), DataStoreError>> + Send;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PutDataResults {
    #[serde(rename = "dataSize")]
    pub size: usize,
}

pub struct GetDataResults {
    pub size: usize,
    pub data: Pin<Box<dyn Stream<Item = u8>>>,
}

/// Legacy `EventLog` trait inherited from upstream `dwn-rs`. See
/// [`LegacyMessageStore`].
pub trait LegacyEventLog: Default {
    fn open(&mut self) -> impl Future<Output = Result<(), EventLogError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()>;

    fn append(
        &self,
        tenant: &str,
        cid: &str,
        indexes: MapValue,
        tags: MapValue,
    ) -> impl Future<Output = Result<(), EventLogError>>;

    fn get_events(
        &self,
        tenant: &str,
        cursor: Option<Cursor>,
    ) -> impl Future<Output = Result<QueryReturn<String>, EventLogError>> + Send;

    fn query_events(
        &self,
        tenant: &str,
        filter: Filters,
        cursor: Option<Cursor>,
    ) -> impl Future<Output = Result<QueryReturn<String>, EventLogError>> + Send;

    fn delete(
        &self,
        tenant: &str,
        cid: &[&str],
    ) -> impl Future<Output = Result<(), EventLogError>> + Send;

    fn clear(&self) -> impl Future<Output = Result<(), EventLogError>> + Send;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LegacyManagedResumableTask<T: Serialize + Sync + Send + Debug> {
    pub id: Ulid,
    pub task: T,
    pub timeout: u64,
    pub retry_count: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ManagedResumableTask<T: Serialize + Sync + Send + Debug> {
    pub id: String,
    pub task: T,
    pub timeout: u64,
    #[serde(rename = "retryCount")]
    pub retry_count: u64,
}

/// Legacy `ResumableTaskStore` trait inherited from upstream `dwn-rs`. See
/// [`LegacyMessageStore`].
pub trait LegacyResumableTaskStore: Default {
    fn open(&mut self) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()> + Send;

    fn register<T: Serialize + Send + Sync + DeserializeOwned + Debug + 'static>(
        &self,
        task: T,
        timeout: u64,
    ) -> impl Future<Output = Result<LegacyManagedResumableTask<T>, ResumableTaskStoreError>> + Send;

    fn grab<T: Serialize + Send + Sync + DeserializeOwned + Debug + Unpin>(
        &self,
        count: u64,
    ) -> impl Future<Output = Result<Vec<LegacyManagedResumableTask<T>>, ResumableTaskStoreError>> + Send;

    fn read<T: Serialize + Send + Sync + DeserializeOwned + Debug>(
        &self,
        task_id: &str,
    ) -> impl Future<Output = Result<Option<LegacyManagedResumableTask<T>>, ResumableTaskStoreError>>
           + Send;

    fn extend(
        &self,
        task_id: &str,
        timeout: u64,
    ) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send;

    fn delete(
        &self,
        task_id: &str,
    ) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send;

    fn clear(&self) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send;
}

/// Queryable index values attached to stored DWN messages and emitted events.
///
/// This mirrors the current TypeScript `KeyValues` contract. Primitive arrays are
/// represented with `Value::Array`.
pub type KeyValues = MapValue;

/// Fixed-width StateIndex hash used for SMT roots, subtree hashes, and leaves.
pub type StateHash = [u8; 32];

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct MessageQueryResult {
    pub messages: Vec<Message<Descriptor>>,
    pub cursor: Option<Cursor>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DataStorePutResult {
    #[serde(rename = "dataSize")]
    pub data_size: usize,
}

pub struct DataStoreGetResult {
    pub data_size: usize,
    pub data_stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProgressToken {
    pub stream_id: String,
    pub epoch: String,
    /// Monotonic decimal string. Compare numerically, not lexicographically.
    pub position: String,
    pub message_cid: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProgressGapReason {
    TokenTooOld,
    EpochMismatch,
    StreamMismatch,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProgressGapInfo {
    pub requested: ProgressToken,
    pub oldest_available: ProgressToken,
    pub latest_available: ProgressToken,
    pub reason: ProgressGapReason,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EventLogEntry {
    pub seq: u64,
    pub event: MessageEvent<Descriptor>,
    pub indexes: KeyValues,
    #[serde(rename = "messageCid", skip_serializing_if = "Option::is_none")]
    pub message_cid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct EventLogReadOptions {
    pub cursor: Option<ProgressToken>,
    pub limit: Option<u64>,
    pub filters: Option<Filters>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct EventLogReadResult {
    pub events: Vec<EventLogEntry>,
    pub cursor: Option<ProgressToken>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct EventLogSubscribeOptions {
    pub cursor: Option<ProgressToken>,
    pub filters: Option<Filters>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum SubscriptionMessage {
    #[serde(rename = "event")]
    Event {
        cursor: ProgressToken,
        event: Box<MessageEvent<Descriptor>>,
    },
    #[serde(rename = "eose")]
    Eose { cursor: ProgressToken },
}

pub type SubscriptionListener = Box<dyn Fn(SubscriptionMessage) + Send + Sync + 'static>;
pub type EventSubscriptionClose =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), EventLogError>> + Send>> + Send + Sync>;

pub struct EventSubscription {
    pub id: String,
    pub close: EventSubscriptionClose,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EventLogReplayBounds {
    pub oldest: ProgressToken,
    pub latest: ProgressToken,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum EventLogTrimBound {
    Sequence(u64),
    Timestamp(String),
}

/// Native message store contract matching the current TypeScript
/// `MessageStore` dependency used by `DwnConfig`.
pub trait MessageStore: Default {
    fn open(&mut self) -> impl Future<Output = Result<(), MessageStoreError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()> + Send;

    fn put(
        &self,
        tenant: &str,
        message: Message<Descriptor>,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send;

    fn get(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<Option<Message<Descriptor>>, MessageStoreError>> + Send;

    /// Applies OR semantics across filter sets and AND semantics within a set.
    fn query(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
        pagination: Option<Pagination>,
    ) -> impl Future<Output = Result<MessageQueryResult, MessageStoreError>> + Send;

    fn count(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
    ) -> impl Future<Output = Result<u64, MessageStoreError>> + Send;

    fn delete(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send;

    fn clear(&self) -> impl Future<Output = Result<(), MessageStoreError>> + Send;
}

/// Native content-addressed data store contract.
pub trait DataStore: Default {
    fn open(&mut self) -> impl Future<Output = Result<(), DataStoreError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()> + Send;

    fn put<T: Stream<Item = Bytes> + Send + Unpin>(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
        data_stream: T,
    ) -> impl Future<Output = Result<DataStorePutResult, DataStoreError>> + Send;

    fn get(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> impl Future<Output = Result<Option<DataStoreGetResult>, DataStoreError>> + Send;

    fn delete(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> impl Future<Output = Result<(), DataStoreError>> + Send;

    fn clear(&self) -> impl Future<Output = Result<(), DataStoreError>> + Send;
}

/// Native StateIndex contract for global and protocol-scoped SMT sync.
pub trait StateIndex: Default {
    fn open(&mut self) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()> + Send;

    fn clear(&self) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn insert(
        &self,
        tenant: &str,
        message_cid: &str,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn delete(
        &self,
        tenant: &str,
        message_cids: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn get_root(&self, tenant: &str) -> impl Future<Output = Result<StateHash, StoreError>> + Send;

    fn get_protocol_root(
        &self,
        tenant: &str,
        protocol: &str,
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send;

    fn get_subtree_hash(
        &self,
        tenant: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send;

    fn get_protocol_subtree_hash(
        &self,
        tenant: &str,
        protocol: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send;

    fn get_leaves(
        &self,
        tenant: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send;

    fn get_protocol_leaves(
        &self,
        tenant: &str,
        protocol: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send;
}

/// Native persistent event log contract with progress tokens and replay.
pub trait EventLog: Default {
    fn open(&mut self) -> impl Future<Output = Result<(), EventLogError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()> + Send;

    fn emit(
        &self,
        tenant: &str,
        event: MessageEvent<Descriptor>,
        indexes: KeyValues,
        message_cid: &str,
    ) -> impl Future<Output = Result<Option<ProgressToken>, EventLogError>> + Send;

    fn read(
        &self,
        tenant: &str,
        options: Option<EventLogReadOptions>,
    ) -> impl Future<Output = Result<EventLogReadResult, EventLogError>> + Send;

    fn subscribe(
        &self,
        tenant: &str,
        id: &str,
        listener: SubscriptionListener,
        options: Option<EventLogSubscribeOptions>,
    ) -> impl Future<Output = Result<EventSubscription, EventLogError>> + Send;

    fn get_replay_bounds(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Option<EventLogReplayBounds>, EventLogError>> + Send;

    fn trim(
        &self,
        tenant: &str,
        older_than: EventLogTrimBound,
    ) -> impl Future<Output = Result<(), EventLogError>> + Send;
}

/// Native resumable task store contract.
pub trait ResumableTaskStore: Default {
    fn open(&mut self) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()> + Send;

    fn register<T: Serialize + Send + Sync + DeserializeOwned + Debug + 'static>(
        &self,
        task: T,
        timeout_in_seconds: u64,
    ) -> impl Future<Output = Result<ManagedResumableTask<T>, ResumableTaskStoreError>> + Send;

    fn grab<T: Serialize + Send + Sync + DeserializeOwned + Debug + Unpin>(
        &self,
        count: u64,
    ) -> impl Future<Output = Result<Vec<ManagedResumableTask<T>>, ResumableTaskStoreError>> + Send;

    fn read<T: Serialize + Send + Sync + DeserializeOwned + Debug>(
        &self,
        task_id: &str,
    ) -> impl Future<Output = Result<Option<ManagedResumableTask<T>>, ResumableTaskStoreError>> + Send;

    fn extend(
        &self,
        task_id: &str,
        timeout_in_seconds: u64,
    ) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send;

    fn delete(
        &self,
        task_id: &str,
    ) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send;

    fn clear(&self) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send;
}

/// Placeholder [`EventLog`] for handlers that do not emit events.
impl EventLog for () {
    fn open(&mut self) -> impl Future<Output = Result<(), EventLogError>> + Send {
        async { Ok(()) }
    }

    fn close(&mut self) -> impl Future<Output = ()> + Send {
        async {}
    }

    fn emit(
        &self,
        _tenant: &str,
        _event: MessageEvent<Descriptor>,
        _indexes: KeyValues,
        _message_cid: &str,
    ) -> impl Future<Output = Result<Option<ProgressToken>, EventLogError>> + Send {
        async { Ok(None) }
    }

    fn read(
        &self,
        _tenant: &str,
        _options: Option<EventLogReadOptions>,
    ) -> impl Future<Output = Result<EventLogReadResult, EventLogError>> + Send {
        async { Ok(EventLogReadResult::default()) }
    }

    fn subscribe(
        &self,
        _tenant: &str,
        id: &str,
        _listener: SubscriptionListener,
        _options: Option<EventLogSubscribeOptions>,
    ) -> impl Future<Output = Result<EventSubscription, EventLogError>> + Send {
        let id = id.to_string();
        async move {
            Ok(EventSubscription {
                id,
                close: Box::new(|| Box::pin(async { Ok(()) })),
            })
        }
    }

    fn get_replay_bounds(
        &self,
        _tenant: &str,
    ) -> impl Future<Output = Result<Option<EventLogReplayBounds>, EventLogError>> + Send {
        async { Ok(None) }
    }

    fn trim(
        &self,
        _tenant: &str,
        _older_than: EventLogTrimBound,
    ) -> impl Future<Output = Result<(), EventLogError>> + Send {
        async { Ok(()) }
    }
}

#[cfg(test)]
mod enbox_store_contract_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn progress_token_serializes_like_typescript() {
        let token = ProgressToken {
            stream_id: "local-dwn".to_string(),
            epoch: "epoch-1".to_string(),
            position: "10".to_string(),
            message_cid: "bafyreigdyrzt5sfp7udm7hu76uh7y26mohmfvhyp6wmu2yxu3ktc4qtr3i".to_string(),
        };

        assert_eq!(
            serde_json::to_value(token).unwrap(),
            json!({
                "streamId": "local-dwn",
                "epoch": "epoch-1",
                "position": "10",
                "messageCid": "bafyreigdyrzt5sfp7udm7hu76uh7y26mohmfvhyp6wmu2yxu3ktc4qtr3i",
            })
        );
    }

    #[test]
    fn progress_gap_reason_serializes_like_typescript() {
        assert_eq!(
            serde_json::to_value(ProgressGapReason::TokenTooOld).unwrap(),
            json!("token_too_old")
        );
        assert_eq!(
            serde_json::to_value(ProgressGapReason::EpochMismatch).unwrap(),
            json!("epoch_mismatch")
        );
        assert_eq!(
            serde_json::to_value(ProgressGapReason::StreamMismatch).unwrap(),
            json!("stream_mismatch")
        );
    }
}
