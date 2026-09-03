#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod concurrent_conformance;
pub mod durable_event_log;
pub mod memory;
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod replication_feed_conformance;
pub mod replication_feed_reader;
pub mod state_index;
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod store_conformance;
pub mod wake;
pub mod write_resolver;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::{fmt::Debug, future::Future, pin::Pin};

use bytes::Bytes;
use futures_util::Stream;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::descriptors::MessageDescriptor;
use crate::events::MessageEvent;
use crate::{
    errors::{
        DataStoreError, EventLogError, MessageStoreError, ResumableTaskStoreError, StoreError,
    },
    filters::filter_key::Filters,
    Cursor,
};
use crate::{Descriptor, MapValue, Message, MessageSort, Pagination, ProgressToken};
pub use replication_feed_reader::ReplicationFeedReader;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ManagedResumableTask<T: Serialize + Sync + Send + Debug> {
    pub id: String,
    pub task: T,
    pub timeout: u64,
    #[serde(rename = "retryCount")]
    pub retry_count: u64,
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

/// A message and its complete replacement query projection inside an atomic
/// latest-state transition.
#[derive(Debug, Clone, PartialEq)]
pub struct LatestStateMutation {
    pub message: Message<Descriptor>,
    pub indexes: KeyValues,
}

/// One indivisible retained-state transition decided by DWN admission.
///
/// The store does not decide which messages win. It atomically persists the
/// supplied new winner, retained-message reindexing, displaced-message removal,
/// and the corresponding durable-feed effects.
#[derive(Debug, Clone, PartialEq)]
pub struct LatestStateTransition {
    pub put: LatestStateMutation,
    pub retains: Vec<LatestStateMutation>,
    pub deletes: Vec<String>,
}

impl LatestStateTransition {
    /// Rejects ambiguous transitions before a backend starts its transaction.
    pub fn validate(&self) -> Result<(), MessageStoreError> {
        let put_cid = self.put.message.cid()?.to_string();
        let mut mutated = BTreeSet::from([put_cid.clone()]);

        for retained in &self.retains {
            let cid = retained.message.cid()?.to_string();
            if !mutated.insert(cid.clone()) {
                return Err(invalid_latest_state_transition(format!(
                    "message CID '{cid}' occurs more than once in put/retains"
                )));
            }
        }
        for cid in &self.deletes {
            if !mutated.insert(cid.clone()) {
                return Err(invalid_latest_state_transition(format!(
                    "message CID '{cid}' is both mutated and deleted"
                )));
            }
        }
        Ok(())
    }
}

fn invalid_latest_state_transition(detail: String) -> MessageStoreError {
    MessageStoreError::StoreError(StoreError::InternalException(format!(
        "MessageStoreLatestStateTransitionInvalid: {detail}"
    )))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestStateTransitionResult {
    pub position: Option<ProgressToken>,
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

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProgressGapReason {
    TokenTooOld,
    EpochMismatch,
    StreamMismatch,
    TokenTooNew,
    MessageMismatch,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum ProgressGapCode {
    #[serde(rename = "ProgressGap")]
    ProgressGap,
}

impl ProgressGapCode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ProgressGap => "ProgressGap",
        }
    }
}

impl std::fmt::Display for ProgressGapCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProgressGapInfo {
    pub requested: ProgressToken,
    pub oldest_available: ProgressToken,
    pub latest_available: ProgressToken,
    pub reason: ProgressGapReason,
    pub code: ProgressGapCode,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EventLogEntry {
    /// Canonical non-negative decimal position assigned to this entry.
    pub seq: String,
    pub event: MessageEvent<Descriptor>,
    pub indexes: KeyValues,
    #[serde(rename = "messageCid", skip_serializing_if = "Option::is_none")]
    pub message_cid: Option<String>,
    /// Inline record data detached from `event.message` for transport.
    #[serde(rename = "encodedData", skip_serializing_if = "Option::is_none")]
    pub encoded_data: Option<String>,
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
    pub drained: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct EventLogSubscribeOptions {
    pub cursor: Option<ProgressToken>,
    pub filters: Option<Filters>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SubscriptionError {
    pub code: SubscriptionErrorCode,
    pub detail: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionErrorCode {
    #[serde(rename = "ProgressGap")]
    ProgressGap,
    #[serde(rename = "MessagesSubscribeDeliveryAuthorizationFailed")]
    DeliveryAuthorizationFailed,
    #[serde(rename = "MessagesSubscribeDeliveryFailed")]
    DeliveryFailed,
}

impl std::fmt::Display for SubscriptionErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ProgressGap => "ProgressGap",
            Self::DeliveryAuthorizationFailed => "MessagesSubscribeDeliveryAuthorizationFailed",
            Self::DeliveryFailed => "MessagesSubscribeDeliveryFailed",
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum SubscriptionMessage {
    #[serde(rename = "event")]
    Event {
        cursor: ProgressToken,
        event: Box<MessageEvent<Descriptor>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        seq: Option<String>,
        #[serde(rename = "messageCid", skip_serializing_if = "Option::is_none")]
        message_cid: Option<String>,
        #[serde(rename = "isLatestBaseState", skip_serializing_if = "Option::is_none")]
        is_latest_base_state: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
        #[serde(rename = "encodedData", skip_serializing_if = "Option::is_none")]
        encoded_data: Option<String>,
    },
    #[serde(rename = "eose")]
    Eose { cursor: ProgressToken },
    #[serde(rename = "error")]
    Error {
        cursor: ProgressToken,
        error: SubscriptionError,
    },
}

pub type SubscriptionListener = Box<dyn Fn(SubscriptionMessage) + Send + Sync + 'static>;
pub type EventSubscriptionClose =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), EventLogError>> + Send>> + Send + Sync>;

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
pub trait MessageStore {
    fn open(&mut self) -> impl Future<Output = Result<(), MessageStoreError>> + Send;

    fn close(&mut self) -> impl Future<Output = ()> + Send;

    fn put<D>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send
    where
        D: MessageDescriptor + Send,
        Message<Descriptor>: From<Message<D>>;

    /// Atomically commits a complete latest-state transition and its durable
    /// feed projection.
    ///
    /// Production stores must override this fail-closed default. It exists so
    /// narrow read-only test doubles do not accidentally claim atomic support.
    fn commit_latest_state(
        &self,
        _tenant: &str,
        _transition: LatestStateTransition,
    ) -> impl Future<Output = Result<LatestStateTransitionResult, MessageStoreError>> + Send {
        async {
            Err(MessageStoreError::StoreError(
                StoreError::InternalException(
                    "MessageStoreAtomicLatestStateUnsupported: store does not implement atomic latest-state transitions"
                        .to_string(),
                ),
            ))
        }
    }

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
pub trait DataStore {
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
pub trait StateIndex {
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
pub trait EventLog {
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
pub trait ResumableTaskStore {
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
    async fn open(&mut self) -> Result<(), EventLogError> {
        Ok(())
    }

    async fn close(&mut self) -> () {
        // no-op
    }

    async fn emit(
        &self,
        _tenant: &str,
        _event: MessageEvent<Descriptor>,
        _indexes: KeyValues,
        _message_cid: &str,
    ) -> Result<Option<ProgressToken>, EventLogError> {
        Ok(None)
    }

    async fn read(
        &self,
        _tenant: &str,
        _options: Option<EventLogReadOptions>,
    ) -> Result<EventLogReadResult, EventLogError> {
        Ok(EventLogReadResult {
            drained: true,
            ..Default::default()
        })
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
                close: Arc::new(|| Box::pin(async { Ok(()) })),
            })
        }
    }

    async fn get_replay_bounds(
        &self,
        _tenant: &str,
    ) -> Result<Option<EventLogReplayBounds>, EventLogError> {
        Ok(None)
    }

    async fn trim(
        &self,
        _tenant: &str,
        _older_than: EventLogTrimBound,
    ) -> Result<(), EventLogError> {
        Ok(())
    }
}

#[cfg(test)]
mod enbox_store_contract_tests {
    use super::*;
    use crate::descriptors::Records;
    use crate::Fields;
    use serde_json::json;

    fn records_write_message() -> Message<Descriptor> {
        Message {
            descriptor: Descriptor::Records(Box::new(Records::Write(Default::default()))),
            fields: Fields::default(),
        }
    }

    fn subscription_event(metadata: bool) -> SubscriptionMessage {
        SubscriptionMessage::Event {
            cursor: ProgressToken {
                stream_id: "local-dwn".to_string(),
                epoch: "epoch-1".to_string(),
                position: "7".to_string(),
                message_cid: Some("cid-7".to_string()),
            },
            event: Box::new(MessageEvent {
                message: records_write_message(),
                initial_write: None,
            }),
            seq: (metadata).then(|| "7".to_string()),
            message_cid: (metadata).then(|| "cid-7".to_string()),
            is_latest_base_state: (metadata).then_some(true),
            protocol: (metadata).then(|| "https://example.com/chat".to_string()),
            encoded_data: (metadata).then(|| "aGk=".to_string()),
        }
    }

    #[test]
    fn subscription_event_serializes_metadata_with_upstream_names() {
        let value = serde_json::to_value(subscription_event(true)).unwrap();

        assert_eq!(value["type"], "event");
        assert_eq!(value["seq"], "7");
        assert_eq!(value["messageCid"], "cid-7");
        assert_eq!(value["isLatestBaseState"], true);
        assert_eq!(value["protocol"], "https://example.com/chat");
        assert_eq!(value["encodedData"], "aGk=");
    }

    #[test]
    fn subscription_event_serializes_false_is_latest_base_state() {
        let message = SubscriptionMessage::Event {
            cursor: ProgressToken {
                stream_id: "local-dwn".to_string(),
                epoch: "epoch-1".to_string(),
                position: "7".to_string(),
                message_cid: Some("cid-7".to_string()),
            },
            event: Box::new(MessageEvent {
                message: records_write_message(),
                initial_write: None,
            }),
            seq: Some("7".to_string()),
            message_cid: Some("cid-7".to_string()),
            is_latest_base_state: Some(false),
            protocol: Some("https://example.com/chat".to_string()),
            encoded_data: Some("aGk=".to_string()),
        };

        let value = serde_json::to_value(message).unwrap();
        assert_eq!(value["isLatestBaseState"], false);
    }

    #[test]
    fn subscription_event_omits_absent_metadata() {
        let value = serde_json::to_value(subscription_event(false)).unwrap();

        for key in [
            "seq",
            "messageCid",
            "isLatestBaseState",
            "protocol",
            "encodedData",
        ] {
            assert!(value.get(key).is_none(), "{key} must be omitted");
        }
    }

    #[test]
    fn subscription_event_decodes_without_metadata_for_backcompat() {
        let json = serde_json::to_value(subscription_event(false)).unwrap();
        let decoded = serde_json::from_value::<SubscriptionMessage>(json).unwrap();

        match decoded {
            SubscriptionMessage::Event {
                seq,
                message_cid,
                is_latest_base_state,
                protocol,
                encoded_data,
                ..
            } => {
                assert_eq!(
                    (
                        seq,
                        message_cid,
                        is_latest_base_state,
                        protocol,
                        encoded_data
                    ),
                    (None, None, None, None, None)
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn progress_token_serializes_like_typescript() {
        let token = ProgressToken {
            stream_id: "local-dwn".to_string(),
            epoch: "epoch-1".to_string(),
            position: "10".to_string(),
            message_cid: Some(
                "bafyreigdyrzt5sfp7udm7hu76uh7y26mohmfvhyp6wmu2yxu3ktc4qtr3i".to_string(),
            ),
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
    fn progress_token_omits_missing_message_cid() {
        let token = ProgressToken {
            stream_id: "local-dwn".to_string(),
            epoch: "epoch-1".to_string(),
            position: "10".to_string(),
            message_cid: None,
        };

        assert_eq!(
            serde_json::to_value(token).unwrap(),
            json!({
                "streamId": "local-dwn",
                "epoch": "epoch-1",
                "position": "10",
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
