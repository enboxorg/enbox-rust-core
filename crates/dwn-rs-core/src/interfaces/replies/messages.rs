use cid::Cid;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
    replies::HasProgressGapInfo, stores::ProgressGapInfo, Descriptor, Message, ProgressToken, Reply,
};

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ReadEntry {
    #[serde(rename = "messageCid")]
    pub cid: String,
    pub message: Option<Message<Descriptor>>,
    #[serde(rename = "encodedData")]
    pub encoded_data: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct Read {
    pub entry: Option<ReadEntry>,
}

impl From<Read> for Reply {
    fn from(val: Read) -> Self {
        Reply::MessageRead(Box::new(val))
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct QueryEntry {
    pub seq: String,
    #[serde(rename = "messageCid")]
    pub cid: Cid,
    pub is_latest_base_state: bool,
    pub protocol: Option<String>,
    pub message: Option<Message<Descriptor>>,
    pub encoded_data: Option<String>,
    pub initial_write: Option<Message<Descriptor>>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct Query {
    pub entries: Option<Vec<QueryEntry>>,
    pub cursor: Option<ProgressToken>,
    pub drained: Option<bool>,
    pub fingerprint: Option<String>,
    pub error: Option<ProgressGapInfo>,
    #[serde(rename = "roleRecordId")]
    pub role_record_id: Option<String>,
}

impl From<Query> for Reply {
    fn from(val: Query) -> Self {
        Reply::MessageQuery(Box::new(val))
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Sync {
    pub root: Option<String>,
    pub hash: Option<String>,
    pub entries: Option<Vec<String>>,
    pub only_remote: Option<Vec<DiffEntries>>,
    pub only_local: Option<Vec<String>>,
}

impl From<Sync> for Reply {
    fn from(val: Sync) -> Self {
        crate::Reply::MessageSync(Box::new(val))
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DiffEntries {
    pub message_cid: Option<String>,
    pub message: Option<Message<Descriptor>>,
    pub encoded_data: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub subscription_id: Option<String>,
    pub error: Option<ProgressGapInfo>,
}

impl From<Subscription> for Reply {
    fn from(val: Subscription) -> Self {
        Reply::MessageSubscription(Box::new(val))
    }
}

impl HasProgressGapInfo for Subscription {
    fn with_progress_gap_info(error: crate::stores::ProgressGapInfo) -> Self {
        Self {
            subscription_id: None,
            error: Some(error),
        }
    }
}
