use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
    errors::EventLogError, replies::HasProgressGapInfo, stores::ProgressGapInfo, Cursor,
    Descriptor, Message, Reply,
};

pub type Delete = ();

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct Write {
    error: Option<ProgressGapInfo>,
}

impl From<Write> for Reply {
    fn from(val: Write) -> Self {
        Reply::RecordsWrite(Box::new(val))
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct ReadEntry {
    #[serde(rename = "recordsWrite")]
    pub records_write: Option<Message<Descriptor>>,
    #[serde(rename = "recordsDelete")]
    pub records_delete: Option<Message<Descriptor>>,
    #[serde(rename = "initialWrite")]
    pub initial_write: Option<Message<Descriptor>>,
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
        Reply::RecordsRead(Box::new(val))
    }
}

#[skip_serializing_none]
#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Clone)]
pub struct Count {
    pub count: Option<u64>,
}

impl From<Count> for Reply {
    fn from(val: Count) -> Self {
        Reply::RecordsCount(Box::new(val))
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EventLogReplyError {
    pub error: Option<ProgressGapInfo>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct QueryEntry {
    #[serde(rename = "initialWrite")]
    pub initial_write: Option<Message<Descriptor>>,
    #[serde(rename = "encodedData")]
    pub encoded_data: Option<String>,
    #[serde(flatten)]
    pub message: Message<Descriptor>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct Query {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<QueryEntry>>,
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProgressGapInfo>,
}

impl From<Query> for Reply {
    fn from(val: Query) -> Self {
        Reply::RecordsQuery(Box::new(val))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct Subscribe {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<QueryEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProgressGapInfo>,
}

impl From<Subscribe> for Reply {
    fn from(val: Subscribe) -> Self {
        Reply::RecordsSubscribe(Box::new(val))
    }
}

impl HasProgressGapInfo for Query {
    fn with_progress_gap_info(error: ProgressGapInfo) -> Self {
        Self {
            error: Some(error),
            ..Default::default()
        }
    }
}

impl HasProgressGapInfo for Subscribe {
    fn with_progress_gap_info(error: ProgressGapInfo) -> Self {
        Self {
            error: Some(error),
            ..Default::default()
        }
    }
}

pub trait HasEventLogError: Default {
    fn with_event_log_error(error: EventLogError) -> Self;
}

impl HasProgressGapInfo for Write {
    fn with_progress_gap_info(error: ProgressGapInfo) -> Self {
        Self { error: Some(error) }
    }
}

#[cfg(test)]
mod tests {
    use crate::stores::{ProgressGapCode, ProgressGapReason, ProgressToken};

    use super::*;

    #[test]
    fn progress_gap_error_keeps_its_wire_code() {
        let token = ProgressToken {
            stream_id: "stream".to_string(),
            epoch: "epoch".to_string(),
            position: "1".to_string(),
            message_cid: "cid".to_string(),
        };
        let reply = Query::with_progress_gap_info(ProgressGapInfo {
            requested: token.clone(),
            oldest_available: token.clone(),
            latest_available: token,
            reason: ProgressGapReason::TokenTooOld,
            code: ProgressGapCode::ProgressGap,
        });

        assert_eq!(
            serde_json::to_value(reply).unwrap()["error"]["code"],
            "ProgressGap"
        );
    }
}
