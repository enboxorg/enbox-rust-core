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
    error: Option<super::Error>,
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

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct Query {
    pub entries: Option<Vec<QueryEntry>>,
    pub cursor: Option<Cursor>,
    pub error: Option<super::Error>,
}

impl From<Query> for Reply {
    fn from(val: Query) -> Self {
        Reply::RecordsQuery(Box::new(val))
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct Subscribe {
    pub entries: Option<Vec<QueryEntry>>,
    pub subscription_id: Option<String>,
    pub cursor: Option<Cursor>,
    pub error: Option<super::Error>,
}

impl From<Subscribe> for Reply {
    fn from(val: Subscribe) -> Self {
        Reply::RecordsSubscribe(Box::new(val))
    }
}

impl HasProgressGapInfo for Query {
    fn with_progress_gap_info(error: ProgressGapInfo) -> Self {
        Self {
            error: Some(super::Error::ProgressGap(error)),
            ..Default::default()
        }
    }
}

impl HasProgressGapInfo for Subscribe {
    fn with_progress_gap_info(error: ProgressGapInfo) -> Self {
        Self {
            error: Some(super::Error::ProgressGap(error)),
            ..Default::default()
        }
    }
}

pub trait HasEventLogError: Default {
    fn with_event_log_error(error: EventLogError) -> Self;
}

impl HasProgressGapInfo for Write {
    fn with_progress_gap_info(error: ProgressGapInfo) -> Self {
        Self {
            error: Some(super::Error::ProgressGap(error)),
        }
    }
}
