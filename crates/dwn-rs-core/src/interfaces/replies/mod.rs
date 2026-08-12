pub mod messages;
pub mod protocols;
pub mod records;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{stores::ProgressGapInfo, SubscriptionID};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Status {
    pub code: i32,
    pub detail: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(bound(serialize = "R: Serialize", deserialize = "R: DeserializeOwned"))]
pub struct Response<R> {
    pub status: Status,
    #[serde(flatten)]
    pub reply: R,
}

impl<R> Response<R> {
    pub fn new(status: Status, reply: R) -> Self {
        Self { status, reply }
    }

    pub fn ok() -> Self
    where
        R: Default,
    {
        Self {
            status: Status {
                code: 200,
                detail: "OK".to_string(),
            },
            reply: R::default(),
        }
    }

    pub fn bad_request(detail: String) -> Self
    where
        R: Default,
    {
        Self {
            status: Status { code: 400, detail },
            reply: R::default(),
        }
    }

    pub fn unauthorized(detail: String) -> Self
    where
        R: Default,
    {
        Self {
            status: Status { code: 401, detail },
            reply: R::default(),
        }
    }

    pub fn not_implemented(detail: String) -> Self
    where
        R: Default,
    {
        Self {
            status: Status { code: 501, detail },
            reply: R::default(),
        }
    }

    pub fn internal_error(detail: String) -> Self
    where
        R: Default,
    {
        Self {
            status: Status { code: 500, detail },
            reply: R::default(),
        }
    }

    pub fn with_reply(&self, reply: R) -> Self {
        Self {
            status: self.status.clone(),
            reply,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Empty {}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Subscribe {
    pub subscription: Option<SubscriptionID>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "code", rename_all = "camelCase")]
pub enum Error {
    ProgressGap(ProgressGapInfo),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Reply {
    Empty(Empty),
    Error(Error),
    RecordsCount(Box<records::Count>),
    RecordsRead(Box<records::Read>),
    RecordsQuery(Box<records::Query>),
    MessageRead(Box<messages::Read>),
    MessageQuery(Box<messages::Query>),
    ProtocolsQuery(Box<protocols::Query>),
    Subscribe(Subscribe),
}

impl Default for Reply {
    fn default() -> Self {
        Reply::Empty(Empty {})
    }
}
