pub mod messages;
pub mod protocols;
pub mod records;

#[cfg(test)]
use std::collections::BTreeMap;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::stores::ProgressGapInfo;

/// Implemented by reply bodies that can report a state-index progress gap.
pub trait HasProgressGapInfo: Default {
    fn with_progress_gap_info(error: ProgressGapInfo) -> Self;
}

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

    pub fn bad_request(detail: impl Into<String>) -> Self
    where
        R: Default,
    {
        Self {
            status: Status {
                code: 400,
                detail: detail.into(),
            },
            reply: R::default(),
        }
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self
    where
        R: Default,
    {
        Self {
            status: Status {
                code: 401,
                detail: detail.into(),
            },
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

    pub fn not_found() -> Self
    where
        R: Default,
    {
        Self {
            status: Status {
                code: 404,
                detail: "Not Found".into(),
            },
            reply: R::default(),
        }
    }

    pub fn not_found_with_reply(reply: R) -> Self {
        Self {
            status: Status {
                code: 404,
                detail: "Not Found".into(),
            },
            reply,
        }
    }

    pub fn gone(detail: String, reply: R) -> Self
    where
        R: Default,
    {
        Self {
            status: Status { code: 410, detail },
            reply,
        }
    }

    pub fn conflict() -> Self
    where
        R: Default,
    {
        Self {
            status: Status {
                code: 409,
                detail: "Conflict".into(),
            },
            reply: R::default(),
        }
    }

    pub fn no_content() -> Self
    where
        R: Default,
    {
        Self {
            status: Status {
                code: 204,
                detail: "No Content".into(),
            },
            reply: R::default(),
        }
    }

    pub fn accepted() -> Self
    where
        R: Default,
    {
        Self {
            status: Status {
                code: 202,
                detail: "Accepted".into(),
            },
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
#[serde(tag = "code", rename_all = "camelCase")]
pub enum Error {
    ProgressGap(ProgressGapInfo),
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum Reply {
    #[default]
    Empty,
    Error(Error),
    RecordsCount(Box<records::Count>),
    RecordsRead(Box<records::Read>),
    RecordsWrite(Box<records::Write>),
    RecordsQuery(Box<records::Query>),
    MessageRead(Box<messages::Read>),
    MessageQuery(Box<messages::Query>),
    MessageSync(Box<messages::Sync>),
    MessageSubscription(Box<messages::Subscription>),
    ProtocolsQuery(Box<protocols::Query>),
    RecordsSubscribe(Box<records::Subscribe>),
    #[cfg(test)]
    General(BTreeMap<String, String>),
}

impl From<()> for Reply {
    fn from(_: ()) -> Self {
        Reply::Empty
    }
}
