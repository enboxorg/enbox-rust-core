pub mod messages;
pub mod protocols;
pub mod records;

#[cfg(test)]
use std::collections::BTreeMap;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::errors::{DwnError, DwnErrorInfo};
use crate::stores::ProgressGapInfo;

/// Implemented by reply bodies that can report a state-index progress gap.
pub trait HasProgressGapInfo: Default {
    fn with_progress_gap_info(error: ProgressGapInfo) -> Self;
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Status {
    pub code: i32,
    pub detail: String,
    #[serde(rename = "errorCode", skip_serializing_if = "Option::is_none", default)]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub info: Option<DwnErrorInfo>,
}

impl Status {
    pub fn new(code: i32, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            error_code: None,
            info: None,
        }
    }

    pub fn from_error(code: i32, error: DwnError) -> Self {
        Self {
            code,
            detail: error.to_string(),
            error_code: Some(error.code.to_string()),
            info: error.info,
        }
    }
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
            status: Status::new(200, "OK"),
            reply: R::default(),
        }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self
    where
        R: Default,
    {
        Self {
            status: Status::new(400, detail),
            reply: R::default(),
        }
    }

    pub fn bad_request_error(error: DwnError) -> Self
    where
        R: Default,
    {
        Self {
            status: Status::from_error(400, error),
            reply: R::default(),
        }
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self
    where
        R: Default,
    {
        Self {
            status: Status::new(401, detail),
            reply: R::default(),
        }
    }

    pub fn not_implemented(detail: impl Into<String>) -> Self
    where
        R: Default,
    {
        Self {
            status: Status::new(501, detail),
            reply: R::default(),
        }
    }

    pub fn internal_error(detail: String) -> Self
    where
        R: Default,
    {
        Self {
            status: Status::new(500, detail),
            reply: R::default(),
        }
    }

    pub fn not_found() -> Self
    where
        R: Default,
    {
        Self {
            status: Status::new(404, "Not Found"),
            reply: R::default(),
        }
    }

    pub fn not_found_with_reply(reply: R) -> Self {
        Self {
            status: Status::new(404, "Not Found"),
            reply,
        }
    }

    pub fn gone(detail: String, reply: R) -> Self
    where
        R: Default,
    {
        Self {
            status: Status::new(410, detail),
            reply,
        }
    }

    pub fn conflict() -> Self
    where
        R: Default,
    {
        Self {
            status: Status::new(409, "Conflict"),
            reply: R::default(),
        }
    }

    pub fn conflict_error(error: DwnError) -> Self
    where
        R: Default,
    {
        Self {
            status: Status::from_error(409, error),
            reply: R::default(),
        }
    }

    pub fn no_content() -> Self
    where
        R: Default,
    {
        Self {
            status: Status::new(204, "No Content"),
            reply: R::default(),
        }
    }

    pub fn accepted() -> Self
    where
        R: Default,
    {
        Self {
            status: Status::new(202, "Accepted"),
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

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum Reply {
    #[default]
    Empty,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::DwnErrorCode;

    #[test]
    fn status_omits_absent_error_metadata() {
        assert_eq!(
            serde_json::to_value(Status::new(409, "Conflict")).unwrap(),
            serde_json::json!({ "code": 409, "detail": "Conflict" })
        );
    }

    #[test]
    fn status_serializes_structured_dwn_error_metadata() {
        let error = DwnError::new(
            DwnErrorCode::RecordsWriteGetInitialWriteNotFound,
            "example failure",
        )
        .with_info(
            [("recordId".to_string(), serde_json::json!("record-1"))]
                .into_iter()
                .collect(),
        );
        assert_eq!(
            serde_json::to_value(Status::from_error(400, error)).unwrap(),
            serde_json::json!({
                "code": 400,
                "detail": "RecordsWriteGetInitialWriteNotFound: example failure",
                "errorCode": "RecordsWriteGetInitialWriteNotFound",
                "info": { "recordId": "record-1" }
            })
        );
    }
}
