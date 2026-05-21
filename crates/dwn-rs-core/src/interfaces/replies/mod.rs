pub mod messages;
pub mod protocols;
pub mod records;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::SubscriptionID;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Status {
    pub code: i32,
    pub detail: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Response {
    pub status: Status,
    #[serde(flatten)]
    pub reply: Reply,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Empty {}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Subscribe {
    pub subscription: Option<SubscriptionID>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Reply {
    Empty(Empty),
    RecordsRead(Box<records::Read>),
    RecordsQuery(Box<records::Query>),
    MessageRead(Box<messages::Read>),
    MessageQuery(Box<messages::Query>),
    ProtocolsQuery(Box<protocols::Query>),
    Subscribe(Subscribe),
}
