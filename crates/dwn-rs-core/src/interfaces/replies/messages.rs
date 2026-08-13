use cid::Cid;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{Cursor, Descriptor, Message};

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ReadEntry {
    #[serde(rename = "messageCid")]
    pub cid: Cid,
    pub message: Option<Message<Descriptor>>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Read {
    pub entry: Option<ReadEntry>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Query {
    pub entries: Option<Vec<Cid>>,
    pub cursor: Option<Cursor>,
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

impl Into<crate::Reply> for Sync {
    fn into(self) -> crate::Reply {
        crate::Reply::MessageSync(Box::new(self))
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
