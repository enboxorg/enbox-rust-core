use std::collections::BTreeMap;

use crate::auth::Authorization;
use crate::descriptors::{MessageParameters, MessageValidator, ValidationError};
use crate::filters::message_filters::Messages as MessagesFilter;

use cid::Cid;
use serde::{Deserialize, Serialize};

use super::{QueryDescriptor, ReadDescriptor, SubscribeDescriptor, SyncDescriptor};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct ReadParameters {
    #[serde(rename = "messageCid")]
    pub message_cid: Cid,
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "permissionGrantId")]
    pub permission_grant_id: Option<String>,
}

impl MessageValidator for ReadParameters {}

impl MessageParameters for ReadParameters {
    type Descriptor = ReadDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let descriptor = ReadDescriptor {
            message_timestamp: self.message_timestamp,
            message_cid: Some(self.message_cid),
            permission_grant_id: self.permission_grant_id.clone(),
        };

        Ok((descriptor, None))
    }

    fn permission_grant_id(&self) -> Option<String> {
        self.permission_grant_id.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct QueryParameters {
    pub filter: Option<Vec<MessagesFilter>>,
    pub cursor: Option<crate::Cursor>,
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "permissionGrantId")]
    pub permission_grant_id: Option<String>,
}

impl MessageValidator for QueryParameters {}

impl MessageParameters for QueryParameters {
    type Descriptor = QueryDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let filters = match self.filter {
            Some(ref filter) => filter.clone(),
            None => Vec::new(),
        };

        let descriptor = QueryDescriptor {
            message_timestamp: self.message_timestamp,
            cursor: self.cursor.clone(),
            filters,
        };

        Ok((descriptor, None))
    }

    fn permission_grant_id(&self) -> Option<String> {
        self.permission_grant_id.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct SubscribeParameters {
    pub filters: Vec<MessagesFilter>,
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "permissionGrantId")]
    pub permission_grant_id: Option<String>,
    pub cursor: Option<crate::stores::ProgressToken>,
}

impl MessageValidator for SubscribeParameters {}

impl MessageParameters for SubscribeParameters {
    type Descriptor = SubscribeDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let filters = self.filters.clone();

        let descriptor = SubscribeDescriptor {
            message_timestamp: self.message_timestamp,
            filters,
            permission_grant_id: self.permission_grant_id.clone(),
            cursor: self.cursor.clone(),
        };

        Ok((descriptor, None))
    }

    fn permission_grant_id(&self) -> Option<String> {
        self.permission_grant_id.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyncAction {
    #[default]
    Root,
    Subtree,
    Leaves,
    Diff,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct SyncParameters {
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: chrono::DateTime<chrono::Utc>,
    pub action: SyncAction,
    pub protocol: Option<String>,
    pub prefix: Option<String>,
    #[serde(rename = "permissionGrantId")]
    pub permission_grant_id: Option<String>,
    pub hashes: Option<BTreeMap<String, String>>,
    pub depth: Option<u16>,
}

impl MessageValidator for SyncParameters {}

impl MessageParameters for SyncParameters {
    type Descriptor = SyncDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let descriptor = SyncDescriptor {
            message_timestamp: self.message_timestamp,
            action: self.action.clone(),
            protocol: self.protocol.clone(),
            prefix: self.prefix.clone(),
            permission_grant_id: self.permission_grant_id.clone(),
            hashes: self.hashes.clone(),
            depth: self.depth,
        };

        Ok((descriptor, None))
    }

    fn permission_grant_id(&self) -> Option<String> {
        self.permission_grant_id.clone()
    }
}
