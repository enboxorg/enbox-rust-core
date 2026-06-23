use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use ssi_dids_core::DIDBuf;

use crate::auth::Authorization;
use crate::descriptors::{
    MessageParameters, MessageValidator, RecordsWriteDescriptor, ValidationError,
};
use crate::{protocols, Message};

use super::{ConfigureDescriptor, QueryDescriptor};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct ConfigureParameters {
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub definition: protocols::Definition,
    #[serde(rename = "permissionGrantId")]
    pub permission_grant_id: Option<String>,
    #[serde(rename = "delegatedGrant")]
    pub delegated_grant: Option<Message<RecordsWriteDescriptor>>,
}

impl MessageValidator for ConfigureDescriptor {}

impl MessageParameters for ConfigureParameters {
    type Descriptor = ConfigureDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let message_timestamp = match self.message_timestamp {
            Some(ts) => ts,
            None => chrono::Utc::now(),
        };

        let descriptor = ConfigureDescriptor {
            message_timestamp,
            definition: self.definition.clone(),
            permission_grant_id: self.permission_grant_id.clone(),
        };

        Ok((descriptor, None))
    }

    fn delegated_grant(&self) -> Option<Message<RecordsWriteDescriptor>> {
        self.delegated_grant.clone()
    }

    fn permission_grant_id(&self) -> Option<String> {
        self.permission_grant_id.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct QueryParameters {
    pub filter: Option<QueryFilterParameters>,
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
        let descriptor = QueryDescriptor {
            message_timestamp: self.message_timestamp,
            filter: self.filter.as_ref().map(|f| QueryFilter {
                protocol: Some(f.protocol.clone()),
                recipient: None,
            }),
            permission_grant_id: self.permission_grant_id.clone(),
        };

        Ok((descriptor, None))
    }

    fn permission_grant_id(&self) -> Option<String> {
        self.permission_grant_id.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct QueryFilterParameters {
    pub protocol: String,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct QueryFilter {
    pub protocol: Option<String>,
    pub recipient: Option<DIDBuf>,
}
