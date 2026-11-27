use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use ssi_dids_core::DIDBuf;

use crate::auth::Authorization;
use crate::descriptors::{
    MessageParameters, MessageValidator, RecordsWriteDescriptor, ValidationError,
};
use crate::modules;
use crate::Message;

use super::{ModulesConfigureDescriptor, ModulesQueryDescriptor};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct ConfigureParameters {
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub definition: modules::Definition,
    #[serde(rename = "permissionGrantId")]
    pub permission_grant_id: Option<String>,
    #[serde(rename = "delegatedGrant")]
    pub delegated_grant: Option<Message<RecordsWriteDescriptor>>,
}

impl MessageValidator for ModulesConfigureDescriptor {}

impl MessageParameters for ConfigureParameters {
    type Descriptor = ModulesConfigureDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let message_timestamp = match self.message_timestamp {
            Some(ts) => ts,
            None => chrono::Utc::now(),
        };

        // The construction half. `RuleSet` collects unknown
        // keys through `#[serde(flatten)]`, so a programmatically built
        // definition can carry `$encryption` just as a parsed one can.
        self.definition
            .validate_reserved_control_namespace()
            .map_err(|error| ValidationError {
                message: error.to_string(),
            })?;

        let descriptor = ModulesConfigureDescriptor {
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
    type Descriptor = ModulesQueryDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let descriptor = ModulesQueryDescriptor {
            message_timestamp: self.message_timestamp,
            filter: self.filter.as_ref().map(|f| QueryFilter {
                module: Some(f.module.clone()),
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
    pub module: String,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct QueryFilter {
    pub module: Option<String>,
    pub recipient: Option<DIDBuf>,
}
