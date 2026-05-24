use crate::auth::Authorization;
use crate::descriptors::MessageDescriptor;
use crate::filters::message_filters::Messages as MessagesFilter;
use std::collections::BTreeMap;

use crate::interfaces::messages::descriptors::{MESSAGES, QUERY, READ, SUBSCRIBE, SYNC};
use cid::Cid;
use dwn_rs_message_derive::descriptor;
use serde::{Deserialize, Serialize};

use super::{MessageParameters, MessageValidator};

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

    async fn build(
        &self,
    ) -> Result<(Self::Descriptor, Option<Self::Fields>), super::ValidationError> {
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

#[descriptor(interface = MESSAGES, method = READ, fields = crate::auth::Authorization, parameters = ReadParameters)]
pub struct ReadDescriptor {
    #[serde(
        rename = "messageTimestamp",
        serialize_with = "crate::ser::serialize_datetime"
    )]
    pub message_timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(
        rename = "messageCid",
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::ser::optional_cid_string"
    )]
    pub message_cid: Option<Cid>,
    #[serde(rename = "permissionGrantId", skip_serializing_if = "Option::is_none")]
    pub permission_grant_id: Option<String>,
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

    async fn build(
        &self,
    ) -> Result<(Self::Descriptor, Option<Self::Fields>), super::ValidationError> {
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

#[descriptor(interface = MESSAGES, method = QUERY, fields = crate::auth::Authorization, parameters = QueryParameters)]
pub struct QueryDescriptor {
    #[serde(
        rename = "messageTimestamp",
        serialize_with = "crate::ser::serialize_datetime"
    )]
    pub message_timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<MessagesFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<crate::Cursor>,
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

    async fn build(
        &self,
    ) -> Result<(Self::Descriptor, Option<Self::Fields>), super::ValidationError> {
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

#[descriptor(interface = MESSAGES, method = SUBSCRIBE, fields = crate::auth::Authorization, parameters = SubscribeParameters)]
pub struct SubscribeDescriptor {
    #[serde(
        rename = "messageTimestamp",
        serialize_with = "crate::ser::serialize_datetime"
    )]
    pub message_timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<MessagesFilter>,
    #[serde(rename = "permissionGrantId", skip_serializing_if = "Option::is_none")]
    pub permission_grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<crate::stores::ProgressToken>,
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

    async fn build(
        &self,
    ) -> Result<(Self::Descriptor, Option<Self::Fields>), super::ValidationError> {
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

#[descriptor(interface = MESSAGES, method = SYNC, fields = crate::auth::Authorization, parameters = SyncParameters)]
pub struct SyncDescriptor {
    #[serde(
        rename = "messageTimestamp",
        serialize_with = "crate::ser::serialize_datetime"
    )]
    pub message_timestamp: chrono::DateTime<chrono::Utc>,
    pub action: SyncAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(rename = "permissionGrantId", skip_serializing_if = "Option::is_none")]
    pub permission_grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u16>,
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde_json::json;

    #[test]
    fn test_read_descriptor() {
        let message_timestamp = DateTime::from_str(
            Utc::now()
                .to_rfc3339_opts(SecondsFormat::Micros, true)
                .as_str(),
        )
        .unwrap();

        // new random DagCbor encoded CID
        let message_cid = Cid::new_v1(0x71, cid::multihash::Multihash::default());
        let descriptor = ReadDescriptor {
            message_timestamp,
            message_cid: Some(message_cid),
            permission_grant_id: None,
        };
        let json = json!({
            "messageTimestamp": message_timestamp,
            "messageCid": message_cid.to_string(),
            "interface": MESSAGES,
            "method": READ,
        });
        assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<ReadDescriptor>(json).unwrap(),
            descriptor
        );
    }

    #[test]
    fn test_query_descriptor() {
        let message_timestamp = DateTime::from_str(
            Utc::now()
                .to_rfc3339_opts(SecondsFormat::Micros, true)
                .as_str(),
        )
        .unwrap();

        let filters = vec![MessagesFilter::default()];
        let cursor = Some(crate::Cursor::default());
        let descriptor = QueryDescriptor {
            message_timestamp,
            filters,
            cursor: cursor.clone(),
        };
        let json = json!({
            "messageTimestamp": message_timestamp,
            "filters": [MessagesFilter::default()],
            "cursor": cursor,
            "interface": MESSAGES,
            "method": QUERY,
        });
        assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<QueryDescriptor>(json).unwrap(),
            descriptor
        );
    }

    #[test]
    fn test_subscribe_descriptor() {
        let message_timestamp = DateTime::from_str(
            Utc::now()
                .to_rfc3339_opts(SecondsFormat::Micros, true)
                .as_str(),
        )
        .unwrap();

        let filters = vec![MessagesFilter::default()];
        let descriptor = SubscribeDescriptor {
            message_timestamp,
            filters,
            permission_grant_id: None,
            cursor: None,
        };
        let json = json!({
            "messageTimestamp": message_timestamp,
            "filters": [MessagesFilter::default()],
            "interface": MESSAGES,
            "method": SUBSCRIBE
        });
        assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<SubscribeDescriptor>(json).unwrap(),
            descriptor
        );
    }

    #[test]
    fn test_sync_descriptor() {
        let message_timestamp = DateTime::from_str(
            Utc::now()
                .to_rfc3339_opts(SecondsFormat::Micros, true)
                .as_str(),
        )
        .unwrap();

        let descriptor = SyncDescriptor {
            message_timestamp,
            action: SyncAction::Diff,
            protocol: Some("http://example.com/protocol".to_string()),
            prefix: None,
            permission_grant_id: Some("grant-1".to_string()),
            hashes: Some(BTreeMap::from([(
                "0101".to_string(),
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            )])),
            depth: Some(4),
        };
        let json = json!({
            "messageTimestamp": message_timestamp,
            "interface": MESSAGES,
            "method": SYNC,
            "action": "diff",
            "protocol": "http://example.com/protocol",
            "permissionGrantId": "grant-1",
            "hashes": {
                "0101": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            },
            "depth": 4,
        });
        assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<SyncDescriptor>(json).unwrap(),
            descriptor
        );
    }
}
