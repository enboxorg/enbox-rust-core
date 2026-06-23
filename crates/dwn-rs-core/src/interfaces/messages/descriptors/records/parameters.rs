use crate::auth::Authorization;
use crate::descriptors::{MessageParameters, MessageValidator, ValidationError};
use crate::encryption::{DerivationScheme, Encryption, EncryptionInput};
use crate::fields::WriteFields;
use crate::filters::message_filters::Records as RecordsFilter;
use crate::{normalize_url, MapValue, Message, Pagination};

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::{
    CountDescriptor, DeleteDescriptor, QueryDescriptor, ReadDescriptor, SubscribeDescriptor,
    WriteDescriptor,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct ReadParameters {
    pub filters: RecordsFilter,
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "permissionGrantId")]
    pub permission_grant_id: Option<String>,
    #[serde(rename = "dateSort", skip_serializing_if = "Option::is_none")]
    pub date_sort: Option<DateSort>,
    #[serde(rename = "protocolRole")]
    pub protocol_role: Option<String>,
    #[serde(rename = "delegatedGrant")]
    pub delegated_grant: Option<Message<WriteDescriptor>>,
}

impl MessageValidator for ReadParameters {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

impl MessageParameters for ReadParameters {
    type Descriptor = ReadDescriptor;
    type Fields = crate::auth::Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let descriptor = ReadDescriptor {
            message_timestamp: self.message_timestamp.unwrap_or_else(chrono::Utc::now),
            filter: self.filters.clone(),
            permission_grant_id: self.permission_grant_id.clone(),
            date_sort: self.date_sort.clone(),
        };

        Ok((descriptor, None))
    }

    fn delegated_grant(&self) -> Option<Message<WriteDescriptor>> {
        self.delegated_grant.clone()
    }

    fn permission_grant_id(&self) -> Option<String> {
        self.permission_grant_id.clone()
    }

    fn protocol_rule(&self) -> Option<String> {
        self.protocol_role.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct CountParameters {
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub filter: RecordsFilter,
    #[serde(rename = "protocolRole")]
    pub protocol_role: Option<String>,
    #[serde(rename = "delegatedGrant")]
    pub delegated_grant: Option<Message<WriteDescriptor>>,
}

impl MessageValidator for CountParameters {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

impl MessageParameters for CountParameters {
    type Descriptor = CountDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let descriptor = CountDescriptor {
            message_timestamp: self.message_timestamp.unwrap_or_else(chrono::Utc::now),
            filter: self.filter.clone(),
        };

        Ok((descriptor, None))
    }

    fn delegated_grant(&self) -> Option<Message<WriteDescriptor>> {
        self.delegated_grant.clone()
    }

    fn protocol_rule(&self) -> Option<String> {
        self.protocol_role.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct QueryParameters {
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub filter: Option<RecordsFilter>,
    #[serde(rename = "dateSort")]
    pub date_sort: Option<DateSort>,
    pub pagination: Option<Pagination>,
    #[serde(rename = "protocolRole")]
    pub protocol_role: Option<String>,
    #[serde(rename = "delegatedGrant")]
    pub delegated_grant: Option<Message<WriteDescriptor>>,
}

impl MessageValidator for QueryParameters {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(ref filter) = self.filter {
            if let Some(published) = filter.published {
                if let Some(date_sort) = &self.date_sort {
                    if (*date_sort == DateSort::PublishedAscending
                        || *date_sort == DateSort::PublishedDescending)
                        && !published
                    {
                        return Err(ValidationError {
                            message: "Cannot sort by publish date when published is false"
                                .to_string(),
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

impl MessageParameters for QueryParameters {
    type Descriptor = QueryDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let descriptor = QueryDescriptor {
            message_timestamp: self.message_timestamp.unwrap_or_else(chrono::Utc::now),
            filter: self.filter.clone().unwrap_or_default(),
            date_sort: self.date_sort.clone(),
            pagination: self.pagination.clone(),
        };

        Ok((descriptor, None))
    }

    fn delegated_grant(&self) -> Option<Message<WriteDescriptor>> {
        self.delegated_grant.clone()
    }

    fn protocol_rule(&self) -> Option<String> {
        self.protocol_role.clone()
    }
}

/// DataSort represents Records ordering for queries.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum DateSort {
    #[serde(rename = "createdAscending")]
    CreatedAscending,
    #[serde(rename = "createdDescending")]
    CreatedDescending,
    #[serde(rename = "publishedAscending")]
    PublishedAscending,
    #[serde(rename = "publishedDescending")]
    PublishedDescending,
    #[serde(rename = "updatedAscending")]
    UpdatedAscending,
    #[serde(rename = "updatedDescending")]
    UpdatedDescending,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct WriteParameters {
    pub recipient: Option<String>,
    pub protocol: Option<String>,
    #[serde(rename = "protocolPath")]
    pub protocol_path: Option<String>,
    #[serde(rename = "protocolRole")]
    pub protocol_role: Option<String>,
    pub schema: Option<String>,
    pub tags: Option<MapValue>,
    #[serde(rename = "recordId")]
    pub record_id: Option<String>,
    #[serde(rename = "parentContextId")]
    pub parent_context_id: Option<String>,
    pub data: Option<Vec<u8>>,
    #[serde(rename = "dataCid")]
    pub data_cid: Option<String>,
    #[serde(rename = "dataSize")]
    pub data_size: Option<u64>,
    #[serde(rename = "dateCreated")]
    pub date_created: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub published: Option<bool>,
    #[serde(rename = "datePublished")]
    pub date_published: Option<chrono::DateTime<chrono::Utc>>,
    pub data_format: String,
    #[serde(rename = "delegatedGrant")]
    pub delegated_grant: Option<Message<WriteDescriptor>>,
    #[serde(rename = "encryptionInput")]
    pub encryption_input: Option<EncryptionInput>,
    #[serde(rename = "permissionGrantId")]
    pub permission_grant_id: Option<String>,
    pub squash: Option<bool>,
}

impl MessageValidator for WriteParameters {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.protocol.is_none() && self.protocol_path.is_some()
            || self.protocol.is_some() && self.protocol_path.is_none()
        {
            return Err(ValidationError {
                message: "protocol and protocolPath must be either both set or both unset"
                    .to_string(),
            });
        }

        if self.data.is_none() && self.data_cid.is_none()
            || self.data.is_some() && self.data_cid.is_some()
        {
            return Err(ValidationError {
                message: "data and dataCid must be either both set or both unset".to_string(),
            });
        }

        if self.data.is_some() && self.data_size.is_none()
            || self.data.is_none() && self.data_size.is_some()
        {
            return Err(ValidationError {
                message: "data and dataSize must be either both set or both unset".to_string(),
            });
        }

        if let Some(encryption_input) = &self.encryption_input {
            encryption_input
                .key_encryption_inputs
                .iter()
                .try_for_each(|input| {
                    match (&input.derivation_scheme, &self.protocol, &self.schema) {
                        (DerivationScheme::ProtocolPath, None, _) => Err(ValidationError {
                            message: "'protocols' encryption requires a protocol".to_string(),
                        }),
                        (DerivationScheme::Schemas, _, None) => Err(ValidationError {
                            message: "'schemas' encryption requires a schema".to_string(),
                        }),
                        (_, Some(_), Some(_)) => Ok(()),
                        (_, _, _) => Ok(()),
                    }
                })?;
        }

        Ok(())
    }
}

impl MessageParameters for WriteParameters {
    type Descriptor = WriteDescriptor;
    type Fields = WriteFields;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let data_cid = match &self.data_cid {
            Some(cid) => cid.clone(),
            None => crate::cid::generate_cid(self.data.as_deref().unwrap_or(&[]))
                .map_err(|e| ValidationError {
                    message: e.to_string(),
                })?
                .to_string(),
        };
        let data_size = self.data_size.unwrap_or_else(|| {
            self.data
                .as_ref()
                .map(|data| data.len() as u64)
                .unwrap_or_default()
        });

        let now = chrono::Utc::now();

        let mut descriptor = WriteDescriptor {
            protocol: self
                .protocol
                .as_ref()
                .and_then(|url| normalize_url(url).ok()),
            protocol_path: self.protocol_path.clone(),
            recipient: self.recipient.clone(),
            schema: self.schema.as_ref().and_then(|url| normalize_url(url).ok()),
            tags: self.tags.clone(),
            parent_id: self.parent_context_id.as_ref().and_then(|context_id| {
                context_id
                    .split("/")
                    .filter(|segment| !segment.is_empty())
                    .last()
                    .map(|s| s.to_string())
            }),
            data_cid,
            data_size,
            date_created: self.date_created.unwrap_or(now),
            message_timestamp: self.message_timestamp.unwrap_or(now),
            published: self.published,
            date_published: self.date_published,
            data_format: self.data_format.clone(),
            permission_grant_id: self.permission_grant_id.clone(),
            squash: self.squash,
        };

        if let (Some(published), None) = (self.published, self.date_published) {
            if published {
                descriptor.date_published = Some(now);
            }
        }

        let mut fields = WriteFields {
            ..Default::default()
        };

        if let Some(encryption_input) = &self.encryption_input {
            fields.encryption =
                Some(
                    Encryption::build_jwe(encryption_input).map_err(|e| ValidationError {
                        message: e.to_string(),
                    })?,
                );
        }
        fields.record_id = self.record_id.clone();

        Ok((descriptor, Some(fields)))
    }

    fn delegated_grant(&self) -> Option<Message<WriteDescriptor>> {
        self.delegated_grant.clone()
    }

    fn permission_grant_id(&self) -> Option<String> {
        self.permission_grant_id.clone()
    }

    fn protocol_rule(&self) -> Option<String> {
        self.protocol_role.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct SubscribeParameters {
    pub filters: RecordsFilter,
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "protocolRole")]
    pub protocol_role: Option<String>,
    #[serde(rename = "dateSort", skip_serializing_if = "Option::is_none")]
    pub date_sort: Option<DateSort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<Pagination>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<crate::stores::ProgressToken>,
    #[serde(rename = "delegatedGrant")]
    pub delegated_grant: Option<Message<WriteDescriptor>>,
}

impl MessageValidator for SubscribeParameters {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

impl MessageParameters for SubscribeParameters {
    type Descriptor = SubscribeDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let descriptor = SubscribeDescriptor {
            message_timestamp: self.message_timestamp.unwrap_or_else(chrono::Utc::now),
            filter: self.filters.clone(),
            date_sort: self.date_sort.clone(),
            pagination: self.pagination.clone(),
            cursor: self.cursor.clone(),
        };

        Ok((descriptor, None))
    }

    fn delegated_grant(&self) -> Option<Message<WriteDescriptor>> {
        self.delegated_grant.clone()
    }

    fn protocol_rule(&self) -> Option<String> {
        self.protocol_role.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct DeleteParameters {
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "messageTimestamp")]
    pub message_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "protocolRole")]
    pub protocol_role: Option<String>,
    #[serde(rename = "prune")]
    pub prune: Option<bool>,
    #[serde(rename = "delegatedGrant")]
    pub delegated_grant: Option<Message<WriteDescriptor>>,
    #[serde(rename = "permissionGrantId")]
    pub permission_grant_id: Option<String>,
}

impl MessageValidator for DeleteParameters {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.record_id.is_empty() {
            return Err(ValidationError {
                message: "recordId is required".to_string(),
            });
        }

        Ok(())
    }
}

impl MessageParameters for DeleteParameters {
    type Descriptor = DeleteDescriptor;
    type Fields = Authorization;

    async fn build(&self) -> Result<(Self::Descriptor, Option<Self::Fields>), ValidationError> {
        let descriptor = DeleteDescriptor {
            message_timestamp: self.message_timestamp.unwrap_or_else(chrono::Utc::now),
            record_id: self.record_id.clone(),
            prune: self.prune.unwrap_or(false),
        };

        Ok((descriptor, None))
    }

    fn delegated_grant(&self) -> Option<Message<WriteDescriptor>> {
        self.delegated_grant.clone()
    }

    fn permission_grant_id(&self) -> Option<String> {
        self.permission_grant_id.clone()
    }

    fn protocol_rule(&self) -> Option<String> {
        self.protocol_role.clone()
    }
}
