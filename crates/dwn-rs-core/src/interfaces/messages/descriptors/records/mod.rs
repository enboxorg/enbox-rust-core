mod parameters;
#[cfg(test)]
mod tests;

pub use inner::*;
pub use parameters::*;

pub use crate::encryption::{EncryptionInput, KeyEncryptionInput};

use dwn_rs_message_derive::interface;

#[interface(RECORDS, union = Records)]
mod inner {
    use super::DateSort;
    use crate::filters::message_filters::Records as RecordsFilter;
    use crate::interfaces::messages::descriptors::{
        COUNT, DELETE, QUERY, READ, RECORDS, SUBSCRIBE, WRITE,
    };
    use crate::{MapValue, Pagination};

    /// ReadDescriptor represents the RecordsRead interface method for reading a given
    /// record by ID.
    #[descriptor(
        method = READ,
        variant = Read,
        boxed,
        fields = crate::auth::Authorization,
        parameters = super::ReadParameters
    )]
    pub struct ReadDescriptor {
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        pub filter: RecordsFilter,
        #[serde(rename = "permissionGrantId", skip_serializing_if = "Option::is_none")]
        pub permission_grant_id: Option<String>,
        #[serde(rename = "dateSort", skip_serializing_if = "Option::is_none")]
        pub date_sort: Option<DateSort>,
    }

    /// CountDescriptor represents the RecordsCount interface method for counting records.
    #[descriptor(
        method = COUNT,
        variant = Count,
        boxed,
        fields = crate::auth::Authorization,
        parameters = super::CountParameters
    )]
    pub struct CountDescriptor {
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        pub filter: RecordsFilter,
    }

    /// QueryDescriptor represents the RecordsQuery interface method for querying records.
    #[descriptor(
        method = QUERY,
        variant = Query,
        boxed,
        fields = crate::auth::Authorization,
        parameters = super::QueryParameters
    )]
    pub struct QueryDescriptor {
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        pub filter: RecordsFilter,
        pub pagination: Option<Pagination>,
        #[serde(rename = "dateSort")]
        pub date_sort: Option<DateSort>,
    }

    /// WriteDescriptor represents the RecordsWrite interface method for writing a record to the DWN.
    /// It can be represented with either no additional fields (`()`), or additional descriptor fields,
    /// as in the case for `encodedData`.
    #[descriptor(
        method = WRITE,
        variant = Write,
        boxed,
        fields = crate::fields::WriteFields,
        parameters = super::WriteParameters
    )]
    pub struct WriteDescriptor {
        pub protocol: Option<String>,
        #[serde(rename = "protocolPath")]
        pub protocol_path: Option<String>,
        pub recipient: Option<String>,
        pub schema: Option<String>,
        pub tags: Option<MapValue>,
        #[serde(rename = "parentId")]
        pub parent_id: Option<String>,
        #[serde(rename = "dataCid")]
        pub data_cid: String,
        #[serde(rename = "dataSize")]
        pub data_size: u64,
        #[serde(
            rename = "dateCreated",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub date_created: chrono::DateTime<chrono::Utc>,
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        pub published: Option<bool>,
        #[serde(
            rename = "datePublished",
            serialize_with = "crate::ser::serialize_optional_datetime"
        )]
        pub date_published: Option<chrono::DateTime<chrono::Utc>>,
        #[serde(rename = "dataFormat")]
        pub data_format: String,
        #[serde(rename = "permissionGrantId")]
        pub permission_grant_id: Option<String>,
        pub squash: Option<bool>,
    }

    /// SubscribeDescriptor represents the RecordsSubscribe interface method for subscribing to
    /// record changes.
    #[descriptor(
        method = SUBSCRIBE,
        variant = Subscribe,
        boxed,
        fields = crate::auth::Authorization,
        parameters = super::SubscribeParameters
    )]
    pub struct SubscribeDescriptor {
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        pub filter: RecordsFilter,
        #[serde(rename = "dateSort", skip_serializing_if = "Option::is_none")]
        pub date_sort: Option<DateSort>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub pagination: Option<Pagination>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cursor: Option<crate::stores::ProgressToken>,
    }

    /// DeleteDescriptor represents the RecordsDelete interface method for deleting a record.
    #[descriptor(
        method = DELETE,
        variant = Delete,
        boxed,
        fields = crate::auth::Authorization,
        parameters = super::DeleteParameters
    )]
    pub struct DeleteDescriptor {
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        #[serde(rename = "recordId")]
        pub record_id: String,
        pub prune: bool,
    }
}
