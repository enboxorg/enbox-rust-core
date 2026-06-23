mod parameters;
#[cfg(test)]
mod tests;

pub use inner::*;
pub use parameters::*;

use dwn_rs_message_derive::interface;

#[interface(MESSAGES, union = Messages)]
mod inner {
    use super::SyncAction;
    use crate::filters::message_filters::Messages as MessagesFilter;
    use crate::interfaces::messages::descriptors::{MESSAGES, QUERY, READ, SUBSCRIBE, SYNC};
    use crate::Cursor;
    use cid::Cid;
    use std::collections::BTreeMap;

    /// ReadDescriptor represents the MessagesRead interface method for reading a message by CID.
    #[descriptor(
        method = READ,
        variant = Read,
        fields = crate::auth::Authorization,
        parameters = super::ReadParameters
    )]
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

    /// QueryDescriptor represents the MessagesQuery interface method for querying messages.
    ///
    /// `no_handler`: deserializable for spec parity, but this implementation has no MessagesQuery
    /// request handler, so it is excluded from `current_handler_kinds()`.
    #[descriptor(
        method = QUERY,
        variant = Query,
        no_handler,
        fields = crate::auth::Authorization,
        parameters = super::QueryParameters
    )]
    pub struct QueryDescriptor {
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub filters: Vec<MessagesFilter>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cursor: Option<Cursor>,
    }

    /// SubscribeDescriptor represents the MessagesSubscribe interface method for subscribing to
    /// message changes.
    #[descriptor(
        method = SUBSCRIBE,
        variant = Subscribe,
        fields = crate::auth::Authorization,
        parameters = super::SubscribeParameters
    )]
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

    /// SyncDescriptor represents the MessagesSync interface method for synchronizing message state.
    #[descriptor(
        method = SYNC,
        variant = Sync,
        fields = crate::auth::Authorization,
        parameters = super::SyncParameters
    )]
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
}
