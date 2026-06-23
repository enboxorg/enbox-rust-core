mod parameters;
#[cfg(test)]
mod tests;

pub use inner::*;
pub use parameters::*;

use dwn_rs_message_derive::interface;

#[interface(PROTOCOLS, union = Protocols)]
mod inner {
    use super::QueryFilter;
    use crate::interfaces::messages::descriptors::{CONFIGURE, PROTOCOLS, QUERY};
    use crate::protocols;

    /// ConfigureDescriptor represents the ProtocolsConfigure interface method for configuring a
    /// protocol on the DWN.
    #[descriptor(
        method = CONFIGURE,
        variant = Configure,
        fields = crate::auth::Authorization,
        parameters = super::ConfigureParameters
    )]
    pub struct ConfigureDescriptor {
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        pub definition: protocols::Definition,
        #[serde(rename = "permissionGrantId", skip_serializing_if = "Option::is_none")]
        pub permission_grant_id: Option<String>,
    }

    /// QueryDescriptor represents the ProtocolsQuery interface method for querying protocols.
    #[descriptor(
        method = QUERY,
        variant = Query,
        fields = crate::auth::Authorization,
        parameters = super::QueryParameters
    )]
    pub struct QueryDescriptor {
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub filter: Option<QueryFilter>,
        #[serde(rename = "permissionGrantId", skip_serializing_if = "Option::is_none")]
        pub permission_grant_id: Option<String>,
    }
}
