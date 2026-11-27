mod parameters;
#[cfg(test)]
mod tests;

pub use inner::*;
pub use parameters::*;

use dwn_rs_message_derive::interface;

#[interface(MODULES, union = Modules)]
mod inner {
    use super::QueryFilter;
    use crate::interfaces::messages::descriptors::{
        CONFIGURE, MODULES, MODULES_CONFIGURE_SCHEMA, MODULES_QUERY_SCHEMA, QUERY,
    };
    use crate::modules;

    /// ModulesConfigureDescriptor represents the ModulesConfigure interface method for configuring a
    /// module on the DWN.
    #[descriptor(
        method = CONFIGURE,
        variant = Configure,
        schema_id = MODULES_CONFIGURE_SCHEMA,
        fields = crate::auth::Authorization,
        parameters = super::ConfigureParameters,
        grant = single
    )]
    pub struct ModulesConfigureDescriptor {
        #[serde(
            rename = "messageTimestamp",
            serialize_with = "crate::ser::serialize_datetime"
        )]
        pub message_timestamp: chrono::DateTime<chrono::Utc>,
        pub definition: modules::Definition,
        #[serde(rename = "permissionGrantId", skip_serializing_if = "Option::is_none")]
        pub permission_grant_id: Option<String>,
    }

    /// ModulesQueryDescriptor represents the ModulesQuery interface method for querying modules.
    #[descriptor(
        method = QUERY,
        variant = Query,
        schema_id = MODULES_QUERY_SCHEMA,
        fields = crate::auth::Authorization,
        parameters = super::QueryParameters,
        grant = single
    )]
    pub struct ModulesQueryDescriptor {
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
