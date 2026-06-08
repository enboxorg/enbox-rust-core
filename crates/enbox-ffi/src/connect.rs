//! FFI request/response shapes for [`dwn_rs_core::connect`] flows.
//!
//! The pure constructor functions (`create_permission_request`,
//! `create_delegate_grant`, `create_grant_revocation`) and the key
//! derivation helpers (`derive_delegate_keys`, `derive_context_key`) are
//! exposed on [`EnboxCore`](crate::EnboxCore) so a mobile host can drive a
//! DWeb Connect flow without a JS runtime.

use chrono::{DateTime, Utc};
use dwn_rs_core::agent::PortableDid;
use dwn_rs_core::connect::{ConnectPermissionRequest, DelegateGrant};
use dwn_rs_core::permissions::PermissionScope;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PermissionRequestInput {
    pub requester: String,
    pub scope: PermissionScope,
    #[serde(default)]
    pub delegated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DelegateGrantInput {
    pub grantor: String,
    pub grantee: String,
    pub scope: PermissionScope,
    pub date_expires: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GrantRevocationInput {
    pub grant: DelegateGrant,
    pub revocation_grant_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeriveDelegateKeysInput {
    pub owner_did: PortableDid,
    #[serde(default)]
    pub requests: Vec<ConnectPermissionRequest>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeriveContextKeyInput {
    pub owner_did: PortableDid,
    pub protocol: String,
    pub context_id: String,
}
