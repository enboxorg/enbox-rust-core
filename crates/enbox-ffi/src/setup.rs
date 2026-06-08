//! Glue between [`dwn_rs_core::setup`] and the FFI surface.
//!
//! Exposes a local [`ProtocolEndpoint`] backed by [`SqliteNativeDwn`] plus
//! the helpers needed to extract a `ProtocolsConfigure`/`ProtocolsQuery`
//! signer from a [`PortableDid`].

use std::sync::Arc;

use chrono::Utc;
use dwn_rs_core::agent::{AgentIdentityError, AgentIdentityResult, PortableDid};
use dwn_rs_core::auth::{Jws, JwsPrivateJwk, PrivateJwkSigner};
use dwn_rs_core::cid::generate_cid_from_json;
use dwn_rs_core::descriptors::{ConfigureDescriptor, ProtocolQueryDescriptor};
use dwn_rs_core::interfaces::messages::descriptors::protocols::QueryFilter;
use dwn_rs_core::protocols::Definition;
use dwn_rs_core::setup::{ProtocolEndpoint, SetupFuture};
use dwn_rs_stores::SqliteNativeDwn;
use serde_json::Value as JsonValue;

/// Build a [`PrivateJwkSigner`] from a [`PortableDid`].
///
/// Picks the first Ed25519 private key in `portable_did.private_keys` and
/// pairs it with the matching verification method id (preferring an
/// `assertion_method` entry, falling back to `authentication`). Errors with
/// `code = "AgentSignerMissing"` if the DID has no usable signing material.
pub fn signer_from_portable_did(
    portable_did: &PortableDid,
) -> AgentIdentityResult<PrivateJwkSigner> {
    let private_jwk = portable_did
        .private_keys
        .iter()
        .find(|jwk| jwk.crv == "Ed25519" && jwk.d.is_some())
        .ok_or_else(|| {
            AgentIdentityError::new(
                "AgentSignerMissing",
                format!(
                    "DID {} does not include an Ed25519 private key suitable for DWN signing",
                    portable_did.uri
                ),
            )
        })?;

    let kid = private_jwk.kid.clone().or_else(|| {
        portable_did
            .document
            .assertion_method
            .first()
            .cloned()
            .or_else(|| portable_did.document.authentication.first().cloned())
    });
    let kid = kid.ok_or_else(|| {
        AgentIdentityError::new(
            "AgentSignerMissing",
            format!(
                "DID {} has no assertion or authentication verification method id",
                portable_did.uri
            ),
        )
    })?;

    let algorithm = private_jwk
        .alg
        .clone()
        .unwrap_or_else(|| "EdDSA".to_string());
    let private = JwsPrivateJwk {
        kty: private_jwk.kty.clone(),
        crv: private_jwk.crv.clone(),
        d: private_jwk
            .d
            .clone()
            .expect("filtered above: Ed25519 private key has d"),
        x: private_jwk.x.clone(),
        y: private_jwk.y.clone(),
        kid: Some(kid.clone()),
        alg: Some(algorithm.clone()),
    };
    Ok(PrivateJwkSigner::new(kid, algorithm, private))
}

/// Build a signed `ProtocolsConfigure` message JSON suitable for
/// `Dwn::process_message`.
pub fn build_signed_protocols_configure(
    definition: Definition,
    signer: &PrivateJwkSigner,
) -> AgentIdentityResult<JsonValue> {
    let descriptor = ConfigureDescriptor {
        message_timestamp: Utc::now(),
        definition,
        permission_grant_id: None,
    };
    sign_descriptor(&descriptor, signer, "AgentProtocolsConfigureInvalid")
}

/// Build a signed `ProtocolsQuery` message JSON filtered by protocol URI.
pub fn build_signed_protocols_query(
    protocol: &str,
    signer: &PrivateJwkSigner,
) -> AgentIdentityResult<JsonValue> {
    let descriptor = ProtocolQueryDescriptor {
        message_timestamp: Utc::now(),
        filter: Some(QueryFilter {
            protocol: Some(protocol.to_string()),
            recipient: None,
        }),
        permission_grant_id: None,
    };
    sign_descriptor(&descriptor, signer, "AgentProtocolsQueryInvalid")
}

fn sign_descriptor<D: serde::Serialize>(
    descriptor: &D,
    signer: &PrivateJwkSigner,
    invalid_code: &str,
) -> AgentIdentityResult<JsonValue> {
    let descriptor_json = serde_json::to_value(descriptor)
        .map_err(|err| AgentIdentityError::new(invalid_code, err.to_string()))?;
    let descriptor_cid = generate_cid_from_json(&descriptor_json)
        .map_err(|err| AgentIdentityError::new(invalid_code, err.to_string()))?
        .to_string();
    let payload = serde_json::json!({ "descriptorCid": descriptor_cid });
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|err| AgentIdentityError::new(invalid_code, err.to_string()))?;
    let signature = Jws::create_general(&payload_bytes, std::slice::from_ref(signer))
        .map_err(|err| AgentIdentityError::new(invalid_code, err.to_string()))?;
    Ok(serde_json::json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    }))
}

/// [`ProtocolEndpoint`] backed by a local [`SqliteNativeDwn`].
///
/// `query_protocol` issues a signed `ProtocolsQuery` filtered by URI and
/// returns the latest `Definition` from the reply body, if any.
/// `configure_protocol` issues a signed `ProtocolsConfigure`.
#[derive(Clone)]
pub struct LocalDwnProtocolEndpoint {
    node: Arc<SqliteNativeDwn>,
    signer: PrivateJwkSigner,
}

impl LocalDwnProtocolEndpoint {
    pub fn new(node: Arc<SqliteNativeDwn>, signer: PrivateJwkSigner) -> Self {
        Self { node, signer }
    }

    async fn process(&self, tenant: &str, message: JsonValue) -> JsonValue {
        let reply = self.node.dwn().process_message(tenant, message).await;
        serde_json::to_value(reply).unwrap_or(JsonValue::Null)
    }
}

impl ProtocolEndpoint for LocalDwnProtocolEndpoint {
    fn query_protocol<'a>(
        &'a self,
        tenant: &'a str,
        protocol: &'a str,
    ) -> SetupFuture<'a, Option<Definition>> {
        Box::pin(async move {
            let message = build_signed_protocols_query(protocol, &self.signer)?;
            let reply = self.process(tenant, message).await;
            require_ok(&reply, "AgentProtocolsQueryRejected")?;
            // DwnReply body is `#[serde(flatten)]`, so the `entries` field
            // lives at the top level of the JSON, not under `body`.
            let Some(entries) = reply.get("entries") else {
                return Ok(None);
            };
            let Some(array) = entries.as_array() else {
                return Ok(None);
            };
            let Some(entry) = array.last() else {
                return Ok(None);
            };
            let definition_json = entry
                .get("descriptor")
                .and_then(|descriptor| descriptor.get("definition"))
                .ok_or_else(|| {
                    AgentIdentityError::new(
                        "AgentProtocolsQueryRejected",
                        "ProtocolsQuery reply entry is missing descriptor.definition",
                    )
                })?;
            let definition: Definition =
                serde_json::from_value(definition_json.clone()).map_err(|err| {
                    AgentIdentityError::new("AgentProtocolsQueryRejected", err.to_string())
                })?;
            Ok(Some(definition))
        })
    }

    fn configure_protocol<'a>(
        &'a self,
        tenant: &'a str,
        definition: Definition,
    ) -> SetupFuture<'a, ()> {
        Box::pin(async move {
            let message = build_signed_protocols_configure(definition, &self.signer)?;
            let reply = self.process(tenant, message).await;
            require_ok(&reply, "AgentProtocolsConfigureRejected")?;
            Ok(())
        })
    }
}

fn require_ok(reply: &JsonValue, error_code: &str) -> AgentIdentityResult<()> {
    let status = reply.get("status").ok_or_else(|| {
        AgentIdentityError::new(error_code, "DWN reply is missing a status object")
    })?;
    let code = status
        .get("code")
        .and_then(|code| code.as_u64())
        .unwrap_or(500);
    if (200..400).contains(&code) {
        return Ok(());
    }
    let detail = status
        .get("detail")
        .and_then(|detail| detail.as_str())
        .unwrap_or("");
    Err(AgentIdentityError::new(
        error_code,
        format!("DWN reply status {code}: {detail}"),
    ))
}
