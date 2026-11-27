//! Glue between [`dwn_rs_agent::auth::setup`] and the FFI surface.
//!
//! Exposes a local [`ModuleEndpoint`] backed by [`SqliteNativeDwn`] plus
//! the helpers needed to extract a `ModulesConfigure`/`ModulesQuery`
//! signer from a [`PortableDid`].

use std::sync::Arc;

use chrono::Utc;
use dwn_rs_agent::agent::{AgentIdentityError, AgentIdentityResult, PortableDid};
use dwn_rs_agent::auth::setup::{ModuleEndpoint, SetupFuture};
use dwn_rs_core::auth::{Jws, PrivateJwkSigner, JWK};
use dwn_rs_core::cid::generate_cid_from_json;
use dwn_rs_core::descriptors::{ModulesConfigureDescriptor, ModulesQueryDescriptor};
use dwn_rs_core::interfaces::messages::descriptors::modules::QueryFilter;
use dwn_rs_core::modules::Definition;
use dwn_rs_stores::SqliteNativeDwn;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use ssi_jwk::{Algorithm, Params};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PushModuleInput {
    pub tenant_did: PortableDid,
    pub remote_url: String,
    pub definition: Definition,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunRestoreFlowInput {
    pub agent_did: PortableDid,
    pub remote_url: String,
    #[serde(default)]
    pub modules: Vec<Definition>,
}

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
        .find(|jwk| {
            matches!(
                &jwk.params,
                Params::OKP(params)
                    if params.curve == "Ed25519" && params.private_key.is_some()
            )
        })
        .ok_or_else(|| {
            AgentIdentityError::new(
                "AgentSignerMissing",
                format!(
                    "DID {} does not include an Ed25519 private key suitable for DWN signing",
                    portable_did.uri
                ),
            )
        })?;

    // `did:jwk` has one canonical verification method (`#0`). Normalize
    // persisted agent identities created before native DID resolution used
    // that method id, rather than allowing a legacy static KID to shadow the
    // method's document.
    let kid = portable_did
        .uri
        .starts_with("did:jwk:")
        .then(|| format!("{}#0", portable_did.uri))
        .or_else(|| private_jwk.key_id.clone())
        .or_else(|| {
            portable_did
                .document
                .verification_relationships
                .assertion_method
                .first()
                .or_else(|| {
                    portable_did
                        .document
                        .verification_relationships
                        .authentication
                        .first()
                })
                .map(|relationship| {
                    relationship
                        .id()
                        .resolve(&portable_did.document.id)
                        .to_string()
                })
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

    let algorithm = private_jwk.algorithm.unwrap_or(Algorithm::EdDSA);
    let mut private: JWK = private_jwk.clone();
    private.key_id = Some(kid.clone());
    Ok(PrivateJwkSigner::new(kid, algorithm, private))
}

/// Build a signed `ModulesConfigure` message JSON suitable for
/// `Dwn::process_message`.
pub async fn build_signed_modules_configure(
    definition: Definition,
    signer: &PrivateJwkSigner,
) -> AgentIdentityResult<JsonValue> {
    let descriptor = ModulesConfigureDescriptor {
        message_timestamp: Utc::now(),
        definition,
        permission_grant_id: None,
    };
    sign_descriptor(&descriptor, signer, "AgentModulesConfigureInvalid").await
}

/// Build a signed `ModulesQuery` message JSON filtered by module URI.
pub async fn build_signed_modules_query(
    module: &str,
    signer: &PrivateJwkSigner,
) -> AgentIdentityResult<JsonValue> {
    let descriptor = ModulesQueryDescriptor {
        message_timestamp: Utc::now(),
        filter: Some(QueryFilter {
            module: Some(module.to_string()),
            recipient: None,
        }),
        permission_grant_id: None,
    };
    sign_descriptor(&descriptor, signer, "AgentModulesQueryInvalid").await
}

async fn sign_descriptor<D: serde::Serialize>(
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
    let signature = Jws::create(&payload_bytes, std::slice::from_ref(signer))
        .await
        .map_err(|err| AgentIdentityError::new(invalid_code, err.to_string()))?;
    Ok(serde_json::json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    }))
}

/// [`ModuleEndpoint`] backed by a local [`SqliteNativeDwn`].
///
/// `query_module` issues a signed `ModulesQuery` filtered by URI and
/// returns the latest `Definition` from the reply body, if any.
/// `configure_module` issues a signed `ModulesConfigure`.
#[derive(Clone)]
pub struct LocalDwnModuleEndpoint {
    node: Arc<SqliteNativeDwn>,
    signer: PrivateJwkSigner,
}

impl LocalDwnModuleEndpoint {
    pub fn new(node: Arc<SqliteNativeDwn>, signer: PrivateJwkSigner) -> Self {
        Self { node, signer }
    }

    async fn process(&self, tenant: &str, message: JsonValue) -> JsonValue {
        let reply = self.node.dwn().process_message(tenant, message).await;
        serde_json::to_value(reply).unwrap_or(JsonValue::Null)
    }
}

impl ModuleEndpoint for LocalDwnModuleEndpoint {
    fn query_module<'a>(
        &'a self,
        tenant: &'a str,
        module: &'a str,
    ) -> SetupFuture<'a, Option<Definition>> {
        Box::pin(async move {
            let message = build_signed_modules_query(module, &self.signer).await?;
            let reply = self.process(tenant, message).await;
            require_ok(&reply, "AgentModulesQueryRejected")?;
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
                        "AgentModulesQueryRejected",
                        "ModulesQuery reply entry is missing descriptor.definition",
                    )
                })?;
            let definition: Definition =
                serde_json::from_value(definition_json.clone()).map_err(|err| {
                    AgentIdentityError::new("AgentModulesQueryRejected", err.to_string())
                })?;
            Ok(Some(definition))
        })
    }

    fn configure_module<'a>(
        &'a self,
        tenant: &'a str,
        definition: Definition,
    ) -> SetupFuture<'a, ()> {
        Box::pin(async move {
            let message = build_signed_modules_configure(definition, &self.signer).await?;
            let reply = self.process(tenant, message).await;
            require_ok(&reply, "AgentModulesConfigureRejected")?;
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

/// [`ModuleEndpoint`] backed by a remote `@enbox/dwn-server`-style HTTP
/// endpoint.
///
/// Sends signed `ModulesQuery`/`ModulesConfigure` messages as body-framed
/// JSON-RPC requests. Mirrors the transport used by
/// [`dwn_rs_core::sync::endpoint::HttpSyncEndpoint`]: the response payload
/// is read from the `dwn-response` header when present, otherwise from
/// the response body.
#[derive(Clone)]
pub struct HttpDwnModuleEndpoint {
    url: String,
    client: reqwest::Client,
    signer: PrivateJwkSigner,
}

impl HttpDwnModuleEndpoint {
    pub fn new(url: impl Into<String>, signer: PrivateJwkSigner) -> AgentIdentityResult<Self> {
        let client = reqwest::Client::builder()
            .user_agent(format!("enbox-ffi/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| {
                AgentIdentityError::new("HttpModuleClientBuildFailed", err.to_string())
            })?;
        Ok(Self::with_client(url, client, signer))
    }

    pub fn with_client(
        url: impl Into<String>,
        client: reqwest::Client,
        signer: PrivateJwkSigner,
    ) -> Self {
        Self {
            url: url.into(),
            client,
            signer,
        }
    }

    async fn process(&self, tenant: &str, message: JsonValue) -> AgentIdentityResult<JsonValue> {
        let envelope = serde_json::json!({
            "jsonrpc": "2.0",
            "id": ulid::Ulid::generate().to_string(),
            "method": "dwn.processMessage",
            "params": { "target": tenant, "message": message }
        });
        let body = dwn_rs_core::utils::http_rpc_framing::encode_request_body(
            &serde_json::to_vec(&envelope).map_err(|err| {
                AgentIdentityError::new("HttpModuleResponseInvalid", err.to_string())
            })?,
            None,
        )
        .map_err(|err| AgentIdentityError::new("HttpModuleResponseInvalid", err.to_string()))?;
        let response = self
            .client
            .post(&self.url)
            .header(
                reqwest::header::CONTENT_TYPE,
                dwn_rs_core::utils::http_rpc_framing::HTTP_DWN_RPC_MEDIA_TYPE,
            )
            .body(body)
            .send()
            .await
            .map_err(|err| AgentIdentityError::new("HttpModuleTransportFailed", err.to_string()))?;
        if !response.status().is_success() {
            return Err(AgentIdentityError::new(
                "HttpModuleTransportFailed",
                format!("remote server returned HTTP {}", response.status()),
            ));
        }

        let payload = if let Some(header) = response.headers().get("dwn-response") {
            header
                .to_str()
                .map_err(|err| {
                    AgentIdentityError::new("HttpModuleResponseInvalid", err.to_string())
                })?
                .to_string()
        } else {
            response.text().await.map_err(|err| {
                AgentIdentityError::new("HttpModuleTransportFailed", err.to_string())
            })?
        };
        let envelope: JsonValue = serde_json::from_str(&payload)
            .map_err(|err| AgentIdentityError::new("HttpModuleResponseInvalid", err.to_string()))?;
        if let Some(error) = envelope.get("error") {
            return Err(AgentIdentityError::new(
                "HttpModuleJsonRpcError",
                error.to_string(),
            ));
        }
        envelope.pointer("/result/reply").cloned().ok_or_else(|| {
            AgentIdentityError::new(
                "HttpModuleResponseInvalid",
                "missing result.reply in JSON-RPC response",
            )
        })
    }
}

impl ModuleEndpoint for HttpDwnModuleEndpoint {
    fn query_module<'a>(
        &'a self,
        tenant: &'a str,
        module: &'a str,
    ) -> SetupFuture<'a, Option<Definition>> {
        Box::pin(async move {
            let message = build_signed_modules_query(module, &self.signer).await?;
            let reply = self.process(tenant, message).await?;
            require_ok(&reply, "HttpModulesQueryRejected")?;
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
                        "HttpModulesQueryRejected",
                        "ModulesQuery reply entry is missing descriptor.definition",
                    )
                })?;
            let definition: Definition =
                serde_json::from_value(definition_json.clone()).map_err(|err| {
                    AgentIdentityError::new("HttpModulesQueryRejected", err.to_string())
                })?;
            Ok(Some(definition))
        })
    }

    fn configure_module<'a>(
        &'a self,
        tenant: &'a str,
        definition: Definition,
    ) -> SetupFuture<'a, ()> {
        Box::pin(async move {
            let message = build_signed_modules_configure(definition, &self.signer).await?;
            let reply = self.process(tenant, message).await?;
            require_ok(&reply, "HttpModulesConfigureRejected")?;
            Ok(())
        })
    }
}
