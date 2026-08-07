use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use ssi_dids_core::document::DIDVerificationMethod;
use ssi_dids_core::{DIDBuf, DIDURLBuf, Document, DID};
use ssi_jwk::JWK;

use crate::auth::jws::JwsError;

pub mod error;
pub mod jwk;
pub mod key;
pub mod r#static;
pub mod universal;

pub use error::ResolverError;
pub use jwk::JwkResolver;
pub use key::KeyResolver;
pub use r#static::StaticPublicKeyResolver;
pub use universal::UniversalResolver;

pub type ResolverFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub equivalent_id: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_id: Option<String>,
    #[serde(flatten)]
    pub properties: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(flatten)]
    pub properties: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub document: Document,
    pub document_metadata: DocumentMetadata,
    pub resolution_metadata: ResolutionMetadata,
}

impl Resolution {
    pub fn new(document: Document) -> Self {
        Self {
            document,
            document_metadata: DocumentMetadata::default(),
            resolution_metadata: ResolutionMetadata::default(),
        }
    }
}

pub trait DidResolver: Send + Sync {
    fn resolve<'a>(&'a self, did: &'a str)
        -> ResolverFuture<'a, Result<Resolution, ResolverError>>;

    /// Resolve a compatibility key identifier which is not a DID URL.
    fn resolve_static_kid(&self, _kid: &str) -> Option<JWK> {
        None
    }
}

pub trait DidMethodResolver: Send + Sync {
    fn method_name(&self) -> &str;

    fn resolve<'a>(&'a self, did: &'a DID)
        -> ResolverFuture<'a, Result<Resolution, ResolverError>>;
}

pub async fn resolve_signing_key(kid: &str, resolver: &dyn DidResolver) -> Result<JWK, JwsError> {
    if !kid.starts_with("did:") {
        return resolver
            .resolve_static_kid(kid)
            .ok_or_else(|| JwsError::PublicKeyNotFound {
                kid: kid.to_string(),
                available_ids: Vec::new(),
            });
    }

    let did_url = kid
        .parse::<DIDURLBuf>()
        .map_err(|_| JwsError::ResolutionFailed {
            did: kid.split('#').next().unwrap_or(kid).to_string(),
            source: ResolverError::InvalidDid,
        })?;
    let did = did_url.did().to_string();
    let resolution = resolver
        .resolve(&did)
        .await
        .map_err(|source| JwsError::ResolutionFailed {
            did: did.clone(),
            source,
        })?;

    if resolution.document.id != *did_url.did() {
        return Err(JwsError::ResolutionFailed {
            did: did.clone(),
            source: ResolverError::InvalidDocument(format!(
                "resolver returned '{}' for requested DID '{did}'",
                resolution.document.id
            )),
        });
    }

    let available_ids = resolution
        .document
        .verification_method
        .iter()
        .map(|method| method.id.to_string())
        .collect::<Vec<_>>();
    resolution
        .document
        .verification_method
        .iter()
        .find(|method| kid.ends_with(method.id.as_str()))
        .and_then(verification_method_jwk)
        .map(|jwk| jwk.to_public())
        .ok_or_else(|| JwsError::PublicKeyNotFound {
            kid: kid.to_string(),
            available_ids,
        })
}

pub(crate) fn verification_method_from_jwk(
    id: &str,
    type_: &str,
    controller: &DIDBuf,
    jwk: JWK,
) -> Result<DIDVerificationMethod, ResolverError> {
    let id = id
        .parse::<DIDURLBuf>()
        .map_err(|_| ResolverError::InvalidDid)?;
    let properties = BTreeMap::from([(
        "publicKeyJwk".to_string(),
        serde_json::to_value(jwk).map_err(|_| ResolverError::InvalidDid)?,
    )]);

    Ok(DIDVerificationMethod::new(
        id,
        type_.to_string(),
        controller.clone(),
        properties,
    ))
}

pub(crate) fn verification_method_jwk(method: &DIDVerificationMethod) -> Option<JWK> {
    method
        .properties
        .get("publicKeyJwk")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}
