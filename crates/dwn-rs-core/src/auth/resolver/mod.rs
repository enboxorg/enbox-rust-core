use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use ssi_dids_core::document::DIDVerificationMethod;
use ssi_dids_core::{DIDBuf, DIDURLBuf, Document, DID};
use ssi_jwk::JWK;

use crate::auth::jws::JwsError;

pub mod dht;
pub mod error;
pub(crate) mod http;
pub mod jwk;
pub mod key;
pub mod r#static;
pub mod universal;
pub mod web;

pub use dht::{DhtResolver, DhtResolverConfig};
pub use error::ResolverError;
pub use jwk::JwkResolver;
pub use key::KeyResolver;
pub use r#static::StaticPublicKeyResolver;
pub use universal::UniversalResolver;
pub use web::{WebResolver, WebResolverConfig};

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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ssi_jwk::JWK;

    use super::*;

    #[derive(Clone)]
    struct DocumentResolver {
        resolution: Resolution,
    }

    impl DidResolver for DocumentResolver {
        fn resolve<'a>(
            &'a self,
            _did: &'a str,
        ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
            Box::pin(async move { Ok(self.resolution.clone()) })
        }
    }

    fn resolver_with_methods(methods: Vec<(&str, JWK)>) -> DocumentResolver {
        let did = "did:example:alice".parse::<DIDBuf>().unwrap();
        let mut document = Document::new(did.clone());
        document.verification_method = methods
            .into_iter()
            .map(|(id, jwk)| verification_method_from_jwk(id, "JsonWebKey2020", &did, jwk).unwrap())
            .collect();
        DocumentResolver {
            resolution: Resolution::new(document),
        }
    }

    #[tokio::test]
    async fn signing_key_uses_suffix_match_without_relationship_gating() {
        let first = JWK::generate_ed25519().unwrap();
        let selected = JWK::generate_ed25519().unwrap();
        let resolver = resolver_with_methods(vec![
            ("did:example:alice#key-1", first),
            ("did:example:alice#key-2", selected.clone()),
        ]);

        // The document deliberately has no authentication or assertionMethod relationships.
        let kid = "did:example:alice?alias=did:example:alice#key-2";
        let resolved = resolve_signing_key(kid, &resolver).await.unwrap();

        assert!(resolved.equals_public(&selected));
        assert!(resolved.is_public());
    }

    #[tokio::test]
    async fn missing_signing_key_reports_available_verification_method_ids() {
        let resolver = resolver_with_methods(vec![
            ("did:example:alice#key-1", JWK::generate_ed25519().unwrap()),
            ("did:example:alice#key-2", JWK::generate_ed25519().unwrap()),
        ]);

        let error = resolve_signing_key("did:example:alice#missing", &resolver)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            JwsError::PublicKeyNotFound {
                ref kid,
                ref available_ids,
            } if kid == "did:example:alice#missing"
                && available_ids == &[
                    "did:example:alice#key-1".to_string(),
                    "did:example:alice#key-2".to_string(),
                ]
        ));
    }

    #[tokio::test]
    async fn non_did_kid_uses_exact_static_lookup_and_returns_only_public_material() {
        let private_jwk = JWK::generate_ed25519().unwrap();
        let resolver = StaticPublicKeyResolver::new(BTreeMap::from([(
            "legacy-key".to_string(),
            private_jwk.clone(),
        )]));

        let resolved = resolve_signing_key("legacy-key", &resolver).await.unwrap();
        assert!(resolved.equals_public(&private_jwk));
        assert!(resolved.is_public());
        assert!(matches!(
            resolve_signing_key("legacy-key#suffix", &resolver).await,
            Err(JwsError::PublicKeyNotFound {
                ref kid,
                ref available_ids,
            }) if kid == "legacy-key#suffix" && available_ids.is_empty()
        ));
    }

    #[tokio::test]
    async fn malformed_did_kid_never_uses_static_lookup() {
        let kid = "did:not a valid DID";
        let resolver = StaticPublicKeyResolver::new(BTreeMap::from([(
            kid.to_string(),
            JWK::generate_ed25519().unwrap(),
        )]));

        assert!(matches!(
            resolve_signing_key(kid, &resolver).await,
            Err(JwsError::ResolutionFailed {
                source: ResolverError::InvalidDid,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn supported_method_failure_is_typed_and_never_uses_fallback() {
        let did = "did:jwk:e30";
        let kid = format!("{did}#0");
        let fallback = StaticPublicKeyResolver::new(BTreeMap::from([(
            kid.clone(),
            JWK::generate_ed25519().unwrap(),
        )]));
        let resolver = UniversalResolver::with_fallback(fallback);

        let error = resolve_signing_key(&kid, &resolver).await.unwrap_err();

        assert!(matches!(
            &error,
            JwsError::ResolutionFailed {
                did,
                source: ResolverError::InvalidDid,
            } if did == "did:jwk:e30"
        ));
        assert_eq!(error.code(), "GeneralJwsVerifierGetPublicKeyNotFound");
    }
}
