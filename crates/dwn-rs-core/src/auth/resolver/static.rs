use std::collections::BTreeMap;

use serde_json::json;
use ssi_dids_core::document::verification_method::ValueOrReference;
use ssi_dids_core::document::VerificationRelationships;
use ssi_dids_core::{DIDBuf, DIDURLBuf, Document};
use ssi_jwk::JWK;

use super::{verification_method_from_jwk, DidResolver, Resolution, ResolverError, ResolverFuture};

const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const JWS_2020_CONTEXT: &str = "https://w3id.org/security/suites/jws-2020/v1";

/// Compatibility resolver for applications that register public keys directly by `kid`.
///
/// DID URL keys are exposed as synthesized DID documents when this resolver is installed as a
/// [`super::UniversalResolver`] fallback. Non-DID key identifiers remain available through
/// [`DidResolver::resolve_static_kid`].
#[derive(Debug, Default, Clone)]
pub struct StaticPublicKeyResolver {
    public_keys: BTreeMap<String, JWK>,
}

impl StaticPublicKeyResolver {
    pub fn new(public_keys: BTreeMap<String, JWK>) -> Self {
        Self { public_keys }
    }

    pub fn insert(&mut self, kid: impl Into<String>, public_jwk: JWK) {
        self.public_keys.insert(kid.into(), public_jwk);
    }
}

impl DidResolver for StaticPublicKeyResolver {
    fn resolve<'a>(
        &'a self,
        did: &'a str,
    ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
        Box::pin(async move {
            let did = did
                .parse::<DIDBuf>()
                .map_err(|_| ResolverError::InvalidDid)?;
            let mut methods = Vec::new();
            let mut references = Vec::new();

            for (kid, jwk) in &self.public_keys {
                let Ok(kid_url) = kid.parse::<DIDURLBuf>() else {
                    continue;
                };
                if did != kid_url.did() {
                    continue;
                }

                methods.push(verification_method_from_jwk(
                    kid,
                    "JsonWebKey2020",
                    &did,
                    jwk.to_public(),
                )?);
                references.push(ValueOrReference::from(kid_url));
            }

            if methods.is_empty() {
                return Err(ResolverError::MethodNotSupported(
                    did.method_name().to_string(),
                ));
            }

            let mut document = Document::new(did);
            document.property_set.insert(
                "@context".to_string(),
                json!([DID_CONTEXT, JWS_2020_CONTEXT]),
            );
            document.verification_method = methods;
            document.verification_relationships = VerificationRelationships {
                authentication: references.clone(),
                assertion_method: references.clone(),
                key_agreement: Vec::new(),
                capability_invocation: references.clone(),
                capability_delegation: references,
            };

            Ok(Resolution::new(document))
        })
    }

    fn resolve_static_kid(&self, kid: &str) -> Option<ssi_jwk::JWK> {
        self.public_keys.get(kid).map(ssi_jwk::JWK::to_public)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ssi_jwk::{Base64urlUInt, OctetParams, Params, JWK};

    use super::*;

    fn private_jwk(byte: u8) -> JWK {
        JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(vec![byte; 32]),
            private_key: Some(Base64urlUInt(vec![byte + 1; 32])),
        }))
    }

    #[tokio::test]
    async fn synthesizes_public_signing_document_for_matching_did_keys() {
        let resolver = StaticPublicKeyResolver::new(BTreeMap::from([
            ("did:example:alice#key-1".to_string(), private_jwk(1)),
            ("did:example:alice#key-2".to_string(), private_jwk(2)),
            ("did:example:bob#key-1".to_string(), private_jwk(3)),
            ("legacy-key".to_string(), private_jwk(4)),
        ]));

        let resolution = DidResolver::resolve(&resolver, "did:example:alice")
            .await
            .unwrap();
        assert_eq!(resolution.document.verification_method.len(), 2);
        assert!(resolution
            .document
            .verification_method
            .iter()
            .all(|method| {
                let jwk = serde_json::from_value::<JWK>(method.properties["publicKeyJwk"].clone())
                    .unwrap();
                jwk.is_public()
            }));
        assert_eq!(
            resolution
                .document
                .verification_relationships
                .authentication
                .len(),
            2
        );
        assert!(resolution
            .document
            .verification_relationships
            .key_agreement
            .is_empty());
        assert!(matches!(
            DidResolver::resolve(&resolver, "did:example:carol").await,
            Err(ResolverError::MethodNotSupported(method)) if method == "example"
        ));
    }

    #[test]
    fn exact_static_lookup_is_public_only() {
        let resolver = StaticPublicKeyResolver::new(BTreeMap::from([(
            "legacy-key".to_string(),
            private_jwk(1),
        )]));

        let jwk = resolver.resolve_static_kid("legacy-key").unwrap();
        assert!(jwk.is_public());
        assert!(resolver.resolve_static_kid("missing").is_none());
    }
}
