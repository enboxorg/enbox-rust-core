//! Registry-based DID resolution with native methods and a compatibility fallback.
//!
//! `did:jwk`, `did:key`, `did:web`, and `did:dht` are registered by default. A registered method
//! is always authoritative: its failure never falls through to statically registered keys.
//! Applications can replace a native method explicitly with [`UniversalResolver::register`].

use std::collections::BTreeMap;
use std::sync::Arc;

use ssi_dids_core::{DIDBuf, DID};
use ssi_jwk::JWK;

use super::{
    DhtResolver, DidMethodResolver, DidResolver, JwkResolver, KeyResolver, Resolution,
    ResolverError, ResolverFuture, WebResolver,
};

#[derive(Clone)]
/// Dispatches complete-document resolution by DID method name.
pub struct UniversalResolver {
    methods: BTreeMap<String, Arc<dyn DidMethodResolver>>,
    fallback: Option<Arc<dyn DidResolver>>,
}

impl UniversalResolver {
    pub fn new() -> Self {
        let mut resolver = Self {
            methods: BTreeMap::new(),
            fallback: None,
        };
        resolver.register(JwkResolver);
        resolver.register(KeyResolver);
        resolver.register(WebResolver::default());
        resolver.register(DhtResolver::default());
        resolver
    }

    pub fn with_fallback<R>(fallback: R) -> Self
    where
        R: DidResolver + 'static,
    {
        Self::with_fallback_arc(Arc::new(fallback))
    }

    pub fn with_fallback_arc(fallback: Arc<dyn DidResolver>) -> Self {
        Self {
            fallback: Some(fallback),
            ..Self::new()
        }
    }

    pub fn with_method<R>(mut self, resolver: R) -> Self
    where
        R: DidMethodResolver + 'static,
    {
        self.register(resolver);
        self
    }

    pub fn register<R>(&mut self, resolver: R)
    where
        R: DidMethodResolver + 'static,
    {
        self.register_arc(Arc::new(resolver));
    }

    pub fn register_arc(&mut self, resolver: Arc<dyn DidMethodResolver>) {
        let method_name = resolver.method_name().to_string();
        self.methods.insert(method_name, resolver);
    }
}

impl Default for UniversalResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DidResolver for UniversalResolver {
    fn resolve<'a>(
        &'a self,
        did: &'a str,
    ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
        Box::pin(async move {
            let parsed = did
                .parse::<DIDBuf>()
                .map_err(|_| ResolverError::InvalidDid)?;

            let resolution = match self.methods.get(parsed.method_name()) {
                Some(method) => method.resolve(&parsed).await?,
                None => match &self.fallback {
                    Some(fallback) => fallback.resolve(&parsed).await?,
                    None => {
                        return Err(ResolverError::MethodNotSupported(
                            parsed.method_name().to_string(),
                        ));
                    }
                },
            };

            validate_document_id(&parsed, resolution)
        })
    }

    fn resolve_static_kid(&self, kid: &str) -> Option<JWK> {
        self.fallback
            .as_ref()
            .and_then(|fallback| fallback.resolve_static_kid(kid))
    }
}

fn validate_document_id(
    requested_did: &DID,
    resolution: Resolution,
) -> Result<Resolution, ResolverError> {
    if resolution.document.id != *requested_did {
        return Err(ResolverError::InvalidDocument(format!(
            "resolver returned '{}' for requested DID '{requested_did}'",
            resolution.document.id
        )));
    }
    Ok(resolution)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ssi_dids_core::Document;
    use ssi_jwk::{Base64urlUInt, OctetParams, Params};

    use super::*;
    use crate::auth::resolver::StaticPublicKeyResolver;

    fn jwk(byte: u8) -> JWK {
        JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(vec![byte; 32]),
            private_key: None,
        }))
    }

    fn did_jwk(jwk: &JWK) -> String {
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(jwk).unwrap());
        format!("did:jwk:{encoded}")
    }

    struct TestMethod {
        method_name: String,
        marker: &'static str,
        fail: bool,
    }

    impl DidMethodResolver for TestMethod {
        fn method_name(&self) -> &str {
            &self.method_name
        }

        fn resolve<'a>(
            &'a self,
            did: &'a DID,
        ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
            Box::pin(async move {
                if self.fail {
                    return Err(ResolverError::NotFound);
                }
                let mut document = Document::new(did.to_owned());
                document.property_set.insert(
                    "resolvedBy".to_string(),
                    serde_json::Value::String(self.marker.to_string()),
                );
                Ok(Resolution::new(document))
            })
        }
    }

    struct WrongDocumentResolver;

    impl DidMethodResolver for WrongDocumentResolver {
        fn method_name(&self) -> &str {
            "wrong"
        }

        fn resolve<'a>(
            &'a self,
            _did: &'a DID,
        ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
            Box::pin(async {
                let document = Document::new("did:wrong:other".parse().unwrap());
                Ok(Resolution::new(document))
            })
        }
    }

    #[tokio::test]
    async fn native_method_wins_over_matching_static_fallback() {
        let native_jwk = jwk(1);
        let did = did_jwk(&native_jwk);
        let fallback = StaticPublicKeyResolver::new(BTreeMap::from([(format!("{did}#0"), jwk(2))]));
        let resolver = UniversalResolver::with_fallback(fallback);

        let resolution = resolver.resolve(&did).await.unwrap();
        let resolved = serde_json::from_value::<JWK>(
            resolution.document.verification_method[0].properties["publicKeyJwk"].clone(),
        )
        .unwrap();
        assert!(resolved.equals_public(&native_jwk));
    }

    #[test]
    fn registers_dht_by_default() {
        assert!(UniversalResolver::new().methods.contains_key("dht"));
    }

    #[tokio::test]
    async fn registered_dht_method_wins_over_matching_static_fallback() {
        let did = "did:dht:alice";
        let fallback = StaticPublicKeyResolver::new(BTreeMap::from([(format!("{did}#0"), jwk(1))]));
        let resolver = UniversalResolver::with_fallback(fallback).with_method(TestMethod {
            method_name: "dht".to_string(),
            marker: "dht",
            fail: false,
        });

        let resolution = resolver.resolve(did).await.unwrap();
        assert_eq!(resolution.document.property_set["resolvedBy"], "dht");
    }

    #[tokio::test]
    async fn malformed_native_method_never_uses_fallback() {
        let did = "did:jwk:e30";
        let fallback = StaticPublicKeyResolver::new(BTreeMap::from([(format!("{did}#0"), jwk(1))]));
        let resolver = UniversalResolver::with_fallback(fallback);

        assert!(matches!(
            resolver.resolve(did).await,
            Err(ResolverError::InvalidDid)
        ));
    }

    #[tokio::test]
    async fn fallback_synthesizes_unregistered_method_document() {
        let fallback = StaticPublicKeyResolver::new(BTreeMap::from([(
            "did:example:alice#key-1".to_string(),
            jwk(1),
        )]));
        let resolver = UniversalResolver::with_fallback(fallback);

        let resolution = resolver.resolve("did:example:alice").await.unwrap();
        assert_eq!(resolution.document.id, "did:example:alice");
        assert_eq!(resolution.document.verification_method.len(), 1);
    }

    #[tokio::test]
    async fn runtime_named_registration_replaces_native_method() {
        let method_name = String::from("jwk");
        let resolver = UniversalResolver::new().with_method(TestMethod {
            method_name,
            marker: "override",
            fail: false,
        });

        let did = did_jwk(&jwk(1));
        let resolution = resolver.resolve(&did).await.unwrap();
        assert_eq!(resolution.document.property_set["resolvedBy"], "override");
    }

    #[tokio::test]
    async fn failing_override_does_not_use_fallback() {
        let did = did_jwk(&jwk(1));
        let fallback = StaticPublicKeyResolver::new(BTreeMap::from([(format!("{did}#0"), jwk(2))]));
        let resolver = UniversalResolver::with_fallback(fallback).with_method(TestMethod {
            method_name: "jwk".to_string(),
            marker: "override",
            fail: true,
        });

        assert!(matches!(
            resolver.resolve(&did).await,
            Err(ResolverError::NotFound)
        ));
    }

    #[tokio::test]
    async fn rejects_document_with_wrong_id() {
        let resolver = UniversalResolver::new().with_method(WrongDocumentResolver);
        assert!(matches!(
            resolver.resolve("did:wrong:requested").await,
            Err(ResolverError::InvalidDocument(_))
        ));
    }
}
