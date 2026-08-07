//! Registry-based DID resolution with native methods and a compatibility fallback.
//!
//! `did:jwk`, `did:key`, `did:web`, and `did:dht` are registered by default. A registered method
//! is always authoritative: its failure never falls through to statically registered keys.
//! Applications can replace a native method explicitly with [`UniversalResolver::register`].

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use ssi_dids_core::{DIDBuf, DID};
use ssi_jwk::JWK;

use super::{
    DhtResolver, DidMethodResolver, DidResolutionCache, DidResolver, JwkResolver, KeyResolver,
    MemoryDidResolutionCache, Resolution, ResolverError, ResolverFuture, WebResolver,
};

const DEFAULT_CACHE_TTL: Duration = Duration::minutes(15);

#[derive(Clone)]
/// Dispatches complete-document resolution by DID method name.
pub struct UniversalResolver {
    methods: BTreeMap<String, Arc<dyn DidMethodResolver>>,
    fallback: Option<Arc<dyn DidResolver>>,
    cache: Arc<dyn DidResolutionCache>,
}

impl UniversalResolver {
    pub fn new() -> Self {
        let mut resolver = Self {
            methods: BTreeMap::new(),
            fallback: None,
            cache: Arc::new(MemoryDidResolutionCache::default()),
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

    /// Replace the complete-document resolution cache used by this resolver.
    pub fn with_resolution_cache<C>(mut self, cache: C) -> Self
    where
        C: DidResolutionCache + 'static,
    {
        self.cache = Arc::new(cache);
        self
    }

    /// Replace the complete-document resolution cache used by this resolver.
    pub fn with_resolution_cache_arc(mut self, cache: Arc<dyn DidResolutionCache>) -> Self {
        self.cache = cache;
        self
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

    async fn cached_resolution(&self, did: &DID, now: DateTime<Utc>) -> Option<Resolution> {
        let did_str = did.as_str();
        let entry = self.cache.get(did_str).await.ok().flatten()?;
        if !entry.is_fresh_at(now) {
            return None;
        }

        match validate_document_id(did, entry.resolution) {
            Ok(resolution) => Some(resolution),
            Err(_) => {
                let _ = self.cache.invalidate(did_str).await;
                None
            }
        }
    }

    async fn cache_resolution(&self, did: &DID, resolution: &Resolution, now: DateTime<Utc>) {
        let fresh_until = cache_fresh_until(resolution, now);
        if fresh_until <= now {
            return;
        }

        let entry = resolution.clone().cached(now, fresh_until);
        let _ = self.cache.put(did.to_string(), entry).await;
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

            let now = Utc::now();
            if let Some(resolution) = self.cached_resolution(&parsed, now).await {
                return Ok(resolution);
            }

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

            let resolution = validate_document_id(&parsed, resolution)?;
            self.cache_resolution(&parsed, &resolution, Utc::now())
                .await;
            Ok(resolution)
        })
    }

    fn resolve_static_kid(&self, kid: &str) -> Option<JWK> {
        self.fallback
            .as_ref()
            .and_then(|fallback| fallback.resolve_static_kid(kid))
    }
}

fn cache_fresh_until(resolution: &Resolution, now: DateTime<Utc>) -> DateTime<Utc> {
    let default_expiry = now + DEFAULT_CACHE_TTL;
    resolution
        .resolution_metadata
        .expires
        .as_deref()
        .and_then(|expires| DateTime::parse_from_rfc3339(expires).ok())
        .map(|expires| expires.with_timezone(&Utc).min(default_expiry))
        .unwrap_or(default_expiry)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ssi_dids_core::Document;
    use ssi_jwk::{Base64urlUInt, OctetParams, Params};

    use super::*;
    use crate::auth::resolver::{
        CachedResolution, MemoryDidResolutionCache, ResolutionCacheError, StaticPublicKeyResolver,
    };

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

    struct CountingMethod {
        method_name: &'static str,
        marker: &'static str,
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    impl DidMethodResolver for CountingMethod {
        fn method_name(&self) -> &str {
            self.method_name
        }

        fn resolve<'a>(
            &'a self,
            did: &'a DID,
        ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
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

    struct FailingCache;

    impl DidResolutionCache for FailingCache {
        fn get<'a>(
            &'a self,
            _did: &'a str,
        ) -> ResolverFuture<'a, Result<Option<CachedResolution>, ResolutionCacheError>> {
            Box::pin(async { Err(ResolutionCacheError::Backend("read failure".to_string())) })
        }

        fn put<'a>(
            &'a self,
            _did: String,
            _entry: CachedResolution,
        ) -> ResolverFuture<'a, Result<(), ResolutionCacheError>> {
            Box::pin(async { Err(ResolutionCacheError::Backend("write failure".to_string())) })
        }

        fn invalidate<'a>(
            &'a self,
            _did: &'a str,
        ) -> ResolverFuture<'a, Result<bool, ResolutionCacheError>> {
            Box::pin(async { Err(ResolutionCacheError::Backend("delete failure".to_string())) })
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

    #[tokio::test]
    async fn caches_validated_successful_resolutions() {
        let cache = MemoryDidResolutionCache::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = UniversalResolver::new()
            .with_resolution_cache(cache)
            .with_method(CountingMethod {
                method_name: "cached",
                marker: "method",
                calls: calls.clone(),
                fail: false,
            });

        for _ in 0..2 {
            let resolution = resolver.resolve("did:cached:alice").await.unwrap();
            assert_eq!(resolution.document.property_set["resolvedBy"], "method");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ignores_expired_or_invalid_cached_resolutions() {
        let cache = MemoryDidResolutionCache::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = UniversalResolver::new()
            .with_resolution_cache(cache.clone())
            .with_method(CountingMethod {
                method_name: "cached",
                marker: "method",
                calls: calls.clone(),
                fail: false,
            });
        let did = "did:cached:alice".parse::<DIDBuf>().unwrap();
        let now = Utc::now();

        cache
            .put(
                did.to_string(),
                Resolution::new(Document::new(did.clone()))
                    .cached(now - Duration::minutes(16), now - Duration::minutes(1)),
            )
            .await
            .unwrap();
        let resolution = resolver.resolve(did.as_str()).await.unwrap();
        assert_eq!(resolution.document.property_set["resolvedBy"], "method");

        cache
            .put(
                did.to_string(),
                Resolution::new(Document::new("did:cached:other".parse().unwrap()))
                    .cached(now, now + Duration::minutes(15)),
            )
            .await
            .unwrap();
        let resolution = resolver.resolve(did.as_str()).await.unwrap();
        assert_eq!(resolution.document.property_set["resolvedBy"], "method");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn resolution_and_cache_errors_are_not_cached_or_masked() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = UniversalResolver::new()
            .with_resolution_cache(FailingCache)
            .with_method(CountingMethod {
                method_name: "cached",
                marker: "method",
                calls: calls.clone(),
                fail: false,
            });

        assert!(resolver.resolve("did:cached:alice").await.is_ok());
        assert!(resolver.resolve("did:cached:alice").await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let failed_calls = Arc::new(AtomicUsize::new(0));
        let failing_resolver = UniversalResolver::new().with_method(CountingMethod {
            method_name: "failed",
            marker: "unused",
            calls: failed_calls.clone(),
            fail: true,
        });
        assert!(matches!(
            failing_resolver.resolve("did:failed:alice").await,
            Err(ResolverError::NotFound)
        ));
        assert!(matches!(
            failing_resolver.resolve("did:failed:alice").await,
            Err(ResolverError::NotFound)
        ));
        assert_eq!(failed_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn document_expiry_caps_the_default_cache_ttl() {
        let now = Utc::now();
        let mut resolution = Resolution::new(Document::new("did:example:alice".parse().unwrap()));
        resolution.resolution_metadata.expires = Some((now + Duration::minutes(5)).to_rfc3339());

        assert_eq!(
            cache_fresh_until(&resolution, now),
            now + Duration::minutes(5)
        );
        resolution.resolution_metadata.expires = Some((now + Duration::minutes(20)).to_rfc3339());
        assert_eq!(cache_fresh_until(&resolution, now), now + DEFAULT_CACHE_TTL);
    }
}
