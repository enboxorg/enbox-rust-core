//! Storage primitives for complete DID-document resolution results.
//!
//! This is deliberately distinct from `identity::agent::PortableDidStore`, which stores
//! agent-owned portable identities and may contain private key material. Resolution results are
//! externally obtained documents whose freshness and version metadata must be retained.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};

use super::{Resolution, ResolverFuture};

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ResolutionCacheError {
    #[error("resolution cache backend failure: {0}")]
    Backend(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// A complete resolved DID document together with its cache freshness bounds.
pub struct CachedResolution {
    pub resolution: Resolution,
    pub cached_at: DateTime<Utc>,
    pub fresh_until: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_until: Option<DateTime<Utc>>,
}

impl CachedResolution {
    pub fn is_fresh_at(&self, now: DateTime<Utc>) -> bool {
        now < self.fresh_until
    }

    pub fn is_usable_stale_at(&self, now: DateTime<Utc>) -> bool {
        !self.is_fresh_at(now) && self.stale_until.is_some_and(|until| now < until)
    }
}

/// Persists complete externally resolved DID documents.
///
/// The resolver owns cache policy and single-flight coordination. Implementations only retain
/// entries and expose explicit invalidation, so a durable backend can be substituted later.
pub trait DidResolutionCache: Send + Sync {
    fn get<'a>(
        &'a self,
        did: &'a str,
    ) -> ResolverFuture<'a, Result<Option<CachedResolution>, ResolutionCacheError>>;

    fn put<'a>(
        &'a self,
        did: String,
        entry: CachedResolution,
    ) -> ResolverFuture<'a, Result<(), ResolutionCacheError>>;

    fn invalidate<'a>(
        &'a self,
        did: &'a str,
    ) -> ResolverFuture<'a, Result<bool, ResolutionCacheError>>;
}

#[derive(Clone, Default)]
/// Process-local storage for resolution-cache entries.
///
/// This implementation intentionally does not decide whether a stale entry may be used; that is
/// resolver policy and differs for ordinary and agent-managed DIDs.
pub struct MemoryDidResolutionCache {
    entries: Arc<RwLock<BTreeMap<String, CachedResolution>>>,
}

impl DidResolutionCache for MemoryDidResolutionCache {
    fn get<'a>(
        &'a self,
        did: &'a str,
    ) -> ResolverFuture<'a, Result<Option<CachedResolution>, ResolutionCacheError>> {
        Box::pin(async move {
            self.entries
                .read()
                .map_err(|error| ResolutionCacheError::Backend(error.to_string()))
                .map(|entries| entries.get(did).cloned())
        })
    }

    fn put<'a>(
        &'a self,
        did: String,
        entry: CachedResolution,
    ) -> ResolverFuture<'a, Result<(), ResolutionCacheError>> {
        Box::pin(async move {
            self.entries
                .write()
                .map_err(|error| ResolutionCacheError::Backend(error.to_string()))?
                .insert(did, entry);
            Ok(())
        })
    }

    fn invalidate<'a>(
        &'a self,
        did: &'a str,
    ) -> ResolverFuture<'a, Result<bool, ResolutionCacheError>> {
        Box::pin(async move {
            Ok(self
                .entries
                .write()
                .map_err(|error| ResolutionCacheError::Backend(error.to_string()))?
                .remove(did)
                .is_some())
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use ssi_dids_core::Document;

    use super::*;

    fn entry() -> CachedResolution {
        let cached_at = Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap();
        Resolution::new(Document::new("did:example:alice".parse().unwrap()))
            .cached(cached_at, cached_at + Duration::minutes(15))
    }

    #[tokio::test]
    async fn stores_and_invalidates_complete_resolution_entries() {
        let cache = MemoryDidResolutionCache::default();
        let entry = entry();

        cache
            .put("did:example:alice".to_string(), entry.clone())
            .await
            .unwrap();
        assert_eq!(cache.get("did:example:alice").await.unwrap(), Some(entry));
        assert!(cache.invalidate("did:example:alice").await.unwrap());
        assert_eq!(cache.get("did:example:alice").await.unwrap(), None);
        assert!(!cache.invalidate("did:example:alice").await.unwrap());
    }

    #[test]
    fn distinguishes_fresh_and_stale_eligibility() {
        let mut entry = entry();
        entry.stale_until = Some(entry.fresh_until + Duration::minutes(5));

        assert!(entry.is_fresh_at(entry.cached_at + Duration::minutes(14)));
        assert!(!entry.is_usable_stale_at(entry.cached_at + Duration::minutes(14)));
        assert!(!entry.is_fresh_at(entry.cached_at + Duration::minutes(16)));
        assert!(entry.is_usable_stale_at(entry.cached_at + Duration::minutes(16)));
        assert!(!entry.is_usable_stale_at(entry.cached_at + Duration::minutes(21)));
    }
}
