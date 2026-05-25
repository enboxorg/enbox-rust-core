//! Composite DID resolver for production DWN nodes.
//!
//! Resolves static verification-method IDs and `did:jwk` DIDs, matching the
//! default TypeScript `UniversalResolver` wiring used by `Dwn.create()`.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::{JwsPublicJwk, JwsPublicKeyResolver};

#[derive(Clone, Default)]
pub struct UniversalResolver {
    fallback: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl UniversalResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_fallback<R>(fallback: R) -> Self
    where
        R: JwsPublicKeyResolver + Send + Sync + 'static,
    {
        Self {
            fallback: Some(Arc::new(fallback)),
        }
    }
}

impl JwsPublicKeyResolver for UniversalResolver {
    fn resolve_public_jwk(&self, kid: &str) -> Option<JwsPublicJwk> {
        if let Some(fallback) = &self.fallback {
            if let Some(jwk) = fallback.resolve_public_jwk(kid) {
                return Some(jwk);
            }
        }
        resolve_did_jwk(kid)
    }
}

fn resolve_did_jwk(kid: &str) -> Option<JwsPublicJwk> {
    let base = kid.split('#').next().unwrap_or(kid);
    let encoded = base.strip_prefix("did:jwk:")?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_did_jwk_public_key() {
        let jwk = JwsPublicJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
            y: None,
            kid: Some("did:example:alice#key1".to_string()),
            alg: Some("EdDSA".to_string()),
        };
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&jwk).unwrap());
        let did = format!("did:jwk:{encoded}");

        let resolver = UniversalResolver::new();
        let resolved = resolver.resolve_public_jwk(&did).expect("did:jwk resolves");
        assert_eq!(resolved.crv, "Ed25519");
    }
}
