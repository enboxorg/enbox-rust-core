//! Composite DID resolver for production DWN nodes.
//!
//! Resolves static verification-method IDs and `did:jwk` / `did:key` DIDs,
//! matching the default TypeScript `UniversalResolver` wiring used by
//! `Dwn.create()`.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::{JwsPublicJwk, JwsPublicKeyResolver};

/// Multicodec varint prefix for an Ed25519 public key (`0xed 0x01`).
///
/// The DID specification fixes this prefix; see
/// <https://w3c-ccg.github.io/did-method-key/#ed25519-x25519>.
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const ED25519_PUBLIC_KEY_LEN: usize = 32;

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
        resolve_did_jwk(kid).or_else(|| resolve_did_key(kid))
    }
}

fn resolve_did_jwk(kid: &str) -> Option<JwsPublicJwk> {
    let base = kid.split('#').next().unwrap_or(kid);
    let encoded = base.strip_prefix("did:jwk:")?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Resolve a `did:key:zXXXX...` DID to a JWS public JWK.
///
/// Only Ed25519 keys are supported because that is the only key type DWN
/// uses for `Authorization` JWS signatures (see [`crate::auth::jws`]). The
/// fragment, when present, must match the multibase identifier exactly
/// (matching `dwn-sdk-js` `DidKeyResolver`).
fn resolve_did_key(kid: &str) -> Option<JwsPublicJwk> {
    let (base, fragment) = match kid.split_once('#') {
        Some((base, fragment)) => (base, Some(fragment)),
        None => (kid, None),
    };
    let identifier = base.strip_prefix("did:key:")?;
    if let Some(fragment) = fragment {
        if fragment != identifier {
            return None;
        }
    }
    let (_, bytes) = multibase::decode(identifier).ok()?;
    let public_key = bytes.strip_prefix(&ED25519_MULTICODEC[..])?;
    if public_key.len() != ED25519_PUBLIC_KEY_LEN {
        return None;
    }
    Some(JwsPublicJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: URL_SAFE_NO_PAD.encode(public_key),
        y: None,
        kid: Some(format!("{base}#{identifier}")),
        alg: Some("EdDSA".to_string()),
    })
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

    /// Reference vector taken from <https://w3c-ccg.github.io/did-method-key/#example-1>:
    /// the Ed25519 key whose base58btc multibase form is
    /// `z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp`.
    const DID_KEY_EXAMPLE: &str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

    #[test]
    fn resolves_did_key_ed25519_without_fragment() {
        let resolver = UniversalResolver::new();
        let resolved = resolver
            .resolve_public_jwk(DID_KEY_EXAMPLE)
            .expect("did:key resolves");
        assert_eq!(resolved.kty, "OKP");
        assert_eq!(resolved.crv, "Ed25519");
        assert_eq!(resolved.alg.as_deref(), Some("EdDSA"));
        assert_eq!(URL_SAFE_NO_PAD.decode(&resolved.x).unwrap().len(), 32);
    }

    #[test]
    fn resolves_did_key_with_matching_fragment_kid() {
        let identifier = DID_KEY_EXAMPLE.strip_prefix("did:key:").unwrap();
        let kid = format!("{DID_KEY_EXAMPLE}#{identifier}");
        let resolver = UniversalResolver::new();
        let resolved = resolver
            .resolve_public_jwk(&kid)
            .expect("did:key#kid resolves");
        assert_eq!(resolved.kid.as_deref(), Some(kid.as_str()));
    }

    #[test]
    fn rejects_did_key_with_mismatched_fragment() {
        let kid = format!("{DID_KEY_EXAMPLE}#different");
        let resolver = UniversalResolver::new();
        assert!(resolver.resolve_public_jwk(&kid).is_none());
    }

    #[test]
    fn rejects_did_key_with_non_ed25519_multicodec() {
        // Construct a did:key for an X25519 key (multicodec 0xec01); we
        // intentionally do not resolve these because JWS signing requires
        // a signature-capable key.
        let mut bytes = vec![0xec, 0x01];
        bytes.extend_from_slice(&[1u8; 32]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &bytes);
        let did = format!("did:key:{encoded}");
        let resolver = UniversalResolver::new();
        assert!(resolver.resolve_public_jwk(&did).is_none());
    }

    #[test]
    fn rejects_did_key_with_wrong_public_key_length() {
        let mut bytes = ED25519_MULTICODEC.to_vec();
        bytes.extend_from_slice(&[1u8; 16]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &bytes);
        let did = format!("did:key:{encoded}");
        let resolver = UniversalResolver::new();
        assert!(resolver.resolve_public_jwk(&did).is_none());
    }

    /// End-to-end test: a JWS signed by an Ed25519 key whose KID is a
    /// `did:key#<identifier>` value must verify against the
    /// `UniversalResolver` without any pre-registered static keys. This
    /// is the path DWeb Connect uses for ephemeral connecting-app DIDs.
    #[test]
    fn verifies_jws_signed_by_did_key_ed25519() {
        use crate::auth::{Jws, JwsPrivateJwk, PrivateJwkSigner};
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();

        let mut multicodec_bytes = ED25519_MULTICODEC.to_vec();
        multicodec_bytes.extend_from_slice(&public_bytes);
        let identifier = multibase::encode(multibase::Base::Base58Btc, &multicodec_bytes);
        let did = format!("did:key:{identifier}");
        let kid = format!("{did}#{identifier}");

        let private_jwk = JwsPrivateJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: URL_SAFE_NO_PAD.encode(public_bytes),
            d: URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
            y: None,
            kid: Some(kid.clone()),
            alg: Some("EdDSA".to_string()),
        };
        let signer = PrivateJwkSigner::new(kid.clone(), "EdDSA", private_jwk);

        let jws =
            Jws::create_general(b"hello, did:key", std::slice::from_ref(&signer)).expect("sign");
        let resolver = UniversalResolver::new();
        let signers = jws
            .verify_signatures(&resolver)
            .expect("did:key signature verifies");
        // verify_signatures returns the DID portion of the kid (fragment stripped).
        assert_eq!(signers, vec![did]);
    }
}
