//! Shared test doubles: a raw-Ed25519 [`JwsSigner`] and a minimal
//! decoder-normal single-VM document.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use ed25519_dalek::{Signer, SigningKey};
use ssi_claims_core::SignatureError;
use ssi_dids_core::{DIDBuf, Document};
use ssi_jws::{JwsSigner, JwsSignerInfo};

pub(crate) struct TestSigner {
    key: SigningKey,
    calls: Arc<AtomicUsize>,
    signature_len: Option<usize>,
}

impl TestSigner {
    pub(crate) fn new(key: SigningKey) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                key,
                calls: calls.clone(),
                signature_len: None,
            },
            calls,
        )
    }

    pub(crate) fn plain(key: SigningKey) -> Self {
        Self::new(key).0
    }

    pub(crate) fn wrong_length(mut self, len: usize) -> Self {
        self.signature_len = Some(len);
        self
    }

    pub(crate) fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl JwsSigner for TestSigner {
    async fn fetch_info(&self) -> Result<JwsSignerInfo, SignatureError> {
        Err(SignatureError::MissingSigner)
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut signature = self.key.sign(signing_bytes).to_bytes().to_vec();
        if let Some(len) = self.signature_len {
            signature.resize(len, 0);
        }
        Ok(signature)
    }
}

/// Minimal decoder-normal document: identity `#0` in all four mandatory
/// relationships, thumbprint kid and default alg already filled.
pub(crate) fn agent_document(identity: &SigningKey) -> (DIDBuf, Document) {
    let did_string = format!(
        "did:dht:{}",
        z32::encode(identity.verifying_key().as_bytes())
    );
    let x = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        URL_SAFE_NO_PAD.encode(identity.verifying_key().as_bytes())
    };
    let kid = {
        use ssi_jwk::{OctetParams, Params, JWK};
        JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: ssi_jwk::Base64urlUInt(identity.verifying_key().as_bytes().to_vec()),
            private_key: None,
        }))
        .thumbprint()
        .unwrap()
    };
    let document: Document = serde_json::from_value(serde_json::json!({
        "id": did_string,
        "verificationMethod": [{
            "id": format!("{did_string}#0"),
            "type": "JsonWebKey",
            "controller": did_string,
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "alg": "EdDSA"},
        }],
        "authentication": [format!("{did_string}#0")],
        "assertionMethod": [format!("{did_string}#0")],
        "capabilityInvocation": [format!("{did_string}#0")],
        "capabilityDelegation": [format!("{did_string}#0")],
    }))
    .unwrap();
    (did_string.parse().unwrap(), document)
}
