//! Publication signing: encode, size-gate, sign, and locally verify.
//!
//! The identity public key always comes from `document.id`; no duplicate
//! key input exists. The BEP44 preimage signs the raw compressed DNS bytes
//! exactly, and the size limit applies to `v` alone — never to the longer
//! signing prefix. A value that fails verification never reaches transport.

use ssi_dids_core::Document;
use ssi_jws::JwsSigner;
use url::Url;

use super::bep44::{
    bep44_signing_payload, decode_identity_key, verify_bep44_message, Bep44Message,
};
use super::encode::encode_document;
use super::error::DhtPublishError;

const MAX_VALUE_BYTES: usize = 1000;
const SIGNATURE_BYTES: usize = 64;

/// A signed publication payload, ready for the relay envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPublish {
    pub sequence: u64,
    pub value: Vec<u8>,
    pub signature: [u8; 64],
}

/// Encode `document`, sign its BEP44 preimage, and verify the signature
/// against the DID identity key before any network access.
///
/// Consumes the signer exactly once on success. Oversized values fail before
/// signing; wrong-length, foreign-key, and invalid signatures fail before
/// transport. `fetch_info` is never consulted.
pub async fn sign_publish<S: JwsSigner>(
    document: &Document,
    types: &[u64],
    gateways: &[Url],
    sequence: u64,
    signer: &S,
) -> Result<SignedPublish, DhtPublishError> {
    let value = encode_document(document, types, gateways)?;
    ensure_value_size(&value)?;

    let identity_key = decode_identity_key(&document.id)?;
    let preimage = bep44_signing_payload(sequence, &value);
    let signature = signer
        .sign_bytes(&preimage)
        .await
        .map_err(|error| DhtPublishError::Signer(error.to_string()))?;
    let signature: [u8; SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| DhtPublishError::InvalidSignature)?;
    verify_bep44_message(
        &identity_key,
        &Bep44Message {
            signature: &signature,
            sequence,
            value: &value,
        },
    )?;

    Ok(SignedPublish {
        sequence,
        value,
        signature,
    })
}

fn ensure_value_size(value: &[u8]) -> Result<(), DhtPublishError> {
    if value.len() <= MAX_VALUE_BYTES {
        Ok(())
    } else {
        Err(DhtPublishError::ValueTooLarge { found: value.len() })
    }
}

/// The exact Pkarr relay envelope: `signature[64] || sequence_be[8] || v`.
pub(crate) fn relay_body(signed: &SignedPublish) -> Vec<u8> {
    let mut body = Vec::with_capacity(72 + signed.value.len());
    body.extend_from_slice(&signed.signature);
    body.extend_from_slice(&signed.sequence.to_be_bytes());
    body.extend_from_slice(&signed.value);
    body
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use ssi_claims_core::SignatureError;
    use ssi_dids_core::DIDBuf;
    use ssi_jws::{JwsSigner, JwsSignerInfo};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::super::codec::decode_document;
    use super::*;

    struct TestSigner {
        key: SigningKey,
        calls: Arc<AtomicUsize>,
        signature_len: Option<usize>,
    }

    impl TestSigner {
        fn new(key: SigningKey) -> (Self, Arc<AtomicUsize>) {
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

        fn wrong_length(mut self, len: usize) -> Self {
            self.signature_len = Some(len);
            self
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

    struct FailingSigner;

    impl JwsSigner for FailingSigner {
        async fn fetch_info(&self) -> Result<JwsSignerInfo, SignatureError> {
            Err(SignatureError::MissingSigner)
        }

        async fn sign_bytes(&self, _signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
            Err(SignatureError::MissingSigner)
        }
    }

    fn agent_document(identity: &SigningKey) -> (String, Document) {
        let did_string = format!(
            "did:dht:{}",
            z32::encode(identity.verifying_key().as_bytes())
        );
        let x = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine as _;
            URL_SAFE_NO_PAD.encode(identity.verifying_key().as_bytes())
        };
        // Decoder-normal input carries the thumbprint kid explicitly.
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
        let document: Document = serde_json::from_value(json!({
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
        (did_string, document)
    }

    fn oversized_document(identity: &SigningKey) -> Document {
        let (did_string, _) = agent_document(identity);
        let x = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine as _;
            URL_SAFE_NO_PAD.encode(identity.verifying_key().as_bytes())
        };
        serde_json::from_value(json!({
            "id": did_string,
            "verificationMethod": [{
                "id": format!("{did_string}#0"),
                "type": "JsonWebKey",
                "controller": did_string,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "alg": "EdDSA"},
            }],
            "authentication": [format!("{did_string}#0")],
            "assertionMethod": [format!("{did_string}#0")],
            "capabilityInvocation": [format!("{did_string}#0")],
            "capabilityDelegation": [format!("{did_string}#0")],
            "service": [{
                "id": format!("{did_string}#dwn"),
                "type": "DecentralizedWebNode",
                "serviceEndpoint": ["https://dwn.example"],
                "pad": "x".repeat(2000),
            }],
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn signs_the_exact_bep44_preimage() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (did_string, document) = agent_document(&identity);
        let (signer, calls) = TestSigner::new(identity);

        let signed = sign_publish(&document, &[], &[], 42, &signer)
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(signed.sequence, 42);
        let expected_value = encode_document(&document, &[], &[]).unwrap();
        assert_eq!(signed.value, expected_value);
        let expected_preimage = bep44_signing_payload(42, &expected_value);
        let did: DIDBuf = did_string.parse().unwrap();
        let key = decode_identity_key(&did).unwrap();
        verify_bep44_message(
            &key,
            &Bep44Message {
                signature: &signed.signature,
                sequence: 42,
                value: &expected_value,
            },
        )
        .unwrap();
        assert_eq!(
            SigningKey::from_bytes(&[7; 32])
                .sign(&expected_preimage)
                .to_bytes(),
            signed.signature
        );

        let body = relay_body(&signed);
        assert_eq!(body.len(), 72 + expected_value.len());
        assert_eq!(&body[..64], &signed.signature);
        assert_eq!(&body[64..72], &42u64.to_be_bytes());
        assert_eq!(&body[72..], &expected_value);
    }

    #[tokio::test]
    async fn value_size_gate_accepts_1000_and_rejects_1001() {
        assert!(ensure_value_size(&vec![0; 999]).is_ok());
        assert!(ensure_value_size(&vec![0; 1000]).is_ok());
        assert_eq!(
            ensure_value_size(&vec![0; 1001]),
            Err(DhtPublishError::ValueTooLarge { found: 1001 })
        );
    }

    #[tokio::test]
    async fn oversized_values_fail_before_signing() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let document = oversized_document(&identity);
        let (signer, calls) = TestSigner::new(identity);

        let error = sign_publish(&document, &[], &[], 1, &signer)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DhtPublishError::ValueTooLarge { found } if found > 1000
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mismatched_signer_fails_local_verification() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (_, document) = agent_document(&identity);
        let (signer, calls) = TestSigner::new(SigningKey::from_bytes(&[8; 32]));

        assert_eq!(
            sign_publish(&document, &[], &[], 1, &signer).await,
            Err(DhtPublishError::InvalidSignature)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wrong_length_signatures_fail() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (_, document) = agent_document(&identity);

        for len in [63, 65] {
            let (signer, _) = TestSigner::new(SigningKey::from_bytes(&[7; 32]));
            assert_eq!(
                sign_publish(&document, &[], &[], 1, &signer.wrong_length(len)).await,
                Err(DhtPublishError::InvalidSignature)
            );
        }
    }

    #[tokio::test]
    async fn signer_errors_surface_typed() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (_, document) = agent_document(&identity);

        assert!(matches!(
            sign_publish(&document, &[], &[], 1, &FailingSigner).await,
            Err(DhtPublishError::Signer(_))
        ));
    }

    #[tokio::test]
    async fn signed_output_decodes_to_its_document() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (did_string, document) = agent_document(&identity);
        let (signer, _) = TestSigner::new(identity);

        let signed = sign_publish(&document, &[], &[], 7, &signer).await.unwrap();
        let did: DIDBuf = did_string.parse().unwrap();
        let (decoded, _) = decode_document(&did, &signed.value).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(document).unwrap()
        );
    }
}
