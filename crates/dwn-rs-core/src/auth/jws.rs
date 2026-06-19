use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD as base64url};
use cid::Cid;
use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use futures_util::{stream, StreamExt, TryStreamExt};
use k256::ecdsa::signature::{Signer as _, Verifier as _};
use k256::ecdsa::{
    Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey,
    VerifyingKey as Secp256k1VerifyingKey,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use serde::{Deserialize, Serialize};
use ssi_claims_core::SignatureError;
use ssi_jws::{JwsPayload, JwsSigner};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::MapValue;

#[derive(Error, Debug)]
pub enum JwsError {
    #[error("Error parsing JWS: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("Error signing JWS: {0}")]
    SignError(#[from] ssi_claims_core::SignatureError),
    #[error("Error parsing JWS: invalid base64url {0}")]
    Base64UrlError(String),
    #[error("JWS protected header is missing required 'kid' property")]
    MissingKid,
    #[error("JWS protected header is missing required 'alg' property")]
    MissingAlg,
    #[error("JWS is missing the required 'payload' property")]
    MissingPayload,
    #[error("JWS is missing the required 'signatures' property")]
    MissingSignatures,
    #[error("JWS signature is missing the required 'protected' property")]
    MissingProtected,
    #[error("JWS signature is missing the required 'signature' property")]
    MissingSignature,
    #[error("public key for kid '{0}' not found")]
    PublicKeyNotFound(String),
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("Unsupported JWS algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Unsupported JWS curve: {0}")]
    UnsupportedCurve(String),
    #[error("Invalid JWS key: {0}")]
    InvalidKey(String),
}

impl JwsError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingKid => "GeneralJwsVerifierMissingKid",
            Self::MissingAlg => "GeneralJwsVerifierMissingAlg",
            Self::PublicKeyNotFound(_) => "GeneralJwsVerifierGetPublicKeyNotFound",
            Self::InvalidSignature => "GeneralJwsVerifierInvalidSignature",
            Self::UnsupportedAlgorithm(_) => "JwsUnsupportedAlgorithm",
            Self::UnsupportedCurve(_) => "JwsVerifySignatureUnsupportedCrv",
            Self::ParseError(_)
            | Self::SignError(_)
            | Self::Base64UrlError(_)
            | Self::MissingPayload
            | Self::MissingSignatures
            | Self::MissingProtected
            | Self::MissingSignature
            | Self::InvalidKey(_) => "JwsError",
        }
    }
}

/// Wire-format JSON Web Signature (general or flattened serialization).
///
/// Fields are optional so a degenerate `{}` value can still be deserialized
/// (e.g. when an `Authorization` is present but unsigned). Methods that
/// require a populated `payload` / `signatures` will return
/// [`JwsError::MissingPayload`] / [`JwsError::MissingSignatures`].
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Jws {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<JwsSignature>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<MapValue>,
    #[serde(flatten)]
    pub extra: MapValue,
}

/// Deprecated alias for [`Jws`] retained during the rename.
#[deprecated(since = "0.2.0", note = "use `Jws` instead")]
pub type JWS = Jws;

/// Deprecated alias for [`Jws`] retained during the rename. Historically
/// this referred to a parallel struct that has been collapsed into [`Jws`].
#[deprecated(since = "0.2.0", note = "use `Jws` instead")]
pub type GeneralJws = Jws;

#[derive(Serialize)]
pub struct Payload {
    #[serde(rename = "descriptorCid", serialize_with = "crate::ser::serialize_cid")]
    pub descriptor_cid: Cid,
    #[serde(
        rename = "delegatedGrantId",
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::ser::optional_cid_string::serialize"
    )]
    pub delegated_grant_id: Option<Cid>,
    #[serde(rename = "permissionGrantId", skip_serializing_if = "Option::is_none")]
    pub permission_grant_id: Option<String>,
    #[serde(rename = "protocolRole", skip_serializing_if = "Option::is_none")]
    pub protocol_role: Option<String>,
}

impl JwsPayload for Payload {
    fn payload_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        let payload = serde_json::to_vec(self).expect("JWS Payload serialization failed.");
        std::borrow::Cow::Owned(payload)
    }
}

#[derive(Serialize)]
pub struct AttestationPayload {
    #[serde(rename = "descriptorCid", serialize_with = "crate::ser::serialize_cid")]
    pub descriptor_cid: Cid,
}

impl JwsPayload for AttestationPayload {
    fn payload_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        let payload =
            serde_json::to_vec(self).expect("JWS AttestationPayload serialization failed.");
        std::borrow::Cow::Owned(payload)
    }
}

impl Jws {
    /// Asynchronously sign `payload` with the supplied [`ssi_jws::JwsSigner`]s.
    pub async fn create<S, P>(payload: P, signers: Option<Vec<S>>) -> Result<Self, JwsError>
    where
        S: JwsSigner,
        P: JwsPayload,
    {
        let encoded_payload = base64url.encode(payload.payload_bytes());

        if let Some(signers) = signers {
            let signatures = Self::generate_signatures(signers, &payload).await?;
            Ok(Self {
                payload: Some(encoded_payload),
                signatures: Some(signatures),
                header: None,
                extra: MapValue::default(),
            })
        } else {
            Err(JwsError::SignError(SignatureError::MissingSigner))
        }
    }

    async fn generate_signatures<S, P>(
        signers: Vec<S>,
        payload: P,
    ) -> Result<Vec<JwsSignature>, JwsError>
    where
        S: JwsSigner,
        P: JwsPayload + Clone + Copy,
    {
        stream::iter(signers)
            .then(|signer| async move {
                let result: Result<JwsSignature, JwsError> = async {
                    let signature = signer.sign_into_decoded(payload).await?;

                    Ok(JwsSignature {
                        protected: Some(signature.header().encode()),
                        signature: Some(signature.signature.encode()),
                        extra: MapValue::default(),
                    })
                }
                .await;

                result
            })
            .try_collect()
            .await
    }

    /// Synchronously sign `payload` using the local [`JwkSigner`] trait.
    pub fn create_general<S>(payload: &[u8], signers: &[S]) -> Result<Self, JwsError>
    where
        S: JwkSigner,
    {
        let encoded_payload = base64url.encode(payload);
        let mut jws = Self {
            payload: Some(encoded_payload),
            signatures: Some(Vec::new()),
            ..Default::default()
        };

        for signer in signers {
            jws.add_signature(signer)?;
        }

        Ok(jws)
    }

    /// Append a signature to an existing JWS.
    pub fn add_signature<S>(&mut self, signer: &S) -> Result<(), JwsError>
    where
        S: JwkSigner,
    {
        let payload = self.payload.as_deref().ok_or(JwsError::MissingPayload)?;
        let protected_header = JwsProtectedHeader {
            kid: Some(signer.key_id().to_string()),
            alg: Some(signer.algorithm().to_string()),
        };
        let protected = base64url.encode(serde_json::to_string(&protected_header)?.as_bytes());
        let signing_input = format!("{}.{}", protected, payload);
        let signature = base64url.encode(signer.sign(signing_input.as_bytes())?);

        self.signatures
            .get_or_insert_with(Vec::new)
            .push(JwsSignature {
                protected: Some(protected),
                signature: Some(signature),
                extra: MapValue::default(),
            });

        Ok(())
    }

    /// Verify the signatures on this JWS, returning the DIDs of the signers.
    pub fn verify_signatures<R>(&self, resolver: &R) -> Result<Vec<String>, JwsError>
    where
        R: JwsPublicKeyResolver + ?Sized,
    {
        let payload = self.payload.as_deref().ok_or(JwsError::MissingPayload)?;
        let signatures = self
            .signatures
            .as_deref()
            .ok_or(JwsError::MissingSignatures)?;
        let mut signers = Vec::new();

        for signature in signatures {
            let protected_b64 = signature
                .protected
                .as_deref()
                .ok_or(JwsError::MissingProtected)?;
            let signature_b64 = signature
                .signature
                .as_deref()
                .ok_or(JwsError::MissingSignature)?;
            let protected_header = decode_protected_header(protected_b64)?;
            let kid = protected_header
                .kid
                .as_deref()
                .ok_or(JwsError::MissingKid)?;

            if protected_header.alg.is_none() {
                return Err(JwsError::MissingAlg);
            }

            let public_jwk = resolver
                .resolve_public_jwk(kid)
                .ok_or_else(|| JwsError::PublicKeyNotFound(kid.to_string()))?;
            if verify_jws_signature(payload, protected_b64, signature_b64, &public_jwk)? {
                signers.push(extract_did(kid).to_string());
            } else {
                return Err(JwsError::InvalidSignature);
            }
        }

        Ok(signers)
    }

    pub fn verify_signatures_public_jwk(
        &self,
        public_jwk: &JwsPublicJwk,
    ) -> Result<bool, JwsError> {
        let payload = self.payload.as_deref().ok_or(JwsError::MissingPayload)?;
        let signatures = self
            .signatures
            .as_deref()
            .ok_or(JwsError::MissingSignatures)?;

        for signature in signatures {
            let protected_b64 = signature
                .protected
                .as_deref()
                .ok_or(JwsError::MissingProtected)?;
            let signature_b64 = signature
                .signature
                .as_deref()
                .ok_or(JwsError::MissingSignature)?;

            if !verify_jws_signature(payload, protected_b64, signature_b64, public_jwk)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// One signature entry inside a [`Jws`] (general or flattened serialization).
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct JwsSignature {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(flatten)]
    pub extra: MapValue,
}

/// Deprecated alias for [`JwsSignature`].
#[deprecated(since = "0.2.0", note = "use `JwsSignature` instead")]
pub type SignatureEntry = JwsSignature;

/// Deprecated alias for [`JwsSignature`].
#[deprecated(since = "0.2.0", note = "use `JwsSignature` instead")]
pub type GeneralJwsSignature = JwsSignature;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct JwsPublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

#[deprecated(since = "0.2.0", note = "use `JwsPublicJwk` instead")]
pub type GeneralJwsPublicJwk = JwsPublicJwk;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct JwsPrivateJwk {
    pub kty: String,
    pub crv: String,
    pub d: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

#[deprecated(since = "0.2.0", note = "use `JwsPrivateJwk` instead")]
pub type GeneralJwsPrivateJwk = JwsPrivateJwk;

#[derive(Debug, Clone)]
pub struct PrivateJwkSigner {
    key_id: String,
    algorithm: String,
    private_jwk: JwsPrivateJwk,
}

/// Local synchronous signer abstraction backed by a private JWK.
pub trait JwkSigner {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, JwsError>;
}

#[deprecated(since = "0.2.0", note = "use `JwkSigner` instead")]
pub use JwkSigner as GeneralJwsSigner;

/// Resolves a `kid` to a public JWK (used for signature verification).
pub trait JwsPublicKeyResolver {
    fn resolve_public_jwk(&self, kid: &str) -> Option<JwsPublicJwk>;
}

#[deprecated(since = "0.2.0", note = "use `JwsPublicKeyResolver` instead")]
pub use JwsPublicKeyResolver as GeneralJwsPublicKeyResolver;

#[derive(Debug, Default, Clone)]
pub struct StaticPublicKeyResolver {
    public_keys: BTreeMap<String, JwsPublicJwk>,
}

#[derive(Serialize, Deserialize)]
struct JwsProtectedHeader {
    kid: Option<String>,
    alg: Option<String>,
}

impl PrivateJwkSigner {
    pub fn new(
        key_id: impl Into<String>,
        algorithm: impl Into<String>,
        private_jwk: JwsPrivateJwk,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            algorithm: algorithm.into(),
            private_jwk,
        }
    }
}

impl JwkSigner for PrivateJwkSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &str {
        &self.algorithm
    }

    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, JwsError> {
        sign_jws_content(&self.algorithm, &self.private_jwk, content)
    }
}

impl StaticPublicKeyResolver {
    pub fn new(public_keys: BTreeMap<String, JwsPublicJwk>) -> Self {
        Self { public_keys }
    }

    pub fn insert(&mut self, kid: impl Into<String>, public_jwk: JwsPublicJwk) {
        self.public_keys.insert(kid.into(), public_jwk);
    }
}

impl JwsPublicKeyResolver for StaticPublicKeyResolver {
    fn resolve_public_jwk(&self, kid: &str) -> Option<JwsPublicJwk> {
        self.public_keys.get(kid).cloned()
    }
}

fn decode_protected_header(protected: &str) -> Result<JwsProtectedHeader, JwsError> {
    let bytes = decode_base64url(protected, "protected header")?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn sign_jws_content(
    algorithm: &str,
    private_jwk: &JwsPrivateJwk,
    content: &[u8],
) -> Result<Vec<u8>, JwsError> {
    match (algorithm, private_jwk.crv.as_str()) {
        ("EdDSA", "Ed25519") => Ok(ed25519_signing_key(private_jwk)?
            .sign(content)
            .to_bytes()
            .to_vec()),
        ("ES256K", "secp256k1") => {
            let signature: Secp256k1Signature = secp256k1_signing_key(private_jwk)?.sign(content);
            Ok(signature.to_bytes().to_vec())
        }
        ("ES256", "P-256") => {
            let signature: P256Signature = p256_signing_key(private_jwk)?.sign(content);
            Ok(signature.to_bytes().to_vec())
        }
        (algorithm, _) => Err(JwsError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

fn verify_jws_signature(
    base64url_payload: &str,
    protected_b64: &str,
    signature_b64: &str,
    public_jwk: &JwsPublicJwk,
) -> Result<bool, JwsError> {
    let signing_input = format!("{}.{}", protected_b64, base64url_payload);
    let signature_bytes = decode_base64url(signature_b64, "signature")?;

    match public_jwk.crv.as_str() {
        "Ed25519" => {
            let signature = Ed25519Signature::from_slice(&signature_bytes)
                .map_err(|err| JwsError::InvalidKey(err.to_string()))?;
            Ok(ed25519_verifying_key(public_jwk)?
                .verify(signing_input.as_bytes(), &signature)
                .is_ok())
        }
        "secp256k1" => {
            let signature = Secp256k1Signature::from_slice(&signature_bytes)
                .map_err(|err| JwsError::InvalidKey(err.to_string()))?;
            Ok(secp256k1_verifying_key(public_jwk)?
                .verify(signing_input.as_bytes(), &signature)
                .is_ok())
        }
        "P-256" => {
            let signature = P256Signature::from_slice(&signature_bytes)
                .map_err(|err| JwsError::InvalidKey(err.to_string()))?;
            Ok(p256_verifying_key(public_jwk)?
                .verify(signing_input.as_bytes(), &signature)
                .is_ok())
        }
        crv => Err(JwsError::UnsupportedCurve(crv.to_string())),
    }
}

fn ed25519_signing_key(jwk: &JwsPrivateJwk) -> Result<Ed25519SigningKey, JwsError> {
    let private_key = decode_base64url(&jwk.d, "Ed25519 private key")?;
    Ok(Ed25519SigningKey::from_bytes(&fixed_32_bytes(
        private_key,
        "Ed25519 private key",
    )?))
}

fn ed25519_verifying_key(jwk: &JwsPublicJwk) -> Result<Ed25519VerifyingKey, JwsError> {
    let public_key = decode_base64url(&jwk.x, "Ed25519 public key")?;
    Ed25519VerifyingKey::from_bytes(&fixed_32_bytes(public_key, "Ed25519 public key")?)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn secp256k1_signing_key(jwk: &JwsPrivateJwk) -> Result<Secp256k1SigningKey, JwsError> {
    let private_key = decode_base64url(&jwk.d, "secp256k1 private key")?;
    Secp256k1SigningKey::from_slice(&private_key)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn secp256k1_verifying_key(jwk: &JwsPublicJwk) -> Result<Secp256k1VerifyingKey, JwsError> {
    Secp256k1VerifyingKey::from_sec1_bytes(&ec_public_key_sec1(jwk)?)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn p256_signing_key(jwk: &JwsPrivateJwk) -> Result<P256SigningKey, JwsError> {
    let private_key = decode_base64url(&jwk.d, "P-256 private key")?;
    P256SigningKey::from_slice(&private_key).map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn p256_verifying_key(jwk: &JwsPublicJwk) -> Result<P256VerifyingKey, JwsError> {
    P256VerifyingKey::from_sec1_bytes(&ec_public_key_sec1(jwk)?)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn ec_public_key_sec1(jwk: &JwsPublicJwk) -> Result<Vec<u8>, JwsError> {
    let x = fixed_32_bytes(
        decode_base64url(&jwk.x, "EC public key x")?,
        "EC public key x",
    )?;
    let y = fixed_32_bytes(
        decode_base64url(
            jwk.y
                .as_deref()
                .ok_or_else(|| JwsError::InvalidKey("EC public key missing y".to_string()))?,
            "EC public key y",
        )?,
        "EC public key y",
    )?;
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04);
    public_key.extend_from_slice(&x);
    public_key.extend_from_slice(&y);

    Ok(public_key)
}

fn fixed_32_bytes(value: Vec<u8>, label: &str) -> Result<[u8; 32], JwsError> {
    value
        .try_into()
        .map_err(|_| JwsError::InvalidKey(format!("{label} must be 32 bytes")))
}

fn decode_base64url(value: &str, label: &str) -> Result<Vec<u8>, JwsError> {
    base64url
        .decode(value)
        .map_err(|err| JwsError::Base64UrlError(format!("{label}: {err}")))
}

fn extract_did(kid: &str) -> &str {
    kid.split('#')
        .next()
        .expect("split always returns one item")
}

#[cfg(test)]
pub struct NoSigner {}

#[cfg(test)]
impl JwsSigner for NoSigner {
    async fn fetch_info(&self) -> Result<ssi_jws::JwsSignerInfo, ssi_claims_core::SignatureError> {
        Ok(ssi_jws::JwsSignerInfo {
            key_id: None,
            algorithm: ssi_jwk::Algorithm::None,
        })
    }

    async fn sign_bytes(
        &self,
        _signing_bytes: &[u8],
    ) -> Result<Vec<u8>, ssi_claims_core::SignatureError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi_jwk::JWK;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_jws_create() {
        let jwk = JWK::generate_secp256k1();
        let jws = Jws::create(b"hello world".to_vec(), Some(vec![jwk]))
            .await
            .expect("could not create JWS");

        assert_eq!(jws.payload, Some("aGVsbG8gd29ybGQ".to_string()));
        assert_eq!(jws.signatures.as_ref().unwrap().len(), 1);
        assert_eq!(
            jws.signatures.as_ref().unwrap()[0]
                .protected
                .as_ref()
                .unwrap(),
            "eyJhbGciOiJFUzI1NksifQ"
        );

        assert!(!jws.signatures.as_ref().unwrap()[0]
            .signature
            .as_ref()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_payload_serializes_grant_fields() {
        let descriptor_cid =
            Cid::from_str("bafyreietui4xdkiu4xvmx4fi2jivjtndbhb4drzpxomrjvd4mdz4w2avra").unwrap();
        let delegated_grant_id =
            Cid::from_str("bafyreia3vo2bkk4b4nshzup55wgkdgwpr5bsa474iyngfcegompdko6kt4").unwrap();

        let payload = Payload {
            descriptor_cid,
            delegated_grant_id: Some(delegated_grant_id),
            permission_grant_id: Some("grant-123".to_string()),
            protocol_role: Some("adminRole".to_string()),
        };

        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            json!({
                "descriptorCid": descriptor_cid.to_string(),
                "delegatedGrantId": delegated_grant_id.to_string(),
                "permissionGrantId": "grant-123",
                "protocolRole": "adminRole",
            })
        );
    }

    #[tokio::test]
    async fn verify_signatures_public_jwk_accepts_valid_signature() {
        let jwk = JWK::generate_secp256k1();
        // Matching public JWK in this crate's shape, derived before signing.
        let public_jwk: JwsPublicJwk =
            serde_json::from_value(serde_json::to_value(&jwk).unwrap()).unwrap();

        let jws = Jws::create(b"hello world".to_vec(), Some(vec![jwk]))
            .await
            .expect("could not create JWS");

        assert!(jws
            .verify_signatures_public_jwk(&public_jwk)
            .expect("verification should not error"));
    }

    #[tokio::test]
    async fn verify_signatures_public_jwk_rejects_tampered_signature() {
        let jwk = JWK::generate_secp256k1();
        let public_jwk: JwsPublicJwk =
            serde_json::from_value(serde_json::to_value(&jwk).unwrap()).unwrap();

        let mut jws = Jws::create(b"hello world".to_vec(), Some(vec![jwk]))
            .await
            .expect("could not create JWS");

        // Flip the first signature char: same base64url length (still decodes),
        // but no longer a valid signature.
        let signature = jws.signatures.as_mut().unwrap()[0]
            .signature
            .as_mut()
            .unwrap();
        let first = signature.remove(0);
        signature.insert(0, if first == 'A' { 'B' } else { 'A' });

        assert!(!jws
            .verify_signatures_public_jwk(&public_jwk)
            .expect("verification should not error"));
    }

    #[tokio::test]
    async fn verify_signatures_public_jwk_rejects_wrong_key() {
        let jws = Jws::create(
            b"hello world".to_vec(),
            Some(vec![JWK::generate_secp256k1()]),
        )
        .await
        .expect("could not create JWS");

        // A different key must not verify the signature.
        let other: JwsPublicJwk =
            serde_json::from_value(serde_json::to_value(JWK::generate_secp256k1()).unwrap())
                .unwrap();

        assert!(!jws
            .verify_signatures_public_jwk(&other)
            .expect("verification should not error"));
    }
}
