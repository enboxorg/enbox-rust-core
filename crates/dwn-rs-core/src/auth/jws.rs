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
            | Self::InvalidKey(_) => "JwsError",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct JWS {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<SignatureEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<MapValue>,
    #[serde(flatten)] // TODO: remove?
    pub extra: MapValue,
}

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

impl JWS {
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
    ) -> Result<Vec<SignatureEntry>, JwsError>
    where
        S: JwsSigner,
        P: JwsPayload + Clone + Copy,
    {
        stream::iter(signers)
            .then(|signer| async move {
                let result: Result<SignatureEntry, JwsError> = async {
                    let signature = signer.sign_into_decoded(payload).await?;

                    Ok(SignatureEntry {
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
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct SignatureEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(flatten)] // TODO: remove?
    pub extra: MapValue,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct GeneralJws {
    pub payload: String,
    pub signatures: Vec<GeneralJwsSignature>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct GeneralJwsSignature {
    pub protected: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct GeneralJwsPublicJwk {
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct GeneralJwsPrivateJwk {
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

#[derive(Debug, Clone)]
pub struct PrivateJwkSigner {
    key_id: String,
    algorithm: String,
    private_jwk: GeneralJwsPrivateJwk,
}

pub trait GeneralJwsSigner {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, JwsError>;
}

pub trait GeneralJwsPublicKeyResolver {
    fn resolve_public_jwk(&self, kid: &str) -> Option<GeneralJwsPublicJwk>;
}

#[derive(Debug, Default, Clone)]
pub struct StaticPublicKeyResolver {
    public_keys: BTreeMap<String, GeneralJwsPublicJwk>,
}

#[derive(Serialize, Deserialize)]
struct GeneralJwsProtectedHeader {
    kid: Option<String>,
    alg: Option<String>,
}

impl GeneralJws {
    pub fn create<S>(payload: &[u8], signers: &[S]) -> Result<Self, JwsError>
    where
        S: GeneralJwsSigner,
    {
        let payload = base64url.encode(payload);
        let mut jws = Self {
            payload,
            signatures: Vec::new(),
        };

        for signer in signers {
            jws.add_signature(signer)?;
        }

        Ok(jws)
    }

    pub fn add_signature<S>(&mut self, signer: &S) -> Result<(), JwsError>
    where
        S: GeneralJwsSigner,
    {
        let protected_header = GeneralJwsProtectedHeader {
            kid: Some(signer.key_id().to_string()),
            alg: Some(signer.algorithm().to_string()),
        };
        let protected = base64url.encode(serde_json::to_string(&protected_header)?.as_bytes());
        let signing_input = format!("{}.{}", protected, self.payload);
        let signature = base64url.encode(signer.sign(signing_input.as_bytes())?);

        self.signatures.push(GeneralJwsSignature {
            protected,
            signature,
        });

        Ok(())
    }

    pub fn verify_signatures<R>(&self, resolver: &R) -> Result<Vec<String>, JwsError>
    where
        R: GeneralJwsPublicKeyResolver + ?Sized,
    {
        let mut signers = Vec::new();

        for signature in &self.signatures {
            let protected_header = signature.protected_header()?;
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
            if verify_general_jws_signature(&self.payload, signature, &public_jwk)? {
                signers.push(extract_did(kid).to_string());
            } else {
                return Err(JwsError::InvalidSignature);
            }
        }

        Ok(signers)
    }
}

impl GeneralJwsSignature {
    fn protected_header(&self) -> Result<GeneralJwsProtectedHeader, JwsError> {
        let protected = decode_base64url(&self.protected, "protected header")?;
        Ok(serde_json::from_slice(&protected)?)
    }
}

impl PrivateJwkSigner {
    pub fn new(
        key_id: impl Into<String>,
        algorithm: impl Into<String>,
        private_jwk: GeneralJwsPrivateJwk,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            algorithm: algorithm.into(),
            private_jwk,
        }
    }
}

impl GeneralJwsSigner for PrivateJwkSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &str {
        &self.algorithm
    }

    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, JwsError> {
        sign_general_jws_content(&self.algorithm, &self.private_jwk, content)
    }
}

impl StaticPublicKeyResolver {
    pub fn new(public_keys: BTreeMap<String, GeneralJwsPublicJwk>) -> Self {
        Self { public_keys }
    }

    pub fn insert(&mut self, kid: impl Into<String>, public_jwk: GeneralJwsPublicJwk) {
        self.public_keys.insert(kid.into(), public_jwk);
    }
}

impl GeneralJwsPublicKeyResolver for StaticPublicKeyResolver {
    fn resolve_public_jwk(&self, kid: &str) -> Option<GeneralJwsPublicJwk> {
        self.public_keys.get(kid).cloned()
    }
}

fn sign_general_jws_content(
    algorithm: &str,
    private_jwk: &GeneralJwsPrivateJwk,
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

fn verify_general_jws_signature(
    base64url_payload: &str,
    signature: &GeneralJwsSignature,
    public_jwk: &GeneralJwsPublicJwk,
) -> Result<bool, JwsError> {
    let signing_input = format!("{}.{}", signature.protected, base64url_payload);
    let signature_bytes = decode_base64url(&signature.signature, "signature")?;

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

fn ed25519_signing_key(jwk: &GeneralJwsPrivateJwk) -> Result<Ed25519SigningKey, JwsError> {
    let private_key = decode_base64url(&jwk.d, "Ed25519 private key")?;
    Ok(Ed25519SigningKey::from_bytes(&fixed_32_bytes(
        private_key,
        "Ed25519 private key",
    )?))
}

fn ed25519_verifying_key(jwk: &GeneralJwsPublicJwk) -> Result<Ed25519VerifyingKey, JwsError> {
    let public_key = decode_base64url(&jwk.x, "Ed25519 public key")?;
    Ed25519VerifyingKey::from_bytes(&fixed_32_bytes(public_key, "Ed25519 public key")?)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn secp256k1_signing_key(jwk: &GeneralJwsPrivateJwk) -> Result<Secp256k1SigningKey, JwsError> {
    let private_key = decode_base64url(&jwk.d, "secp256k1 private key")?;
    Secp256k1SigningKey::from_slice(&private_key)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn secp256k1_verifying_key(jwk: &GeneralJwsPublicJwk) -> Result<Secp256k1VerifyingKey, JwsError> {
    Secp256k1VerifyingKey::from_sec1_bytes(&ec_public_key_sec1(jwk)?)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn p256_signing_key(jwk: &GeneralJwsPrivateJwk) -> Result<P256SigningKey, JwsError> {
    let private_key = decode_base64url(&jwk.d, "P-256 private key")?;
    P256SigningKey::from_slice(&private_key).map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn p256_verifying_key(jwk: &GeneralJwsPublicJwk) -> Result<P256VerifyingKey, JwsError> {
    P256VerifyingKey::from_sec1_bytes(&ec_public_key_sec1(jwk)?)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn ec_public_key_sec1(jwk: &GeneralJwsPublicJwk) -> Result<Vec<u8>, JwsError> {
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
        let jws = JWS::create(b"hello world".to_vec(), Some(vec![jwk]))
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
}
