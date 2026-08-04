use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD as base64url};
use cid::Cid;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use k256::ecdsa::signature::Verifier as _;
use k256::ecdsa::{Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Serialize};
use ssi_claims_core::SignatureError;
pub use ssi_jwk::JWK;
use ssi_jwk::{ECParams, OctetParams, Params};
use ssi_jws::{JwsPayload, JwsSigner};
use std::collections::BTreeMap;
use thiserror::Error;

pub use ssi_jwk::Algorithm;

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

/// Pre-serialized JWS payload for a `RecordsWrite`/`ProtocolsConfigure`-style authorization
/// signature. Serialization happens once in [`AuthorizationPayload::new`], which is fallible, so
/// [`JwsPayload::payload_bytes`] (an infallible trait method defined upstream) never needs to
/// panic on a serialization failure.
#[derive(Clone)]
pub struct AuthorizationPayload {
    bytes: Vec<u8>,
}

impl AuthorizationPayload {
    pub fn new(
        descriptor_cid: Cid,
        delegated_grant_id: Option<Cid>,
        permission_grant_id: Option<String>,
        protocol_role: Option<String>,
    ) -> Result<Self, JwsError> {
        #[derive(Serialize)]
        struct Repr {
            #[serde(rename = "descriptorCid", serialize_with = "crate::ser::serialize_cid")]
            descriptor_cid: Cid,
            #[serde(
                rename = "delegatedGrantId",
                skip_serializing_if = "Option::is_none",
                serialize_with = "crate::ser::optional_cid_string::serialize"
            )]
            delegated_grant_id: Option<Cid>,
            #[serde(rename = "permissionGrantId", skip_serializing_if = "Option::is_none")]
            permission_grant_id: Option<String>,
            #[serde(rename = "protocolRole", skip_serializing_if = "Option::is_none")]
            protocol_role: Option<String>,
        }
        let bytes = serde_json::to_vec(&Repr {
            descriptor_cid,
            delegated_grant_id,
            permission_grant_id,
            protocol_role,
        })?;
        Ok(Self { bytes })
    }
}

impl JwsPayload for AuthorizationPayload {
    fn payload_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Borrowed(&self.bytes)
    }
}

/// Stable copy of a generic JWS payload and its protected-header metadata.
///
/// A snapshot ensures the outer General JWS payload and every signature are derived from the
/// same bytes even if a custom [`JwsPayload`] implementation changes between calls.
struct PayloadSnapshot {
    bytes: Vec<u8>,
    cty: Option<String>,
    typ: Option<String>,
}

impl PayloadSnapshot {
    fn new<P>(payload: &P) -> Self
    where
        P: JwsPayload + ?Sized,
    {
        Self {
            bytes: payload.payload_bytes().into_owned(),
            cty: payload.cty().map(ToOwned::to_owned),
            typ: payload.typ().map(ToOwned::to_owned),
        }
    }
}

impl JwsPayload for PayloadSnapshot {
    fn payload_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Borrowed(&self.bytes)
    }

    fn cty(&self) -> Option<&str> {
        self.cty.as_deref()
    }

    fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }
}

/// Pre-serialized JWS payload for a `RecordsWrite` attestation signature. See
/// [`AuthorizationPayload`] for why serialization is fallible at construction rather than inside
/// the infallible trait method.
#[derive(Clone)]
pub struct AttestationPayload {
    bytes: Vec<u8>,
}

impl AttestationPayload {
    pub fn new(descriptor_cid: Cid) -> Result<Self, JwsError> {
        #[derive(Serialize)]
        struct Repr {
            #[serde(rename = "descriptorCid", serialize_with = "crate::ser::serialize_cid")]
            descriptor_cid: Cid,
        }
        let bytes = serde_json::to_vec(&Repr { descriptor_cid })?;
        Ok(Self { bytes })
    }
}

impl JwsPayload for AttestationPayload {
    fn payload_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Borrowed(&self.bytes)
    }
}

impl Jws {
    /// Asynchronously sign `payload` with the supplied [`ssi_jws::JwsSigner`]s.
    pub async fn create<S, P>(payload: P, signers: Option<Vec<S>>) -> Result<Self, JwsError>
    where
        S: JwsSigner,
        P: JwsPayload,
    {
        let snapshot = PayloadSnapshot::new(&payload);
        let encoded_payload = base64url.encode(&snapshot.bytes);
        let signers = signers.ok_or(JwsError::SignError(SignatureError::MissingSigner))?;
        if signers.is_empty() {
            return Err(JwsError::SignError(SignatureError::MissingSigner));
        }

        let signatures = Self::generate_signatures(signers, &snapshot).await?;

        Ok(Self {
            payload: Some(encoded_payload),
            signatures: Some(signatures),
            header: None,
            extra: MapValue::default(),
        })
    }

    async fn generate_signatures<S>(
        signers: Vec<S>,
        payload: &PayloadSnapshot,
    ) -> Result<Vec<JwsSignature>, JwsError>
    where
        S: JwsSigner,
    {
        let mut signatures = Vec::with_capacity(signers.len());

        for signer in signers {
            let signed = signer.sign_into_decoded(payload).await?;

            signatures.push(JwsSignature {
                protected: Some(signed.header().encode()),
                signature: Some(signed.signature.encode()),
                extra: MapValue::default(),
            });
        }

        Ok(signatures)
    }

    /// Synchronously sign `payload` using the local [`JwkSigner`] trait.
    pub fn create_general<S>(payload: &[u8], signers: &[S]) -> Result<Self, JwsError>
    where
        S: JwkSigner,
    {
        if signers.is_empty() {
            return Err(JwsError::SignError(SignatureError::MissingSigner));
        }

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

    pub fn verify_signatures_public_jwk(&self, public_jwk: &JWK) -> Result<bool, JwsError> {
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

/// Compatibility alias for the SSI JWK type used by signature verification.
#[deprecated(since = "0.2.0", note = "use `ssi_jwk::JWK` instead")]
pub type JwsPublicJwk = JWK;

#[deprecated(since = "0.2.0", note = "use `ssi_jwk::JWK` instead")]
pub type GeneralJwsPublicJwk = JWK;

/// Compatibility alias for the SSI JWK type used by local signing.
#[deprecated(since = "0.2.0", note = "use `ssi_jwk::JWK` instead")]
pub type JwsPrivateJwk = JWK;

/// Build an SSI Ed25519 JWK from base64url key material.
pub fn ed25519_jwk(
    public_key: &str,
    private_key: Option<&str>,
    key_id: Option<&str>,
) -> Result<JWK, JwsError> {
    let mut jwk = JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_string(),
        public_key: ssi_jwk::Base64urlUInt(decode_base64url(public_key, "Ed25519 public key")?),
        private_key: private_key
            .map(|private_key| {
                decode_base64url(private_key, "Ed25519 private key").map(ssi_jwk::Base64urlUInt)
            })
            .transpose()?,
    }));
    jwk.key_id = key_id.map(ToString::to_string);
    jwk.algorithm = Some(ssi_jwk::Algorithm::EdDSA);
    Ok(jwk)
}

#[deprecated(since = "0.2.0", note = "use `ssi_jwk::JWK` instead")]
pub type GeneralJwsPrivateJwk = JWK;

#[derive(Debug, Clone)]
pub struct PrivateJwkSigner {
    key_id: String,
    algorithm: Algorithm,
    private_jwk: JWK,
}

/// Local synchronous signer abstraction backed by a private JWK.
pub trait JwkSigner {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> Algorithm;
    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, JwsError>;
}

#[deprecated(since = "0.2.0", note = "use `JwkSigner` instead")]
pub use JwkSigner as GeneralJwsSigner;

/// Resolves a `kid` to a public JWK (used for signature verification).
pub trait JwsPublicKeyResolver {
    fn resolve_public_jwk(&self, kid: &str) -> Option<JWK>;
}

#[deprecated(since = "0.2.0", note = "use `JwsPublicKeyResolver` instead")]
pub use JwsPublicKeyResolver as GeneralJwsPublicKeyResolver;

#[derive(Debug, Default, Clone)]
pub struct StaticPublicKeyResolver {
    public_keys: BTreeMap<String, JWK>,
}

#[derive(Serialize, Deserialize)]
struct JwsProtectedHeader {
    kid: Option<String>,
    alg: Option<String>,
}

impl PrivateJwkSigner {
    pub fn new(
        key_id: impl Into<String>,
        algorithm: impl Into<Algorithm>,
        private_jwk: JWK,
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

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, JwsError> {
        sign_jws_content(self.algorithm, &self.private_jwk, content)
    }
}

impl StaticPublicKeyResolver {
    pub fn new(public_keys: BTreeMap<String, JWK>) -> Self {
        Self { public_keys }
    }

    pub fn insert(&mut self, kid: impl Into<String>, public_jwk: JWK) {
        self.public_keys.insert(kid.into(), public_jwk);
    }
}

impl JwsPublicKeyResolver for StaticPublicKeyResolver {
    fn resolve_public_jwk(&self, kid: &str) -> Option<JWK> {
        self.public_keys.get(kid).cloned()
    }
}

fn decode_protected_header(protected: &str) -> Result<JwsProtectedHeader, JwsError> {
    let bytes = decode_base64url(protected, "protected header")?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn sign_jws_content(
    algorithm: Algorithm,
    private_jwk: &JWK,
    content: &[u8],
) -> Result<Vec<u8>, JwsError> {
    ssi_jws::sign_bytes(algorithm, content, private_jwk)
        .map_err(|error| map_ssi_sign_error(algorithm, error))
}

fn map_ssi_sign_error(algorithm: Algorithm, error: ssi_jws::Error) -> JwsError {
    match error {
        ssi_jws::Error::AlgorithmNotImplemented(_)
        | ssi_jws::Error::UnsupportedAlgorithm(_)
        | ssi_jws::Error::MissingFeatures(_) => {
            JwsError::UnsupportedAlgorithm(algorithm.to_string())
        }
        ssi_jws::Error::Jwk(ssi_jwk::Error::CurveNotImplemented(crv))
        | ssi_jws::Error::CurveNotImplemented(crv) => JwsError::UnsupportedCurve(crv),
        err => JwsError::InvalidKey(err.to_string()),
    }
}

fn verify_jws_signature(
    base64url_payload: &str,
    protected_b64: &str,
    signature_b64: &str,
    public_jwk: &JWK,
) -> Result<bool, JwsError> {
    let signing_input = format!("{}.{}", protected_b64, base64url_payload);
    let signature_bytes = decode_base64url(signature_b64, "signature")?;

    match jwk_curve(public_jwk)? {
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

fn ed25519_verifying_key(jwk: &JWK) -> Result<Ed25519VerifyingKey, JwsError> {
    let public_key = okp_params(jwk)?.public_key.0.clone();
    Ed25519VerifyingKey::from_bytes(&fixed_32_bytes(public_key, "Ed25519 public key")?)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn secp256k1_verifying_key(jwk: &JWK) -> Result<Secp256k1VerifyingKey, JwsError> {
    Secp256k1VerifyingKey::from_sec1_bytes(&ec_public_key_sec1(jwk)?)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn p256_verifying_key(jwk: &JWK) -> Result<P256VerifyingKey, JwsError> {
    P256VerifyingKey::from_sec1_bytes(&ec_public_key_sec1(jwk)?)
        .map_err(|err| JwsError::InvalidKey(err.to_string()))
}

fn ec_public_key_sec1(jwk: &JWK) -> Result<Vec<u8>, JwsError> {
    let params = ec_params(jwk)?;
    let x = fixed_32_bytes(
        params
            .x_coordinate
            .as_ref()
            .ok_or_else(|| JwsError::InvalidKey("EC public key missing x".to_string()))?
            .0
            .clone(),
        "EC public key x",
    )?;
    let y = fixed_32_bytes(
        params
            .y_coordinate
            .as_ref()
            .ok_or_else(|| JwsError::InvalidKey("EC public key missing y".to_string()))?
            .0
            .clone(),
        "EC public key y",
    )?;
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04);
    public_key.extend_from_slice(&x);
    public_key.extend_from_slice(&y);

    Ok(public_key)
}

pub(crate) fn jwk_curve(jwk: &JWK) -> Result<&str, JwsError> {
    match &jwk.params {
        Params::OKP(params) => Ok(&params.curve),
        Params::EC(params) => params
            .curve
            .as_deref()
            .ok_or_else(|| JwsError::InvalidKey("EC key missing crv".to_string())),
        _ => Err(JwsError::InvalidKey(
            "JWS key must be an EC or octet key pair".to_string(),
        )),
    }
}

pub(crate) fn okp_params(jwk: &JWK) -> Result<&OctetParams, JwsError> {
    match &jwk.params {
        Params::OKP(params) => Ok(params),
        _ => Err(JwsError::InvalidKey(
            "JWS key is not an octet key pair".to_string(),
        )),
    }
}

fn ec_params(jwk: &JWK) -> Result<&ECParams, JwsError> {
    match &jwk.params {
        Params::EC(params) => Ok(params),
        _ => Err(JwsError::InvalidKey("JWS key is not an EC key".to_string())),
    }
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
        Ok(ssi_jws::JwsSignerInfo::new(None, ssi_jwk::Algorithm::None))
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
    use std::{
        borrow::Cow,
        str::FromStr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    struct CountingPayload {
        calls: Arc<AtomicUsize>,
    }

    impl JwsPayload for CountingPayload {
        fn typ(&self) -> Option<&str> {
            Some("JWT")
        }

        fn cty(&self) -> Option<&str> {
            Some("application/json")
        }

        fn payload_bytes(&self) -> Cow<'_, [u8]> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Cow::Borrowed(b"stable payload")
        }
    }

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

    #[tokio::test]
    async fn create_snapshots_payload_bytes_and_header_metadata_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let payload = CountingPayload {
            calls: Arc::clone(&calls),
        };

        let jws = Jws::create(
            payload,
            Some(vec![JWK::generate_ed25519().expect("generate Ed25519 JWK")]),
        )
        .await
        .expect("sign snapshotted payload");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            jws.payload.as_deref(),
            Some(base64url.encode(b"stable payload").as_str())
        );

        let protected = jws.signatures.as_ref().unwrap()[0]
            .protected
            .as_deref()
            .unwrap();
        let header = ssi_jws::Header::decode(protected.as_bytes()).unwrap();
        assert_eq!(header.type_.as_deref(), Some("JWT"));
        assert_eq!(header.content_type.as_deref(), Some("application/json"));
    }

    #[tokio::test]
    async fn create_rejects_empty_signer_list() {
        let error = Jws::create(b"payload".to_vec(), Some(Vec::<JWK>::new()))
            .await
            .expect_err("empty signer list must fail");

        assert!(matches!(
            error,
            JwsError::SignError(SignatureError::MissingSigner)
        ));
    }

    #[test]
    fn create_general_rejects_empty_signer_list() {
        let error = Jws::create_general::<PrivateJwkSigner>(b"payload", &[])
            .expect_err("empty signer list must fail");

        assert!(matches!(
            error,
            JwsError::SignError(SignatureError::MissingSigner)
        ));
    }

    #[test]
    fn signing_maps_ssi_algorithm_and_curve_errors() {
        let key = JWK::generate_ed25519().expect("generate Ed25519 JWK");
        let signer = PrivateJwkSigner::new("did:example:alice#key-1", Algorithm::ES256, key);
        assert!(matches!(
            Jws::create_general(b"payload", &[signer]),
            Err(JwsError::UnsupportedAlgorithm(ref name)) if name == "ES256"
        ));

        let mapped = map_ssi_sign_error(
            Algorithm::EdDSA,
            ssi_jws::Error::Jwk(ssi_jwk::Error::CurveNotImplemented("Ed448".to_string())),
        );
        assert!(matches!(
            mapped,
            JwsError::UnsupportedCurve(ref curve) if curve == "Ed448"
        ));
    }

    #[test]
    fn test_payload_serializes_grant_fields() {
        let descriptor_cid =
            Cid::from_str("bafyreietui4xdkiu4xvmx4fi2jivjtndbhb4drzpxomrjvd4mdz4w2avra").unwrap();
        let delegated_grant_id =
            Cid::from_str("bafyreia3vo2bkk4b4nshzup55wgkdgwpr5bsa474iyngfcegompdko6kt4").unwrap();

        let payload = AuthorizationPayload::new(
            descriptor_cid,
            Some(delegated_grant_id),
            Some("grant-123".to_string()),
            Some("adminRole".to_string()),
        )
        .unwrap();

        let value: serde_json::Value = serde_json::from_slice(&payload.payload_bytes()).unwrap();
        assert_eq!(
            value,
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
        let public_jwk: JWK = serde_json::from_value(serde_json::to_value(&jwk).unwrap()).unwrap();

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
        let public_jwk: JWK = serde_json::from_value(serde_json::to_value(&jwk).unwrap()).unwrap();

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
        let other: JWK =
            serde_json::from_value(serde_json::to_value(JWK::generate_secp256k1()).unwrap())
                .unwrap();

        assert!(!jws
            .verify_signatures_public_jwk(&other)
            .expect("verification should not error"));
    }
}
