use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD as base64url};
use cid::Cid;
use serde::{Deserialize, Serialize};
use ssi_claims_core::SignatureError;
pub use ssi_jwk::JWK;
use ssi_jwk::{OctetParams, Params};
use ssi_jws::{JwsPayload, JwsSignerInfo};
use thiserror::Error;

pub use ssi_jwk::Algorithm;
pub use ssi_jws::JwsSigner;

use crate::auth::resolver::{resolve_signing_key, DidResolver, ResolverError};
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
    #[error(
        "public key for kid '{kid}' not found; available verification methods: {available_ids:?}"
    )]
    PublicKeyNotFound {
        kid: String,
        available_ids: Vec<String>,
    },
    #[error("failed to resolve DID '{did}': {source}")]
    ResolutionFailed {
        did: String,
        #[source]
        source: ResolverError,
    },
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
            Self::PublicKeyNotFound { .. } | Self::ResolutionFailed { .. } => {
                "GeneralJwsVerifierGetPublicKeyNotFound"
            }
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

#[derive(Debug)]
struct VerificationInput {
    kid: Option<String>,
    algorithm: Algorithm,
    signing_bytes: Vec<u8>,
    signature: Vec<u8>,
}

impl Jws {
    /// Sign `payload` as a General JWS using the supplied SSI signers.
    ///
    /// The DWN wire format orders `kid` before `alg` in the protected header. This method keeps
    /// that byte-level compatibility while preserving SSI payload and signer metadata and
    /// delegating cryptography to [`JwsSigner`].
    pub async fn create<S, P>(payload: &P, signers: &[S]) -> Result<Self, JwsError>
    where
        S: JwsSigner,
        P: JwsPayload + ?Sized,
    {
        if signers.is_empty() {
            return Err(JwsError::SignError(SignatureError::MissingSigner));
        }

        let snapshot = PayloadSnapshot::new(payload);
        let encoded_payload = base64url.encode(&snapshot.bytes);
        let signatures = Self::generate_signatures(signers, &encoded_payload, &snapshot).await?;

        Ok(Self {
            payload: Some(encoded_payload),
            signatures: Some(signatures),
            header: None,
            extra: MapValue::default(),
        })
    }

    async fn generate_signatures<S>(
        signers: &[S],
        encoded_payload: &str,
        payload: &PayloadSnapshot,
    ) -> Result<Vec<JwsSignature>, JwsError>
    where
        S: JwsSigner,
    {
        let mut signatures = Vec::with_capacity(signers.len());

        for signer in signers {
            signatures.push(
                Self::sign_encoded_payload(
                    encoded_payload,
                    signer,
                    payload.typ.as_deref(),
                    payload.cty.as_deref(),
                )
                .await?,
            );
        }

        Ok(signatures)
    }

    /// Append a signature to an existing JWS.
    pub async fn add_signature<S>(&mut self, signer: &S) -> Result<(), JwsError>
    where
        S: JwsSigner,
    {
        let payload = self.payload.as_deref().ok_or(JwsError::MissingPayload)?;
        let signature = Self::sign_encoded_payload(payload, signer, None, None).await?;

        self.signatures.get_or_insert_with(Vec::new).push(signature);

        Ok(())
    }

    async fn sign_encoded_payload<S>(
        encoded_payload: &str,
        signer: &S,
        typ: Option<&str>,
        cty: Option<&str>,
    ) -> Result<JwsSignature, JwsError>
    where
        S: JwsSigner,
    {
        let info = signer.fetch_info().await?;
        let protected = base64url.encode(serde_json::to_vec(&JwsProtectedHeader {
            kid: info.kid,
            alg: Some(info.alg.to_string()),
            jwk: info.jwk,
            x5c: info.x5c,
            typ: typ.map(ToOwned::to_owned),
            cty: cty.map(ToOwned::to_owned),
        })?);
        let signing_input = format!("{protected}.{encoded_payload}");
        let signature = signer.sign_bytes(signing_input.as_bytes()).await?;

        Ok(JwsSignature {
            protected: Some(protected),
            signature: Some(base64url.encode(signature)),
            extra: MapValue::default(),
        })
    }

    /// Verify the signatures on this JWS, returning the DIDs of the signers.
    pub async fn verify_signatures(
        &self,
        resolver: &dyn DidResolver,
    ) -> Result<Vec<String>, JwsError> {
        let payload = self.payload.as_deref().ok_or(JwsError::MissingPayload)?;
        let signatures = self
            .signatures
            .as_deref()
            .ok_or(JwsError::MissingSignatures)?;
        let mut signers = Vec::new();

        for signature in signatures {
            let input = prepare_verification(payload, signature)?;
            let kid = input.kid.as_deref().ok_or(JwsError::MissingKid)?;

            let public_jwk = resolve_signing_key(kid, resolver).await?;
            if verify_jws_signature(
                input.algorithm,
                &input.signing_bytes,
                &input.signature,
                &public_jwk,
            )? {
                signers.push(extract_did(kid));
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
            let input = prepare_verification(payload, signature)?;

            if !verify_jws_signature(
                input.algorithm,
                &input.signing_bytes,
                &input.signature,
                public_jwk,
            )? {
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

#[derive(Debug, Clone)]
pub struct PrivateJwkSigner {
    key_id: String,
    algorithm: Algorithm,
    private_jwk: JWK,
}

#[derive(Serialize)]
struct JwsProtectedHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<JWK>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5c: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<String>,
}

#[derive(Deserialize)]
struct VerificationProtectedHeader {
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

impl JwsSigner for PrivateJwkSigner {
    async fn fetch_info(&self) -> Result<JwsSignerInfo, SignatureError> {
        Ok(JwsSignerInfo::new(
            Some(self.key_id.clone()),
            self.algorithm,
        ))
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        ssi_jws::sign_bytes(self.algorithm, signing_bytes, &self.private_jwk).map_err(Into::into)
    }
}

fn decode_protected_header(protected: &str) -> Result<VerificationProtectedHeader, JwsError> {
    let bytes = decode_base64url(protected, "protected header")?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn parse_algorithm(value: &str) -> Result<Algorithm, JwsError> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|_| JwsError::UnsupportedAlgorithm(value.to_owned()))
}

fn prepare_verification(
    base64url_payload: &str,
    signature: &JwsSignature,
) -> Result<VerificationInput, JwsError> {
    let protected = signature
        .protected
        .as_deref()
        .ok_or(JwsError::MissingProtected)?;
    let signature = signature
        .signature
        .as_deref()
        .ok_or(JwsError::MissingSignature)?;
    let protected_header = decode_protected_header(protected)?;
    let algorithm_name = protected_header
        .alg
        .as_deref()
        .ok_or(JwsError::MissingAlg)?;
    let algorithm = parse_algorithm(algorithm_name)?;

    Ok(VerificationInput {
        kid: protected_header.kid,
        algorithm,
        signing_bytes: format!("{protected}.{base64url_payload}").into_bytes(),
        signature: decode_base64url(signature, "signature")?,
    })
}

fn verify_jws_signature(
    algorithm: Algorithm,
    signing_input: &[u8],
    signature_bytes: &[u8],
    public_jwk: &JWK,
) -> Result<bool, JwsError> {
    let key_algorithm = public_jwk.get_algorithm().ok_or_else(|| {
        JwsError::InvalidKey("unable to determine JWS algorithm from public key".to_string())
    })?;
    if !key_algorithm.is_compatible_with(algorithm) {
        return Ok(false);
    }

    match ssi_jws::verify_bytes(algorithm, signing_input, public_jwk, signature_bytes) {
        Ok(()) => Ok(true),
        Err(
            ssi_jws::Error::AlgorithmMismatch
            | ssi_jws::Error::CryptoErr(_)
            | ssi_jws::Error::InvalidSignature
            | ssi_jws::Error::UnexpectedSignatureLength(_, _)
            | ssi_jws::Error::Jwk(ssi_jwk::Error::CryptoErr(_)),
        ) => Ok(false),
        Err(error) => Err(map_ssi_verify_error(algorithm, error)),
    }
}

fn map_ssi_verify_error(algorithm: Algorithm, error: ssi_jws::Error) -> JwsError {
    match error {
        ssi_jws::Error::AlgorithmNotImplemented(_)
        | ssi_jws::Error::UnsupportedAlgorithm(_)
        | ssi_jws::Error::MissingFeatures(_) => {
            JwsError::UnsupportedAlgorithm(algorithm.to_string())
        }
        ssi_jws::Error::Jwk(ssi_jwk::Error::CurveNotImplemented(curve))
        | ssi_jws::Error::CurveNotImplemented(curve) => JwsError::UnsupportedCurve(curve),
        error => JwsError::InvalidKey(error.to_string()),
    }
}

fn decode_base64url(value: &str, label: &str) -> Result<Vec<u8>, JwsError> {
    base64url
        .decode(value)
        .map_err(|err| JwsError::Base64UrlError(format!("{label}: {err}")))
}

fn extract_did(kid: &str) -> String {
    kid.parse::<ssi_dids_core::DIDURLBuf>()
        .map(|did_url| did_url.did().to_string())
        .unwrap_or_else(|_| kid.to_string())
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
    use crate::auth::resolver::{StaticPublicKeyResolver, UniversalResolver};
    use serde_json::json;
    use ssi_jwk::JWK;
    use std::{
        borrow::Cow,
        collections::BTreeMap,
        str::FromStr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    struct CountingPayload {
        calls: Arc<AtomicUsize>,
    }

    struct MetadataSigner {
        private_jwk: JWK,
    }

    impl JwsSigner for MetadataSigner {
        async fn fetch_info(&self) -> Result<JwsSignerInfo, SignatureError> {
            let mut info = JwsSignerInfo::new(
                Some("did:example:alice#key-1".to_string()),
                Algorithm::EdDSA,
            );
            info.jwk = Some(self.private_jwk.to_public());
            info.x5c = Some(vec!["certificate".to_string()]);
            Ok(info)
        }

        async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
            ssi_jws::sign_bytes(Algorithm::EdDSA, signing_bytes, &self.private_jwk)
                .map_err(Into::into)
        }
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
        let jws = Jws::create(b"hello world".as_slice(), &[jwk])
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

        let signer = MetadataSigner {
            private_jwk: JWK::generate_ed25519().expect("generate Ed25519 JWK"),
        };
        let expected_public_jwk = signer.private_jwk.to_public();
        let jws = Jws::create(&payload, &[signer])
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
        let protected_json = String::from_utf8(decode_base64url(protected, "header").unwrap())
            .expect("protected header must be UTF-8");
        assert!(
            protected_json.starts_with(r#"{"kid":"did:example:alice#key-1","alg":"EdDSA","jwk":"#)
        );
        let header = ssi_jws::Header::decode(protected.as_bytes()).unwrap();
        assert_eq!(header.key_id.as_deref(), Some("did:example:alice#key-1"));
        assert_eq!(header.jwk, Some(expected_public_jwk));
        assert_eq!(
            header.x509_certificate_chain,
            Some(vec!["certificate".to_string()])
        );
        assert_eq!(header.type_.as_deref(), Some("JWT"));
        assert_eq!(header.content_type.as_deref(), Some("application/json"));
    }

    #[tokio::test]
    async fn create_rejects_empty_signer_list() {
        let error = Jws::create::<JWK, _>(b"payload".as_slice(), &[])
            .await
            .expect_err("empty signer list must fail");

        assert!(matches!(
            error,
            JwsError::SignError(SignatureError::MissingSigner)
        ));
    }

    #[tokio::test]
    async fn private_jwk_signer_reports_ssi_algorithm_errors() {
        let key = JWK::generate_ed25519().expect("generate Ed25519 JWK");
        let signer = PrivateJwkSigner::new("did:example:alice#key-1", Algorithm::ES256, key);
        assert!(matches!(
            Jws::create(b"payload".as_slice(), &[signer]).await,
            Err(JwsError::SignError(SignatureError::UnsupportedAlgorithm(ref name)))
                if name == "ES256"
        ));
    }

    #[tokio::test]
    async fn private_jwk_signer_exposes_ssi_signer_metadata() {
        let signer = PrivateJwkSigner::new(
            "did:example:alice#key-1",
            Algorithm::EdDSA,
            JWK::generate_ed25519().expect("generate Ed25519 JWK"),
        );

        let info = signer.fetch_info().await.expect("fetch SSI signer info");

        assert_eq!(info.kid.as_deref(), Some("did:example:alice#key-1"));
        assert_eq!(info.alg, Algorithm::EdDSA);
    }

    #[tokio::test]
    async fn add_signature_uses_ssi_signers() {
        let alice_key = JWK::generate_ed25519().expect("generate Ed25519 JWK");
        let alice_public = alice_key.to_public();
        let alice = PrivateJwkSigner::new("did:example:alice#key-1", Algorithm::EdDSA, alice_key);
        let bob_key = JWK::generate_secp256k1();
        let bob_public = bob_key.to_public();
        let bob = PrivateJwkSigner::new("did:example:bob#key-1", Algorithm::ES256K, bob_key);

        let mut jws = Jws::create(b"payload".as_slice(), &[alice])
            .await
            .expect("sign with Alice");
        jws.add_signature(&bob).await.expect("sign with Bob");

        let resolver = StaticPublicKeyResolver::new(BTreeMap::from([
            ("did:example:alice#key-1".to_string(), alice_public),
            ("did:example:bob#key-1".to_string(), bob_public),
        ]));
        assert_eq!(
            jws.verify_signatures(&resolver).await.unwrap(),
            ["did:example:alice", "did:example:bob"]
        );
    }

    #[tokio::test]
    async fn native_did_resolution_cannot_be_shadowed_by_static_keys() {
        let private_jwk = JWK::generate_ed25519().unwrap();
        let public_jwk = private_jwk.to_public();
        let encoded = base64url.encode(serde_json::to_vec(&public_jwk).unwrap());
        let did = format!("did:jwk:{encoded}");
        let kid = format!("{did}#0");
        let signer = PrivateJwkSigner::new(kid.clone(), Algorithm::EdDSA, private_jwk);
        let jws = Jws::create(b"native wins".as_slice(), &[signer])
            .await
            .unwrap();

        let fallback =
            StaticPublicKeyResolver::new(BTreeMap::from([(kid, JWK::generate_ed25519().unwrap())]));
        let resolver = UniversalResolver::with_fallback(fallback);

        assert_eq!(jws.verify_signatures(&resolver).await.unwrap(), [did]);
    }

    #[tokio::test]
    async fn verifies_multiple_signatures_across_native_did_methods() {
        let jwk_private = JWK::generate_ed25519().unwrap();
        let jwk_public = jwk_private.to_public();
        let jwk_did = format!(
            "did:jwk:{}",
            base64url.encode(serde_json::to_vec(&jwk_public).unwrap())
        );
        let jwk_signer =
            PrivateJwkSigner::new(format!("{jwk_did}#0"), Algorithm::EdDSA, jwk_private);

        let key_private = JWK::generate_ed25519().unwrap();
        let Params::OKP(key_params) = &key_private.params else {
            panic!("generated Ed25519 JWK must use OKP parameters");
        };
        let mut multicodec_key = vec![0xed, 0x01];
        multicodec_key.extend_from_slice(&key_params.public_key.0);
        let identifier = multibase::encode(multibase::Base::Base58Btc, multicodec_key);
        let key_did = format!("did:key:{identifier}");
        let key_signer = PrivateJwkSigner::new(
            format!("{key_did}#{identifier}"),
            Algorithm::EdDSA,
            key_private,
        );

        let jws = Jws::create(b"two native methods".as_slice(), &[jwk_signer, key_signer])
            .await
            .unwrap();
        let resolver = UniversalResolver::new();

        assert_eq!(
            jws.verify_signatures(&resolver).await.unwrap(),
            [jwk_did, key_did]
        );
    }

    #[test]
    fn prepare_verification_parses_protected_input_once() {
        let protected = base64url.encode(
            serde_json::to_vec(&json!({
                "kid": "did:example:alice#key-1",
                "alg": "EdDSA",
            }))
            .unwrap(),
        );
        let signature_bytes = [1, 2, 3, 4];
        let signature = JwsSignature {
            protected: Some(protected.clone()),
            signature: Some(base64url.encode(signature_bytes)),
            ..Default::default()
        };

        let input = prepare_verification("cGF5bG9hZA", &signature).unwrap();

        assert_eq!(input.kid.as_deref(), Some("did:example:alice#key-1"));
        assert_eq!(input.algorithm, Algorithm::EdDSA);
        assert_eq!(
            input.signing_bytes,
            format!("{protected}.cGF5bG9hZA").into_bytes()
        );
        assert_eq!(input.signature, signature_bytes);
    }

    #[test]
    fn prepare_verification_rejects_missing_and_unknown_algorithms() {
        let signature_for_header = |header: serde_json::Value| JwsSignature {
            protected: Some(base64url.encode(serde_json::to_vec(&header).unwrap())),
            signature: Some(base64url.encode([1, 2, 3, 4])),
            ..Default::default()
        };

        let missing = prepare_verification("cGF5bG9hZA", &signature_for_header(json!({})))
            .expect_err("missing alg must fail");
        assert!(matches!(missing, JwsError::MissingAlg));

        let unknown = prepare_verification(
            "cGF5bG9hZA",
            &signature_for_header(json!({ "alg": "not-an-ssi-algorithm" })),
        )
        .expect_err("unknown alg must fail");
        assert!(matches!(
            unknown,
            JwsError::UnsupportedAlgorithm(ref name) if name == "not-an-ssi-algorithm"
        ));
    }

    #[test]
    fn verify_signatures_public_jwk_requires_protected_algorithm() {
        let jws = Jws {
            payload: Some("cGF5bG9hZA".to_string()),
            signatures: Some(vec![JwsSignature {
                protected: Some(base64url.encode(b"{}")),
                signature: Some(base64url.encode([1, 2, 3, 4])),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let public_jwk = JWK::generate_ed25519().expect("generate Ed25519 JWK");

        assert!(matches!(
            jws.verify_signatures_public_jwk(&public_jwk),
            Err(JwsError::MissingAlg)
        ));
    }

    #[tokio::test]
    async fn ssi_verification_accepts_supported_key_algorithms() {
        let cases = [
            (
                JWK::generate_ed25519().expect("generate Ed25519 JWK"),
                Algorithm::EdDSA,
            ),
            (JWK::generate_secp256k1(), Algorithm::ES256K),
            (JWK::generate_p256(), Algorithm::ES256),
        ];

        for (private_jwk, algorithm) in cases {
            let public_jwk = private_jwk.to_public();
            let signer = PrivateJwkSigner::new("did:example:alice#key-1", algorithm, private_jwk);
            let jws = Jws::create(b"payload".as_slice(), &[signer])
                .await
                .expect("sign payload");

            assert!(jws
                .verify_signatures_public_jwk(&public_jwk)
                .expect("SSI verification should succeed for the matching algorithm"));
        }
    }

    #[tokio::test]
    async fn protected_algorithm_must_be_compatible_with_resolved_key() {
        let private_jwk = JWK::generate_ed25519().expect("generate Ed25519 JWK");
        let public_jwk = private_jwk.to_public();
        let kid = "did:example:alice#key-1";
        let payload = base64url.encode(b"payload");
        let protected = base64url.encode(
            serde_json::to_vec(&json!({
                "kid": kid,
                "alg": "ES256K",
            }))
            .unwrap(),
        );
        let signing_input = format!("{protected}.{payload}");

        // The bytes carry a valid Ed25519 signature, but the protected header
        // falsely labels it as ES256K.
        let signature =
            ssi_jws::sign_bytes(Algorithm::EdDSA, signing_input.as_bytes(), &private_jwk)
                .expect("sign deliberately mislabeled input");
        let jws = Jws {
            payload: Some(payload),
            signatures: Some(vec![JwsSignature {
                protected: Some(protected),
                signature: Some(base64url.encode(signature)),
                ..Default::default()
            }]),
            ..Default::default()
        };

        assert!(!jws
            .verify_signatures_public_jwk(&public_jwk)
            .expect("algorithm mismatch is a failed verification"));

        let mut resolver = StaticPublicKeyResolver::default();
        resolver.insert(kid, public_jwk);
        assert!(matches!(
            jws.verify_signatures(&resolver).await,
            Err(JwsError::InvalidSignature)
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

        let jws = Jws::create(b"hello world".as_slice(), &[jwk])
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

        let mut jws = Jws::create(b"hello world".as_slice(), &[jwk])
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
        let jws = Jws::create(b"hello world".as_slice(), &[JWK::generate_secp256k1()])
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
