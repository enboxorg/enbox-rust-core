use super::{fixed_32, AgentIdentityError, AgentIdentityResult, PortableDid};
use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use ssi_dids_core::document::verification_method::ValueOrReference;
use ssi_dids_core::document::{DIDVerificationMethod, Service};
use ssi_dids_core::{DIDBuf, Document};
use ssi_jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub(crate) fn ed25519_public_bytes(jwk: &JWK) -> AgentIdentityResult<[u8; 32]> {
    match &jwk.to_public().params {
        Params::OKP(params) if params.curve == "Ed25519" => fixed_32(&params.public_key.0),
        _ => Err(AgentIdentityError::invalid_key_material(
            "agent key must be Ed25519",
        )),
    }
}

pub(crate) fn x25519_public_bytes(jwk: &JWK) -> AgentIdentityResult<[u8; 32]> {
    match &jwk.to_public().params {
        Params::OKP(params) if params.curve == "X25519" => fixed_32(&params.public_key.0),
        _ => Err(AgentIdentityError::invalid_key_material(
            "agent encryption key must be X25519",
        )),
    }
}

/// Decoder-normal public JWK value: thumbprint kid with the default
/// algorithm filled in, so construction output already matches decode output.
pub(crate) fn dht_public_jwk(
    private_jwk: &JWK,
    default_alg: &str,
) -> AgentIdentityResult<JsonValue> {
    let public_jwk = private_jwk.to_public();
    let kid = public_jwk
        .thumbprint()
        .map_err(|err| AgentIdentityError::did(format!("cannot thumbprint public JWK: {err:?}")))?;
    let mut value = serde_json::to_value(public_jwk)
        .map_err(|err| AgentIdentityError::did(format!("invalid public JWK: {err}")))?;
    value["kid"] = JsonValue::String(kid);
    value["alg"] = JsonValue::String(default_alg.to_string());
    Ok(value)
}

pub(crate) fn ed25519_private_jwk(private_key: [u8; 32], alg: Option<&str>) -> JWK {
    let public_key = ed25519_public_key_bytes(private_key);
    let mut jwk = JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(public_key.to_vec()),
        private_key: Some(Base64urlUInt(private_key.to_vec())),
    }));
    jwk.algorithm = alg.map(|_| Algorithm::EdDSA);
    jwk
}

pub(crate) fn ed25519_public_key_bytes(private_key: [u8; 32]) -> [u8; 32] {
    Ed25519SigningKey::from_bytes(&private_key)
        .verifying_key()
        .to_bytes()
}

pub(crate) fn x25519_private_jwk(private_key: [u8; 32]) -> JWK {
    let static_secret = X25519StaticSecret::from(private_key);
    let public_key = X25519PublicKey::from(&static_secret).to_bytes();
    JWK::from(Params::OKP(OctetParams {
        curve: "X25519".to_string(),
        public_key: Base64urlUInt(public_key.to_vec()),
        private_key: Some(Base64urlUInt(private_key.to_vec())),
    }))
}

pub(crate) fn did_jwk_uri(public_jwk: &JWK) -> AgentIdentityResult<String> {
    let mut jwk = public_jwk.to_public();
    jwk.key_id = None;
    jwk.algorithm = None;
    let encoded = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&jwk).map_err(|err| AgentIdentityError::did(err.to_string()))?);
    Ok(format!("did:jwk:{encoded}"))
}

pub(crate) fn key_uri_for_jwk(jwk: &JWK) -> AgentIdentityResult<String> {
    if let Some(kid) = &jwk.key_id {
        return Ok(kid.clone());
    }
    let public_jwk = jwk.to_public();
    let bytes = serde_json::to_vec(&public_jwk)
        .map_err(|err| AgentIdentityError::key_manager(err.to_string()))?;
    Ok(format!(
        "urn:jwk:sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
}

pub(crate) fn jwk_curve(jwk: &JWK) -> Option<&str> {
    match &jwk.params {
        Params::OKP(params) => Some(&params.curve),
        Params::EC(params) => params.curve.as_deref(),
        _ => None,
    }
}

pub(crate) fn verification_method_jwk(method: &DIDVerificationMethod) -> Option<JWK> {
    method
        .properties
        .get("publicKeyJwk")
        .cloned()
        .and_then(|mut value| {
            // The DID DHT decoder fills non-JOSE default algorithms such as
            // ECDH-ES+A256KW, which the closed Algorithm enum cannot name. Key
            // identity never depends on the algorithm string.
            if let Some(object) = value.as_object_mut() {
                object.remove("alg");
            }
            serde_json::from_value(value).ok()
        })
}

pub(crate) fn relationship_id(document: &Document, relationship: &ValueOrReference) -> String {
    relationship.id().resolve(&document.id).to_string()
}

/// Current time, behind one choke point so a future injectable clock has a single migration site.
pub(crate) fn now_utc() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

pub(crate) fn key_agreement_root_key_id(
    tenant_did: &PortableDid,
    missing: impl Fn(String) -> AgentIdentityError,
    not_x25519: impl Fn(String) -> AgentIdentityError,
) -> AgentIdentityResult<String> {
    let Some(root_key) = tenant_did
        .document
        .verification_relationships
        .key_agreement
        .first()
    else {
        return Err(missing(format!(
            "DID {} does not have a keyAgreement verification method",
            tenant_did.uri
        )));
    };
    let root_key_id = relationship_id(&tenant_did.document, root_key);
    let method = tenant_did
        .document
        .verification_method
        .iter()
        .find(|method| method.id.as_str() == root_key_id)
        .ok_or_else(|| {
            missing(format!(
                "keyAgreement method {root_key_id} is missing from the DID document"
            ))
        })?;
    let public_jwk = verification_method_jwk(method).ok_or_else(|| {
        missing(format!(
            "keyAgreement method {root_key_id} does not contain a public JWK"
        ))
    })?;
    if jwk_curve(&public_jwk) != Some("X25519") {
        return Err(not_x25519(format!(
            "keyAgreement method {root_key_id} uses {}, but X25519 key agreement is required",
            jwk_curve(&public_jwk).unwrap_or("unknown")
        )));
    }
    Ok(root_key_id)
}

pub(crate) fn relationship_contains(
    document: &Document,
    relationships: &[ValueOrReference],
    method: &DIDVerificationMethod,
) -> bool {
    relationships
        .iter()
        .any(|relationship| *relationship.id().resolve(&document.id) == *method.id)
}

pub(crate) fn okp_params(jwk: &JWK) -> AgentIdentityResult<&OctetParams> {
    match &jwk.params {
        Params::OKP(params) => Ok(params),
        _ => Err(AgentIdentityError::key_manager(
            "key is not an octet key pair JWK",
        )),
    }
}

pub(crate) fn with_key_id(mut jwk: JWK, key_id: impl Into<String>) -> JWK {
    jwk.key_id = Some(key_id.into());
    jwk
}

pub(crate) fn parse_did(value: &str) -> AgentIdentityResult<DIDBuf> {
    value
        .parse()
        .map_err(|err| AgentIdentityError::did(format!("invalid DID {value}: {err}")))
}

pub(crate) fn parse_verification_reference(value: &str) -> AgentIdentityResult<ValueOrReference> {
    value
        .parse::<ssi_dids_core::DIDURLBuf>()
        .map(|url| ValueOrReference::Reference(url.into()))
        .map_err(|err| AgentIdentityError::did(format!("invalid DID URL {value}: {err}")))
}

pub(crate) fn did_verification_method(
    id: &str,
    controller: &DIDBuf,
    public_jwk: JWK,
) -> AgentIdentityResult<DIDVerificationMethod> {
    let public_key_jwk =
        serde_json::to_value(public_jwk).map_err(|err| AgentIdentityError::did(err.to_string()))?;
    did_method_with_jwk_value(id, "JsonWebKey2020", controller, public_key_jwk)
}

pub(crate) fn did_method_with_jwk_value(
    id: &str,
    method_type: &str,
    controller: &DIDBuf,
    public_key_jwk: JsonValue,
) -> AgentIdentityResult<DIDVerificationMethod> {
    let id = id
        .parse()
        .map_err(|err| AgentIdentityError::did(format!("invalid DID URL {id}: {err}")))?;
    let properties = BTreeMap::from([("publicKeyJwk".to_string(), public_key_jwk)]);
    Ok(DIDVerificationMethod::new(
        id,
        method_type.to_string(),
        controller.clone(),
        properties,
    ))
}

pub(crate) fn did_service(id: &str, endpoints: Vec<String>) -> AgentIdentityResult<Service> {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "type": "DecentralizedWebNode",
        "serviceEndpoint": endpoints,
    }))
    .map_err(|err| AgentIdentityError::did(format!("invalid DID service: {err}")))
}
