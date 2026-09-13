//! Verified grant-key resolution: deciding whether a delivered key is usable
//! *now*, for a target record.
//!
//! Admission checks a delivery at its signed timestamp against historical
//! state; resolution re-checks at the current time against current state.
//! The two read authority differently on purpose — timestamped definition
//! versus current definition, revocation-at-or-before-timestamp versus any
//! revocation — so they share the coverage predicate but never a helper.
//!
//! Pure functions over caller-supplied evidence, no store or key access:
//! fetching the current definition, checking revocation, and decrypting the
//! delivery belong to the wiring layer. Failures yield no usable key and
//! never populate a cache; that invariant is the caller's to keep.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use ssi_jwk::JWK;
use thiserror::Error;

use crate::encryption::protocol::GRANT_KEY_PAYLOAD_SCHEMA_URI;
use crate::encryption::x25519::{private_key_bytes, public_jwk};
use crate::encryption::KEY_AGREEMENT_ALGORITHM;
use crate::interfaces::messages::protocols::Definition;
use crate::permissions::grant_key_coverage::{
    eligible_grant_scope, grant_covers_delivered_scope, matches_subtree, DeliveredScope,
    GrantedScope,
};
use crate::permissions::PermissionGrant;

/// A decrypted grant-key payload, structurally validated. Shape follows the
/// agent `assertGrantKeyPayload` / `isProtocolPathKeyMaterial` /
/// `isX25519KeyMaterial` predicates; additional properties are accepted.
#[derive(Debug, Clone, Deserialize)]
pub struct GrantKeyPayload {
    #[serde(rename = "grantId")]
    pub grant_id: String,
    pub scope: PayloadScope,
    #[serde(rename = "keyMaterial")]
    pub key_material: KeyMaterial,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PayloadScope {
    pub scheme: String,
    pub protocol: String,
    #[serde(rename = "protocolPath", default)]
    pub protocol_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyMaterial {
    pub algorithm: String,
    #[serde(rename = "derivationScheme")]
    pub derivation_scheme: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "derivationPath")]
    pub derivation_path: Vec<String>,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: JWK,
    #[serde(rename = "privateKeyJwk")]
    pub private_key_jwk: JWK,
}

/// The delivery record's tags as plain strings.
#[derive(Debug, Clone)]
pub struct DeliveryTags {
    pub grant_id: String,
    pub protocol: String,
    pub protocol_path: Option<String>,
    pub key_id: String,
}

/// The record a resolved key must open.
#[derive(Debug, Clone)]
pub struct ResolutionTarget {
    pub protocol: String,
    pub protocol_path: Option<String>,
}

/// Everything resolution verifies, in one place. The definition is the
/// *current* configuration and `revoked` is *any* revocation: both differ
/// from admission on purpose.
#[derive(Debug, Clone)]
pub struct ResolutionInput<'a> {
    pub grant: &'a PermissionGrant,
    pub grantor: &'a str,
    pub grantee: &'a str,
    pub delivery_path: &'a str,
    pub has_envelope: bool,
    pub tags: DeliveryTags,
    pub payload: &'a GrantKeyPayload,
    pub target: ResolutionTarget,
    pub definition: Option<&'a Definition>,
    pub revoked: bool,
    pub now: DateTime<Utc>,
}

/// A key the resolution boundary releases: id plus private material plus the
/// scope it was verified for.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedGrantKey {
    pub key_id: String,
    pub private_key_jwk: JWK,
    pub scope: GrantedScope,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ResolutionError {
    #[error("grant-key payload is not JSON: {0}")]
    Malformed(String),
    #[error("grant-key payload fails its schema: {0}")]
    SchemaInvalid(String),
    #[error("delivery is not a grant-key record: {0}")]
    Representation(String),
    #[error("grant-key payload does not match record tags")]
    TagMismatch,
    #[error("grant-key payload is not covered by the referenced grant")]
    GrantMismatch,
    #[error("grant-key references an inactive permission grant")]
    Inactive,
    #[error("grant-key references an expired permission grant")]
    Expired,
    #[error("grant-key references a revoked permission grant")]
    Revoked,
    #[error("grant-key scope is outside the permission grant scope")]
    ScopeMismatch,
    #[error("grant-key scope does not cover the target record")]
    TargetNotCovered,
    #[error("grant-key derivation path does not match its scope")]
    DerivationMismatch,
    #[error("grant-key key id does not match delivered key material")]
    KeyMismatch,
    #[error("grant-key coverage needs the current protocol definition")]
    DefinitionMissing,
}

/// Parses and structurally validates a decrypted payload from either delivery
/// representation. Schema first, then typed: the schema owns shapes the types
/// cannot express, mirroring admission order.
pub fn parse_grant_key_payload(bytes: &[u8]) -> Result<GrantKeyPayload, ResolutionError> {
    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| ResolutionError::Malformed(error.to_string()))?;
    crate::validation::validate_against_schema(GRANT_KEY_PAYLOAD_SCHEMA_URI, &raw)
        .map_err(|error| ResolutionError::SchemaInvalid(error.to_string()))?;
    serde_json::from_value(raw).map_err(|error| ResolutionError::Malformed(error.to_string()))
}

/// Verifies a delivered key is usable now, for the target record. Any failure
/// yields no key; a historically admitted delivery routinely fails here after
/// expiry or revocation, and that rejects the key without deleting the record.
pub fn verify_grant_key_resolution(
    input: ResolutionInput<'_>,
) -> Result<VerifiedGrantKey, ResolutionError> {
    let payload = input.payload;

    let is_grant_key = input.delivery_path == "grantKey";
    let is_wrapped = input.delivery_path == "wrappedGrantKey";
    if !is_grant_key && !is_wrapped
        || is_grant_key && !input.has_envelope
        || is_wrapped && input.has_envelope
    {
        return Err(ResolutionError::Representation(format!(
            "delivery at '{}' misrepresents its encryption",
            input.delivery_path
        )));
    }

    if payload.grant_id != input.tags.grant_id
        || payload.scope.protocol != input.tags.protocol
        || payload.key_material.key_id != input.tags.key_id
        || payload.scope.protocol_path != input.tags.protocol_path
    {
        return Err(ResolutionError::TagMismatch);
    }

    if payload.grant_id != input.grant.id
        || input.grant.grantor != input.grantor
        || input.grant.grantee != input.grantee
    {
        return Err(ResolutionError::GrantMismatch);
    }

    if input.now < input.grant.date_granted {
        return Err(ResolutionError::Inactive);
    }
    if input.now >= input.grant.date_expires {
        return Err(ResolutionError::Expired);
    }
    if input.revoked {
        return Err(ResolutionError::Revoked);
    }

    if payload.scope.scheme != "protocolPath" {
        return Err(ResolutionError::ScopeMismatch);
    }
    let Some(eligible) = eligible_grant_scope(&input.grant.scope) else {
        return Err(ResolutionError::ScopeMismatch);
    };
    let delivered = DeliveredScope {
        protocol: &payload.scope.protocol,
        protocol_path: payload.scope.protocol_path.as_deref(),
    };
    if !grant_covers_delivered_scope(&eligible, &delivered, None) {
        let Some(_) = delivered.protocol_path else {
            return Err(ResolutionError::ScopeMismatch);
        };
        let Some(definition) = input.definition else {
            return Err(ResolutionError::DefinitionMissing);
        };
        if !grant_covers_delivered_scope(&eligible, &delivered, Some(definition)) {
            return Err(ResolutionError::ScopeMismatch);
        }
    }

    if payload.scope.protocol != input.target.protocol
        || !covers_target(&payload.scope, &input.target)
    {
        return Err(ResolutionError::TargetNotCovered);
    }

    let mut expected = vec!["protocolPath".to_string(), payload.scope.protocol.clone()];
    if let Some(path) = &payload.scope.protocol_path {
        expected.extend(path.split('/').map(str::to_string));
    }
    if payload.key_material.derivation_path != expected {
        return Err(ResolutionError::DerivationMismatch);
    }

    if payload.key_material.algorithm != KEY_AGREEMENT_ALGORITHM
        || payload.key_material.derivation_scheme != "protocolPath"
    {
        return Err(ResolutionError::KeyMismatch);
    }
    let public_id = payload
        .key_material
        .public_key_jwk
        .thumbprint()
        .map_err(|_| ResolutionError::KeyMismatch)?;
    let derived_id = derived_public_id(&payload.key_material.private_key_jwk)?;
    if payload.key_material.key_id != public_id || payload.key_material.key_id != derived_id {
        return Err(ResolutionError::KeyMismatch);
    }

    Ok(VerifiedGrantKey {
        key_id: payload.key_material.key_id.clone(),
        private_key_jwk: payload.key_material.private_key_jwk.clone(),
        scope: GrantedScope {
            protocol: payload.scope.protocol.clone(),
            protocol_path: payload.scope.protocol_path.clone(),
        },
    })
}

/// Whether a payload scope opens the target record: the protocols must match,
/// and a path scope must be the target path or an ancestor of it.
fn covers_target(scope: &PayloadScope, target: &ResolutionTarget) -> bool {
    let Some(scope_path) = &scope.protocol_path else {
        return true;
    };
    let Some(target_path) = &target.protocol_path else {
        return false;
    };
    matches_subtree(scope_path, target_path)
}

fn derived_public_id(private_jwk: &JWK) -> Result<String, ResolutionError> {
    let private_bytes = private_key_bytes(private_jwk).map_err(|_| ResolutionError::KeyMismatch)?;
    let secret = x25519_dalek::StaticSecret::from(private_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    public_jwk(public.as_bytes())
        .thumbprint()
        .map_err(|_| ResolutionError::KeyMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{ProtocolPath, RecordsMethod, RecordsScope};
    use chrono::TimeZone;

    const PROTOCOL: &str = "http://example.com/threads";

    fn keypair() -> (JWK, JWK, String) {
        use ssi_jwk::{Base64urlUInt, OctetParams, Params};

        let secret = x25519_dalek::StaticSecret::random();
        let public = x25519_dalek::PublicKey::from(&secret);
        let private_jwk = JWK::from(Params::OKP(OctetParams {
            curve: "X25519".to_string(),
            public_key: Base64urlUInt(public.as_bytes().to_vec()),
            private_key: Some(Base64urlUInt(secret.to_bytes().to_vec())),
        }));
        let public_jwk = public_jwk(public.as_bytes());
        let key_id = public_jwk.thumbprint().expect("thumbprint");
        (public_jwk, private_jwk, key_id)
    }

    fn make_payload(key_id: &str, public_key_jwk: JWK, private_key_jwk: JWK) -> GrantKeyPayload {
        GrantKeyPayload {
            grant_id: "grant-1".to_string(),
            scope: PayloadScope {
                scheme: "protocolPath".to_string(),
                protocol: PROTOCOL.to_string(),
                protocol_path: Some("team".to_string()),
            },
            key_material: KeyMaterial {
                algorithm: KEY_AGREEMENT_ALGORITHM.to_string(),
                derivation_scheme: "protocolPath".to_string(),
                key_id: key_id.to_string(),
                derivation_path: vec![
                    "protocolPath".to_string(),
                    PROTOCOL.to_string(),
                    "team".to_string(),
                ],
                public_key_jwk,
                private_key_jwk,
            },
        }
    }

    fn grant() -> PermissionGrant {
        use chrono::TimeZone;

        PermissionGrant {
            id: "grant-1".to_string(),
            grantor: "did:example:alice".to_string(),
            grantee: "did:example:bob".to_string(),
            date_granted: Utc.with_ymd_and_hms(2024, 12, 1, 0, 0, 0).unwrap(),
            date_expires: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
            delegated: None,
            scope: crate::permissions::PermissionScope::Records(RecordsScope {
                protocol: PROTOCOL.to_string(),
                method: RecordsMethod::Read,
                selector: Some(crate::permissions::RecordsSelector::ProtocolPath(
                    ProtocolPath("team".to_string()),
                )),
            }),
            conditions: None,
            connect_session: None,
        }
    }

    fn input<'a>(
        grant: &'a PermissionGrant,
        payload: &'a GrantKeyPayload,
        key_id: &str,
    ) -> ResolutionInput<'a> {
        ResolutionInput {
            grant,
            grantor: "did:example:alice",
            grantee: "did:example:bob",
            delivery_path: "grantKey",
            has_envelope: true,
            tags: DeliveryTags {
                grant_id: "grant-1".to_string(),
                protocol: PROTOCOL.to_string(),
                protocol_path: Some("team".to_string()),
                key_id: key_id.to_string(),
            },
            payload,
            target: ResolutionTarget {
                protocol: PROTOCOL.to_string(),
                protocol_path: Some("team/doc".to_string()),
            },
            definition: None,
            revoked: false,
            now: Utc.with_ymd_and_hms(2025, 1, 3, 0, 0, 0).unwrap(),
        }
    }

    // Covers: ENBOX-ENC-002, DWN-AUTH-005, DWN-ENC-001
    #[test]
    fn valid_resolution_releases_the_key() {
        let (public, private, key_id) = keypair();
        let payload = make_payload(&key_id, public, private.clone());
        let grant = grant();
        let verified = verify_grant_key_resolution(input(&grant, &payload, &key_id))
            .expect("valid resolution");
        assert_eq!(verified.key_id, key_id);
        assert_eq!(
            verified.private_key_jwk, private,
            "the released material is the delivered private key"
        );
    }

    // Covers: ENBOX-ENC-002
    #[test]
    fn resolution_rejects_every_mismatch() {
        let (public, private, key_id) = keypair();
        let (other_public, other_private, other_id) = keypair();
        let grant = grant();

        let payload = make_payload(&key_id, public.clone(), private.clone());
        let mut bad_tags = input(&grant, &payload, &key_id).tags;
        bad_tags.key_id = other_id.clone();
        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                tags: bad_tags,
                ..input(&grant, &payload, &key_id)
            }),
            Err(ResolutionError::TagMismatch)
        );

        let mut foreign_grant = grant.clone();
        foreign_grant.grantee = "did:example:carol".to_string();
        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                grant: &foreign_grant,
                ..input(&grant, &payload, &key_id)
            }),
            Err(ResolutionError::GrantMismatch)
        );

        let mut expired = grant.clone();
        expired.date_expires = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                grant: &expired,
                ..input(&grant, &payload, &key_id)
            }),
            Err(ResolutionError::Expired)
        );

        let mut future = grant.clone();
        future.date_granted = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                grant: &future,
                ..input(&grant, &payload, &key_id)
            }),
            Err(ResolutionError::Inactive)
        );

        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                delivery_path: "epochKey",
                ..input(&grant, &payload, &key_id)
            }),
            Err(ResolutionError::Representation(
                "delivery at 'epochKey' misrepresents its encryption".to_string()
            ))
        );
        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                has_envelope: false,
                ..input(&grant, &payload, &key_id)
            }),
            Err(ResolutionError::Representation(
                "delivery at 'grantKey' misrepresents its encryption".to_string()
            ))
        );

        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                revoked: true,
                ..input(&grant, &payload, &key_id)
            }),
            Err(ResolutionError::Revoked)
        );

        // Consistent tags and payload outside the grant subtree: without a
        // definition the role exception is undecidable, which reads as
        // missing evidence rather than scope denial.
        let mut uncovered = payload.clone();
        uncovered.scope.protocol_path = Some("other".to_string());
        let mut uncovered_input = input(&grant, &payload, &key_id);
        uncovered_input.tags.protocol_path = Some("other".to_string());
        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                payload: &uncovered,
                ..uncovered_input
            }),
            Err(ResolutionError::DefinitionMissing)
        );

        // With evidence that still covers nothing, it is scope denial.
        let empty = Definition {
            protocol: PROTOCOL.to_string(),
            published: true,
            uses: None,
            key_agreement: None,
            types: std::collections::BTreeMap::new(),
            structure: std::collections::BTreeMap::new(),
        };
        let mut evidenced_input = input(&grant, &payload, &key_id);
        evidenced_input.tags.protocol_path = Some("other".to_string());
        evidenced_input.definition = Some(&empty);
        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                payload: &uncovered,
                ..evidenced_input
            }),
            Err(ResolutionError::ScopeMismatch)
        );

        let mut off_target = input(&grant, &payload, &key_id);
        off_target.target.protocol_path = Some("other/doc".to_string());
        assert_eq!(
            verify_grant_key_resolution(off_target),
            Err(ResolutionError::TargetNotCovered)
        );

        let mut bad_path = payload.clone();
        bad_path.key_material.derivation_path.pop();
        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                payload: &bad_path,
                ..input(&grant, &payload, &key_id)
            }),
            Err(ResolutionError::DerivationMismatch)
        );

        let impostor = make_payload(&other_id, other_public, other_private.clone());
        let verified = verify_grant_key_resolution(input(&grant, &impostor, &other_id))
            .expect("self-consistent keys resolve");
        assert_eq!(verified.key_id, other_id);

        // Right public key but another keypair's private key: the derived
        // public id stops matching.
        assert_eq!(
            verify_grant_key_resolution(ResolutionInput {
                payload: &make_payload(&key_id, public, other_private),
                ..input(&grant, &payload, &key_id)
            }),
            Err(ResolutionError::KeyMismatch)
        );
    }

    // Covers: ENBOX-ENC-002
    #[test]
    fn payload_parsing_rejects_malformed_and_schema_invalid() {
        assert!(matches!(
            parse_grant_key_payload(b"not json{{{"),
            Err(ResolutionError::Malformed(_))
        ));

        let (_, _, key_id) = keypair();
        let mut raw = serde_json::to_value(valid_payload_json(&key_id)).unwrap();
        raw.as_object_mut().unwrap().remove("keyMaterial");
        assert!(matches!(
            parse_grant_key_payload(&serde_json::to_vec(&raw).unwrap()),
            Err(ResolutionError::SchemaInvalid(_))
        ));

        let parsed =
            parse_grant_key_payload(&serde_json::to_vec(&valid_payload_json(&key_id)).unwrap())
                .expect("schema-valid payload parses");
        assert_eq!(parsed.key_material.key_id, key_id);
    }

    fn valid_payload_json(key_id: &str) -> serde_json::Value {
        serde_json::json!({
            "grantId": "grant-1",
            "scope": {"scheme": "protocolPath", "protocol": PROTOCOL},
            "keyMaterial": {
                "algorithm": "X25519-HKDF-SHA256+A256KW",
                "derivationScheme": "protocolPath",
                "keyId": key_id,
                "derivationPath": ["protocolPath", PROTOCOL],
                "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": key_id},
                "privateKeyJwk": {"kty": "OKP", "crv": "X25519", "x": key_id},
            },
        })
    }
}
