//! Encryption-control record types.
//!
//! Control records live at reserved virtual protocol paths inside the source
//! protocol ([`ENCRYPTION_CONTROL_ROOT_PATH`]). They carry no application rule
//! set, so their shape is fixed here rather than by a protocol definition:
//! an *audience* publishes a role's public key plus the owner seal over its
//! private key; a *delivery* hands that private key to one recipient.
//!
//! Identity is a tag tuple, not a record id. The four-field [`AudienceId`]
//! names one stored audience exactly; the three-field [`AudienceScope`] inside
//! it is the group over which exactly one audience is *current*. Keeping the
//! two apart is what stops a lookup that happens to know a key id from being
//! confused with the projection that decides which key is live.

use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

use super::{
    SealKeyWrap, ENCRYPTION_CONTROL_AUDIENCE_PATH, ENCRYPTION_CONTROL_DELIVERY_PATH,
    ENCRYPTION_CONTROL_ROOT_PATH,
};
use crate::descriptors::records::records_write_descriptor;
use crate::errors::{DwnError, DwnErrorCode};
use crate::{Descriptor, Message, Value};

/// JSON Schema `$id` for the audience record payload.
pub const ENCRYPTION_AUDIENCE_SCHEMA: &str =
    "https://identity.foundation/dwn/json-schemas/encryption/audience.json";

/// Which reserved control path a record sits at.
///
/// Replaces a bare "is this a control path" predicate: nearly every control
/// rule differs between the two, so callers want the answer, not a bool they
/// must re-derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlKind {
    Audience,
    Delivery,
}

impl ControlKind {
    pub fn from_protocol_path(protocol_path: &str) -> Option<Self> {
        match protocol_path {
            ENCRYPTION_CONTROL_AUDIENCE_PATH => Some(Self::Audience),
            ENCRYPTION_CONTROL_DELIVERY_PATH => Some(Self::Delivery),
            _ => None,
        }
    }

    pub fn of(message: &Message<Descriptor>) -> Option<Self> {
        Self::from_protocol_path(&records_write_descriptor(message).ok()?.protocol_path)
    }

    pub const fn protocol_path(self) -> &'static str {
        match self {
            Self::Audience => ENCRYPTION_CONTROL_AUDIENCE_PATH,
            Self::Delivery => ENCRYPTION_CONTROL_DELIVERY_PATH,
        }
    }

    /// Failure identities differ per kind, so callers report which sort of
    /// control record was malformed rather than a single blurred code.
    const fn missing_tag_code(self) -> DwnErrorCode {
        match self {
            Self::Audience => DwnErrorCode::EncryptionControlValidateAudienceMissingRequiredTag,
            Self::Delivery => DwnErrorCode::EncryptionControlValidateDeliveryMissingRequiredTag,
        }
    }

    const fn tags_mismatch_code(self) -> DwnErrorCode {
        match self {
            Self::Audience => DwnErrorCode::EncryptionControlValidateAudienceTagsMismatch,
            Self::Delivery => DwnErrorCode::EncryptionControlValidateDeliveryTagsMismatch,
        }
    }
}

/// The group within which exactly one audience is current: a role in one
/// context of one protocol. Deliberately excludes `keyId` — grouping by key
/// would make every key its own group and defeat the projection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AudienceScope {
    pub protocol: String,
    pub role_path: String,
    /// Empty for a root role; non-empty names the ancestor context.
    pub context_id: String,
}

impl AudienceScope {
    /// Whether this scope names a root role, whose context is empty by
    /// construction.
    pub fn is_root_role(&self) -> bool {
        self.context_id.is_empty()
    }

    /// Depth of the role's parent, i.e. how many ancestor context segments a
    /// nested role is addressed by. Zero for a root role.
    pub fn role_parent_depth(&self) -> usize {
        self.role_path.split('/').count() - 1
    }

    /// A root role is addressed with no context; a nested role must name the
    /// ancestor context it lives in. Anything else is an unaddressable scope,
    /// not a defaulting opportunity.
    pub fn validate_context_depth(&self) -> Result<(), DwnError> {
        if (self.role_parent_depth() == 0) != self.context_id.is_empty() {
            return Err(DwnError::new(
                DwnErrorCode::EncryptionControlValidateAudienceContextIdInvalid,
                format!(
                    "role '{}' is inconsistent with contextId '{}'",
                    self.role_path, self.context_id
                ),
            ));
        }
        Ok(())
    }
}

/// One stored audience, named exactly. A delivery references its audience by
/// the whole tuple, so a superseded key stays addressable after it stops being
/// current.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AudienceId {
    pub scope: AudienceScope,
    pub key_id: String,
}

impl AudienceId {
    /// Reads the identity tuple from a control record's tags.
    ///
    /// Tags are the only carrier: control records have no rule set to derive
    /// these from, and the descriptor's `protocol` must agree with the tag so a
    /// record cannot claim membership in a protocol it was not written under.
    pub fn from_message(
        message: &Message<Descriptor>,
        kind: ControlKind,
    ) -> Result<Self, DwnError> {
        let descriptor = records_write_descriptor(message)
            .map_err(|error| DwnError::new(kind.missing_tag_code(), error))?;
        let id = Self {
            scope: AudienceScope {
                protocol: required_string_tag(message, "protocol", kind)?,
                role_path: required_string_tag(message, "rolePath", kind)?,
                context_id: required_string_tag(message, "contextId", kind)?,
            },
            key_id: required_string_tag(message, "keyId", kind)?,
        };
        if id.scope.protocol != descriptor.protocol {
            return Err(DwnError::new(
                kind.tags_mismatch_code(),
                format!(
                    "control record protocol tag '{}' must match descriptor protocol '{}'",
                    id.scope.protocol, descriptor.protocol
                ),
            ));
        }
        Ok(id)
    }
}

/// Required string tag accessor.
///
/// Control records carry their identity in tags, so a missing or non-string
/// tag is a malformed record rather than a default to fill in.
pub fn required_string_tag(
    message: &Message<Descriptor>,
    tag: &str,
    kind: ControlKind,
) -> Result<String, DwnError> {
    let missing = || {
        DwnError::new(
            kind.missing_tag_code(),
            format!("control record requires a string '{tag}' tag"),
        )
    };
    match records_write_descriptor(message)
        .map_err(|_| missing())?
        .tags
        .as_ref()
        .and_then(|tags| tags.get(tag))
    {
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(missing()),
    }
}

/// The plaintext payload of an audience record.
///
/// `sealedPrivateKey` reuses [`SealKeyWrap`], whose tagged representation
/// already pins `derivationScheme: "seal"` and the key-agreement algorithm, so
/// those constants are enforced by the type rather than restated here.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct AudiencePayload {
    pub protocol: String,
    #[serde(rename = "rolePath")]
    pub role_path: String,
    #[serde(rename = "contextId")]
    pub context_id: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: JWK,
    #[serde(rename = "sealedPrivateKey")]
    pub sealed_private_key: SealKeyWrap,
}

impl AudiencePayload {
    /// Parses and schema-validates audience bytes.
    ///
    /// Schema first, then typed: the schema owns constraints the types cannot
    /// express (base64url shapes, key-id patterns), which is the same order
    /// admission applies to whole messages. A schema failure is reported as
    /// itself rather than re-badged as a control error, matching the TypeScript.
    pub fn parse(bytes: &[u8]) -> Result<Self, DwnError> {
        let raw: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
            DwnError::new(
                DwnErrorCode::SchemaValidatorFailure,
                format!("audience payload must be JSON: {error}"),
            )
        })?;
        crate::validation::validate_against_schema(ENCRYPTION_AUDIENCE_SCHEMA, &raw)?;
        serde_json::from_value(raw)
            .map_err(|error| DwnError::new(DwnErrorCode::SchemaValidatorFailure, error.to_string()))
    }

    /// Whether the payload's own key id is the thumbprint of the key it
    /// publishes. A payload that names a key it does not carry is not
    /// admissible; a matching thumbprint proves naming, never unsealing.
    pub fn verify_key_id(&self) -> Result<(), DwnError> {
        let thumbprint = self.public_key_jwk.thumbprint().map_err(|error| {
            DwnError::new(
                DwnErrorCode::EncryptionControlValidateAudienceKeyIdMismatch,
                error.to_string(),
            )
        })?;
        if thumbprint != self.key_id {
            return Err(DwnError::new(
                DwnErrorCode::EncryptionControlValidateAudienceKeyIdMismatch,
                "audience keyId must match publicKeyJwk thumbprint",
            ));
        }
        Ok(())
    }

    /// Whether the seal was produced under the role key that governs this
    /// audience, given that role's `$keyAgreement` public key.
    pub fn verify_seal_key_id(&self, role_key: &JWK) -> Result<(), DwnError> {
        let mismatch = |detail: String| {
            DwnError::new(
                DwnErrorCode::EncryptionControlValidateAudienceSealKeyIdMismatch,
                detail,
            )
        };
        let thumbprint = role_key.thumbprint().map_err(|e| mismatch(e.to_string()))?;
        if thumbprint != self.sealed_private_key.key_id() {
            return Err(mismatch(
                "audience seal keyId must match the role $keyAgreement thumbprint".to_string(),
            ));
        }
        Ok(())
    }

    /// The identity this payload claims, for comparison against the record's
    /// tags. A payload that disagrees with its own tags is not admissible.
    pub fn claimed_id(&self) -> AudienceId {
        AudienceId {
            scope: AudienceScope {
                protocol: self.protocol.clone(),
                role_path: self.role_path.clone(),
                context_id: self.context_id.clone(),
            },
            key_id: self.key_id.clone(),
        }
    }
}

/// Whether a protocol path is a reserved encryption-control path whose records
/// never participate in representation-policy checks.
pub fn is_encryption_control_path(protocol_path: &str) -> bool {
    ControlKind::from_protocol_path(protocol_path).is_some()
}

/// Whether a protocol path sits anywhere under the reserved namespace, whether
/// or not it is one of the two real control paths.
pub fn is_reserved_control_namespace(protocol_path: &str) -> bool {
    protocol_path == ENCRYPTION_CONTROL_ROOT_PATH
        || protocol_path.starts_with(&format!("{ENCRYPTION_CONTROL_ROOT_PATH}/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PROTOCOL: &str = "https://example.com/protocol/threads";
    const PUBLIC_JWK: &str =
        r#"{"kty":"OKP","crv":"X25519","x":"Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI"}"#;

    fn public_jwk() -> JWK {
        serde_json::from_str(PUBLIC_JWK).expect("fixture key")
    }

    fn control_message(protocol_path: &str, tags: serde_json::Value) -> Message<Descriptor> {
        serde_json::from_value(json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "protocol": PROTOCOL,
                "protocolPath": protocol_path,
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 0,
                "dataFormat": "application/json",
                "dateCreated": "2025-01-01T00:00:00.000000Z",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "tags": tags
            },
            "recordId": "control-record"
        }))
        .expect("control fixture must deserialize")
    }

    fn audience_tags(role_path: &str, context_id: &str, key_id: &str) -> serde_json::Value {
        json!({
            "protocol": PROTOCOL,
            "rolePath": role_path,
            "contextId": context_id,
            "keyId": key_id,
        })
    }

    fn audience_payload_json(key_id: &str, seal_key_id: &str) -> serde_json::Value {
        json!({
            "protocol": PROTOCOL,
            "rolePath": "member",
            "contextId": "",
            "keyId": key_id,
            "publicKeyJwk": serde_json::to_value(public_jwk()).unwrap(),
            "sealedPrivateKey": {
                "algorithm": "X25519-HKDF-SHA256+A256KW",
                "derivationScheme": "seal",
                "keyId": seal_key_id,
                "ephemeralPublicKey": serde_json::to_value(public_jwk()).unwrap(),
                "encryptedKey": "T42gGabDj__6KG89Wz97VBmlDEmkJj3HjLh-dPX-KzEbTi6z6DMLoA"
            }
        })
    }

    // Covers: ENBOX-ENC-001
    #[test]
    fn control_kind_is_exactly_the_two_reserved_paths() {
        assert_eq!(
            ControlKind::from_protocol_path("$encryption/audience"),
            Some(ControlKind::Audience)
        );
        assert_eq!(
            ControlKind::from_protocol_path("$encryption/delivery"),
            Some(ControlKind::Delivery)
        );
        // The namespace root and invented siblings are reserved but are not
        // themselves control record paths.
        for reserved_but_not_a_control_path in ["$encryption", "$encryption/other", "thread"] {
            assert_eq!(
                ControlKind::from_protocol_path(reserved_but_not_a_control_path),
                None,
                "{reserved_but_not_a_control_path} is not a control path"
            );
        }
        assert!(is_reserved_control_namespace("$encryption"));
        assert!(is_reserved_control_namespace("$encryption/other"));
        assert!(!is_reserved_control_namespace("$encryptionish"));
    }

    // Covers: ENBOX-ENC-001, DWN-PROTO-002
    #[test]
    fn identity_comes_from_tags_and_must_agree_with_the_descriptor() {
        let message = control_message(
            ControlKind::Audience.protocol_path(),
            audience_tags("thread/member", "thread-1", "key-1"),
        );
        let id = AudienceId::from_message(&message, ControlKind::Audience).expect("valid tags");
        assert_eq!(id.scope.role_path, "thread/member");
        assert_eq!(id.scope.context_id, "thread-1");
        assert_eq!(id.key_id, "key-1");

        // A record may not claim a protocol it was not written under.
        let mismatched = control_message(
            ControlKind::Audience.protocol_path(),
            json!({
                "protocol": "https://example.com/other",
                "rolePath": "member", "contextId": "", "keyId": "key-1"
            }),
        );
        assert_eq!(
            AudienceId::from_message(&mismatched, ControlKind::Audience)
                .expect_err("protocol tag must match descriptor")
                .code,
            DwnErrorCode::EncryptionControlValidateAudienceTagsMismatch
        );
    }

    // Covers: ENBOX-ENC-001
    #[test]
    fn missing_tags_report_the_kind_that_was_malformed() {
        for (kind, expected) in [
            (
                ControlKind::Audience,
                DwnErrorCode::EncryptionControlValidateAudienceMissingRequiredTag,
            ),
            (
                ControlKind::Delivery,
                DwnErrorCode::EncryptionControlValidateDeliveryMissingRequiredTag,
            ),
        ] {
            // Every required tag, dropped one at a time.
            for dropped in ["protocol", "rolePath", "contextId", "keyId"] {
                let mut tags = audience_tags("member", "", "key-1");
                tags.as_object_mut().unwrap().remove(dropped);
                let message = control_message(kind.protocol_path(), tags);
                assert_eq!(
                    AudienceId::from_message(&message, kind)
                        .expect_err("missing tag must be rejected")
                        .code,
                    expected,
                    "{kind:?} missing {dropped}"
                );
            }
            // A tag of the wrong type is malformed, not absent-with-a-default.
            let message = control_message(
                kind.protocol_path(),
                json!({"protocol": PROTOCOL, "rolePath": 7, "contextId": "", "keyId": "key-1"}),
            );
            assert_eq!(
                AudienceId::from_message(&message, kind)
                    .expect_err("non-string tag must be rejected")
                    .code,
                expected
            );
        }
    }

    // Covers: DWN-PROTO-002
    #[test]
    fn context_depth_must_match_role_depth() {
        let cases = [
            ("member", "", true),
            ("member", "thread-1", false),
            ("thread/member", "thread-1", true),
            ("thread/member", "", false),
            ("a/b/member", "x/y", true),
        ];
        for (role_path, context_id, expected_ok) in cases {
            let scope = AudienceScope {
                protocol: PROTOCOL.to_string(),
                role_path: role_path.to_string(),
                context_id: context_id.to_string(),
            };
            assert_eq!(
                scope.validate_context_depth().is_ok(),
                expected_ok,
                "role '{role_path}' with context '{context_id}'"
            );
            if !expected_ok {
                assert_eq!(
                    scope.validate_context_depth().unwrap_err().code,
                    DwnErrorCode::EncryptionControlValidateAudienceContextIdInvalid
                );
            }
        }
    }

    // Covers: ENBOX-ENC-001
    #[test]
    fn audience_payload_key_ids_are_commitments_to_real_keys() {
        let thumbprint = public_jwk().thumbprint().unwrap();
        let payload = AudiencePayload::parse(
            serde_json::to_vec(&audience_payload_json(&thumbprint, &thumbprint))
                .unwrap()
                .as_slice(),
        )
        .expect("well-formed payload");

        payload.verify_key_id().expect("keyId is the thumbprint");
        payload
            .verify_seal_key_id(&public_jwk())
            .expect("seal keyId is the role key thumbprint");
        assert_eq!(payload.claimed_id().key_id, thumbprint);

        // A payload naming a key it does not carry is not admissible.
        let wrong = AudiencePayload::parse(
            serde_json::to_vec(&audience_payload_json(
                "0000000000000000000000000000000000000000000",
                &thumbprint,
            ))
            .unwrap()
            .as_slice(),
        )
        .expect("shape is still valid");
        assert_eq!(
            wrong.verify_key_id().unwrap_err().code,
            DwnErrorCode::EncryptionControlValidateAudienceKeyIdMismatch
        );
        assert_eq!(
            payload
                .verify_seal_key_id(&serde_json::from_str::<JWK>(
                    r#"{"kty":"OKP","crv":"X25519","x":"B6r_Pp_BZydVRPTDpqF82Dfy7G54zYpXsePfs8wDWnY"}"#
                ).unwrap())
                .unwrap_err()
                .code,
            DwnErrorCode::EncryptionControlValidateAudienceSealKeyIdMismatch
        );
    }

    // Covers: ENBOX-ENC-001
    // The vendored schema earns its place here: each of these is well-typed as
    // far as serde is concerned, and only the schema rejects it.
    #[test]
    fn audience_schema_rejects_what_the_types_alone_would_accept() {
        let thumbprint = public_jwk().thumbprint().unwrap();
        type Corrupt = fn(&mut serde_json::Value);
        let cases: [(&str, Corrupt); 4] = [
            (
                "keyId that is not a 43-character base64url thumbprint",
                |payload| payload["keyId"] = json!("short"),
            ),
            ("sealed keyId that is not a thumbprint", |payload| {
                payload["sealedPrivateKey"]["keyId"] = json!("short")
            }),
            ("encryptedKey that is not base64url", |payload| {
                payload["sealedPrivateKey"]["encryptedKey"] = json!("not/base64+")
            }),
            ("public key on the wrong curve", |payload| {
                payload["publicKeyJwk"]["crv"] = json!("Ed25519")
            }),
        ];

        for (label, corrupt) in cases {
            let mut payload = audience_payload_json(&thumbprint, &thumbprint);
            corrupt(&mut payload);
            let error = AudiencePayload::parse(serde_json::to_vec(&payload).unwrap().as_slice())
                .expect_err(label);
            assert_eq!(
                error.code,
                DwnErrorCode::SchemaValidatorFailure,
                "{label} must be a schema failure, got: {error}"
            );
        }

        // `additionalProperties: false` is enforced too.
        let mut extra = audience_payload_json(&thumbprint, &thumbprint);
        extra["unexpected"] = json!(true);
        assert!(AudiencePayload::parse(serde_json::to_vec(&extra).unwrap().as_slice()).is_err());
    }
}
