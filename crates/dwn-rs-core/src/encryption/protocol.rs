//! Fixed core definition for the DWN encryption protocol.
//!
//! Mirrors `EncryptionProtocol.definition` from `@enbox/dwn-sdk-js`
//! (`protocols/encryption.ts:54-100`): the two immutable root types
//! `grantKey` (encrypted) and `wrappedGrantKey` (plaintext envelope), with
//! create/anyone and read/recipient-of-that-path actions. Like every core
//! protocol this definition is returned by lookup precedence, never installed.

use std::collections::BTreeMap;

use crate::descriptors::records::{records_write_descriptor, write_fields};
use crate::descriptors::Descriptor;
use crate::encryption::{
    ENCRYPTION_PROTOCOL_GRANT_KEY_PATH, ENCRYPTION_PROTOCOL_URI,
    ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
};
use crate::errors::{DwnError, DwnErrorCode};
use crate::handlers::configure::{fetch_protocol_definition, ProtocolDefinitionLookupError};
use crate::interfaces::messages::protocols::{
    Action, ActionWho, Can, Definition, ProvidedTags, RuleSet, TagType, Tags, Type, Who,
};
use crate::interfaces::replies::{Response, Status};
use crate::permissions::errors::{GrantError, PermissionError};
use crate::permissions::grant_key_coverage::{
    eligible_grant_scope, grant_covers_delivered_scope, DeliveredScope,
};
use crate::permissions::{
    fetch_grant, message_author, verify_grant_not_revoked, MAX_ENCODED_DATA_SIZE,
};
use crate::utils::canonical_rfc3339;
use crate::{MapValue, Message, Value};
use thiserror::Error;

/// Schema URI for the decrypted `grantKey` payload shape (no local file: the
/// SDK carries no `grant-key.json`; the shape is enforced by agent code).
pub const GRANT_KEY_PAYLOAD_SCHEMA_URI: &str =
    "https://identity.foundation/dwn/json-schemas/encryption/grant-key.json";
/// Schema URI for the `wrappedGrantKey` inline envelope.
pub const WRAPPED_GRANT_KEY_ENVELOPE_SCHEMA_URI: &str =
    "https://identity.foundation/dwn/json-schemas/encryption/wrapped-grant-key-envelope.json";

/// Length of a base64url-encoded 32-byte JWK thumbprint: the delivery key id
/// shape upstream pins as `^[A-Za-z0-9_-]{43}$`.
const KEY_ID_LEN: usize = 43;

fn string_tag(min_length: Option<usize>, max_length: Option<usize>) -> ProvidedTags {
    ProvidedTags {
        tag_type: TagType::String,
        items: None,
        contains: None,
        enum_values: Vec::new(),
        max_length,
        min_length,
        minimum: None,
        maximum: None,
        exclusive_minimum: None,
        exclusive_maximum: None,
        min_items: None,
        max_items: None,
        unique_items: None,
        min_contains: None,
        max_contains: None,
    }
}

fn delivery_tags() -> Tags {
    Tags {
        required_tags: vec![
            "grantId".to_string(),
            "protocol".to_string(),
            "keyId".to_string(),
        ],
        allow_undefined_tags: Some(false),
        tags: BTreeMap::from([
            ("grantId".to_string(), string_tag(None, None)),
            // Upstream additionally constrains keyId by pattern
            // `^[A-Za-z0-9_-]{43}$`; the typed tag model carries lengths only,
            // so the pattern is enforced by delivery admission instead.
            (
                "keyId".to_string(),
                string_tag(Some(KEY_ID_LEN), Some(KEY_ID_LEN)),
            ),
            ("protocol".to_string(), string_tag(None, None)),
            ("protocolPath".to_string(), string_tag(None, None)),
        ]),
    }
}

fn delivery_rule_set(path: &str) -> RuleSet {
    RuleSet {
        immutable: Some(true),
        actions: vec![
            Action::Who(ActionWho {
                who: Who::Anyone,
                of: None,
                can: vec![Can::Create],
            }),
            Action::Who(ActionWho {
                who: Who::Recipient,
                of: Some(path.to_string()),
                can: vec![Can::Read],
            }),
        ],
        tags: Some(delivery_tags()),
        ..Default::default()
    }
}

pub fn encryption_protocol_definition() -> Definition {
    Definition {
        protocol: ENCRYPTION_PROTOCOL_URI.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([
            (
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH.to_string(),
                Type {
                    schema: Some(GRANT_KEY_PAYLOAD_SCHEMA_URI.to_string()),
                    data_formats: Some(vec!["application/json".to_string()]),
                    encryption_required: Some(true),
                },
            ),
            (
                ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH.to_string(),
                Type {
                    schema: Some(WRAPPED_GRANT_KEY_ENVELOPE_SCHEMA_URI.to_string()),
                    data_formats: Some(vec!["application/json".to_string()]),
                    encryption_required: None,
                },
            ),
        ]),
        structure: BTreeMap::from([
            (
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH.to_string(),
                delivery_rule_set(ENCRYPTION_PROTOCOL_GRANT_KEY_PATH),
            ),
            (
                ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH.to_string(),
                delivery_rule_set(ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH),
            ),
        ]),
    }
}

/// Admission failures for a grant-key delivery, each naming the upstream
/// error identity it preserves. Reply status is classified off these variants
/// (see [`GrantKeyError::reply`]), never off a string prefix.
#[derive(Error, Debug)]
pub enum GrantKeyError {
    #[error("{0}")]
    MissingEncryption(String),
    #[error("{0}")]
    EncryptionNotAllowed(String),
    #[error("{0}")]
    MissingTag(String),
    #[error("{0}")]
    AuthorMismatch(String),
    #[error("{0}")]
    RecipientMismatch(String),
    #[error("{0}")]
    ScopeMismatch(String),
    #[error("{0}")]
    NotYetActive(String),
    #[error("{0}")]
    GrantExpired(String),
    #[error("{0}")]
    GrantRevoked(String),
    #[error("{0}")]
    GrantMissing(String),
    #[error("{0}")]
    ProtocolNotFound(String),
    #[error("{0}")]
    WrappedDeliveryInvalid(String),
    #[error("{0}")]
    SchemaUnexpectedRecord(String),
    #[error("grant-key admission failed: {0}")]
    Internal(String),
}

impl GrantKeyError {
    /// The stable wire identity, if the failure has an upstream one. Storage
    /// and lookup failures stay unmapped: they are retryable transport state,
    /// not scope denial.
    pub fn code(&self) -> Option<DwnErrorCode> {
        match self {
            Self::MissingEncryption(_) => {
                Some(DwnErrorCode::EncryptionProtocolValidateEncryptedDeliveryMissingEncryption)
            }
            Self::EncryptionNotAllowed(_) => {
                Some(DwnErrorCode::ProtocolAuthorizationEncryptionNotAllowed)
            }
            Self::MissingTag(_) => {
                Some(DwnErrorCode::EncryptionProtocolValidateGrantKeyMissingRequiredTag)
            }
            Self::AuthorMismatch(_) => {
                Some(DwnErrorCode::EncryptionProtocolValidateGrantKeyAuthorMismatch)
            }
            Self::RecipientMismatch(_) => {
                Some(DwnErrorCode::EncryptionProtocolValidateGrantKeyRecipientMismatch)
            }
            Self::ScopeMismatch(_) => {
                Some(DwnErrorCode::EncryptionProtocolValidateGrantKeyGrantScopeMismatch)
            }
            Self::NotYetActive(_) => Some(DwnErrorCode::GrantAuthorizationGrantNotYetActive),
            Self::GrantExpired(_) => Some(DwnErrorCode::GrantAuthorizationGrantExpired),
            Self::GrantRevoked(_) => Some(DwnErrorCode::GrantAuthorizationGrantRevoked),
            Self::GrantMissing(_) => Some(DwnErrorCode::GrantAuthorizationGrantMissing),
            Self::ProtocolNotFound(_) => Some(DwnErrorCode::ProtocolAuthorizationProtocolNotFound),
            Self::WrappedDeliveryInvalid(_) => {
                Some(DwnErrorCode::EncryptionProtocolValidateGrantKeyWrappedDeliveryInvalid)
            }
            Self::SchemaUnexpectedRecord(_) => {
                Some(DwnErrorCode::EncryptionProtocolValidateSchemaUnexpectedRecord)
            }
            Self::Internal(_) => None,
        }
    }

    pub(crate) fn detail(&self) -> &str {
        match self {
            Self::MissingEncryption(detail)
            | Self::EncryptionNotAllowed(detail)
            | Self::MissingTag(detail)
            | Self::AuthorMismatch(detail)
            | Self::RecipientMismatch(detail)
            | Self::ScopeMismatch(detail)
            | Self::NotYetActive(detail)
            | Self::GrantExpired(detail)
            | Self::GrantRevoked(detail)
            | Self::GrantMissing(detail)
            | Self::ProtocolNotFound(detail)
            | Self::WrappedDeliveryInvalid(detail)
            | Self::SchemaUnexpectedRecord(detail)
            | Self::Internal(detail) => detail,
        }
    }

    /// Reply classified by variant: writer-authorization failures are 401,
    /// every other identified failure is 400, unmapped transport failures
    /// are 500.
    pub fn reply<R: Default>(&self) -> Response<R> {
        let Some(code) = self.code() else {
            return Response::internal_error(self.to_string());
        };
        let error = DwnError::new(code, self.detail());
        match self {
            Self::AuthorMismatch(_) | Self::RecipientMismatch(_) => Response {
                status: Status::from_error(401, error),
                reply: R::default(),
            },
            _ => Response::bad_request_error(error),
        }
    }
}

fn grant_error(error: PermissionError) -> GrantKeyError {
    match error {
        PermissionError::InvalidGrant(GrantError::NotFound(id)) => {
            GrantKeyError::GrantMissing(format!("could not find permission grant {id}"))
        }
        PermissionError::InvalidGrant(GrantError::Expired) => {
            GrantKeyError::GrantExpired("grant-key references an expired permission grant".into())
        }
        PermissionError::InvalidGrant(GrantError::Revoked) => {
            GrantKeyError::GrantRevoked("grant-key references a revoked permission grant".into())
        }
        error => GrantKeyError::Internal(error.to_string()),
    }
}

/// Delivery admission: representation, tags, grant, activity, Author,
/// recipient, then scope against the grant. Runs on descriptor metadata alone;
/// wrapped payload bytes are validated separately once data is present.
pub async fn pre_process_encryption_write<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
) -> Result<(), GrantKeyError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor = records_write_descriptor(message)
        .map_err(|error| GrantKeyError::Internal(error.to_string()))?;
    if descriptor.protocol.as_str() != ENCRYPTION_PROTOCOL_URI {
        return Ok(());
    }
    let is_grant_key = descriptor.protocol_path.as_str() == ENCRYPTION_PROTOCOL_GRANT_KEY_PATH;
    let is_wrapped =
        descriptor.protocol_path.as_str() == ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH;
    if !is_grant_key && !is_wrapped {
        return Ok(());
    }

    let has_envelope = write_fields(message)
        .map(|fields| fields.encryption.is_some())
        .map_err(|error| GrantKeyError::Internal(error.to_string()))?;
    if is_grant_key {
        if !has_envelope {
            return Err(GrantKeyError::MissingEncryption(
                "grantKey records must be encrypted.".into(),
            ));
        }
    } else {
        if has_envelope {
            return Err(GrantKeyError::EncryptionNotAllowed(
                "wrappedGrantKey records must be plaintext at the DWN record level.".into(),
            ));
        }
        if descriptor.data_size > MAX_ENCODED_DATA_SIZE {
            return Err(GrantKeyError::MissingEncryption(format!(
                "wrappedGrantKey records must be at most {MAX_ENCODED_DATA_SIZE} bytes \
                 to validate inline, got {}.",
                descriptor.data_size
            )));
        }
    }

    let tags = descriptor.tags.as_ref();
    let grant_id = required_tag(tags, "grantId")?;
    let protocol = required_tag(tags, "protocol")?;
    let protocol_path = optional_tag(tags, "protocolPath")?;
    let key_id = required_tag(tags, "keyId")?;
    if key_id.len() != KEY_ID_LEN
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(GrantKeyError::MissingTag(format!(
            "grantKey tag 'keyId' must match ^[A-Za-z0-9_-]{{43}}$, got '{key_id}'."
        )));
    }

    let grant = fetch_grant(tenant, message_store, &grant_id)
        .await
        .map_err(grant_error)?;
    let message_timestamp = descriptor.message_timestamp;
    if message_timestamp < grant.date_granted {
        return Err(GrantKeyError::NotYetActive(
            "grant-key references a permission grant that is not active yet.".into(),
        ));
    }
    if message_timestamp >= grant.date_expires {
        return Err(GrantKeyError::GrantExpired(
            "grant-key references an expired permission grant.".into(),
        ));
    }
    verify_grant_not_revoked(tenant, message_timestamp, &grant, message_store)
        .await
        .map_err(grant_error)?;

    if message_author(message).as_deref() != Some(grant.grantor.as_str()) {
        return Err(GrantKeyError::AuthorMismatch(format!(
            "grant-key author must be permission grantor {}.",
            grant.grantor
        )));
    }
    if descriptor.recipient.as_deref() != Some(grant.grantee.as_str()) {
        return Err(GrantKeyError::RecipientMismatch(format!(
            "grant-key recipient must be permission grantee {}.",
            grant.grantee
        )));
    }

    let Some(eligible) = eligible_grant_scope(&grant.scope) else {
        return Err(GrantKeyError::ScopeMismatch(
            "grant-key must reference an eligible Records Read or Write grant.".into(),
        ));
    };
    if eligible.protocol != protocol {
        return Err(GrantKeyError::ScopeMismatch(format!(
            "grant-key protocol {protocol} is outside the permission grant scope."
        )));
    }
    let delivered = DeliveredScope {
        protocol: &protocol,
        protocol_path: protocol_path.as_deref(),
    };
    if grant_covers_delivered_scope(&eligible, &delivered, None) {
        return Ok(());
    }
    if protocol_path.is_none() {
        return Err(scope_mismatch(None));
    }
    let definition = fetch_protocol_definition(
        tenant,
        &protocol,
        message_store,
        Some(&canonical_rfc3339(message_timestamp)),
    )
    .await
    .map_err(|error| match error {
        ProtocolDefinitionLookupError::NotFound(uri) => {
            GrantKeyError::ProtocolNotFound(format!("unable to find protocol definition for {uri}"))
        }
        error => GrantKeyError::Internal(error.to_string()),
    })?;
    if grant_covers_delivered_scope(&eligible, &delivered, Some(&definition)) {
        return Ok(());
    }
    Err(scope_mismatch(protocol_path.as_deref()))
}

fn scope_mismatch(protocol_path: Option<&str>) -> GrantKeyError {
    GrantKeyError::ScopeMismatch(format!(
        "grant-key protocolPath {} is outside the permission grant scope.",
        protocol_path.unwrap_or("<protocol>")
    ))
}

fn required_tag(tags: Option<&MapValue>, name: &str) -> Result<String, GrantKeyError> {
    tags.and_then(|tags| tags.get(name))
        .and_then(tag_str)
        .ok_or_else(|| {
            GrantKeyError::MissingTag(format!(
                "grantKey records must include string tag '{name}'."
            ))
        })
}

fn optional_tag(tags: Option<&MapValue>, name: &str) -> Result<Option<String>, GrantKeyError> {
    match tags.and_then(|tags| tags.get(name)) {
        None => Ok(None),
        Some(value) => tag_str(value).map(Some).ok_or_else(|| {
            GrantKeyError::MissingTag(format!("grantKey tag '{name}' must be a string."))
        }),
    }
}

/// Tag strings in either wire shape: plain strings arrive as `String`, while
/// CID-looking values (notably every grant id) arrive as `Cid`.
fn tag_str(value: &Value) -> Option<String> {
    match value {
        Value::String(string) => Some(string.clone()),
        Value::Cid(cid) => Some(cid.to_string()),
        _ => None,
    }
}
/// Validates wrapped delivery bytes once data is present. `grantKey`
/// records pass through: the node never inspects their plaintext. Anything
/// else under this protocol is owned by record validation, not payloads.
pub fn validate_encryption_delivery(
    message: &Message<Descriptor>,
    data: &[u8],
) -> Result<(), GrantKeyError> {
    let descriptor = records_write_descriptor(message)
        .map_err(|error| GrantKeyError::Internal(error.to_string()))?;
    if descriptor.protocol.as_str() != ENCRYPTION_PROTOCOL_URI
        || descriptor.protocol_path.as_str() != ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH
    {
        return Ok(());
    }
    let envelope: serde_json::Value = serde_json::from_slice(data).map_err(|error| {
        GrantKeyError::MissingEncryption(format!(
            "wrappedGrantKey records must carry a valid wrapped grantKey envelope: {error}"
        ))
    })?;
    crate::validation::validate_against_schema(WRAPPED_GRANT_KEY_ENVELOPE_SCHEMA_URI, &envelope)
        .map_err(|error| GrantKeyError::WrappedDeliveryInvalid(error.to_string()))?;
    Ok(())
}

/// Rejects records under the encryption protocol at any path other than the
/// two delivery roots. Payload validation needs the data bytes and lands
/// separately; this runs on descriptor metadata alone.
pub fn validate_encryption_record_schema(
    message: &Message<Descriptor>,
) -> Result<(), GrantKeyError> {
    let descriptor = records_write_descriptor(message)
        .map_err(|error| GrantKeyError::Internal(error.to_string()))?;
    if descriptor.protocol.as_str() != ENCRYPTION_PROTOCOL_URI {
        return Ok(());
    }
    match descriptor.protocol_path.as_str() {
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH | ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH => Ok(()),
        protocol_path => Err(GrantKeyError::SchemaUnexpectedRecord(format!(
            "unexpected encryption record: {protocol_path}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptors::{Records, RecordsWriteDescriptor};
    use crate::fields::WriteFields;

    // Covers: ENBOX-ENC-002
    #[test]
    fn encryption_protocol_definition_matches_typescript() {
        let definition = encryption_protocol_definition();
        assert_eq!(
            definition.protocol, ENCRYPTION_PROTOCOL_URI,
            "published core URI"
        );
        assert!(definition.published, "core definition is published");

        let grant_key = &definition.types[ENCRYPTION_PROTOCOL_GRANT_KEY_PATH];
        assert_eq!(
            grant_key.data_formats.as_deref(),
            Some(["application/json".to_string()].as_slice())
        );
        assert_eq!(grant_key.encryption_required, Some(true));
        assert_eq!(
            grant_key.schema.as_deref(),
            Some(GRANT_KEY_PAYLOAD_SCHEMA_URI)
        );

        let wrapped = &definition.types[ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH];
        assert_eq!(
            wrapped.data_formats.as_deref(),
            Some(["application/json".to_string()].as_slice())
        );
        assert_eq!(wrapped.encryption_required, None);
        assert_eq!(
            wrapped.schema.as_deref(),
            Some(WRAPPED_GRANT_KEY_ENVELOPE_SCHEMA_URI)
        );

        for (path, of) in [
            (
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
            ),
            (
                ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
                ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
            ),
        ] {
            let rule_set = definition
                .rule_at(path)
                .unwrap_or_else(|| panic!("{path} is a root type"));
            assert_eq!(rule_set.immutable, Some(true));
            assert_eq!(
                rule_set.actions,
                vec![
                    Action::Who(ActionWho {
                        who: Who::Anyone,
                        of: None,
                        can: vec![Can::Create],
                    }),
                    Action::Who(ActionWho {
                        who: Who::Recipient,
                        of: Some(of.to_string()),
                        can: vec![Can::Read],
                    }),
                ],
                "{path} actions"
            );
            let tags = rule_set.tags.as_ref().expect("{path} carries tags");
            assert_eq!(
                tags.required_tags,
                vec![
                    "grantId".to_string(),
                    "protocol".to_string(),
                    "keyId".to_string()
                ]
            );
            assert_eq!(tags.allow_undefined_tags, Some(false));
            let key_id = &tags.tags["keyId"];
            assert_eq!(key_id.min_length, Some(KEY_ID_LEN));
            assert_eq!(key_id.max_length, Some(KEY_ID_LEN));
        }
    }

    // Covers: ENBOX-ENC-002
    #[test]
    fn encryption_record_schema_accepts_only_delivery_paths() {
        for path in [
            ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
            ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
        ] {
            let message = delivery_message(path);
            assert!(
                validate_encryption_record_schema(&message).is_ok(),
                "{path} is a delivery root"
            );
        }
        let message = delivery_message("epochKey");
        let error = validate_encryption_record_schema(&message).expect_err("third path rejected");
        assert_eq!(
            error.code(),
            Some(DwnErrorCode::EncryptionProtocolValidateSchemaUnexpectedRecord),
            "unexpected identity: {error:?}"
        );
    }

    fn delivery_message(protocol_path: &str) -> Message<Descriptor> {
        Message {
            descriptor: Descriptor::Records(Box::new(Records::Write(Box::new(
                RecordsWriteDescriptor {
                    protocol: ENCRYPTION_PROTOCOL_URI.to_string(),
                    protocol_path: protocol_path.to_string(),
                    ..Default::default()
                },
            )))),
            fields: crate::Fields::Write(WriteFields::default()),
        }
    }
}
