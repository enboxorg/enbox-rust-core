//! Referential integrity for records writes: the protocol rules governing
//! one write, enforced against its descriptor.
//!
//! Resolution (which definition, rule set, type, and key agreement govern the
//! write) lives in [`super::policy`]; this module enforces the resolved
//! policy: representation, immutability, size, squash, and parentage.

use crate::descriptors::{
    records::{is_initial_write, records_write_descriptor, write_fields},
    Descriptor,
};
use crate::dwn::core_protocol::CoreProtocolRegistry;
use crate::encryption::control::ControlKind;
use crate::encryption::{
    KeyEncryption, ENCRYPTION_PROTOCOL_GRANT_KEY_PATH, ENCRYPTION_PROTOCOL_URI,
};
use crate::errors::{DwnError, DwnErrorCode};
use crate::handlers::records::common::{context_id, fetch_parent_record, message_record_id};
use crate::Message;

use super::policy::EffectivePolicy;
use super::write::RecordsWriteValidationError;

pub(crate) async fn validate_referential_integrity<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    author: &str,
    registry: &CoreProtocolRegistry,
    message_store: &MessageStore,
) -> Result<(), RecordsWriteValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor = records_write_descriptor(message).map_err(|error| error.to_string())?;
    let protocol_path = descriptor.protocol_path.clone();

    // Control records live at virtual paths the protocol never declares, so
    // there is no type or rule set to validate them against. They are
    // admitted on their own fixed contract instead, and the application
    // encryption-policy checks below deliberately do not apply: a control
    // record's representation is fixed by its kind, not by the protocol.
    if let Some(kind) = ControlKind::from_protocol_path(&protocol_path) {
        return super::control::validate_referential_integrity(
            tenant,
            message,
            kind,
            author,
            message_store,
        )
        .await
        .map_err(RecordsWriteValidationError::from);
    }

    let policy = EffectivePolicy::resolve(tenant, message, author, registry, message_store).await?;
    let definition = &policy.definition;
    let rule_set = &policy.rule_set;
    let type_name = policy.type_name.as_str();
    let fields = write_fields(message).map_err(|error| error.to_string())?;
    let has_envelope = fields.encryption.is_some();
    if policy.encryption_required && !has_envelope {
        return Err(DwnError::new(
            DwnErrorCode::ProtocolAuthorizationEncryptionRequired,
            format!(
                "type '{type_name}' requires encryption but message has no encryption metadata"
            ),
        )
        .into());
    }
    if !policy.encryption_required && has_envelope {
        return Err(DwnError::new(
            DwnErrorCode::ProtocolAuthorizationEncryptionNotAllowed,
            format!("type '{type_name}' requires plaintext but message has encryption metadata"),
        )
        .into());
    }
    if policy.encryption_required {
        match &policy.key_agreement {
            Some(agreement) => {
                let key_id = agreement
                    .public_key_jwk
                    .thumbprint()
                    .map_err(|error| RecordsWriteValidationError::Internal(error.to_string()))?;
                let Some(envelope) = fields.encryption.as_ref() else {
                    return Err(DwnError::new(
                        DwnErrorCode::ProtocolAuthorizationEncryptionRequired,
                        format!(
                            "type '{type_name}' requires encryption but message has no encryption metadata"
                        ),
                    )
                    .into());
                };
                let has_protocol_path_entry = envelope.key_encryption.iter().any(|entry| {
                    matches!(entry, KeyEncryption::ProtocolPath { key_id: id, .. } if id == &key_id)
                });
                if !has_protocol_path_entry {
                    return Err(DwnError::new(
                        DwnErrorCode::ProtocolAuthorizationEncryptionProtocolPathEntryMissing,
                        format!(
                            "encrypted record is missing a protocolPath keyEncryption entry for '{protocol_path}'"
                        ),
                    )
                    .into());
                }
            }
            None => {
                let dynamic_recipient = definition.protocol == ENCRYPTION_PROTOCOL_URI
                    && descriptor.protocol_path == ENCRYPTION_PROTOCOL_GRANT_KEY_PATH;
                if !dynamic_recipient {
                    return Err(DwnError::new(
                        DwnErrorCode::ProtocolAuthorizationEncryptionKeyAgreementMissing,
                        format!("encrypted protocol path '{protocol_path}' has no $keyAgreement"),
                    )
                    .into());
                }
            }
        }
    }

    if rule_set.immutable == Some(true) && !is_initial_write(message, author)? {
        return Err(DwnError::new(
            DwnErrorCode::ProtocolAuthorizationImmutableRecord,
            format!(
                "record at protocol path '{protocol_path}' is immutable: updates are not allowed."
            ),
        )
        .into());
    }

    if let Some(size) = &rule_set.size {
        if let Some(min) = size.min {
            if descriptor.data_size < min {
                return Err(format!(
                    "ProtocolAuthorizationInvalidDataSize: dataSize {} is smaller than minimum {}",
                    descriptor.data_size, min
                )
                .into());
            }
        }
        if let Some(max) = size.max {
            if descriptor.data_size > max {
                return Err(format!(
                    "ProtocolAuthorizationInvalidDataSize: dataSize {} exceeds maximum {}",
                    descriptor.data_size, max
                )
                .into());
            }
        }
    }

    if descriptor.squash == Some(true)
        && (rule_set.squash != Some(true) || !is_initial_write(message, author)?)
    {
        return Err("ProtocolAuthorizationInvalidSquash: squash writes must be initial writes at a $squash path".to_string().into());
    }

    if let Some(parent_id) = &descriptor.parent_id {
        let parent_protocol = policy
            .definition
            .parent_protocol(descriptor.protocol_path.as_str());
        let parent = fetch_parent_record(tenant, parent_id, &parent_protocol, message_store)
            .await?
            .ok_or_else(|| {
                // A missing parent and a tombstoned parent are indistinguishable on the
                // client-facing reply; the replication apply layer classifies a tombstone
                // as terminal locally. See `record_has_tombstone`.
                let code = if parent_protocol != descriptor.protocol {
                    DwnErrorCode::ProtocolAuthorizationCrossProtocolParentNotFound
                } else {
                    DwnErrorCode::ProtocolAuthorizationParentRecordNotFound
                };
                DwnError::new(
                    code,
                    format!(
                        "could not find parent record '{parent_id}' in protocol '{parent_protocol}'"
                    ),
                )
            })?;
        let parent_descriptor =
            records_write_descriptor(&parent).map_err(|error| error.to_string())?;
        let type_name = descriptor
            .protocol_path
            .rsplit('/')
            .next()
            .unwrap_or_default();
        let expected_path = format!("{}/{type_name}", parent_descriptor.protocol_path);
        if expected_path != descriptor.protocol_path {
            return Err(DwnError::new(
                DwnErrorCode::ProtocolAuthorizationIncorrectProtocolPath,
                format!(
                    "declared protocol path '{}' does not extend parent path '{}'",
                    descriptor.protocol_path, parent_descriptor.protocol_path
                ),
            )
            .into());
        }
        let parent_context = context_id(&parent).ok_or_else(|| {
            DwnError::new(
                DwnErrorCode::ProtocolAuthorizationIncorrectContextId,
                "parent contextId is required",
            )
        })?;
        let record_id = message_record_id(message).ok_or_else(|| {
            DwnError::new(
                DwnErrorCode::ProtocolAuthorizationIncorrectContextId,
                "recordId is required",
            )
        })?;
        let expected_context = format!("{parent_context}/{record_id}");
        let context_id = write_fields(message)
            .map_err(|error| error.to_string())?
            .context_id
            .clone()
            .ok_or_else(|| {
                DwnError::new(
                    DwnErrorCode::ProtocolAuthorizationIncorrectContextId,
                    "contextId is required",
                )
            })?;
        if context_id != expected_context {
            return Err(DwnError::new(
                DwnErrorCode::ProtocolAuthorizationIncorrectContextId,
                format!(
                    "declared contextId '{context_id}' is not the expected '{expected_context}'"
                ),
            )
            .into());
        }
    } else if descriptor.protocol_path.contains('/') {
        return Err(DwnError::new(
            DwnErrorCode::ProtocolAuthorizationParentlessIncorrectProtocolPath,
            format!(
                "declared protocol path '{}' is not valid for records with no parent",
                descriptor.protocol_path
            ),
        )
        .into());
    }

    Ok(())
}
