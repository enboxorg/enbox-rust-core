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
use crate::handlers::records::common::{context_id, fetch_newest_write};
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
        let parent = fetch_newest_write(tenant, parent_id, message_store).await?;
        let parent_context = context_id(&parent).ok_or_else(|| {
            "ProtocolAuthorizationParentContextMissing: parent contextId is required".to_string()
        })?;
        let context_id = write_fields(message)
            .map_err(|error| error.to_string())?
            .context_id
            .clone()
            .ok_or_else(|| {
                "ProtocolAuthorizationContextMissing: contextId is required".to_string()
            })?;
        if !context_id.starts_with(&format!("{parent_context}/")) {
            return Err(
                "ProtocolAuthorizationContextMismatch: contextId must be under parent context"
                    .to_string()
                    .into(),
            );
        }
    }

    Ok(())
}
