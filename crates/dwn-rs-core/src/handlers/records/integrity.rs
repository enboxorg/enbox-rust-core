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
use crate::encryption::control::{AudienceId, AudienceScope, ControlKind};
use crate::encryption::{
    EncryptionEnvelope, KeyEncryption, ENCRYPTION_PROTOCOL_GRANT_KEY_PATH, ENCRYPTION_PROTOCOL_URI,
};
use crate::errors::{DwnError, DwnErrorCode};
use crate::handlers::records::common::{context_id, fetch_parent_record, message_record_id};
use crate::interfaces::messages::protocols::{
    parse_cross_protocol_ref, Action, Can, Definition, RuleSet,
};
use crate::stores::MessageStore;
use crate::Message;

use super::policy::EffectivePolicy;
use super::write::RecordsWriteValidationError;

pub(crate) async fn validate_referential_integrity<M>(
    tenant: &str,
    message: &Message<Descriptor>,
    author: &str,
    registry: &CoreProtocolRegistry,
    message_store: &M,
) -> Result<(), RecordsWriteValidationError>
where
    M: MessageStore + Sync,
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
                validate_role_audiences(
                    tenant,
                    message,
                    definition,
                    rule_set,
                    envelope,
                    message_store,
                )
                .await?;
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
                // A missing parent and a pruned parent are indistinguishable on the
                // client-facing reply; the replication apply layer classifies a prune
                // as terminal locally. See `record_has_prune`.
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

async fn validate_role_audiences<M>(
    tenant: &str,
    message: &Message<Descriptor>,
    definition: &Definition,
    rule_set: &RuleSet,
    envelope: &EncryptionEnvelope,
    message_store: &M,
) -> Result<(), RecordsWriteValidationError>
where
    M: MessageStore + Sync,
{
    let record_context = context_id(message);
    for action in &rule_set.actions {
        let Action::Role(action) = action else {
            continue;
        };
        if !action.can.contains(&Can::Read) {
            continue;
        }

        let (protocol, role_path) = match parse_cross_protocol_ref(&action.role) {
            Some(parsed) => {
                let Some(protocol) = definition
                    .uses
                    .as_ref()
                    .and_then(|uses| uses.get(parsed.alias))
                else {
                    continue;
                };
                (protocol.as_str(), parsed.protocol_path)
            }
            None => (definition.protocol.as_str(), action.role.as_str()),
        };
        let Some(audience_context) =
            super::common::role_audience_context_id(role_path, record_context.as_deref())
        else {
            continue;
        };

        let matching_entries: Vec<&KeyEncryption> = envelope
            .key_encryption
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    KeyEncryption::RoleAudience {
                        protocol: entry_protocol,
                        role_path: entry_role_path,
                        ..
                    } if entry_protocol == protocol && entry_role_path == role_path
                )
            })
            .collect();
        if matching_entries.is_empty() {
            return Err(DwnError::new(
                DwnErrorCode::ProtocolAuthorizationEncryptionRoleAudienceEntryMissing,
                format!(
                    "encrypted record is missing a roleAudience keyEncryption entry for role '{role_path}'"
                ),
            )
            .into());
        }

        let mut missing_key_ids = Vec::with_capacity(matching_entries.len());
        for entry in matching_entries {
            let KeyEncryption::RoleAudience { key_id, .. } = entry else {
                unreachable!("matching entries are roleAudience entries");
            };
            let id = AudienceId {
                scope: AudienceScope {
                    protocol: protocol.to_string(),
                    role_path: role_path.to_string(),
                    context_id: audience_context.clone(),
                },
                key_id: key_id.clone(),
            };
            if super::control::stored_audience_exists(tenant, &id, message_store).await? {
                missing_key_ids.clear();
                break;
            }
            missing_key_ids.push(key_id.as_str());
        }
        if !missing_key_ids.is_empty() {
            return Err(DwnError::new(
                DwnErrorCode::ProtocolAuthorizationEncryptionRoleAudienceMissing,
                format!(
                    "encrypted record references no retained audience for protocol '{protocol}', role '{role_path}', context '{audience_context}', and key IDs [{}]",
                    missing_key_ids.join(", ")
                ),
            )
            .into());
        }
    }
    Ok(())
}
