//! Referential integrity for records writes: the module rules governing
//! one write, enforced against its descriptor.
//!
//! Resolution (which definition, rule set, type, and key agreement govern the
//! write) lives in [`super::policy`]; this module enforces the resolved
//! policy: representation, immutability, size, squash, and parentage.

use crate::descriptors::{
    records::{is_initial_write, records_write_descriptor, write_fields},
    Descriptor,
};
use crate::dwn::core_module::CoreModuleRegistry;
use crate::encryption::control::{AudienceId, AudienceScope, ControlKind};
use crate::encryption::{
    EncryptionEnvelope, KeyEncryption, ENCRYPTION_MODULE_GRANT_KEY_PATH, ENCRYPTION_MODULE_URI,
};
use crate::errors::{DwnError, DwnErrorCode};
use crate::handlers::records::common::{context_id, fetch_parent_record, message_record_id};
use crate::interfaces::messages::modules::Can;
use crate::stores::MessageStore;
use crate::Message;

use super::policy::EffectivePolicy;
use super::write::RecordsWriteValidationError;

pub(crate) async fn validate_referential_integrity<M>(
    tenant: &str,
    message: &Message<Descriptor>,
    author: &str,
    registry: &CoreModuleRegistry,
    message_store: &M,
) -> Result<(), RecordsWriteValidationError>
where
    M: MessageStore + Sync,
{
    let descriptor = records_write_descriptor(message).map_err(|error| error.to_string())?;
    let module_path = descriptor.module_path.clone();

    // Control records live at virtual paths the module never declares, so
    // there is no type or rule set to validate them against. They are
    // admitted on their own fixed contract instead, and the application
    // encryption-policy checks below deliberately do not apply: a control
    // record's representation is fixed by its kind, not by the module.
    if let Some(kind) = ControlKind::from_module_path(&module_path) {
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
            DwnErrorCode::ModuleAuthorizationEncryptionRequired,
            format!(
                "type '{type_name}' requires encryption but message has no encryption metadata"
            ),
        )
        .into());
    }
    if !policy.encryption_required && has_envelope {
        return Err(DwnError::new(
            DwnErrorCode::ModuleAuthorizationEncryptionNotAllowed,
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
                        DwnErrorCode::ModuleAuthorizationEncryptionRequired,
                        format!(
                            "type '{type_name}' requires encryption but message has no encryption metadata"
                        ),
                    )
                    .into());
                };
                let has_module_path_entry = envelope.key_encryption.iter().any(|entry| {
                    matches!(entry, KeyEncryption::ModulePath { key_id: id, .. } if id == &key_id)
                });
                if !has_module_path_entry {
                    return Err(DwnError::new(
                        DwnErrorCode::ModuleAuthorizationEncryptionModulePathEntryMissing,
                        format!(
                            "encrypted record is missing a modulePath keyEncryption entry for '{module_path}'"
                        ),
                    )
                    .into());
                }
                validate_role_audiences(tenant, message, &policy, envelope, message_store).await?;
            }
            None => {
                let dynamic_recipient = definition.module == ENCRYPTION_MODULE_URI
                    && descriptor.module_path == ENCRYPTION_MODULE_GRANT_KEY_PATH;
                if !dynamic_recipient {
                    return Err(DwnError::new(
                        DwnErrorCode::ModuleAuthorizationEncryptionKeyAgreementMissing,
                        format!("encrypted module path '{module_path}' has no $keyAgreement"),
                    )
                    .into());
                }
            }
        }
    }

    if rule_set.immutable == Some(true) && !is_initial_write(message, author)? {
        return Err(DwnError::new(
            DwnErrorCode::ModuleAuthorizationImmutableRecord,
            format!("record at module path '{module_path}' is immutable: updates are not allowed."),
        )
        .into());
    }

    if let Some(size) = &rule_set.size {
        if let Some(min) = size.min {
            if descriptor.data_size < min {
                return Err(format!(
                    "ModuleAuthorizationInvalidDataSize: dataSize {} is smaller than minimum {}",
                    descriptor.data_size, min
                )
                .into());
            }
        }
        if let Some(max) = size.max {
            if descriptor.data_size > max {
                return Err(format!(
                    "ModuleAuthorizationInvalidDataSize: dataSize {} exceeds maximum {}",
                    descriptor.data_size, max
                )
                .into());
            }
        }
    }

    if descriptor.squash == Some(true)
        && (rule_set.squash != Some(true) || !is_initial_write(message, author)?)
    {
        return Err("ModuleAuthorizationInvalidSquash: squash writes must be initial writes at a $squash path".to_string().into());
    }

    verify_module_path_and_context_id(tenant, message, &policy.node, message_store).await?;

    Ok(())
}

/// Verifies the declared parent and context against the resolved node's
/// physical parent, independent of declared path depth.
async fn verify_module_path_and_context_id<M>(
    tenant: &str,
    message: &Message<Descriptor>,
    node: &crate::interfaces::messages::modules::graph::ResolvedModuleNode,
    message_store: &M,
) -> Result<(), RecordsWriteValidationError>
where
    M: MessageStore + Sync,
{
    let descriptor = records_write_descriptor(message).map_err(|error| error.to_string())?;
    let Some(parent_id) = &descriptor.parent_id else {
        if node.expected_parent.is_some() {
            return Err(DwnError::new(
                DwnErrorCode::ModuleAuthorizationParentlessIncorrectModulePath,
                format!(
                    "declared module path '{}' requires a physical parent.",
                    descriptor.module_path
                ),
            )
            .into());
        }
        return Ok(());
    };
    let Some(expected) = &node.expected_parent else {
        return Err(DwnError::new(
            DwnErrorCode::ModuleAuthorizationIncorrectModulePath,
            format!(
                "root module path '{}' cannot have a parent.",
                descriptor.module_path
            ),
        )
        .into());
    };
    let parent = fetch_parent_record(
        tenant,
        parent_id,
        &expected.owning_module_uri,
        message_store,
    )
    .await?
    .ok_or_else(|| {
        // A missing parent and a pruned parent are indistinguishable on the
        // client-facing reply; the replication apply layer classifies a prune
        // as terminal locally. See `record_has_prune`.
        DwnError::new(
            DwnErrorCode::ModuleAuthorizationParentRecordNotFound,
            format!(
                "could not find parent record '{parent_id}' in module '{}'",
                expected.owning_module_uri
            ),
        )
    })?;
    let parent_descriptor = records_write_descriptor(&parent).map_err(|error| error.to_string())?;
    if parent_descriptor.module != expected.owning_module_uri
        || parent_descriptor.module_path != expected.owning_module_path
    {
        return Err(DwnError::new(
            DwnErrorCode::ModuleAuthorizationIncorrectModulePath,
            format!(
                "parent record does not match the resolved parent of module path '{}'.",
                descriptor.module_path
            ),
        )
        .into());
    }
    let parent_context = context_id(&parent).ok_or_else(|| {
        DwnError::new(
            DwnErrorCode::ModuleAuthorizationIncorrectContextId,
            "parent contextId is required",
        )
    })?;
    let record_id = message_record_id(message).ok_or_else(|| {
        DwnError::new(
            DwnErrorCode::ModuleAuthorizationIncorrectContextId,
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
                DwnErrorCode::ModuleAuthorizationIncorrectContextId,
                "contextId is required",
            )
        })?;
    if context_id != expected_context {
        return Err(DwnError::new(
            DwnErrorCode::ModuleAuthorizationIncorrectContextId,
            format!("declared contextId '{context_id}' is not the expected '{expected_context}'"),
        )
        .into());
    }
    Ok(())
}

async fn validate_role_audiences<M>(
    tenant: &str,
    message: &Message<Descriptor>,
    policy: &EffectivePolicy,
    envelope: &EncryptionEnvelope,
    message_store: &M,
) -> Result<(), RecordsWriteValidationError>
where
    M: MessageStore + Sync,
{
    let record_context = context_id(message);
    for action in &policy.node.actions {
        let Some(role) = &action.resolved_role else {
            continue;
        };
        if !action.rule.can().contains(&Can::Read) {
            continue;
        }
        let Some(audience_context) =
            crate::interfaces::messages::modules::graph::role_audience_context_id(
                role.parent_physical_depth,
                record_context.as_deref(),
            )
        else {
            return Err(DwnError::new(
                DwnErrorCode::ModuleAuthorizationMissingContextId,
                format!(
                    "could not resolve the encryption audience context for '{}'.",
                    role.raw_role
                ),
            )
            .into());
        };

        let matching_entries: Vec<&KeyEncryption> = envelope
            .key_encryption
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    KeyEncryption::RoleAudience {
                        module: entry_module,
                        role_path: entry_role_path,
                        ..
                    } if entry_module == &role.owning_module_uri
                        && entry_role_path == &role.owning_module_path
                )
            })
            .collect();
        if matching_entries.is_empty() {
            return Err(DwnError::new(
                DwnErrorCode::ModuleAuthorizationEncryptionRoleAudienceEntryMissing,
                format!(
                    "encrypted record is missing a roleAudience keyEncryption entry for role '{}'",
                    role.owning_module_path
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
                    module: role.owning_module_uri.clone(),
                    role_path: role.owning_module_path.clone(),
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
                DwnErrorCode::ModuleAuthorizationEncryptionRoleAudienceMissing,
                format!(
                    "encrypted record references no retained audience for module '{}', role '{}', context '{audience_context}', and key IDs [{}]",
                    role.owning_module_uri,
                    role.owning_module_path,
                    missing_key_ids.join(", ")
                ),
            )
            .into());
        }
    }
    Ok(())
}
