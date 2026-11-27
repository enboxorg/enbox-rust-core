//! The effective policy governing one records write: the definition,
//! rule set, type, and key agreement resolved for the record timestamp.
//!
//! Extracted from the write handler so timestamp-relative definition
//! resolution (`DWN-PROTO-004`), `$ref` composition (`DWN-PROTO-005`), and the
//! encryption-representation gate (`DWN-ENC-001`) read in one place instead of
//! interleaved with enforcement. Enforcement stays with the caller.

use crate::descriptors::records::records_write_descriptor;
use crate::descriptors::{Descriptor, RecordsWriteDescriptor};
use crate::dwn::core_module::CoreModuleRegistry;
use crate::errors::{DwnError, DwnErrorCode};
use crate::handlers::modules::configure::fetch_module_definition;
use crate::interfaces::messages::modules::{Definition, ModuleKeyAgreement, RuleSet};
use crate::Message;

use super::common::governing_timestamp;
use super::write::RecordsWriteValidationError;

/// The module rules governing one write, resolved for its timestamp.
pub(crate) struct EffectivePolicy {
    pub definition: Definition,
    pub rule_set: RuleSet,
    pub type_name: String,
    pub encryption_required: bool,
    pub key_agreement: Option<ModuleKeyAgreement>,
}

impl EffectivePolicy {
    pub(crate) async fn resolve<MessageStore>(
        tenant: &str,
        message: &Message<Descriptor>,
        author: &str,
        registry: &CoreModuleRegistry,
        message_store: &MessageStore,
    ) -> Result<Self, RecordsWriteValidationError>
    where
        MessageStore: crate::stores::MessageStore + Sync,
    {
        let descriptor = records_write_descriptor(message).map_err(|error| error.to_string())?;
        let governing_timestamp =
            governing_timestamp(tenant, message, message_store, author).await?;

        // check if module is defined in the core_module_registry and use that
        // definition, otherwise fetch the module definition from the message store
        let definition = if registry.has(&descriptor.module) {
            registry.get_definition(&descriptor.module).ok_or_else(|| {
                format!(
                    "ModuleAuthorizationInvalidModule: {} is not defined",
                    descriptor.module
                )
            })?
        } else {
            fetch_module_definition(
                tenant,
                &descriptor.module,
                message_store,
                Some(&governing_timestamp),
            )
            .await?
        };
        let rule_set = definition
            .rule_at(descriptor.module_path.as_str())
            .ok_or_else(|| {
                format!(
                    "ModuleAuthorizationInvalidModulePath: {} is not defined",
                    descriptor.module_path
                )
            })?
            .clone();

        // Covers: DWN-PROTO-001, DWN-PROTO-004, DWN-PROTO-005, DWN-ENC-001
        // Module-declared encryption representation is enforced at admission
        // against the definition governing the record timestamp. A record at
        // a `$ref` position resolves its type from the referenced module's
        // `types`, keyed by the local structure key; locally declared
        // descendants follow the composing type map. The key agreement is
        // always the composing rule set at the declared path: a `$ref` node
        // carries no `$keyAgreement`, so an encrypted record written at the
        // attachment point has no reachable key namespace.
        let referenced = referenced_definition_for_ref_path(
            tenant,
            descriptor,
            &definition,
            &governing_timestamp,
            message_store,
        )
        .await?;
        let ref_position = definition.ref_position(descriptor.module_path.as_str());
        let (types, type_name) = match (&referenced, &ref_position) {
            (Some(referenced), Some(_)) => (&referenced.types, descriptor.module_path.clone()),
            _ => (
                &definition.types,
                descriptor
                    .module_path
                    .split('/')
                    .next_back()
                    .unwrap_or_default()
                    .to_string(),
            ),
        };
        let module_type = types.get(&type_name);
        if referenced.is_some() && module_type.is_none() {
            return Err(DwnError::new(
                DwnErrorCode::ModuleAuthorizationInvalidType,
                format!(
                    "type '{type_name}' is not defined in the referenced module for '$ref' path '{}'",
                    descriptor.module_path
                ),
            )
            .into());
        }
        let key_agreement = rule_set.key_agreement.clone();
        let encryption_required =
            module_type.and_then(|module_type| module_type.encryption_required) == Some(true);

        Ok(Self {
            definition,
            rule_set,
            type_name,
            encryption_required,
            key_agreement,
        })
    }
}

async fn referenced_definition_for_ref_path<MessageStore>(
    tenant: &str,
    descriptor: &RecordsWriteDescriptor,
    definition: &Definition,
    governing_timestamp: &str,
    message_store: &MessageStore,
) -> Result<Option<Definition>, RecordsWriteValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(parsed) = definition.ref_position(descriptor.module_path.as_str()) else {
        return Ok(None);
    };
    let ref_uri = definition
        .uses
        .as_ref()
        .and_then(|uses| uses.get(parsed.alias))
        .ok_or_else(|| {
            format!(
                "ModulesConfigureInvalidRefAlias: '$ref' alias '{}' at module path '{}' does not exist in the 'uses' map.",
                parsed.alias, descriptor.module_path
            )
        })?;
    Ok(Some(
        fetch_module_definition(tenant, ref_uri, message_store, Some(governing_timestamp)).await?,
    ))
}
