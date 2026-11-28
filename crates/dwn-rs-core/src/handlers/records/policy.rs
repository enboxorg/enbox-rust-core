//! The effective policy governing one records write: the definition,
//! rule set, type, and key agreement resolved for the record timestamp.
//!
//! Resolution loads the module dependency graph at the governing timestamp so
//! composed paths, physical ancestry, and rendered types are all decided in
//! one place (`DWN-PROTO-004`, `DWN-PROTO-005`). Enforcement stays with the
//! caller.

use crate::descriptors::records::records_write_descriptor;
use crate::descriptors::Descriptor;
use crate::dwn::core_module::CoreModuleRegistry;
use crate::errors::{DwnError, DwnErrorCode};
use crate::handlers::modules::configure::fetch_module_definition;
use crate::interfaces::messages::modules::graph::{
    load_module_graph, ModuleGraphLoadError, ResolvedModuleGraph, ResolvedModuleNode,
    ResolvedModuleNodeKind,
};
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
    pub node: ResolvedModuleNode,
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
        let root_definition = if registry.has(&descriptor.module) {
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

        // Covers: DWN-PROTO-001, DWN-PROTO-004, DWN-PROTO-005
        // The whole dependency closure resolves at the record's governing
        // timestamp; declared path depth never decides physical ancestry.
        let graph = load_definition_graph(
            root_definition,
            tenant,
            message_store,
            Some(governing_timestamp.as_str()),
        )
        .await?;
        let definition = graph
            .definitions_by_uri
            .get(&descriptor.module)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "ModuleAuthorizationInvalidModule: {} is not defined",
                    descriptor.module
                )
            })?;
        let node = graph
            .record_node(&descriptor.module_path)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "ModuleAuthorizationInvalidModulePath: {} is not defined",
                    descriptor.module_path
                )
            })?;
        if node.kind == ResolvedModuleNodeKind::Ref {
            return Err(DwnError::new(
                DwnErrorCode::ModuleAuthorizationRefNodeWriteNotAllowed,
                format!(
                    "modulePath '{}' is a virtual reference, not a local record.",
                    descriptor.module_path
                ),
            )
            .into());
        }

        let module_type = graph
            .definitions_by_uri
            .get(&node.owning_module_uri)
            .and_then(|definition| definition.types.get(&node.type_name))
            .cloned();
        let Some(module_type) = module_type else {
            return Err(DwnError::new(
                DwnErrorCode::ModuleAuthorizationInvalidType,
                format!(
                    "type '{}' is not defined in module '{}'",
                    node.type_name, node.owning_module_uri
                ),
            )
            .into());
        };
        let encryption_required = module_type.encryption_required == Some(true);
        let key_agreement = node.rule_set.key_agreement.clone();

        Ok(Self {
            definition,
            rule_set: node.rule_set.clone(),
            type_name: node.type_name.clone(),
            encryption_required,
            key_agreement,
            node,
        })
    }
}

/// Loads a definition's dependency closure at one governing snapshot.
pub(crate) async fn load_definition_graph<MessageStore>(
    root_definition: Definition,
    tenant: &str,
    message_store: &MessageStore,
    message_timestamp: Option<&str>,
) -> Result<ResolvedModuleGraph, RecordsWriteValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let tenant = tenant.to_string();
    let message_timestamp = message_timestamp.map(str::to_string);
    load_module_graph(root_definition, move |uri| {
        let tenant = tenant.clone();
        let message_timestamp = message_timestamp.clone();
        let message_store = message_store;
        async move {
            match fetch_module_definition(
                &tenant,
                &uri,
                message_store,
                message_timestamp.as_deref(),
            )
            .await
            {
                Ok(definition) => Ok(Some(definition)),
                Err(
                    crate::handlers::modules::configure::ModuleDefinitionLookupError::NotFound(_),
                ) => Ok(None),
                Err(error) => Err(ModuleGraphLoadError::Store(error.to_string())),
            }
        }
    })
    .await
    .map_err(graph_validation_error)
}

/// Maps a graph load failure onto the write handler's error classes.
pub(crate) fn graph_validation_error(error: ModuleGraphLoadError) -> RecordsWriteValidationError {
    match error {
        ModuleGraphLoadError::Store(detail) => RecordsWriteValidationError::Internal(detail),
        ModuleGraphLoadError::Definition(error) => match DwnErrorCode::try_from(error.code) {
            Ok(code) => RecordsWriteValidationError::Dwn(DwnError::new(code, error.message)),
            Err(_) => RecordsWriteValidationError::Detail(error.to_string()),
        },
    }
}
