use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound;

use crate::descriptors::{Descriptor, Modules, ModulesConfigureDescriptor};
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::interfaces::messages::modules::{self as module_types, Definition, RuleSet};
use crate::interfaces::replies::Status;
use crate::stores::KeyValues;
use crate::{canonical_rfc3339, permissions, Response};
use crate::{Message, Value};

const MODULES_INTERFACE: &str = "Modules";
const CONFIGURE_METHOD: &str = "Configure";

pub(crate) fn modules_configure_descriptor(
    message: &Message<Descriptor>,
) -> Result<&ModulesConfigureDescriptor, String> {
    match &message.descriptor {
        Descriptor::Modules(modules) => match modules.as_ref() {
            Modules::Configure(descriptor) => Ok(descriptor),
            _ => Err("expected ModulesConfigure message".to_string()),
        },
        _ => Err("expected ModulesConfigure message".to_string()),
    }
}

pub(crate) fn message_cid(message: &Message<Descriptor>) -> Result<String, String> {
    message
        .cid()
        .map(|cid| cid.to_string())
        .map_err(|err| err.to_string())
}

pub(crate) fn module_configure_filters(module: &str, latest_only: bool) -> Filters {
    let mut filters = BTreeMap::new();
    filters.insert(
        FilterKey::Index("interface".to_string()),
        Filter::Equal(Value::String(MODULES_INTERFACE.to_string())),
    );
    filters.insert(
        FilterKey::Index("method".to_string()),
        Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
    );
    filters.insert(
        FilterKey::Index("module".to_string()),
        Filter::Equal(Value::String(module.to_string())),
    );
    if latest_only {
        filters.insert(
            FilterKey::Index("isLatestBaseState".to_string()),
            Filter::Equal(Value::Bool(true)),
        );
    }
    Filters::from(filters)
}

pub(crate) fn latest_configure_filters() -> Filters {
    let mut filters = BTreeMap::new();
    filters.insert(
        FilterKey::Index("interface".to_string()),
        Filter::Equal(Value::String(MODULES_INTERFACE.to_string())),
    );
    filters.insert(
        FilterKey::Index("method".to_string()),
        Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
    );
    filters.insert(
        FilterKey::Index("isLatestBaseState".to_string()),
        Filter::Equal(Value::Bool(true)),
    );
    Filters::from(filters)
}

pub(crate) fn module_definition_lookup_filters(
    module: &str,
    message_timestamp: Option<&str>,
) -> Filters {
    let mut filters = BTreeMap::new();
    filters.insert(
        FilterKey::Index("interface".to_string()),
        Filter::Equal(Value::String(MODULES_INTERFACE.to_string())),
    );
    filters.insert(
        FilterKey::Index("method".to_string()),
        Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
    );
    filters.insert(
        FilterKey::Index("module".to_string()),
        Filter::Equal(Value::String(module.to_string())),
    );

    if let Some(timestamp) = message_timestamp {
        filters.insert(
            FilterKey::Index("messageTimestamp".to_string()),
            Filter::Range(RangeFilter::Numeric(
                Bound::Unbounded,
                Bound::Included(Value::String(timestamp.to_string())),
            )),
        );
    } else {
        filters.insert(
            FilterKey::Index("isLatestBaseState".to_string()),
            Filter::Equal(Value::Bool(true)),
        );
    }

    Filters::from(filters)
}

pub(crate) fn module_definition_history_filters(module: &str) -> Filters {
    let mut filters = BTreeMap::new();
    filters.insert(
        FilterKey::Index("interface".to_string()),
        Filter::Equal(Value::String(MODULES_INTERFACE.to_string())),
    );
    filters.insert(
        FilterKey::Index("method".to_string()),
        Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
    );
    filters.insert(
        FilterKey::Index("module".to_string()),
        Filter::Equal(Value::String(module.to_string())),
    );
    Filters::from(filters)
}

pub(crate) fn configure_indexes(
    descriptor: &ModulesConfigureDescriptor,
    author: Option<&str>,
    is_latest_base_state: bool,
) -> KeyValues {
    let mut indexes = BTreeMap::new();
    indexes.insert(
        "interface".to_string(),
        Value::String(MODULES_INTERFACE.to_string()),
    );
    indexes.insert(
        "method".to_string(),
        Value::String(CONFIGURE_METHOD.to_string()),
    );
    indexes.insert(
        "messageTimestamp".to_string(),
        Value::String(canonical_rfc3339(descriptor.message_timestamp)),
    );
    indexes.insert(
        "module".to_string(),
        Value::String(descriptor.definition.module.clone()),
    );
    indexes.insert(
        "published".to_string(),
        Value::Bool(descriptor.definition.published),
    );
    indexes.insert(
        "isLatestBaseState".to_string(),
        Value::Bool(is_latest_base_state),
    );
    if let Some(author) = author {
        indexes.insert("author".to_string(), Value::String(author.to_string()));
    }
    if let Some(permission_grant_id) = &descriptor.permission_grant_id {
        indexes.insert(
            "permissionGrantId".to_string(),
            Value::String(permission_grant_id.clone()),
        );
    }
    indexes
}

pub(crate) fn compare_configure_messages(
    left_cid: &str,
    left: &Message<Descriptor>,
    right_cid: &str,
    right: &Message<Descriptor>,
) -> Ordering {
    let left_timestamp = modules_configure_descriptor(left)
        .map(|descriptor| descriptor.message_timestamp)
        .ok();
    let right_timestamp = modules_configure_descriptor(right)
        .map(|descriptor| descriptor.message_timestamp)
        .ok();
    left_timestamp
        .cmp(&right_timestamp)
        .then_with(|| left_cid.cmp(right_cid))
}

pub(crate) fn extract_author(message: &Message<Descriptor>) -> Option<String> {
    permissions::message_author(message)
}

pub(crate) fn validate_refs_and_roles_recursively(
    rule_set: &BTreeMap<String, RuleSet>,
    module_path: &str,
    referenced: &BTreeMap<String, Definition>,
) -> Result<(), String> {
    for (key, child_rule_set) in rule_set {
        let child_module_path = if module_path.is_empty() {
            key.clone()
        } else {
            format!("{module_path}/{key}")
        };

        if let Some(reference) = &child_rule_set.reference {
            if let Some(parsed) = module_types::parse_cross_module_ref(reference) {
                let definition = referenced.get(parsed.alias).ok_or_else(|| {
                    format!(
                        "ModulesConfigureInvalidRefAlias: '$ref' alias '{}' at module path '{}' was not found.",
                        parsed.alias, child_module_path
                    )
                })?;
                let mut current = &definition.structure;
                let mut traversed = Vec::new();
                for segment in parsed.module_path.split('/') {
                    traversed.push(segment);
                    let Some(node) = current.get(segment) else {
                        return Err(format!(
                            "ModulesConfigureInvalidRefModulePath: '$ref' at module path '{child_module_path}' references type path '{}' which does not exist in module '{}'.",
                            parsed.module_path, definition.module
                        ));
                    };
                    if node.reference.is_some() {
                        return Err(format!(
                            "ModulesConfigureInvalidRefTargetThroughRef: '$ref' at module path '{child_module_path}' references type path '{}' in module '{}', but node '{}' is itself a '$ref'.",
                            parsed.module_path,
                            definition.module,
                            traversed.join("/")
                        ));
                    }
                    current = &node.rules;
                }
            }
        }

        for action in &child_rule_set.actions {
            match action {
                module_types::Action::Role(action) => {
                    if let Some(parsed) = module_types::parse_cross_module_ref(&action.role) {
                        let definition = referenced.get(parsed.alias).ok_or_else(|| {
                            format!(
                                "ModulesConfigureInvalidCrossModuleRole: alias '{}' at module path '{}' was not found.",
                                parsed.alias, child_module_path
                            )
                        })?;
                        let Some(role_rule_set) = definition.rule_at(parsed.module_path) else {
                            return Err(format!(
                                "ModulesConfigureInvalidCrossModuleRole: role '{}' at module path '{}' does not exist in module '{}'.",
                                action.role, child_module_path, definition.module
                            ));
                        };
                        if role_rule_set.role != Some(true) {
                            return Err(format!(
                                "ModulesConfigureInvalidCrossModuleRole: role '{}' at module path '{}' does not point to a valid role in module '{}'.",
                                action.role, child_module_path, definition.module
                            ));
                        }
                        let role_type = parsed
                            .module_path
                            .split('/')
                            .next_back()
                            .unwrap_or_default();
                        let role_type_encrypted = definition
                            .types
                            .get(role_type)
                            .and_then(|module_type| module_type.encryption_required)
                            == Some(true);
                        if role_type_encrypted {
                            return Err(format!(
                                "ModulesConfigureInvalidEncryptedRoleType: cross-module role '{}' at module path '{}' resolves to encrypted type '{role_type}' in module '{}'; role records cannot be encrypted.",
                                action.role, child_module_path, definition.module
                            ));
                        }
                    }
                }
                module_types::Action::Who(action) => {
                    if let Some(of) = &action.of {
                        if let Some(parsed) = module_types::parse_cross_module_ref(of) {
                            let definition = referenced.get(parsed.alias).ok_or_else(|| {
                                format!(
                                    "ModulesConfigureInvalidCrossModuleOf: alias '{}' at module path '{}' was not found.",
                                    parsed.alias, child_module_path
                                )
                            })?;
                            if definition.rule_at(parsed.module_path).is_none() {
                                return Err(format!(
                                    "ModulesConfigureInvalidCrossModuleOf: reference '{}' at module path '{}' does not point to a valid type path in module '{}'.",
                                    of, child_module_path, definition.module
                                ));
                            }
                        }
                    }
                }
            }
        }

        validate_refs_and_roles_recursively(&child_rule_set.rules, &child_module_path, referenced)?;
    }

    Ok(())
}

pub(crate) fn store_error_reply<R: Default>(detail: String) -> Response<R> {
    Response::new(Status::new(500, detail), R::default())
}
