use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound;

use serde_json::Value as JsonValue;

use crate::descriptors::{ConfigureDescriptor, Descriptor, Protocols};
use crate::dwn::DwnReply;
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::interfaces::messages::protocols::{self as protocol_types, Definition, RuleSet};
use crate::interfaces::replies::Status;
use crate::stores::KeyValues;
use crate::{canonical_rfc3339, permissions};
use crate::{Message, Value};

const PROTOCOLS_INTERFACE: &str = "Protocols";
const CONFIGURE_METHOD: &str = "Configure";

pub(crate) fn parse_message(raw_message: &JsonValue) -> Result<Message<Descriptor>, String> {
    serde_json::from_value(raw_message.clone()).map_err(|err| err.to_string())
}

pub(crate) fn protocols_configure_descriptor(
    message: &Message<Descriptor>,
) -> Result<&ConfigureDescriptor, String> {
    match &message.descriptor {
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            Protocols::Configure(descriptor) => Ok(descriptor),
            _ => Err("expected ProtocolsConfigure message".to_string()),
        },
        _ => Err("expected ProtocolsConfigure message".to_string()),
    }
}

pub(crate) fn protocols_query_descriptor(
    message: &Message<Descriptor>,
) -> Result<&crate::descriptors::ProtocolQueryDescriptor, String> {
    match &message.descriptor {
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            Protocols::Query(descriptor) => Ok(descriptor),
            _ => Err("expected ProtocolsQuery message".to_string()),
        },
        _ => Err("expected ProtocolsQuery message".to_string()),
    }
}

pub(crate) fn message_cid(message: &Message<Descriptor>) -> Result<String, String> {
    message
        .cid()
        .map(|cid| cid.to_string())
        .map_err(|err| err.to_string())
}

pub(crate) fn protocol_configure_filters(protocol: &str, latest_only: bool) -> Filters {
    let mut filters = BTreeMap::new();
    filters.insert(
        FilterKey::Index("interface".to_string()),
        Filter::Equal(Value::String(PROTOCOLS_INTERFACE.to_string())),
    );
    filters.insert(
        FilterKey::Index("method".to_string()),
        Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
    );
    filters.insert(
        FilterKey::Index("protocol".to_string()),
        Filter::Equal(Value::String(protocol.to_string())),
    );
    if latest_only {
        filters.insert(
            FilterKey::Index("isLatestBaseState".to_string()),
            Filter::Equal(Value::Bool(true)),
        );
    }
    Filters::from(filters)
}

pub(crate) fn protocol_definition_lookup_filters(
    protocol: &str,
    message_timestamp: Option<&str>,
) -> Filters {
    let mut filters = BTreeMap::new();
    filters.insert(
        FilterKey::Index("interface".to_string()),
        Filter::Equal(Value::String(PROTOCOLS_INTERFACE.to_string())),
    );
    filters.insert(
        FilterKey::Index("method".to_string()),
        Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
    );
    filters.insert(
        FilterKey::Index("protocol".to_string()),
        Filter::Equal(Value::String(protocol.to_string())),
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

pub(crate) fn configure_indexes(
    descriptor: &ConfigureDescriptor,
    author: Option<&str>,
    is_latest_base_state: bool,
) -> KeyValues {
    let mut indexes = BTreeMap::new();
    indexes.insert(
        "interface".to_string(),
        Value::String(PROTOCOLS_INTERFACE.to_string()),
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
        "protocol".to_string(),
        Value::String(descriptor.definition.protocol.clone()),
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
    let left_timestamp = protocols_configure_descriptor(left)
        .map(|descriptor| descriptor.message_timestamp)
        .ok();
    let right_timestamp = protocols_configure_descriptor(right)
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
    protocol_path: &str,
    referenced: &BTreeMap<String, Definition>,
) -> Result<(), String> {
    for (key, child_rule_set) in rule_set {
        let child_protocol_path = if protocol_path.is_empty() {
            key.clone()
        } else {
            format!("{protocol_path}/{key}")
        };

        if let Some(reference) = &child_rule_set.reference {
            if let Some(parsed) = protocol_types::parse_cross_protocol_ref(reference) {
                let definition = referenced.get(parsed.alias).ok_or_else(|| {
                    format!(
                        "ProtocolsConfigureInvalidRefAlias: '$ref' alias '{}' at protocol path '{}' was not found.",
                        parsed.alias, child_protocol_path
                    )
                })?;
                validate_ref_target(
                    &definition.protocol,
                    &definition.structure,
                    parsed.protocol_path,
                    &child_protocol_path,
                )?;
            }
        }

        for action in &child_rule_set.actions {
            match action {
                protocol_types::Action::Role(action) => {
                    if let Some(parsed) = protocol_types::parse_cross_protocol_ref(&action.role) {
                        let definition = referenced.get(parsed.alias).ok_or_else(|| {
                            format!(
                                "ProtocolsConfigureInvalidCrossProtocolRole: alias '{}' at protocol path '{}' was not found.",
                                parsed.alias, child_protocol_path
                            )
                        })?;
                        let Some(role_rule_set) = protocol_types::get_rule_set_at_path(
                            parsed.protocol_path,
                            &definition.structure,
                        ) else {
                            return Err(format!(
                                "ProtocolsConfigureInvalidCrossProtocolRole: role '{}' at protocol path '{}' does not exist in protocol '{}'.",
                                action.role, child_protocol_path, definition.protocol
                            ));
                        };
                        if role_rule_set.role != Some(true) {
                            return Err(format!(
                                "ProtocolsConfigureInvalidCrossProtocolRole: role '{}' at protocol path '{}' does not point to a valid role in protocol '{}'.",
                                action.role, child_protocol_path, definition.protocol
                            ));
                        }
                    }
                }
                protocol_types::Action::Who(action) => {
                    if let Some(of) = &action.of {
                        if let Some(parsed) = protocol_types::parse_cross_protocol_ref(of) {
                            let definition = referenced.get(parsed.alias).ok_or_else(|| {
                                format!(
                                    "ProtocolsConfigureInvalidCrossProtocolOf: alias '{}' at protocol path '{}' was not found.",
                                    parsed.alias, child_protocol_path
                                )
                            })?;
                            if protocol_types::get_rule_set_at_path(
                                parsed.protocol_path,
                                &definition.structure,
                            )
                            .is_none()
                            {
                                return Err(format!(
                                    "ProtocolsConfigureInvalidCrossProtocolOf: reference '{}' at protocol path '{}' does not point to a valid type path in protocol '{}'.",
                                    of, child_protocol_path, definition.protocol
                                ));
                            }
                        }
                    }
                }
            }
        }

        validate_refs_and_roles_recursively(
            &child_rule_set.rules,
            &child_protocol_path,
            referenced,
        )?;
    }

    Ok(())
}

pub(crate) fn validate_ref_target(
    protocol: &str,
    structure: &BTreeMap<String, RuleSet>,
    target_path: &str,
    source_path: &str,
) -> Result<(), String> {
    let mut current = structure;
    let mut traversed = Vec::new();
    for segment in target_path.split('/') {
        traversed.push(segment);
        let Some(node) = current.get(segment) else {
            return Err(format!(
                "ProtocolsConfigureInvalidRefProtocolPath: '$ref' at protocol path '{source_path}' references type path '{target_path}' which does not exist in protocol '{protocol}'."
            ));
        };
        if node.reference.is_some() {
            return Err(format!(
                "ProtocolsConfigureInvalidRefTargetThroughRef: '$ref' at protocol path '{source_path}' references type path '{target_path}' in protocol '{protocol}', but node '{}' is itself a '$ref'.",
                traversed.join("/")
            ));
        }
        current = &node.rules;
    }
    Ok(())
}

pub(crate) fn store_error_reply(detail: String) -> DwnReply {
    DwnReply {
        status: Status { code: 500, detail },
        body: BTreeMap::new(),
    }
}
