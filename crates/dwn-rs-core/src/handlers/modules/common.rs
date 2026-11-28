use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound;

use crate::descriptors::{Descriptor, Modules, ModulesConfigureDescriptor};
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
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

pub(crate) fn store_error_reply<R: Default>(detail: String) -> Response<R> {
    Response::new(Status::new(500, detail), R::default())
}
