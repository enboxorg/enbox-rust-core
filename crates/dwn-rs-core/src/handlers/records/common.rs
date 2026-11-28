use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use serde_json::Value as JsonValue;

use crate::descriptors::records::{entry_id, is_initial_write};
use crate::descriptors::{
    messages::record_id,
    records::{records_write_descriptor, write_fields, write_fields_mut},
    DeleteDescriptor, Descriptor, Records, RecordsWriteDescriptor, SubscribeDescriptor,
};
use crate::dwn::core_module::CoreModuleRegistry;
use crate::errors::{DwnError, DwnErrorCode, EventLogError};
use crate::filters::message_filters::Records as RecordsFilter;
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::handlers::configure::fetch_module_definition;
use crate::handlers::modules::configure::ModuleDefinitionLookupError;
use crate::handlers::records::subscribe::RecordsSubscribeReply;
use crate::interfaces::messages::modules::graph::{
    role_audience_context_id, ResolvedActorReference, ResolvedModuleGraph, ResolvedModuleNode,
    ResolvedModuleNodeKind, ResolvedRoleReference,
};
use crate::interfaces::messages::modules::{
    self as module_types, Action, Can, Definition, RuleSet, Who,
};
use crate::interfaces::replies::Status;
use crate::permissions::{self, AuthorizationContext};
use crate::replies::records::{QueryEntry, Subscribe};
use crate::replies::HasProgressGapInfo;
use crate::stores::write_resolver::InitialWriteResolver;
use crate::stores::{EventSubscription, KeyValues, RecordLimitOccupancy};
use crate::SubtreeFilter;
use crate::{canonical_rfc3339, Message, MessageSort, Pagination, Response, SortDirection, Value};

use super::{RecordsAuthorizationKind, MAX_ENCODED_DATA_SIZE, RECORDS_INTERFACE, WRITE_METHOD};

#[derive(Debug)]
pub(crate) enum QueryAuthorizationResult {
    Unauthorized(ModuleAuthorizationError),
}

pub(crate) fn records_delete_descriptor(
    message: &Message<Descriptor>,
) -> Result<&DeleteDescriptor, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Delete(descriptor) => Ok(descriptor),
            _ => Err("RecordsDeleteDescriptorExpected: message is not RecordsDelete".to_string()),
        },
        _ => Err("RecordsDeleteDescriptorExpected: message is not RecordsDelete".to_string()),
    }
}

pub(crate) fn records_subscribe_descriptor(
    message: &Message<Descriptor>,
) -> Result<&SubscribeDescriptor, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Subscribe(descriptor) => Ok(descriptor),
            _ => Err(
                "RecordsSubscribeDescriptorExpected: message is not RecordsSubscribe".to_string(),
            ),
        },
        _ => Err("RecordsSubscribeDescriptorExpected: message is not RecordsSubscribe".to_string()),
    }
}

pub(crate) fn validate_records_write_integrity(
    message: &Message<Descriptor>,
    signature: &AuthorizationContext,
) -> Result<(), String> {
    let records_write_data_authdata = signature.payload.as_records_write().ok_or_else(|| {
        "RecordsWriteValidateIntegrityAuthorizationPayloadMissing: authorization payload is required".to_string()
    })?;

    let record_id = record_id(message).ok_or_else(|| {
        "RecordsWriteValidateIntegrityRecordIdMissing: recordId is required".to_string()
    })?;
    if records_write_data_authdata.record_id != record_id {
        return Err("RecordsWriteValidateIntegrityRecordIdUnauthorized: recordId in message does not match recordId in authorization".to_string());
    }

    // Encrypted records carry an `encryption` envelope whose `initializationVector`
    // JSON Schema can only constrain to base64url, not to 16 decoded bytes re-checks
    // the decoded length and every key-encryption entry during `RecordsWrite.parse`
    // via `Encryption.validateEncryptionProperty`; mirror that so an inbound message
    // with a malformed IV or ephemeral key is rejected at admission rather than failing
    // decryption later.
    if let Some(encryption) = write_fields(message)
        .map_err(|error| error.to_string())?
        .encryption
        .as_ref()
    {
        encryption.validate().map_err(|error| match error {
            crate::encryption::EncryptionError::InvalidInitializationVectorLength { found } => {
                format!(
                    "RecordsWriteValidateIntegrityEncryptionInitializationVectorInvalid: A256CTR initializationVector must decode to 16 bytes, got {found}"
                )
            }
            crate::encryption::EncryptionError::InvalidBase64Url { label, error } => {
                format!(
                    "RecordsWriteValidateIntegrityEncryptionInitializationVectorInvalid: {label} must be valid base64url: {error}"
                )
            }
            other => format!(
                "RecordsWriteValidateIntegrityEncryptionEphemeralPublicKeyInvalid: {other}"
            ),
        })?;
    }

    // `contextId` is a module-only surface: per DWN spec.md:1028 a record NOT
    // attached to a module MUST NOT have a contextId, and upstream implementations
    // including enbox's own dwn-sdk-js do not require a contextId for non-module records.
    // `We therefore treat it as optional and only require the value to agree with the
    // signature payload (both-absent is valid), matching upstream `validateIntegrity`.
    let context_id = context_id(message);
    let signature_context_id = records_write_data_authdata.context_id.clone();
    if context_id != Some(signature_context_id) {
        return Err("RecordsWriteValidateIntegrityContextIdNotInSignerSignaturePayload: contextId in message does not match contextId in authorization".to_string());
    }

    if is_initial_write(message, &signature.author)? {
        let descriptor = records_write_descriptor(message)?;
        if descriptor.message_timestamp != descriptor.date_created {
            return Err(format!(
                "RecordsWriteValidateIntegrityDateCreatedMismatch: messageTimestamp {} must match dateCreated {} for the initial write",
                canonical_rfc3339(descriptor.message_timestamp),
                canonical_rfc3339(descriptor.date_created),
            ));
        }
        // Only a module-scoped root record carries the deterministic
        // `contextId == recordId`. Upstream gates this check on
        // `descriptor.module !== undefined`; a module-less record has no
        // contextId to validate.
        if descriptor.parent_id.is_none() && context_id.as_deref() != Some(record_id.as_str()) {
            return Err("RecordsWriteValidateIntegrityContextIdMismatch: root contextId must match recordId".to_string());
        }
    }
    Ok(())
}

pub(crate) fn context_id(message: &Message<Descriptor>) -> Option<String> {
    write_fields(message).ok()?.context_id.clone()
}

pub(crate) fn message_record_id(message: &Message<Descriptor>) -> Option<String> {
    record_id(message).or_else(|| {
        records_delete_descriptor(message)
            .ok()
            .map(|d| d.record_id.clone())
    })
}

/// Finds the record's initial write among `messages`. The initial write is
/// identified by its own author, not by the caller, so a co-update by a
/// different author still resolves the same initial write.
pub(crate) fn find_initial_write(
    messages: &[Message<Descriptor>],
    _author: &str,
) -> Option<Message<Descriptor>> {
    messages
        .iter()
        .find(|message| {
            let own_author = extract_author(message).unwrap_or_default();
            records_write_descriptor(message).is_ok()
                && is_initial_write(message, &own_author).unwrap_or(false)
        })
        .cloned()
}

pub(crate) fn verify_immutable_properties(
    initial_write: &Message<Descriptor>,
    new_message: &Message<Descriptor>,
) -> Result<(), DwnError> {
    let initial = records_write_descriptor(initial_write).map_err(|detail| {
        DwnError::new(DwnErrorCode::RecordsWriteImmutablePropertyChanged, detail)
    })?;
    let new = records_write_descriptor(new_message).map_err(|detail| {
        DwnError::new(DwnErrorCode::RecordsWriteImmutablePropertyChanged, detail)
    })?;
    let changed = [
        ("interface", initial.interface(), new.interface()),
        ("method", initial.method(), new.method()),
    ]
    .into_iter()
    .find(|(_, left, right)| left != right)
    .map(|(property, _, _)| property.to_string())
    .or_else(|| {
        [
            (
                "module",
                &Some(initial.module.clone()),
                &Some(new.module.clone()),
            ),
            (
                "modulePath",
                &Some(initial.module_path.clone()),
                &Some(new.module_path.clone()),
            ),
            ("recipient", &initial.recipient, &new.recipient),
            ("schema", &initial.schema, &new.schema),
            ("parentId", &initial.parent_id, &new.parent_id),
            (
                "permissionGrantId",
                &initial.permission_grant_id,
                &new.permission_grant_id,
            ),
        ]
        .into_iter()
        .find(|(_, left, right)| left != right)
        .map(|(property, _, _)| property.to_string())
    })
    .or_else(|| (initial.date_created != new.date_created).then(|| "dateCreated".to_string()))
    .or_else(|| (initial.squash != new.squash).then(|| "squash".to_string()));

    if let Some(property) = changed {
        return Err(DwnError::new(
            DwnErrorCode::RecordsWriteImmutablePropertyChanged,
            format!("{property} is an immutable property"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_data_integrity(
    expected_data_cid: &str,
    expected_data_size: u64,
    actual_data_cid: &str,
    actual_data_size: u64,
) -> Result<(), DwnError> {
    if expected_data_cid != actual_data_cid {
        return Err(DwnError::new(
            DwnErrorCode::RecordsWriteDataCidMismatch,
            format!("actual data CID {actual_data_cid} does not match dataCid in descriptor: {expected_data_cid}"),
        ));
    }
    if expected_data_size != actual_data_size {
        return Err(DwnError::new(
            DwnErrorCode::RecordsWriteDataSizeMismatch,
            format!("actual data size {actual_data_size} bytes does not match dataSize in descriptor: {expected_data_size}"),
        ));
    }
    Ok(())
}

pub(crate) fn encoded_data_bytes(message: &Message<Descriptor>) -> Result<Option<Bytes>, String> {
    write_fields(message)
        .map_err(|error| error.to_string())?
        .encoded_data
        .as_ref()
        .map(|encoded| {
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map(Bytes::from)
                .map_err(|err| format!("RecordsWriteEncodedDataInvalid: {err}"))
        })
        .transpose()
}

pub(crate) fn set_encoded_data(
    message: &mut Message<Descriptor>,
    encoded_data: Option<String>,
) -> Result<(), String> {
    write_fields_mut(message)
        .map_err(|error| error.to_string())?
        .encoded_data = encoded_data;
    Ok(())
}

pub(crate) fn records_write_indexes(
    message: &Message<Descriptor>,
    author: &str,
    is_latest_base_state: bool,
) -> Result<KeyValues, String> {
    let descriptor = records_write_descriptor(message)?;
    let mut indexes = descriptor_indexes(descriptor)?;
    indexes.remove("tags");
    indexes.insert(
        "isLatestBaseState".to_string(),
        Value::Bool(is_latest_base_state),
    );
    indexes.insert(
        "published".to_string(),
        Value::Bool(descriptor.published.unwrap_or(false)),
    );
    indexes.insert(
        "squash".to_string(),
        Value::Bool(descriptor.squash.unwrap_or(false)),
    );
    indexes.insert("author".to_string(), Value::String(author.to_string()));
    let record_id = record_id(message)
        .ok_or_else(|| "RecordsWriteMissingRecordId: recordId is required".to_string())?;
    indexes.insert("recordId".to_string(), Value::String(record_id));
    indexes.insert(
        "entryId".to_string(),
        Value::String(entry_id(author, descriptor)?),
    );
    if let Some(context_id) = context_id(message) {
        indexes.insert("contextId".to_string(), Value::String(context_id));
    }
    if is_latest_base_state {
        if let Some(tags) = &descriptor.tags {
            for (key, value) in tags {
                indexes.insert(format!("tag.{key}"), value.clone());
            }
        }
    }
    Ok(indexes)
}

pub(crate) fn records_delete_indexes(
    message: &Message<Descriptor>,
    initial_write: &Message<Descriptor>,
    author: &str,
) -> Result<KeyValues, String> {
    let descriptor = records_delete_descriptor(message)?;
    let initial = records_write_descriptor(initial_write)?;
    let mut indexes = descriptor_indexes(descriptor)?;
    indexes.insert("isLatestBaseState".to_string(), Value::Bool(true));
    indexes.insert("author".to_string(), Value::String(author.to_string()));
    indexes.insert("module".to_string(), Value::String(initial.module.clone()));
    indexes.insert(
        "modulePath".to_string(),
        Value::String(initial.module_path.clone()),
    );
    if let Some(recipient) = &initial.recipient {
        indexes.insert("recipient".to_string(), Value::String(recipient.clone()));
    }
    if let Some(schema) = &initial.schema {
        indexes.insert("schema".to_string(), Value::String(schema.clone()));
    }
    if let Some(parent_id) = &initial.parent_id {
        indexes.insert("parentId".to_string(), Value::String(parent_id.clone()));
    }
    indexes.insert(
        "dateCreated".to_string(),
        Value::String(canonical_rfc3339(initial.date_created).to_string()),
    );
    if let Some(context_id) = context_id(initial_write) {
        indexes.insert("contextId".to_string(), Value::String(context_id));
    }
    Ok(indexes)
}

pub(crate) fn descriptor_indexes<T: serde::Serialize>(descriptor: &T) -> Result<KeyValues, String> {
    let descriptor = serde_json::to_value(descriptor).map_err(|err| err.to_string())?;
    let object = descriptor
        .as_object()
        .ok_or_else(|| "DescriptorIndexInvalid: descriptor must be an object".to_string())?;
    Ok(object
        .iter()
        .filter_map(|(key, value)| json_to_index_value(value).map(|value| (key.clone(), value)))
        .collect())
}

pub(crate) fn json_to_index_value(value: &JsonValue) -> Option<Value> {
    match value {
        JsonValue::Null => None,
        JsonValue::Bool(value) => Some(Value::Bool(*value)),
        JsonValue::Number(value) => value
            .as_i64()
            .map(Value::Number)
            .or_else(|| value.as_u64().map(|value| Value::Number(value as i64)))
            .or_else(|| value.as_f64().map(Value::Float)),
        JsonValue::String(value) => Some(Value::String(value.clone())),
        JsonValue::Array(values) => Some(Value::Array(
            values.iter().filter_map(json_to_index_value).collect(),
        )),
        JsonValue::Object(values) => Some(Value::Map(
            values
                .iter()
                .filter_map(|(key, value)| {
                    json_to_index_value(value).map(|value| (key.clone(), value))
                })
                .collect(),
        )),
    }
}

pub(crate) fn records_filter_to_filter_map(
    filter: &RecordsFilter,
    date_sort: Option<&crate::descriptors::records::DateSort>,
) -> BTreeMap<FilterKey, Filter<Value>> {
    let mut map = BTreeMap::new();
    insert_string_vec_filter(&mut map, "author", filter.author.as_ref());
    insert_string_filter(&mut map, "attester", filter.attester.as_ref());
    insert_string_vec_filter(&mut map, "recipient", filter.recipient.as_ref());
    insert_string_filter(&mut map, "module", filter.module.as_ref());
    insert_string_filter(&mut map, "modulePath", filter.module_path.as_ref());
    insert_bool_filter(&mut map, "published", filter.published);
    insert_string_filter(&mut map, "schema", filter.schema.as_ref());
    insert_string_filter(&mut map, "recordId", filter.record_id.as_ref());
    insert_string_filter(&mut map, "parentId", filter.parent_id.as_ref());
    insert_string_filter(&mut map, "dataFormat", filter.data_format.as_ref());
    if let Some(context_id) = &filter.context_id {
        map.insert(
            FilterKey::Index("contextId".to_string()),
            Filter::Subtree(SubtreeFilter {
                subtree: context_id.clone(),
            }),
        );
    }
    if let Some(data_cid) = &filter.data_cid {
        map.insert(
            FilterKey::Index("dataCid".to_string()),
            Filter::Equal(Value::String(data_cid.to_string())),
        );
    }
    if let Some(data_size) = &filter.data_size {
        map.insert(
            FilterKey::Index("dataSize".to_string()),
            range_u64_filter(data_size),
        );
    }
    if let Some(date_created) = &filter.date_created {
        map.insert(
            FilterKey::Index("dateCreated".to_string()),
            range_string_filter(date_created),
        );
    }
    if let Some(date_published) = &filter.date_published {
        map.insert(FilterKey::Index("published".to_string()), bool_filter(true));
        map.insert(
            FilterKey::Index("datePublished".to_string()),
            range_string_filter(date_published),
        );
    }
    if let Some(date_updated) = &filter.date_updated {
        map.insert(
            FilterKey::Index("messageTimestamp".to_string()),
            range_string_filter(date_updated),
        );
    }
    if filter.published != Some(true)
        && matches!(
            date_sort,
            Some(crate::descriptors::records::DateSort::PublishedAscending)
                | Some(crate::descriptors::records::DateSort::PublishedDescending)
        )
    {
        map.insert(FilterKey::Index("published".to_string()), bool_filter(true));
    }
    if let Some(tags) = &filter.tags {
        for (key, value) in tags {
            map.insert(FilterKey::Index(format!("tag.{key}")), value.clone());
        }
    }
    map
}

pub(crate) fn insert_string_filter(
    map: &mut BTreeMap<FilterKey, Filter<Value>>,
    key: &str,
    value: Option<&String>,
) {
    if let Some(value) = value {
        map.insert(FilterKey::Index(key.to_string()), string_filter(value));
    }
}

pub(crate) fn insert_bool_filter(
    map: &mut BTreeMap<FilterKey, Filter<Value>>,
    key: &str,
    value: Option<bool>,
) {
    if let Some(value) = value {
        map.insert(FilterKey::Index(key.to_string()), bool_filter(value));
    }
}

pub(crate) fn insert_string_vec_filter(
    map: &mut BTreeMap<FilterKey, Filter<Value>>,
    key: &str,
    value: Option<&Vec<String>>,
) {
    let Some(values) = value else {
        return;
    };
    if values.is_empty() {
        return;
    }
    let filter = if values.len() == 1 {
        string_filter(&values[0])
    } else {
        Filter::OneOf(values.iter().cloned().map(Value::String).collect())
    };
    map.insert(FilterKey::Index(key.to_string()), filter);
}

pub(crate) fn range_u64_filter(range: &RangeFilter<u64>) -> Filter<Value> {
    Filter::Range(match range {
        RangeFilter::Numeric(lower, upper) => {
            RangeFilter::Numeric(bound_u64_to_value(lower), bound_u64_to_value(upper))
        }
        RangeFilter::Criterion(lower, upper) => {
            RangeFilter::Criterion(bound_u64_to_value(lower), bound_u64_to_value(upper))
        }
    })
}

pub(crate) fn range_string_filter(range: &RangeFilter<String>) -> Filter<Value> {
    Filter::Range(match range {
        RangeFilter::Numeric(lower, upper) => {
            RangeFilter::Numeric(bound_string_to_value(lower), bound_string_to_value(upper))
        }
        RangeFilter::Criterion(lower, upper) => {
            RangeFilter::Criterion(bound_string_to_value(lower), bound_string_to_value(upper))
        }
    })
}

pub(crate) fn bound_u64_to_value(bound: &Bound<u64>) -> Bound<Value> {
    match bound {
        Bound::Included(value) => Bound::Included(Value::Number(*value as i64)),
        Bound::Excluded(value) => Bound::Excluded(Value::Number(*value as i64)),
        Bound::Unbounded => Bound::Unbounded,
    }
}

pub(crate) fn bound_string_to_value(bound: &Bound<String>) -> Bound<Value> {
    match bound {
        Bound::Included(value) => Bound::Included(Value::String(value.clone())),
        Bound::Excluded(value) => Bound::Excluded(Value::String(value.clone())),
        Bound::Unbounded => Bound::Unbounded,
    }
}

pub(crate) fn owner_records_filter(
    filter: &RecordsFilter,
    date_sort: Option<&crate::descriptors::records::DateSort>,
) -> BTreeMap<FilterKey, Filter<Value>> {
    let mut map = records_filter_to_filter_map(filter, date_sort);
    map.insert(
        FilterKey::Index("interface".to_string()),
        string_filter(RECORDS_INTERFACE),
    );
    map.insert(
        FilterKey::Index("method".to_string()),
        string_filter(WRITE_METHOD),
    );
    map.insert(
        FilterKey::Index("isLatestBaseState".to_string()),
        bool_filter(true),
    );
    map
}

pub(crate) fn owner_records_event_filter(
    filter: &RecordsFilter,
) -> BTreeMap<FilterKey, Filter<Value>> {
    let mut map = records_filter_to_filter_map(filter, None);
    map.insert(
        FilterKey::Index("interface".to_string()),
        string_filter(RECORDS_INTERFACE),
    );
    map.insert(
        FilterKey::Index("method".to_string()),
        Filter::OneOf(vec![
            Value::String(WRITE_METHOD.to_string()),
            Value::String("Delete".to_string()),
        ]),
    );
    map
}

pub(crate) fn published_records_filter(
    filter: &RecordsFilter,
    date_sort: Option<&crate::descriptors::records::DateSort>,
) -> BTreeMap<FilterKey, Filter<Value>> {
    let mut map = owner_records_filter(filter, date_sort);
    map.insert(FilterKey::Index("published".to_string()), bool_filter(true));
    map
}

pub(crate) fn published_records_event_filter(
    filter: &RecordsFilter,
) -> BTreeMap<FilterKey, Filter<Value>> {
    let mut map = owner_records_event_filter(filter);
    map.insert(FilterKey::Index("published".to_string()), bool_filter(true));
    map
}

pub(crate) fn non_owner_records_filters(
    filter: &RecordsFilter,
    date_sort: Option<&crate::descriptors::records::DateSort>,
    author: &str,
    module_authorized: bool,
    exact_audience: bool,
) -> Vec<BTreeMap<FilterKey, Filter<Value>>> {
    let mut filters = Vec::new();
    if filter_includes_published_records(filter) {
        filters.push(published_records_filter(filter, date_sort));
    }
    if filter_includes_unpublished_records(filter) {
        // An exactly pinned audience tuple names one role's directory, which
        // any authenticated requester may reach. It is its own candidate
        // branch rather than a relaxation of the others, so it widens nothing
        // else the requester could not already see.
        if exact_audience {
            let mut map = owner_records_filter(filter, date_sort);
            map.insert(
                FilterKey::Index("published".to_string()),
                bool_filter(false),
            );
            filters.push(map);
        }
        if should_build_author_filter(filter, author) {
            let mut map = owner_records_filter(filter, date_sort);
            map.insert(
                FilterKey::Index("author".to_string()),
                string_filter(author),
            );
            map.insert(
                FilterKey::Index("published".to_string()),
                bool_filter(false),
            );
            filters.push(map);
        }
        if module_authorized {
            let mut map = owner_records_filter(filter, date_sort);
            map.insert(
                FilterKey::Index("published".to_string()),
                bool_filter(false),
            );
            filters.push(map);
        }
        if should_build_recipient_filter(filter, author) {
            let mut map = owner_records_filter(filter, date_sort);
            map.insert(
                FilterKey::Index("recipient".to_string()),
                string_filter(author),
            );
            map.insert(
                FilterKey::Index("published".to_string()),
                bool_filter(false),
            );
            filters.push(map);
        }
    }
    filters
}

pub(crate) fn non_owner_records_event_filters(
    filter: &RecordsFilter,
    author: &str,
    module_authorized: bool,
    exact_audience: bool,
) -> Vec<BTreeMap<FilterKey, Filter<Value>>> {
    let mut filters = Vec::new();
    if filter_includes_published_records(filter) {
        filters.push(published_records_event_filter(filter));
    }
    if filter_includes_unpublished_records(filter) {
        if exact_audience {
            let mut map = owner_records_event_filter(filter);
            map.insert(
                FilterKey::Index("published".to_string()),
                bool_filter(false),
            );
            filters.push(map);
        }
        if should_build_author_filter(filter, author) {
            let mut map = owner_records_event_filter(filter);
            map.insert(
                FilterKey::Index("author".to_string()),
                string_filter(author),
            );
            map.insert(
                FilterKey::Index("published".to_string()),
                bool_filter(false),
            );
            filters.push(map);
        }
        if module_authorized {
            let mut map = owner_records_event_filter(filter);
            map.insert(
                FilterKey::Index("published".to_string()),
                bool_filter(false),
            );
            filters.push(map);
        }
        if should_build_recipient_filter(filter, author) {
            let mut map = owner_records_event_filter(filter);
            map.insert(
                FilterKey::Index("recipient".to_string()),
                string_filter(author),
            );
            map.insert(
                FilterKey::Index("published".to_string()),
                bool_filter(false),
            );
            filters.push(map);
        }
    }
    filters
}

pub(crate) fn filter_includes_published_records(filter: &RecordsFilter) -> bool {
    filter.date_published.is_some() || filter.published != Some(false)
}

pub(crate) fn filter_includes_unpublished_records(filter: &RecordsFilter) -> bool {
    if filter.date_published.is_none() && filter.published.is_none() {
        return true;
    }
    filter.published == Some(false)
}

pub(crate) fn should_build_author_filter(filter: &RecordsFilter, author: &str) -> bool {
    filter
        .author
        .as_ref()
        .is_none_or(|authors| authors.is_empty() || authors.iter().any(|value| value == author))
}

pub(crate) fn should_build_recipient_filter(filter: &RecordsFilter, recipient: &str) -> bool {
    filter.recipient.as_ref().is_none_or(|recipients| {
        recipients.is_empty() || recipients.iter().any(|value| value == recipient)
    })
}

pub(crate) fn should_module_authorize(ctx: &AuthorizationContext) -> bool {
    ctx.payload.module_role().is_some()
}

/// Names the published sort when one is requested, for the parse-time rule
/// rejecting `published:false` combined with a published sort. The wire code
/// stays with each calling handler.
pub(crate) fn published_sort_name(
    date_sort: &Option<crate::descriptors::records::DateSort>,
) -> Option<&'static str> {
    match date_sort {
        Some(crate::descriptors::records::DateSort::PublishedAscending) => {
            Some("PublishedAscending")
        }
        Some(crate::descriptors::records::DateSort::PublishedDescending) => {
            Some("PublishedDescending")
        }
        _ => None,
    }
}

/// Reads the `$recordLimit` max governing a module path at the request
/// timestamp, with the resolved physical depth that scopes occupancy. A
/// missing module or absent rule means no restriction; any other failure is an
/// error, never unrestricted visibility.
async fn record_limit_policy<MessageStore>(
    tenant: &str,
    module: &str,
    module_path: &str,
    message_store: &MessageStore,
    request_timestamp: &str,
) -> Result<Option<(u64, usize)>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let definition =
        match fetch_module_definition(tenant, module, message_store, Some(request_timestamp)).await
        {
            Ok(definition) => definition,
            Err(ModuleDefinitionLookupError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
    let graph = crate::handlers::records::policy::load_definition_graph(
        definition,
        tenant,
        message_store,
        Some(request_timestamp),
    )
    .await
    .map_err(|error| error.to_string())?;
    let Some(node) = graph.record_node(module_path) else {
        return Ok(None);
    };
    Ok(node
        .rule_set
        .record_limit
        .as_ref()
        .map(|rule| (rule.max, node.physical_depth)))
}

/// Derives the read-time occupancy policy for a collection filter, mirroring
/// the upstream scope selection: root paths carry no scope, `parentId`
/// passes through, and a `contextId` at target depth contributes its direct
/// parent while deeper selections scope the subtree itself.
pub(crate) async fn resolve_record_limit_policy<MessageStore>(
    tenant: &str,
    filter: &RecordsFilter,
    message_store: &MessageStore,
    request_timestamp: &str,
) -> Result<Option<RecordLimitOccupancy>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let (Some(module), Some(module_path)) =
        (filter.module.as_deref(), filter.module_path.as_deref())
    else {
        return Ok(None);
    };
    let Some((max, physical_depth)) = record_limit_policy(
        tenant,
        module,
        module_path,
        message_store,
        request_timestamp,
    )
    .await?
    else {
        return Ok(None);
    };
    let mut policy = RecordLimitOccupancy {
        module: module.to_string(),
        module_path: module_path.to_string(),
        context_id: None,
        parent_id: None,
        max,
    };
    // Root paths carry no occupancy scope; nested paths group by physical
    // direct-parent context rather than declared path depth.
    if physical_depth == 1 {
        return Ok(Some(policy));
    }
    if let Some(parent_id) = filter.parent_id.as_deref() {
        policy.parent_id = Some(vec![parent_id.to_string()]);
    }
    let Some(context_id) = filter.context_id.as_deref() else {
        return Ok(Some(policy));
    };
    // A context at target depth selects its direct parent (which still has at
    // least one segment on a nested path); deeper selections scope the
    // subtree itself.
    let context_depth = context_id.split('/').count();
    policy.context_id = Some(if context_depth == physical_depth {
        parent_context_id(context_id).unwrap_or_default()
    } else {
        context_id.to_string()
    });
    Ok(Some(policy))
}

/// Derives the occupancy policy for one matched write, as the read
/// top-1 membership check requires. Root records carry no scope; nested
/// records contribute their direct-parent context so siblings consume slots.
pub(crate) async fn message_record_limit_policy<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
    request_timestamp: &str,
) -> Result<Option<RecordLimitOccupancy>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor = records_write_descriptor(message).map_err(|detail| detail.to_string())?;
    let Some((max, physical_depth)) = record_limit_policy(
        tenant,
        &descriptor.module,
        &descriptor.module_path,
        message_store,
        request_timestamp,
    )
    .await?
    else {
        return Ok(None);
    };
    let mut policy = RecordLimitOccupancy {
        module: descriptor.module.clone(),
        module_path: descriptor.module_path.clone(),
        context_id: None,
        parent_id: None,
        max,
    };
    if physical_depth == 1 {
        return Ok(Some(policy));
    }
    if let Some(context_id) = context_id(message) {
        let parent = parent_context_id(&context_id).unwrap_or_default();
        if !parent.is_empty() {
            policy.context_id = Some(parent);
        }
    }
    Ok(Some(policy))
}

pub(crate) fn date_sort_to_message_sort(
    date_sort: Option<&crate::descriptors::records::DateSort>,
    read_default: bool,
) -> MessageSort {
    match date_sort {
        Some(crate::descriptors::records::DateSort::CreatedAscending) => {
            MessageSort::DateCreated(SortDirection::Ascending)
        }
        Some(crate::descriptors::records::DateSort::CreatedDescending) => {
            MessageSort::DateCreated(SortDirection::Descending)
        }
        Some(crate::descriptors::records::DateSort::PublishedAscending) => {
            MessageSort::DatePublished(SortDirection::Ascending)
        }
        Some(crate::descriptors::records::DateSort::PublishedDescending) => {
            MessageSort::DatePublished(SortDirection::Descending)
        }
        Some(crate::descriptors::records::DateSort::UpdatedAscending) => {
            MessageSort::Timestamp(SortDirection::Ascending)
        }
        Some(crate::descriptors::records::DateSort::UpdatedDescending) => {
            MessageSort::Timestamp(SortDirection::Descending)
        }
        None if read_default => MessageSort::Timestamp(SortDirection::Descending),
        None => MessageSort::DateCreated(SortDirection::Ascending),
    }
}

pub(crate) async fn authorize_records_read<MessageStore>(
    tenant: &str,
    read_message: &Message<Descriptor>,
    signature: Option<&AuthorizationContext>,
    matched_records_write: &Message<Descriptor>,
    message_store: &MessageStore,
) -> Result<(), ModuleAuthorizationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor = records_write_descriptor(matched_records_write)
        .map_err(|error| ModuleAuthorizationError::internal(error.to_string()))?;
    if signature.map(|signature| signature.author.as_str()) == Some(tenant)
        || descriptor.published == Some(true)
    {
        return Ok(());
    }
    if let Some(signature) = signature {
        if descriptor.recipient.as_deref() == Some(signature.author.as_str())
            || extract_author(matched_records_write).as_deref() == Some(signature.author.as_str())
        {
            return Ok(());
        }
        if permissions::authorize_records_read_with_grant(
            tenant,
            read_message,
            matched_records_write,
            signature,
            message_store,
        )
        .await
        .map_err(grant_authorization_error)?
        {
            return Ok(());
        }
        let evaluation_timestamp = canonical_rfc3339(read_message.message_timestamp());
        return authorize_against_module(
            tenant,
            matched_records_write,
            signature,
            RecordsAuthorizationKind::Read,
            Some(&evaluation_timestamp),
            message_store,
        )
        .await;
    }
    Err(DwnError::new(
        DwnErrorCode::ModuleAuthorizationActionNotAllowed,
        "anonymous read is not authorized",
    )
    .into())
}

/// A grant failure is a denial only for the classified scope, validity, and
/// authority outcomes; anything else means the grant machinery could not
/// decide, which says nothing about authority and must propagate.
fn grant_authorization_error(
    error: permissions::errors::PermissionError,
) -> ModuleAuthorizationError {
    use permissions::errors::{
        AuthorizationRequestError, AuthorizationValidationError, GrantError, PermissionError,
    };
    let detail = error.to_string();
    match &error {
        PermissionError::InvalidGrant(
            GrantError::NotFound(_)
            | GrantError::NotActive
            | GrantError::Expired
            | GrantError::Revoked
            | GrantError::OutsideScope
            | GrantError::Unauthorized
            | GrantError::InvalidScopeForTarget(..),
        )
        | PermissionError::AuthorizationValidationError(
            AuthorizationValidationError::UnexpectedGrantee(..)
            | AuthorizationValidationError::UnexpectedGrantor(..)
            | AuthorizationValidationError::BadRequest(
                AuthorizationRequestError::GrantScopeMismatch(..),
            ),
        ) => ModuleAuthorizationError::Detail(detail),
        _ => ModuleAuthorizationError::internal(detail),
    }
}

pub(crate) async fn authorize_records_delete<MessageStore>(
    tenant: &str,
    delete_message: &Message<Descriptor>,
    initial_write: &Message<Descriptor>,
    signature: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<(), ModuleAuthorizationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if permissions::authorize_records_delete_with_grant(
        tenant,
        delete_message,
        initial_write,
        signature,
        message_store,
    )
    .await
    .map_err(|error| error.to_string())?
    {
        return Ok(());
    }
    if signature.author == tenant {
        return Ok(());
    }
    let prune = records_delete_descriptor(delete_message)?.prune;
    let evaluation_timestamp = canonical_rfc3339(delete_message.message_timestamp());
    authorize_against_module(
        tenant,
        initial_write,
        signature,
        RecordsAuthorizationKind::Delete { prune },
        Some(&evaluation_timestamp),
        message_store,
    )
    .await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedModuleRole {
    pub module: String,
    pub module_path: String,
    pub context_id_prefix: Option<String>,
    pub role_record_id: String,
}

/// A module-authorization failure. `Code` carries a stable [`DwnErrorCode`],
/// `Detail` an action-rule rejection, and `Internal` an operational failure
/// (store, parse, or unexpected) that proves nothing about the requester's
/// authority.
#[derive(Debug)]
pub(crate) enum ModuleAuthorizationError {
    Code(DwnError),
    Detail(String),
    Internal(String),
}

impl From<DwnError> for ModuleAuthorizationError {
    fn from(error: DwnError) -> Self {
        Self::Code(error)
    }
}

impl From<String> for ModuleAuthorizationError {
    fn from(detail: String) -> Self {
        Self::Detail(detail)
    }
}

impl std::fmt::Display for ModuleAuthorizationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code(error) => error.fmt(formatter),
            Self::Detail(detail) | Self::Internal(detail) => formatter.write_str(detail),
        }
    }
}

impl ModuleAuthorizationError {
    pub(crate) fn internal(detail: impl Into<String>) -> Self {
        Self::Internal(detail.into())
    }

    /// Whether the failure is a classified authorization denial, which hides a
    /// candidate, rather than a failure that proves nothing about authority and
    /// must propagate. Only the codes upstream classifies as denials hide a
    /// candidate, so a code added later fails closed until it is classified.
    pub(crate) fn is_denial(&self) -> bool {
        match self {
            Self::Detail(_) => true,
            Self::Internal(_) => false,
            Self::Code(error) => matches!(
                error.code,
                DwnErrorCode::EncryptionControlReadUnauthorized
                    | DwnErrorCode::ModuleAuthorizationActionNotAllowed
                    | DwnErrorCode::ModuleAuthorizationActionRulesNotFound
                    | DwnErrorCode::ModuleAuthorizationMatchingRoleRecordNotFound
                    | DwnErrorCode::ModuleAuthorizationMissingContextId
                    | DwnErrorCode::ModuleAuthorizationNotARole
            ),
        }
    }

    /// The HTTP 401 status carrying the stable code when one is present.
    pub(crate) fn into_status(self) -> Status {
        match self {
            Self::Code(error) => Status::from_error(401, error),
            Self::Detail(detail) => Status::new(401, detail),
            Self::Internal(detail) => Status::new(500, detail),
        }
    }
}

/// Verifies the role named by `moduleRole` and returns its resolved address.
///
/// The invoked role resolves in the target module's lexical namespace through
/// the dependency graph. Its audience context comes from the resolved physical
/// parent depth, and `author` must hold an active role record for the owning
/// module path in that context.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_invoked_role<MessageStore>(
    tenant: &str,
    author: &str,
    invoked_role: Option<&str>,
    graph: &ResolvedModuleGraph,
    context_id: Option<&str>,
    message_store: &MessageStore,
) -> Result<Option<ResolvedModuleRole>, ModuleAuthorizationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(invoked_role) = invoked_role else {
        return Ok(None);
    };

    let role = graph.resolve_invoked_role(invoked_role).map_err(|error| {
        ModuleAuthorizationError::Code(DwnError::new(
            DwnErrorCode::ModuleAuthorizationNotARole,
            format!("module path '{invoked_role}' does not resolve to a role record: {error}"),
        ))
    })?;

    let Some(audience_context) = role_audience_context_id(role.parent_physical_depth, context_id)
    else {
        return Err(DwnError::new(
            DwnErrorCode::ModuleAuthorizationMissingContextId,
            format!(
                "could not verify role '{invoked_role}' because contextId is missing or too shallow"
            ),
        )
        .into());
    };

    let role_record = query_role_records(
        tenant,
        author,
        &role.owning_module_uri,
        &role.owning_module_path,
        &audience_context,
        message_store,
    )
    .await
    .map_err(ModuleAuthorizationError::internal)?;
    let Some(role_record) = role_record else {
        return Err(DwnError::new(
            DwnErrorCode::ModuleAuthorizationMatchingRoleRecordNotFound,
            format!(
                "no matching role record found for module path '{}'",
                role.owning_module_path
            ),
        )
        .into());
    };

    Ok(Some(ResolvedModuleRole {
        module: role.owning_module_uri.clone(),
        module_path: role.owning_module_path.clone(),
        context_id_prefix: (!audience_context.is_empty()).then_some(audience_context),
        role_record_id: record_id(&role_record).unwrap_or_default(),
    }))
}

/// Authorizes a role-invoking collection filter against the module graph
/// governing `request_timestamp` (`DWN-PROTO-004`), never blindly the newest
/// configuration. Every lookup failure denies: a missing definition cannot
/// prove role authority.
pub(crate) async fn authorize_module_query_or_subscribe<MessageStore>(
    tenant: &str,
    filter: &RecordsFilter,
    auth_ctx: &AuthorizationContext,
    message_store: &MessageStore,
    request_timestamp: &str,
    kind: RecordsAuthorizationKind,
) -> Result<ResolvedModuleRole, ModuleAuthorizationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let module = filter.module.as_deref().ok_or_else(|| {
        "ModuleAuthorizationMissingModule: role-authorized query must include module".to_string()
    })?;
    let module_path = filter.module_path.as_deref().ok_or_else(|| {
        "ModuleAuthorizationMissingModulePath: role-authorized query must include modulePath"
            .to_string()
    })?;
    let definition = crate::handlers::modules::configure::fetch_module_definition(
        tenant,
        module,
        message_store,
        Some(request_timestamp),
    )
    .await
    .map_err(|err| err.to_string())?;
    let graph = crate::handlers::records::policy::load_definition_graph(
        definition,
        tenant,
        message_store,
        Some(request_timestamp),
    )
    .await
    .map_err(|err| err.to_string())?;

    let node = graph
        .record_node(module_path)
        .filter(|node| node.kind == ResolvedModuleNodeKind::Record)
        .ok_or_else(|| {
            DwnError::new(
                DwnErrorCode::ModuleAuthorizationMissingRuleSet,
                format!("no local record type defined for modulePath {module_path}"),
            )
        })?;

    let invoked_role = auth_ctx
        .module_role()
        .ok_or_else(|| "moduleRole is required".to_string())?;

    let can = match kind {
        RecordsAuthorizationKind::Subscribe => Can::Read,
        RecordsAuthorizationKind::Count | RecordsAuthorizationKind::Query => Can::Read,
        _ => Can::Read,
    };

    // Verify the invoked role before matching action rules, so a malformed or
    // unheld role is rejected even when no rule would have authorized it.
    let resolved = verify_invoked_role(
        tenant,
        &auth_ctx.author,
        Some(invoked_role),
        &graph,
        filter.context_id.as_deref(),
        message_store,
    )
    .await?
    .expect("invoked role is present");

    let invoked = graph.resolve_invoked_role(invoked_role).ok();
    let rule_allows = node.actions.iter().any(|action| {
        if !action.rule.can().contains(&can) {
            return false;
        }
        match &action.rule {
            Action::Role(_) => same_role_address(invoked.as_ref(), action.resolved_role.as_ref()),
            Action::Who(who) => who.who == Who::Anyone,
        }
    });
    if !rule_allows {
        return Err(DwnError::new(
            DwnErrorCode::ModuleAuthorizationActionNotAllowed,
            "no action rule allows the invoked role",
        )
        .into());
    }
    let _ = resolved;
    Ok(resolved)
}

fn same_role_address(
    left: Option<&ResolvedRoleReference>,
    right: Option<&ResolvedRoleReference>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            left.owning_module_uri == right.owning_module_uri
                && left.owning_module_path == right.owning_module_path
        }
        _ => false,
    }
}

pub(crate) async fn authorize_against_module<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    auth: &AuthorizationContext,
    kind: RecordsAuthorizationKind,
    evaluation_timestamp: Option<&str>,
    message_store: &MessageStore,
) -> Result<(), ModuleAuthorizationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let author = auth.author.as_str();
    let descriptor = records_write_descriptor(message)
        .map_err(|error| ModuleAuthorizationError::internal(error.to_string()))?;
    let module = descriptor.module.clone();
    let module_path = descriptor.module_path.clone();
    // Read and Delete evaluate at the operation's own timestamp; Write resolves
    // the governing timestamp from the record (initial write time for updates).
    let evaluation_timestamp = match evaluation_timestamp {
        Some(timestamp) => timestamp.to_string(),
        None => governing_timestamp(tenant, message, message_store, author)
            .await
            .map_err(|error| ModuleAuthorizationError::internal(error.to_string()))?,
    };
    let definition = fetch_module_definition(
        tenant,
        module.as_str(),
        message_store,
        Some(&evaluation_timestamp),
    )
    .await
    .map_err(|error| match error {
        ModuleDefinitionLookupError::NotFound(module) => {
            ModuleAuthorizationError::Code(DwnError::new(
                DwnErrorCode::ModuleAuthorizationModuleNotFound,
                format!("unable to find module definition for {module}"),
            ))
        }
        other => ModuleAuthorizationError::internal(other.to_string()),
    })?;
    let graph = crate::handlers::records::policy::load_definition_graph(
        definition,
        tenant,
        message_store,
        Some(&evaluation_timestamp),
    )
    .await
    .map_err(|err| ModuleAuthorizationError::internal(err.to_string()))?;

    let for_write = matches!(kind, RecordsAuthorizationKind::Write);
    let node = match graph.record_node(&module_path) {
        Some(node) if node.kind == ResolvedModuleNodeKind::Record => node,
        Some(_) => {
            let code = if for_write {
                DwnErrorCode::ModuleAuthorizationRefNodeWriteNotAllowed
            } else {
                DwnErrorCode::ModuleAuthorizationMissingRuleSet
            };
            return Err(DwnError::new(
                code,
                format!("modulePath '{module_path}' is a virtual reference, not a local record."),
            )
            .into());
        }
        None => {
            let code = if for_write {
                DwnErrorCode::ModuleAuthorizationInvalidType
            } else {
                DwnErrorCode::ModuleAuthorizationMissingRuleSet
            };
            return Err(DwnError::new(
                code,
                format!("no local record type defined for modulePath {module_path}"),
            )
            .into());
        }
    };

    let invoked_role = auth.module_role();
    if invoked_role.is_some() {
        verify_invoked_role(
            tenant,
            author,
            invoked_role,
            &graph,
            context_id(message).as_deref(),
            message_store,
        )
        .await?;
    }
    let chain = construct_record_chain(tenant, message, message_store)
        .await
        .map_err(ModuleAuthorizationError::internal)?;
    let actions =
        actions_for_message_kind(tenant, message, author, kind, &node.rule_set, message_store)
            .await?;
    authorize_actions(author, invoked_role, &graph, &actions, node, &chain)?;
    Ok(())
}

/// Matches the invoked rule against the node's declared actions.
pub(crate) fn authorize_actions(
    author: &str,
    invoked_role: Option<&str>,
    graph: &ResolvedModuleGraph,
    actions: &[Can],
    node: &ResolvedModuleNode,
    record_chain: &[Message<Descriptor>],
) -> Result<(), DwnError> {
    let invoked = invoked_role.and_then(|raw| graph.resolve_invoked_role(raw).ok());
    for action in &node.actions {
        if !action.rule.can().iter().any(|can| actions.contains(can)) {
            continue;
        }
        match &action.rule {
            Action::Who(who_rule) => {
                if who_rule.who == Who::Anyone {
                    return Ok(());
                }
                // An invoked role replaces actor selection: only an `anyone`
                // rule or an exactly matching `role` rule can authorize it.
                if invoked.is_some() {
                    continue;
                }
                match (&who_rule.who, &action.resolved_actor) {
                    (Who::Recipient, None) => {
                        if record_chain
                            .last()
                            .and_then(|message| records_write_descriptor(message).ok())
                            .and_then(|descriptor| descriptor.recipient.as_deref())
                            == Some(author)
                        {
                            return Ok(());
                        }
                    }
                    (_, Some(actor))
                        if actor_matches(author, &who_rule.who, actor, record_chain) =>
                    {
                        return Ok(());
                    }
                    _ => {}
                }
            }
            Action::Role(_) => {
                if same_role_address(invoked.as_ref(), action.resolved_role.as_ref()) {
                    return Ok(());
                }
            }
        }
    }
    Err(DwnError::new(
        DwnErrorCode::ModuleAuthorizationActionNotAllowed,
        format!("inbound message action for {author} is not allowed"),
    ))
}

/// Whether the record at the resolved actor's physical depth is the named
/// ancestor and satisfies the actor selector.
fn actor_matches(
    author: &str,
    who: &Who,
    actor: &ResolvedActorReference,
    record_chain: &[Message<Descriptor>],
) -> bool {
    let Some(index) = actor.physical_depth.checked_sub(1) else {
        return false;
    };
    let Some(record) = record_chain.get(index) else {
        return false;
    };
    let Ok(descriptor) = records_write_descriptor(record) else {
        return false;
    };
    if descriptor.module != actor.owning_module_uri
        || descriptor.module_path != actor.owning_module_path
    {
        return false;
    }
    match who {
        Who::Author => extract_author(record).as_deref() == Some(author),
        Who::Recipient => descriptor.recipient.as_deref() == Some(author),
        Who::Anyone => true,
    }
}

pub(crate) fn check_actor(
    author: &str,
    who: &Who,
    of: Option<&str>,
    record_chain: &[Message<Descriptor>],
    definition: Option<&Definition>,
) -> bool {
    let Some(of) = of else {
        return false;
    };
    let parsed_cross_ref = module_types::parse_cross_module_ref(of);
    record_chain.iter().any(|message| {
        let Ok(descriptor) = records_write_descriptor(message) else {
            return false;
        };
        let path_matches = if let Some(parsed) = parsed_cross_ref.as_ref() {
            definition
                .and_then(|definition| definition.uses.as_ref())
                .and_then(|uses| uses.get(parsed.alias))
                .is_some_and(|module| {
                    descriptor.module == *module && descriptor.module_path == parsed.module_path
                })
        } else {
            descriptor.module_path == of
        };
        if !path_matches {
            return false;
        }
        match who {
            Who::Author => extract_author(message).as_deref() == Some(author),
            Who::Recipient => descriptor.recipient.as_deref() == Some(author),
            Who::Anyone => true,
        }
    })
}

/// The retained, latest-state role record that gives `recipient` the role
/// `role_path` in `module`, scoped by the role-audience `audience_context`.
///
/// A root role has an empty audience context and applies tenant-wide; a nested
/// role is scoped by the ancestor context at its physical parent depth. The
/// caller resolves that context, so this lookup never defaults an unscoped
/// search that would match role holders in unrelated contexts.
pub(crate) async fn query_role_records<MessageStore>(
    tenant: &str,
    recipient: &str,
    module: &str,
    role_path: &str,
    audience_context: &str,
    message_store: &MessageStore,
) -> Result<Option<Message<Descriptor>>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let mut filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("method", string_filter(WRITE_METHOD)),
        ("module", string_filter(module)),
        ("modulePath", string_filter(role_path)),
        ("recipient", string_filter(recipient)),
        ("isLatestBaseState", bool_filter(true)),
    ]);
    if !audience_context.is_empty() {
        filter.insert(
            FilterKey::Index("contextId".to_string()),
            Filter::Subtree(SubtreeFilter {
                subtree: audience_context.to_string(),
            }),
        );
    }
    message_store
        .query(
            tenant,
            Filters::from(filter),
            None,
            Some(Pagination::with_limit(1)),
            None,
        )
        .await
        .map(|result| result.messages.into_iter().next())
        .map_err(|err| err.to_string())
}

/// Whether `recipient` holds `role_path` in `module`, within the resolved
/// audience context. See [`query_role_records`].
pub(crate) async fn role_record_exists<MessageStore>(
    tenant: &str,
    recipient: &str,
    module: &str,
    role_path: &str,
    audience_context: &str,
    message_store: &MessageStore,
) -> Result<bool, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    query_role_records(
        tenant,
        recipient,
        module,
        role_path,
        audience_context,
        message_store,
    )
    .await
    .map(|record| record.is_some())
}

pub(crate) async fn actions_for_message_kind<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    author: &str,
    kind: RecordsAuthorizationKind,
    rule_set: &RuleSet,
    message_store: &MessageStore,
) -> Result<Vec<Can>, ModuleAuthorizationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    match kind {
        RecordsAuthorizationKind::Write => {
            if is_initial_write(message, author).map_err(ModuleAuthorizationError::internal)? {
                if rule_set.actions.is_empty() {
                    return Err(DwnError::new(
                        DwnErrorCode::ModuleAuthorizationActionRulesNotFound,
                        format!("no action rule defined for initial write by author {author}"),
                    )
                    .into());
                }
                let squash = records_write_descriptor(message)
                    .map_err(|error| ModuleAuthorizationError::internal(error.to_string()))?
                    .squash
                    == Some(true);
                Ok(rule_set.initial_write_actions(squash))
            } else if let Some(record_id) = record_id(message) {
                let initial = fetch_initial_write_message(tenant, &record_id, message_store)
                    .await
                    .map_err(ModuleAuthorizationError::internal)?;
                if initial
                    .and_then(|message| extract_author(&message))
                    .as_deref()
                    == Some(author)
                {
                    Ok(vec![Can::CoUpdate, Can::Update])
                } else {
                    Ok(vec![Can::CoUpdate])
                }
            } else {
                Ok(Vec::new())
            }
        }
        RecordsAuthorizationKind::Read
        | RecordsAuthorizationKind::Query
        | RecordsAuthorizationKind::Count
        | RecordsAuthorizationKind::Subscribe => Ok(vec![Can::Read]),
        RecordsAuthorizationKind::Delete { prune } => {
            let mut actions = if prune {
                vec![Can::CoPrune]
            } else {
                vec![Can::CoDelete]
            };
            if let Some(record_id) = record_id(message).or_else(|| message_record_id(message)) {
                let initial = fetch_initial_write_message(tenant, &record_id, message_store)
                    .await
                    .map_err(ModuleAuthorizationError::internal)?;
                if initial
                    .and_then(|message| extract_author(&message))
                    .as_deref()
                    == Some(author)
                {
                    actions.push(if prune { Can::Prune } else { Can::Delete });
                }
            }
            Ok(actions)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum GoverningTimestampError {
    #[error(transparent)]
    Dwn(#[from] DwnError),
    #[error("{0}")]
    Detail(String),
}

impl From<String> for GoverningTimestampError {
    fn from(detail: String) -> Self {
        Self::Detail(detail)
    }
}

pub(crate) async fn governing_timestamp<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
    author: &str,
) -> Result<String, GoverningTimestampError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if is_initial_write(message, author)? {
        return Ok(canonical_rfc3339(message.message_timestamp()));
    }
    let record_id = record_id(message)
        .ok_or_else(|| "RecordsWriteMissingRecordId: recordId is required".to_string())?;
    let initial = fetch_initial_write_message(tenant, &record_id, message_store)
        .await?
        .ok_or_else(|| {
            DwnError::new(
                DwnErrorCode::RecordsWriteGetInitialWriteNotFound,
                "Initial write is not found.",
            )
        })?;
    Ok(canonical_rfc3339(initial.message_timestamp()))
}

pub(crate) async fn construct_record_chain<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
) -> Result<Vec<Message<Descriptor>>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let mut chain = Vec::new();
    let mut current = Some(message.clone());
    while let Some(record) = current {
        let parent_id = records_write_descriptor(&record)?.parent_id.clone();
        chain.push(record);
        current = match parent_id {
            Some(parent_id) => Some(fetch_newest_write(tenant, &parent_id, message_store).await?),
            None => None,
        };
    }
    chain.reverse();
    Ok(chain)
}

/// Per-message projection capability for read surfaces. Query, Subscribe,
pub(crate) async fn attach_initial_writes(
    tenant: &str,
    messages: Vec<Message<Descriptor>>,
    resolver: &dyn InitialWriteResolver,
) -> Result<Vec<QueryEntry>, EventLogError>
where
{
    let mut entries = Vec::new();

    for message in messages {
        let initial_write = resolver
            .resolve_initial_write(tenant, &message)
            .await?
            .map(Into::into);

        entries.push(QueryEntry {
            message,
            initial_write,
            encoded_data: None,
        });
    }

    Ok(entries)
}

pub(crate) async fn fetch_record_messages<MessageStore>(
    tenant: &str,
    record_id: &str,
    message_store: &MessageStore,
) -> Result<Vec<Message<Descriptor>>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("recordId", string_filter(record_id)),
    ]);
    message_store
        .query(tenant, Filters::from(filter), None, None, None)
        .await
        .map(|result| result.messages)
        .map_err(|err| err.to_string())
}

pub(crate) async fn fetch_newest_write<MessageStore>(
    tenant: &str,
    record_id: &str,
    message_store: &MessageStore,
) -> Result<Message<Descriptor>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("method", string_filter(WRITE_METHOD)),
        ("recordId", string_filter(record_id)),
    ]);
    let result = message_store
        .query(
            tenant,
            Filters::from(filter),
            Some(MessageSort::Timestamp(SortDirection::Descending)),
            Some(Pagination::with_limit(1)),
            None,
        )
        .await
        .map_err(|err| err.to_string())?;
    result
        .messages
        .into_iter()
        .next()
        .ok_or_else(|| "RecordsWriteGetNewestWriteRecordNotFound: record not found".to_string())
}

/// The retained initial write that proves `record_id` is an addressable parent
/// in `module`, unless that Record has been pruned.
///
/// Structural ancestry is the retained initial write, not current liveness. A
/// soft delete leaves the parent usable as an ancestor; an arbitrary later
/// write is not a substitute for the initial write. A `prune: true` delete
/// removes the parent as ancestry even though its initial write is retained.
pub(crate) async fn fetch_parent_record<MessageStore>(
    tenant: &str,
    record_id: &str,
    module: &str,
    message_store: &MessageStore,
) -> Result<Option<Message<Descriptor>>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if record_has_prune(tenant, record_id, message_store).await? {
        return Ok(None);
    }
    let Some(initial) = fetch_initial_write_message(tenant, record_id, message_store).await? else {
        return Ok(None);
    };
    let descriptor = records_write_descriptor(&initial).map_err(|error| error.to_string())?;
    if descriptor.module != module {
        return Ok(None);
    }
    Ok(Some(initial))
}

/// Whether `record_id` has a retained `prune: true` delete. Prune is the
/// explicit subtree-removal operation, so it removes the Record as structural
/// ancestry even though the initial write is retained. Prune evidence is
/// module-agnostic and tenant-scoped: a delete in another tenant supplies
/// none. Callers use this to classify a missing parent as terminal without
/// putting that distinction on the client-facing reply.
pub(crate) async fn record_has_prune<MessageStore>(
    tenant: &str,
    record_id: &str,
    message_store: &MessageStore,
) -> Result<bool, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let prune_filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("method", string_filter(crate::descriptors::DELETE)),
        ("recordId", string_filter(record_id)),
        ("prune", bool_filter(true)),
    ]);
    message_store
        .query(
            tenant,
            Filters::from(prune_filter),
            None,
            Some(Pagination::with_limit(1)),
            None,
        )
        .await
        .map(|result| !result.messages.is_empty())
        .map_err(|err| err.to_string())
}

pub(crate) async fn fetch_initial_write_message<MessageStore>(
    tenant: &str,
    record_id: &str,
    message_store: &MessageStore,
) -> Result<Option<Message<Descriptor>>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let filter = filter_map([("entryId", string_filter(record_id))]);
    message_store
        .query(
            tenant,
            Filters::from(filter),
            None,
            Some(Pagination::with_limit(1)),
            None,
        )
        .await
        .map(|result| result.messages.into_iter().next())
        .map_err(|err| err.to_string())
}

pub(crate) fn newest_message(messages: &[Message<Descriptor>]) -> Option<Message<Descriptor>> {
    messages.iter().cloned().max_by(compare_messages)
}

pub(crate) fn compare_messages(
    left: &Message<Descriptor>,
    right: &Message<Descriptor>,
) -> Ordering {
    // Every descriptor carries a timestamp, so comparison is total; callers
    // only ever pass record messages.
    left.message_timestamp()
        .cmp(&right.message_timestamp())
        .then_with(|| message_cid(left).ok().cmp(&message_cid(right).ok()))
}

pub(crate) fn message_cid(message: &Message<Descriptor>) -> Result<String, String> {
    message
        .cid()
        .map_err(|err| err.to_string())
        .map(|cid| cid.to_string())
}

pub(crate) fn extract_author(message: &Message<Descriptor>) -> Option<String> {
    permissions::message_author(message)
}

pub(crate) async fn delete_from_data_store_if_needed<DataStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    newest_message: &Message<Descriptor>,
    data_store: &DataStore,
) -> Result<(), String>
where
    DataStore: crate::stores::DataStore + Sync,
{
    let Ok(descriptor) = records_write_descriptor(message) else {
        return Ok(());
    };
    if descriptor.data_size <= MAX_ENCODED_DATA_SIZE {
        return Ok(());
    }
    if records_write_descriptor(newest_message)
        .ok()
        .is_some_and(|newest| newest.data_cid == descriptor.data_cid)
    {
        return Ok(());
    }
    if let Some(record_id) = record_id(message) {
        data_store
            .delete(tenant, &record_id, &descriptor.data_cid)
            .await
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

pub(crate) async fn purge_record_descendants<MessageStore, DataStore>(
    tenant: &str,
    record_id: &str,
    message_store: &MessageStore,
    data_store: &DataStore,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Sync,
    DataStore: crate::stores::DataStore + Sync,
{
    let filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("parentId", string_filter(record_id)),
    ]);
    let child_messages = message_store
        .query(tenant, Filters::from(filter), None, None, None)
        .await
        .map_err(|err| err.to_string())?
        .messages;
    let mut by_record = BTreeMap::<String, Vec<Message<Descriptor>>>::new();
    for message in child_messages {
        if let Some(record_id) = message_record_id(&message) {
            by_record.entry(record_id).or_default().push(message);
        }
    }
    for child_record_id in by_record.keys() {
        Box::pin(purge_record_descendants(
            tenant,
            child_record_id,
            message_store,
            data_store,
        ))
        .await?;
    }
    for messages in by_record.values() {
        purge_record_messages(tenant, messages, message_store, data_store).await?;
    }
    Ok(())
}

pub(crate) async fn purge_record_messages<MessageStore, DataStore>(
    tenant: &str,
    record_messages: &[Message<Descriptor>],
    message_store: &MessageStore,
    data_store: &DataStore,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Sync,
    DataStore: crate::stores::DataStore + Sync,
{
    if let Some(newest_write) = newest_message(
        &record_messages
            .iter()
            .filter(|message| records_write_descriptor(message).is_ok())
            .cloned()
            .collect::<Vec<_>>(),
    ) {
        if let (Some(record_id), Ok(descriptor)) = (
            record_id(&newest_write),
            records_write_descriptor(&newest_write),
        ) {
            data_store
                .delete(tenant, &record_id, &descriptor.data_cid)
                .await
                .map_err(|err| err.to_string())?;
        }
    }
    for message in record_messages {
        let cid = message_cid(message)?;
        message_store
            .delete(tenant, &cid)
            .await
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

pub(crate) fn parent_context_id(context_id: &str) -> Option<String> {
    context_id
        .rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .or_else(|| Some(String::new()))
}

pub(crate) fn string_filter(value: &str) -> Filter<Value> {
    Filter::Equal(Value::String(value.to_string()))
}

pub(crate) fn bool_filter(value: bool) -> Filter<Value> {
    Filter::Equal(Value::Bool(value))
}

pub(crate) fn filter_map<const N: usize>(
    items: [(&str, Filter<Value>); N],
) -> BTreeMap<FilterKey, Filter<Value>> {
    items
        .into_iter()
        .map(|(key, value)| (FilterKey::Index(key.to_string()), value))
        .collect()
}

pub(crate) fn core_module_error_reply<R: Default>(
    registry: &CoreModuleRegistry,
    detail: String,
) -> Response<R> {
    if registry.map_error_to_status_code(&detail) == Some(401) {
        Response::unauthorized(detail)
    } else {
        Response::bad_request(detail)
    }
}

pub(crate) fn store_error_reply<R: Default>(detail: impl Into<String>) -> Response<R> {
    Response {
        status: Status::new(500, detail),
        reply: R::default(),
    }
}

pub(crate) fn records_subscribe_reply(
    reply: Response<Subscribe>,
    subscription: Option<EventSubscription>,
) -> RecordsSubscribeReply {
    RecordsSubscribeReply {
        reply,
        subscription,
    }
}

pub(crate) fn event_log_error_reply<R>(error: EventLogError) -> Response<R>
where
    R: Default + HasProgressGapInfo,
{
    match error {
        EventLogError::ProgressGap(gap_info) => Response {
            status: Status::new(410, "Progress token gap"),
            reply: R::with_progress_gap_info(*gap_info),
        },
        other => Response::internal_error(other.to_string()),
    }
}

pub(crate) trait DescriptorMethod {
    fn interface(&self) -> &'static str;
    fn method(&self) -> &'static str;
}

impl DescriptorMethod for RecordsWriteDescriptor {
    fn interface(&self) -> &'static str {
        RECORDS_INTERFACE
    }

    fn method(&self) -> &'static str {
        WRITE_METHOD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::messages::modules::graph::resolve_module_graph;
    use crate::interfaces::messages::modules::{RuleSet, Type};
    use crate::stores::{memory::MemoryMessageStore, MessageQueryResult, MessageStore};
    use serde_json::json;

    const ROLE_TEST_TENANT: &str = "did:example:tenant";
    const ROLE_TEST_AUTHOR: &str = "did:example:alice";
    const ROLE_TEST_MODULE: &str = "https://example.com/module/chat";
    const ROLE_TEST_TIME: &str = "2025-01-01T00:00:00.000000Z";

    fn text_type() -> Type {
        Type {
            schema: None,
            data_formats: None,
            encryption_required: None,
        }
    }

    fn test_graph(definition: Definition, dependency: Option<Definition>) -> ResolvedModuleGraph {
        let lookup = move |uri: &str| {
            dependency
                .as_ref()
                .filter(|dependency| dependency.module == uri)
                .cloned()
        };
        resolve_module_graph(definition, &lookup, true).expect("test graph must resolve")
    }

    fn role_definition(uses: Option<BTreeMap<String, String>>) -> Definition {
        Definition {
            module: ROLE_TEST_MODULE.to_string(),
            published: false,
            uses,
            key_agreement: None,
            types: BTreeMap::from([
                ("thread".to_string(), text_type()),
                ("participant".to_string(), text_type()),
            ]),
            structure: BTreeMap::from([(
                "thread".to_string(),
                RuleSet {
                    rules: BTreeMap::from([(
                        "participant".to_string(),
                        RuleSet {
                            role: Some(true),
                            ..Default::default()
                        },
                    )]),
                    ..Default::default()
                },
            )]),
        }
    }

    async fn put_role_record(
        store: &MemoryMessageStore,
        module: &str,
        module_path: &str,
        context_id: &str,
        record_id: &str,
    ) -> String {
        let message: Message<Descriptor> = serde_json::from_value(json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "dateCreated": "2025-01-01T00:00:00.000000Z",
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 0,
                "dataFormat": "application/json",
                "module": module,
                "modulePath": module_path,
                "recipient": ROLE_TEST_AUTHOR
            },
            "recordId": record_id,
            "contextId": context_id
        }))
        .expect("role record must deserialize");

        let indexes = BTreeMap::from([
            (
                "interface".to_string(),
                Value::String(RECORDS_INTERFACE.to_string()),
            ),
            (
                "method".to_string(),
                Value::String(WRITE_METHOD.to_string()),
            ),
            ("module".to_string(), Value::String(module.to_string())),
            (
                "modulePath".to_string(),
                Value::String(module_path.to_string()),
            ),
            (
                "recipient".to_string(),
                Value::String(ROLE_TEST_AUTHOR.to_string()),
            ),
            ("isLatestBaseState".to_string(), Value::Bool(true)),
            (
                "messageTimestamp".to_string(),
                Value::String("2025-01-01T00:00:00.000000Z".to_string()),
            ),
            (
                "contextId".to_string(),
                Value::String(context_id.to_string()),
            ),
        ]);

        store
            .put(ROLE_TEST_TENANT, message.clone(), indexes)
            .await
            .expect("role record must be stored");
        message_cid(&message).expect("role record must have a CID")
    }

    #[tokio::test]
    async fn query_role_resolution_returns_active_ordinary_role_record() {
        let store = MemoryMessageStore::default();
        put_role_record(
            &store,
            ROLE_TEST_MODULE,
            "thread/participant",
            "thread-1",
            "role-record-1",
        )
        .await;
        let graph = test_graph(role_definition(None), None);

        let resolved = verify_invoked_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            Some("thread/participant"),
            &graph,
            Some("thread-1/message-1"),
            &store,
        )
        .await
        .expect("active role must authorize")
        .expect("invoked role must resolve");

        assert_eq!(resolved.module, ROLE_TEST_MODULE);
        assert_eq!(resolved.module_path, "thread/participant");
        assert_eq!(resolved.context_id_prefix.as_deref(), Some("thread-1"));
        assert_eq!(resolved.role_record_id, "role-record-1");
    }

    #[tokio::test]
    async fn query_role_resolution_rejects_missing_or_wrong_role() {
        let store = MemoryMessageStore::default();
        let graph = test_graph(role_definition(None), None);

        let missing_record = verify_invoked_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            Some("thread/participant"),
            &graph,
            Some("thread-1/message-1"),
            &store,
        )
        .await;
        assert!(missing_record.is_err());

        put_role_record(
            &store,
            ROLE_TEST_MODULE,
            "thread/participant",
            "thread-1",
            "role-record-1",
        )
        .await;

        let wrong_role = verify_invoked_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            Some("thread/moderator"),
            &graph,
            Some("thread-1/message-1"),
            &store,
        )
        .await;
        assert!(wrong_role.is_err());
    }

    #[tokio::test]
    async fn query_role_resolution_resolves_cross_module_role() {
        const ROLES_MODULE: &str = "https://example.com/module/roles";

        let store = MemoryMessageStore::default();
        put_role_record(
            &store,
            ROLES_MODULE,
            "team/member",
            "team-1",
            "cross-role-record",
        )
        .await;

        let roles_definition = Definition {
            module: ROLES_MODULE.to_string(),
            published: false,
            uses: None,
            key_agreement: None,
            types: BTreeMap::from([
                ("team".to_string(), text_type()),
                ("member".to_string(), text_type()),
            ]),
            structure: BTreeMap::from([(
                "team".to_string(),
                RuleSet {
                    rules: BTreeMap::from([(
                        "member".to_string(),
                        RuleSet {
                            role: Some(true),
                            ..Default::default()
                        },
                    )]),
                    ..Default::default()
                },
            )]),
        };
        crate::testing::put_module_definition(
            ROLE_TEST_TENANT,
            &store,
            roles_definition.clone(),
            ROLE_TEST_TIME,
        )
        .await;

        let definition = role_definition(Some(BTreeMap::from([(
            "roles".to_string(),
            ROLES_MODULE.to_string(),
        )])));
        let graph = test_graph(definition, Some(roles_definition));
        let resolved = verify_invoked_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            Some("roles:team/member"),
            &graph,
            Some("team-1/thread-1"),
            &store,
        )
        .await
        .expect("cross-module role must resolve")
        .expect("invoked role must resolve");

        assert_eq!(resolved.module, ROLES_MODULE);
        assert_eq!(resolved.module_path, "team/member");
        assert_eq!(resolved.role_record_id, "cross-role-record");
    }

    #[tokio::test]
    async fn query_role_resolution_rejects_unknown_cross_module_alias_and_sibling_context() {
        let store = MemoryMessageStore::default();
        put_role_record(
            &store,
            ROLE_TEST_MODULE,
            "thread/participant",
            "thread-1",
            "role-record-1",
        )
        .await;
        let graph = test_graph(role_definition(None), None);

        let unknown_alias = verify_invoked_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            Some("roles:team/member"),
            &graph,
            Some("team-1/thread-1"),
            &store,
        )
        .await;
        assert!(unknown_alias
            .expect_err("unknown alias must fail")
            .to_string()
            .contains("no alias 'roles'"));

        let sibling_context = verify_invoked_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            Some("thread/participant"),
            &graph,
            Some("thread-2/message-1"),
            &store,
        )
        .await;
        assert!(sibling_context.is_err());
    }

    fn encrypted_write_message(initialization_vector: &str) -> JsonValue {
        // Non-initial write: `recordId` differs from the entry ID so the
        // date-created/context-id initial-write checks are not exercised here.
        json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "dateCreated": "2025-01-01T00:00:00.000000Z",
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 38,
                "dataFormat": "text/plain",
                "module": "https://example.com/module/jwe",
                "modulePath": "thread/message"
            },
            "recordId": "some-non-initial-record-id",
            "contextId": "some-context-id",
            "encryption": {
                "algorithm": "A256CTR",
                "initializationVector": initialization_vector,
                "keyEncryption": [{
                    "algorithm": "X25519-HKDF-SHA256+A256KW",
                    "keyId": "Qae4_6ZxDDA_vn260RVhSSBbdzwqIE0b2eWfSC7o50Q",
                    "derivationScheme": "modulePath",
                    "ephemeralPublicKey": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
                    },
                    "encryptedKey": "KihbqckheDvgI4ZRJNu3el6L0dM8GLhXp_trR3P-vEpVs_pRpJbwjg"
                }]
            },
            "authorization": {
                "signature": {
                    "payload": "cGF5bG9hZA",
                    "signatures": [{
                        "protected": "eyJraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkxIiwiYWxnIjoiRWREU0EifQ",
                        "signature": "c2lnbmF0dXJl"
                    }]
                }
            }
        })
    }

    fn integrity_message(raw: &JsonValue) -> Message<Descriptor> {
        serde_json::from_value(raw.clone()).expect("message must deserialize")
    }

    #[test]
    fn records_write_integrity_validates_encryption_iv_length() {
        // 16-byte IV decodes to the required A256CTR counter block length.
        let ok = integrity_message(&encrypted_write_message("oKGio6SlpqeoqaqrrK2urw"));
        let signature = AuthorizationContext {
            signer: "did:example:alice".to_string(),
            author: "did:example:alice".to_string(),
            payload: crate::permissions::VerifiedAuthorizationPayload::RecordsWrite(
                crate::auth::jws::RecordsWriteAuthorizationPayloadData {
                    descriptor_cid: String::new(),
                    record_id: "some-non-initial-record-id".to_string(),
                    context_id: "some-context-id".to_string(),
                    attestation_cid: None,
                    encryption_cid: None,
                    permission_grant_id: None,
                    delegated_grant_id: None,
                    module_role: None,
                },
            ),
            permission_grant_invocation: crate::auth::jws::PermissionGrantInvocation::None,
            author_delegated_grant: None,
            owner: None,
        };
        validate_records_write_integrity(&ok, &signature).expect("16-byte IV must validate");

        // 15-byte IV must be rejected at integrity time with the upstream code.
        let short_iv = integrity_message(&encrypted_write_message("AAECAwQFBgcICQoLDA0O"));
        let error = validate_records_write_integrity(&short_iv, &signature)
            .expect_err("must reject 15-byte IV");
        assert!(
            error.starts_with("RecordsWriteValidateIntegrityEncryptionInitializationVectorInvalid"),
            "unexpected error: {error}"
        );
    }

    // Covers: DWN-PROTO-001, DWN-PROTO-002
    #[test]
    fn records_filter_converts_context_id_to_boundary_aware_subtree() {
        let filter = RecordsFilter {
            context_id: Some("a/b".to_string()),
            ..Default::default()
        };
        let map = records_filter_to_filter_map(&filter, None);
        assert_eq!(
            map.get(&FilterKey::Index("contextId".to_string())),
            Some(&Filter::Subtree(SubtreeFilter {
                subtree: "a/b".to_string(),
            })),
            "contextId must use boundary-aware subtree matching, never a raw lexical prefix"
        );
    }

    const HISTORY_T1: &str = "2025-01-01T00:00:00.000000Z";
    const HISTORY_T2: &str = "2025-01-01T00:10:00.000000Z";
    const HISTORY_MID: &str = "2025-01-01T00:05:00.000000Z";
    const HISTORY_LATE: &str = "2025-01-01T00:20:00.000000Z";
    const HISTORY_EARLY: &str = "2024-01-01T00:00:00.000000Z";

    fn history_configure_message(timestamp: &str, participant_read: bool) -> Message<Descriptor> {
        let participant = if participant_read {
            json!({
                "$role": true,
                "$actions": [{"role": "thread/participant", "can": ["read"]}]
            })
        } else {
            json!({})
        };
        serde_json::from_value(json!({
            "descriptor": {
                "interface": "Modules",
                "method": "Configure",
                "messageTimestamp": timestamp,
                "definition": {
                    "module": ROLE_TEST_MODULE,
                    "published": participant_read,
                    "types": { "thread": {}, "participant": {} },
                    "structure": { "thread": { "participant": participant } }
                }
            }
        }))
        .expect("configure message must deserialize")
    }

    async fn put_history_configure(
        store: &MemoryMessageStore,
        timestamp: &str,
        participant_read: bool,
    ) {
        let message = history_configure_message(timestamp, participant_read);
        let is_configure = matches!(
            &message.descriptor,
            Descriptor::Modules(modules)
                if matches!(modules.as_ref(), crate::descriptors::Modules::Configure(_))
        );
        assert!(is_configure, "seeded message must be a ModulesConfigure");
        let indexes = BTreeMap::from([
            (
                "interface".to_string(),
                Value::String("Modules".to_string()),
            ),
            ("method".to_string(), Value::String("Configure".to_string())),
            (
                "messageTimestamp".to_string(),
                Value::String(timestamp.to_string()),
            ),
            (
                "module".to_string(),
                Value::String(ROLE_TEST_MODULE.to_string()),
            ),
            ("published".to_string(), Value::Bool(participant_read)),
            ("isLatestBaseState".to_string(), Value::Bool(true)),
        ]);
        store
            .put(ROLE_TEST_TENANT, message, indexes)
            .await
            .expect("configure must store");
    }

    fn role_query_auth_ctx() -> AuthorizationContext {
        use crate::auth::jws::{AuthorizationPayloadData, PermissionGrantInvocation};
        use crate::permissions::VerifiedAuthorizationPayload;

        AuthorizationContext {
            signer: ROLE_TEST_AUTHOR.to_string(),
            author: ROLE_TEST_AUTHOR.to_string(),
            payload: VerifiedAuthorizationPayload::Generic(AuthorizationPayloadData {
                descriptor_cid: String::new(),
                delegated_grant_id: None,
                permission_grant_id: None,
                permission_grant_ids: None,
                module_role: Some("thread/participant".to_string()),
            }),
            permission_grant_invocation: PermissionGrantInvocation::None,
            author_delegated_grant: None,
            owner: None,
        }
    }

    struct FailingMessageStore;

    impl crate::stores::MessageStore for FailingMessageStore {
        async fn open(&mut self) -> Result<(), crate::errors::MessageStoreError> {
            Ok(())
        }

        async fn close(&mut self) {}

        async fn put<D>(
            &self,
            _tenant: &str,
            _message: Message<D>,
            _indexes: KeyValues,
        ) -> Result<(), crate::errors::MessageStoreError>
        where
            D: crate::descriptors::MessageDescriptor + Send,
            Message<Descriptor>: From<Message<D>>,
        {
            unimplemented!("read-only stub")
        }

        async fn get(
            &self,
            _tenant: &str,
            _cid: &str,
        ) -> Result<Option<Message<Descriptor>>, crate::errors::MessageStoreError> {
            unimplemented!("read-only stub")
        }

        async fn query(
            &self,
            _tenant: &str,
            _filters: Filters,
            _sort: Option<MessageSort>,
            _pagination: Option<Pagination>,
            _record_limit: Option<crate::stores::RecordLimitOccupancy>,
        ) -> Result<MessageQueryResult, crate::errors::MessageStoreError> {
            Err(crate::errors::MessageStoreError::StoreError(
                crate::errors::StoreError::InternalException("failing store".to_string()),
            ))
        }

        async fn count(
            &self,
            _tenant: &str,
            _filters: Filters,
            _sort: Option<MessageSort>,
            _record_limit: Option<crate::stores::RecordLimitOccupancy>,
        ) -> Result<u64, crate::errors::MessageStoreError> {
            unimplemented!("read-only stub")
        }

        async fn delete(
            &self,
            _tenant: &str,
            _cid: &str,
        ) -> Result<(), crate::errors::MessageStoreError> {
            unimplemented!("read-only stub")
        }

        async fn clear(&self) -> Result<(), crate::errors::MessageStoreError> {
            unimplemented!("read-only stub")
        }
    }

    // Covers: DWN-PROTO-004
    #[tokio::test]
    async fn module_definition_selects_governing_version() {
        let store = MemoryMessageStore::default();
        put_history_configure(&store, HISTORY_T1, true).await;
        put_history_configure(&store, HISTORY_T2, false).await;

        let mid = fetch_module_definition(
            ROLE_TEST_TENANT,
            ROLE_TEST_MODULE,
            &store,
            Some(HISTORY_MID),
        )
        .await
        .expect("definition at MID must resolve");
        assert!(mid.published, "request between configures sees v1");

        let late = fetch_module_definition(
            ROLE_TEST_TENANT,
            ROLE_TEST_MODULE,
            &store,
            Some(HISTORY_LATE),
        )
        .await
        .expect("definition after reconfigure sees v2");
        assert!(!late.published, "request after reconfigure sees v2");

        let early = fetch_module_definition(
            ROLE_TEST_TENANT,
            ROLE_TEST_MODULE,
            &store,
            Some(HISTORY_EARLY),
        )
        .await
        .expect("request before retained history falls back to the earliest configure");
        assert!(early.published, "earliest retained configure is v1");
    }

    // Covers: DWN-PROTO-002
    #[test]
    fn role_audience_context_uses_role_parent_physical_depth() {
        assert_eq!(role_audience_context_id(0, None).as_deref(), Some(""));
        assert_eq!(
            role_audience_context_id(1, Some("thread-id/record-id")).as_deref(),
            Some("thread-id")
        );
        assert_eq!(role_audience_context_id(3, Some("only-one-segment")), None);
        assert_eq!(role_audience_context_id(1, Some("")), None);
        assert_eq!(role_audience_context_id(1, Some("/")), None);
        assert_eq!(role_audience_context_id(1, Some("a//b")), None);
    }

    // Covers: DWN-PROTO-001
    #[tokio::test]
    async fn module_definition_preserves_fail_closed_classification() {
        use crate::handlers::modules::configure::ModuleDefinitionLookupError;

        let empty = MemoryMessageStore::default();
        assert!(
            matches!(
                fetch_module_definition(
                    ROLE_TEST_TENANT,
                    ROLE_TEST_MODULE,
                    &empty,
                    Some(HISTORY_MID),
                )
                .await,
                Err(ModuleDefinitionLookupError::NotFound(_))
            ),
            "absent module is the only non-error case"
        );

        let failing = FailingMessageStore;
        assert!(
            matches!(
                fetch_module_definition(
                    ROLE_TEST_TENANT,
                    ROLE_TEST_MODULE,
                    &failing,
                    Some(HISTORY_MID),
                )
                .await,
                Err(ModuleDefinitionLookupError::Store(_))
            ),
            "I/O failure must surface as store error, never as absent"
        );

        let forged = MemoryMessageStore::default();
        let message: Message<Descriptor> = serde_json::from_value(json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": HISTORY_T1,
                "dateCreated": HISTORY_T1,
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 0,
                "dataFormat": "application/json",
                "module": ROLE_TEST_MODULE,
                "modulePath": "thread/participant",
                "recipient": ROLE_TEST_AUTHOR
            },
            "recordId": "forged-record",
            "contextId": "thread-1"
        }))
        .expect("forged message must deserialize");
        forged
            .put(
                ROLE_TEST_TENANT,
                message,
                BTreeMap::from([
                    (
                        "interface".to_string(),
                        Value::String("Modules".to_string()),
                    ),
                    ("method".to_string(), Value::String("Configure".to_string())),
                    (
                        "module".to_string(),
                        Value::String(ROLE_TEST_MODULE.to_string()),
                    ),
                    (
                        "messageTimestamp".to_string(),
                        Value::String(HISTORY_T1.to_string()),
                    ),
                    ("isLatestBaseState".to_string(), Value::Bool(true)),
                ]),
            )
            .await
            .expect("forged row must store");
        assert!(
            matches!(
                fetch_module_definition(
                    ROLE_TEST_TENANT,
                    ROLE_TEST_MODULE,
                    &forged,
                    Some(HISTORY_MID),
                )
                .await,
                Err(ModuleDefinitionLookupError::InvalidMessage(_))
            ),
            "corrupt definition must surface as invalid, never as absent"
        );
    }

    // Covers: DWN-PROTO-004, DWN-PROTO-002
    #[tokio::test]
    async fn role_authorization_uses_request_time_definition() {
        let store = MemoryMessageStore::default();
        put_history_configure(&store, HISTORY_T1, true).await;
        put_history_configure(&store, HISTORY_T2, false).await;
        put_role_record(
            &store,
            ROLE_TEST_MODULE,
            "thread/participant",
            "thread-1",
            "role-record-1",
        )
        .await;
        let auth_ctx = role_query_auth_ctx();
        let filter = RecordsFilter {
            module: Some(ROLE_TEST_MODULE.to_string()),
            module_path: Some("thread/participant".to_string()),
            context_id: Some("thread-1/message-1".to_string()),
            ..Default::default()
        };

        let resolved = authorize_module_query_or_subscribe(
            ROLE_TEST_TENANT,
            &filter,
            &auth_ctx,
            &store,
            HISTORY_MID,
            RecordsAuthorizationKind::Query,
        )
        .await
        .expect("role allowed under v1 must authorize at MID");
        assert_eq!(resolved.role_record_id, "role-record-1");

        assert!(
            authorize_module_query_or_subscribe(
                ROLE_TEST_TENANT,
                &filter,
                &auth_ctx,
                &store,
                HISTORY_LATE,
                RecordsAuthorizationKind::Query,
            )
            .await
            .is_err(),
            "role removed by v2 must not authorize at LATE"
        );
    }

    const LIMITED_MODULE: &str = "http://example.com/limited";
    const POLICY_T1: &str = "2025-01-01T00:00:00.000000Z";

    fn limit_filter(
        module_path: Option<&str>,
        parent_id: Option<&str>,
        context_id: Option<&str>,
    ) -> RecordsFilter {
        RecordsFilter {
            module: Some(LIMITED_MODULE.to_string()),
            module_path: module_path.map(str::to_string),
            parent_id: parent_id.map(str::to_string),
            context_id: context_id.map(str::to_string),
            ..Default::default()
        }
    }

    fn limit_write_message(module_path: &str, context_id: Option<&str>) -> Message<Descriptor> {
        serde_json::from_value(json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": POLICY_T1,
                "dateCreated": POLICY_T1,
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 0,
                "dataFormat": "application/json",
                "module": LIMITED_MODULE,
                "modulePath": module_path,
                "recipient": ROLE_TEST_AUTHOR
            },
            "recordId": "limit-record-1",
            "contextId": context_id
        }))
        .expect("limit write must deserialize")
    }

    // Covers: DWN-PROTO-004
    #[tokio::test]
    async fn record_limit_policy_root_path_has_no_scope() {
        let store = MemoryMessageStore::default();
        crate::testing::put_limited_threads_module(ROLE_TEST_TENANT, &store).await;
        let policy = resolve_record_limit_policy(
            ROLE_TEST_TENANT,
            &limit_filter(Some("post"), None, None),
            &store,
            POLICY_T1,
        )
        .await
        .expect("root policy must resolve")
        .expect("root path has a limit");
        assert_eq!(policy.max, 2);
        assert_eq!(policy.module, LIMITED_MODULE);
        assert_eq!(policy.module_path, "post");
        assert_eq!(policy.context_id, None);
        assert_eq!(policy.parent_id, None);
    }

    // Covers: DWN-PROTO-004
    #[tokio::test]
    async fn record_limit_policy_nested_scope_selection() {
        let store = MemoryMessageStore::default();
        crate::testing::put_limited_threads_module(ROLE_TEST_TENANT, &store).await;

        let parent = resolve_record_limit_policy(
            ROLE_TEST_TENANT,
            &limit_filter(Some("thread/message"), Some("thread-1"), None),
            &store,
            POLICY_T1,
        )
        .await
        .expect("parent policy must resolve")
        .expect("nested path has a limit");
        assert_eq!(parent.max, 1);
        assert_eq!(parent.parent_id, Some(vec!["thread-1".to_string()]));
        assert_eq!(parent.context_id, None);

        let exact = resolve_record_limit_policy(
            ROLE_TEST_TENANT,
            &limit_filter(Some("thread/message"), None, Some("ctx-a/ctx-b")),
            &store,
            POLICY_T1,
        )
        .await
        .expect("exact policy must resolve")
        .expect("nested path has a limit");
        assert_eq!(exact.context_id, Some("ctx-a".to_string()));
        assert_eq!(exact.parent_id, None);

        let deeper = resolve_record_limit_policy(
            ROLE_TEST_TENANT,
            &limit_filter(Some("thread/message"), None, Some("ctx-a/ctx-b/ctx-c")),
            &store,
            POLICY_T1,
        )
        .await
        .expect("deep policy must resolve")
        .expect("nested path has a limit");
        assert_eq!(deeper.context_id, Some("ctx-a/ctx-b/ctx-c".to_string()));

        let unscoped = resolve_record_limit_policy(
            ROLE_TEST_TENANT,
            &limit_filter(Some("thread/message"), None, None),
            &store,
            POLICY_T1,
        )
        .await
        .expect("unscoped policy must resolve")
        .expect("nested path has a limit");
        assert_eq!(unscoped.context_id, None);
        assert_eq!(unscoped.parent_id, None);
    }

    // Covers: DWN-PROTO-001
    #[tokio::test]
    async fn record_limit_policy_absent_means_unlimited() {
        let store = MemoryMessageStore::default();
        crate::testing::put_limited_threads_module(ROLE_TEST_TENANT, &store).await;

        assert_eq!(
            resolve_record_limit_policy(
                ROLE_TEST_TENANT,
                &limit_filter(None, None, None),
                &store,
                POLICY_T1,
            )
            .await
            .expect("missing module must not fail"),
            None,
            "filter without module selects no policy"
        );
        assert_eq!(
            resolve_record_limit_policy(
                "did:example:bob",
                &limit_filter(Some("post"), None, None),
                &store,
                POLICY_T1,
            )
            .await
            .expect("unconfigured tenant must not fail"),
            None,
            "unknown tenant selects no policy"
        );
        assert_eq!(
            resolve_record_limit_policy(
                ROLE_TEST_TENANT,
                &limit_filter(Some("thread"), None, None),
                &store,
                POLICY_T1,
            )
            .await
            .expect("rule-less path must not fail"),
            None,
            "path without a rule selects no policy"
        );
    }

    // Covers: DWN-PROTO-001
    #[tokio::test]
    async fn record_limit_policy_store_failure_errors() {
        let failing = FailingMessageStore;
        assert!(
            resolve_record_limit_policy(
                ROLE_TEST_TENANT,
                &limit_filter(Some("post"), None, None),
                &failing,
                POLICY_T1,
            )
            .await
            .is_err(),
            "definition lookup failure must error, never widen"
        );
    }

    // Covers: DWN-PROTO-004
    #[tokio::test]
    async fn message_record_limit_policy_uses_direct_parent() {
        let store = MemoryMessageStore::default();
        crate::testing::put_limited_threads_module(ROLE_TEST_TENANT, &store).await;

        let nested = message_record_limit_policy(
            ROLE_TEST_TENANT,
            &limit_write_message("thread/message", Some("thread-1/message-1")),
            &store,
            POLICY_T1,
        )
        .await
        .expect("message policy must resolve")
        .expect("nested path has a limit");
        assert_eq!(nested.max, 1);
        assert_eq!(nested.context_id, Some("thread-1".to_string()));

        let root = message_record_limit_policy(
            ROLE_TEST_TENANT,
            &limit_write_message("post", None),
            &store,
            POLICY_T1,
        )
        .await
        .expect("root message policy must resolve")
        .expect("root path has a limit");
        assert_eq!(root.context_id, None);
    }

    async fn put_limit_history_configure(store: &MemoryMessageStore, timestamp: &str, max: u64) {
        let message: Message<Descriptor> = serde_json::from_value(json!({
            "descriptor": {
                "interface": "Modules",
                "method": "Configure",
                "messageTimestamp": timestamp,
                "definition": {
                    "module": LIMITED_MODULE,
                    "published": false,
                    "types": { "post": {} },
                    "structure": {
                        "post": { "$recordLimit": { "max": max } }
                    }
                }
            }
        }))
        .expect("limit configure must deserialize");
        let indexes = BTreeMap::from([
            (
                "interface".to_string(),
                Value::String("Modules".to_string()),
            ),
            ("method".to_string(), Value::String("Configure".to_string())),
            (
                "messageTimestamp".to_string(),
                Value::String(timestamp.to_string()),
            ),
            (
                "module".to_string(),
                Value::String(LIMITED_MODULE.to_string()),
            ),
            ("published".to_string(), Value::Bool(false)),
            ("isLatestBaseState".to_string(), Value::Bool(true)),
        ]);
        store
            .put(ROLE_TEST_TENANT, message, indexes)
            .await
            .expect("limit configure must store");
    }

    // Covers: DWN-PROTO-004
    #[tokio::test]
    async fn record_limit_policy_follows_module_history() {
        let store = MemoryMessageStore::default();
        put_limit_history_configure(&store, HISTORY_T1, 2).await;
        put_limit_history_configure(&store, HISTORY_T2, 5).await;

        let mid = resolve_record_limit_policy(
            ROLE_TEST_TENANT,
            &limit_filter(Some("post"), None, None),
            &store,
            HISTORY_MID,
        )
        .await
        .expect("mid policy must resolve")
        .expect("post path has a limit");
        assert_eq!(mid.max, 2, "request between configures sees v1");

        let late = resolve_record_limit_policy(
            ROLE_TEST_TENANT,
            &limit_filter(Some("post"), None, None),
            &store,
            HISTORY_LATE,
        )
        .await
        .expect("late policy must resolve")
        .expect("post path has a limit");
        assert_eq!(late.max, 5, "request after reconfigure sees v2");
    }

    // Covers: DWN-AUTH-005
    #[tokio::test]
    async fn subscribe_delivery_role_removed_is_terminal() {
        use super::super::subscribe::{authorize_records_delivery, DeliveryAuthorization};
        use crate::stores::SubscriptionErrorCode;

        let store = MemoryMessageStore::default();
        put_history_configure(&store, HISTORY_T1, true).await;
        let role_cid = put_role_record(
            &store,
            ROLE_TEST_MODULE,
            "thread/participant",
            "thread-1",
            "role-record-1",
        )
        .await;

        let request = crate::testing::signed_records_subscribe_message(
            RecordsFilter {
                module: Some(ROLE_TEST_MODULE.to_string()),
                module_path: Some("thread/participant".to_string()),
                context_id: Some("thread-1/message-1".to_string()),
                ..Default::default()
            },
            None,
            HISTORY_MID,
        )
        .await;
        let message: Message<Descriptor> =
            serde_json::from_value(request).expect("subscribe request must deserialize");
        let auth = DeliveryAuthorization {
            message,
            filter: RecordsFilter {
                module: Some(ROLE_TEST_MODULE.to_string()),
                module_path: Some("thread/participant".to_string()),
                context_id: Some("thread-1/message-1".to_string()),
                ..Default::default()
            },
            auth_ctx: role_query_auth_ctx(),
            grant_valid_at_open: false,
            role_invoked: true,
            request_timestamp: HISTORY_MID.to_string(),
            control_only: false,
        };

        authorize_records_delivery(ROLE_TEST_TENANT, &auth, &store)
            .await
            .expect("active role must authorize delivery");

        store
            .delete(ROLE_TEST_TENANT, &role_cid)
            .await
            .expect("role record must delete");
        let error = authorize_records_delivery(ROLE_TEST_TENANT, &auth, &store)
            .await
            .expect_err("removed role must fail delivery");
        assert_eq!(
            error.code,
            SubscriptionErrorCode::RecordsDeliveryAuthorizationFailed
        );
    }

    // Covers: DWN-PROTO-005, DWN-PROTO-003
    fn actor_chain_entry(message: serde_json::Value) -> Message<Descriptor> {
        serde_json::from_value(message).expect("actor message must deserialize")
    }

    fn cross_of_definition(alias_module: &str) -> Definition {
        Definition {
            module: "https://example.com/composing".to_string(),
            published: false,
            uses: Some(BTreeMap::from([(
                "threads".to_string(),
                alias_module.to_string(),
            )])),
            key_agreement: None,
            types: BTreeMap::new(),
            structure: BTreeMap::new(),
        }
    }

    // Covers: DWN-PROTO-005, DWN-PROTO-003
    #[tokio::test]
    async fn check_actor_cross_of_matches_module_and_path() {
        use crate::testing::{signed_write_message, WriteSpec};

        const THREADS_A: &str = "https://a.example/threads";
        const THREADS_B: &str = "https://b.example/threads";

        let chain_a = vec![actor_chain_entry(
            signed_write_message(WriteSpec {
                module: THREADS_A.to_string(),
                module_path: "thread".to_string(),
                ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
            })
            .await,
        )];
        let chain_b = vec![actor_chain_entry(
            signed_write_message(WriteSpec {
                module: THREADS_B.to_string(),
                module_path: "thread".to_string(),
                ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
            })
            .await,
        )];

        let definition = cross_of_definition(THREADS_A);
        // A cross-module `of` matches both module URI and path.
        assert!(check_actor(
            ROLE_TEST_AUTHOR,
            &Who::Author,
            Some("threads:thread"),
            &chain_a,
            Some(&definition)
        ));
        // The same path in another module does not match.
        assert!(!check_actor(
            ROLE_TEST_AUTHOR,
            &Who::Author,
            Some("threads:thread"),
            &chain_b,
            Some(&definition)
        ));
        // A local `of` matches by path alone, even in a referenced module.
        assert!(check_actor(
            ROLE_TEST_AUTHOR,
            &Who::Author,
            Some("thread"),
            &chain_b,
            Some(&definition)
        ));
    }

    // Covers: DWN-PROTO-005
    #[tokio::test]
    async fn actor_matches_checks_resolved_physical_depth_positionally() {
        use crate::testing::{signed_write_message, WriteSpec};

        const THREADS: &str = "http://example.com/threads";
        const DEPTH_ONE_RECIPIENT: &str = "did:example:depth-one";
        const DEPTH_TWO_RECIPIENT: &str = "did:example:depth-two";

        let depth_one: Message<Descriptor> = serde_json::from_value(
            signed_write_message(WriteSpec {
                module: THREADS.to_string(),
                module_path: "thread".to_string(),
                recipient: Some(DEPTH_ONE_RECIPIENT.to_string()),
                ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
            })
            .await,
        )
        .unwrap();
        let depth_two: Message<Descriptor> = serde_json::from_value(
            signed_write_message(WriteSpec {
                module: THREADS.to_string(),
                module_path: "thread".to_string(),
                recipient: Some(DEPTH_TWO_RECIPIENT.to_string()),
                ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
            })
            .await,
        )
        .unwrap();
        let chain = vec![depth_one, depth_two];

        let actor_at_depth_two = ResolvedActorReference {
            owning_module_uri: THREADS.to_string(),
            owning_module_path: "thread".to_string(),
            who: Who::Recipient,
            raw_of: "threads:thread".to_string(),
            physical_depth: 2,
        };

        assert!(actor_matches(
            DEPTH_TWO_RECIPIENT,
            &Who::Recipient,
            &actor_at_depth_two,
            &chain
        ));
        assert!(!actor_matches(
            DEPTH_ONE_RECIPIENT,
            &Who::Recipient,
            &actor_at_depth_two,
            &chain
        ));
    }
}
