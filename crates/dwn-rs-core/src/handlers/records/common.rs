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
use crate::dwn::core_protocol::CoreProtocolRegistry;
use crate::encryption::Encryption;
use crate::errors::{DwnError, DwnErrorCode, EventLogError};
use crate::filters::message_filters::Records as RecordsFilter;
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::handlers::configure::fetch_protocol_definition;
use crate::handlers::records::subscribe::RecordsSubscribeReply;
use crate::interfaces::messages::protocols::{
    self as protocol_types, Action, Can, Definition, RuleSet, Who,
};
use crate::interfaces::replies::Status;
use crate::permissions::{self, AuthorizationContext};
use crate::replies::records::{QueryEntry, Subscribe};
use crate::replies::HasProgressGapInfo;
use crate::stores::write_resolver::InitialWriteResolver;
use crate::stores::{EventSubscription, KeyValues};
use crate::{canonical_rfc3339, Message, MessageSort, Pagination, Response, SortDirection, Value};

use super::{RecordsAuthorizationKind, MAX_ENCODED_DATA_SIZE, RECORDS_INTERFACE, WRITE_METHOD};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QueryAuthorizationResult {
    Unauthorized(String),
}

pub(crate) fn parse_message(raw_message: &JsonValue) -> Result<Message<Descriptor>, String> {
    serde_json::from_value(raw_message.clone()).map_err(|err| format!("MessageParseFailed: {err}"))
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
        match encryption {
            Encryption::Envelope(envelope) => {
                envelope.validate().map_err(|error| match error {
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
            Encryption::LegacyJwe(_) => {
                // Legacy JWE is deprecated. It's only valid for decryption of existing records, not
                // for new writes. Reject any new writes with a legacy JWE.
                return Err("RecordsWriteValidateIntegrityEncryptionLegacyJweInvalid: Legacy JWE is deprecated and not allowed for new writes".to_string());
            }
        }
    }

    // `contextId` is a protocol-only surface: per DWN spec.md:1028 a record NOT
    // attached to a protocol MUST NOT have a contextId, and upstream implementations
    // including enbox's own dwn-sdk-js do not require a contextId for non-protocol records.
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
        // Only a protocol-scoped root record carries the deterministic
        // `contextId == recordId`. Upstream gates this check on
        // `descriptor.protocol !== undefined`; a protocol-less record has no
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

pub(crate) fn find_initial_write(
    messages: &[Message<Descriptor>],
    author: &str,
) -> Option<Message<Descriptor>> {
    messages
        .iter()
        .find(|message| {
            records_write_descriptor(message).is_ok()
                && is_initial_write(message, author).unwrap_or(false)
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
                "protocol",
                &Some(initial.protocol.clone()),
                &Some(new.protocol.clone()),
            ),
            (
                "protocolPath",
                &Some(initial.protocol_path.clone()),
                &Some(new.protocol_path.clone()),
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
    indexes.insert(
        "protocol".to_string(),
        Value::String(initial.protocol.clone()),
    );
    indexes.insert(
        "protocolPath".to_string(),
        Value::String(initial.protocol_path.clone()),
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
    insert_string_filter(&mut map, "protocol", filter.protocol.as_ref());
    insert_string_filter(&mut map, "protocolPath", filter.protocol_path.as_ref());
    insert_bool_filter(&mut map, "published", filter.published);
    insert_string_filter(&mut map, "schema", filter.schema.as_ref());
    insert_string_filter(&mut map, "recordId", filter.record_id.as_ref());
    insert_string_filter(&mut map, "parentId", filter.parent_id.as_ref());
    insert_string_filter(&mut map, "dataFormat", filter.data_format.as_ref());
    if let Some(context_id) = &filter.context_id {
        map.insert(
            FilterKey::Index("contextId".to_string()),
            Filter::Prefix(Value::String(context_id.clone())),
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
    protocol_authorized: bool,
) -> Vec<BTreeMap<FilterKey, Filter<Value>>> {
    let mut filters = Vec::new();
    if filter_includes_published_records(filter) {
        filters.push(published_records_filter(filter, date_sort));
    }
    if filter_includes_unpublished_records(filter) {
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
        if protocol_authorized {
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
    protocol_authorized: bool,
) -> Vec<BTreeMap<FilterKey, Filter<Value>>> {
    let mut filters = Vec::new();
    if filter_includes_published_records(filter) {
        filters.push(published_records_event_filter(filter));
    }
    if filter_includes_unpublished_records(filter) {
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
        if protocol_authorized {
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

pub(crate) fn should_protocol_authorize(ctx: &AuthorizationContext) -> bool {
    ctx.payload.protocol_role().is_some()
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
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor = records_write_descriptor(matched_records_write)?;
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
        .map_err(|error| error.to_string())?
        {
            return Ok(());
        }
        return authorize_against_protocol(
            tenant,
            matched_records_write,
            &signature.author,
            RecordsAuthorizationKind::Read,
            message_store,
        )
        .await;
    }
    Err("ProtocolAuthorizationActionNotAllowed: anonymous read is not authorized".to_string())
}

pub(crate) async fn authorize_records_delete<MessageStore>(
    tenant: &str,
    delete_message: &Message<Descriptor>,
    initial_write: &Message<Descriptor>,
    signature: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<(), String>
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
    authorize_against_protocol(
        tenant,
        initial_write,
        &signature.author,
        RecordsAuthorizationKind::Delete { prune },
        message_store,
    )
    .await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedProtocolRole {
    pub protocol: String,
    pub protocol_path: String,
    pub context_id_prefix: Option<String>,
    pub role_record_id: String,
}

pub(crate) async fn authorize_protocol_query_or_subscribe<MessageStore>(
    tenant: &str,
    filter: &RecordsFilter,
    auth_ctx: &AuthorizationContext,
    message_store: &MessageStore,
    kind: RecordsAuthorizationKind,
) -> Result<ResolvedProtocolRole, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let protocol = filter.protocol.as_deref().ok_or_else(|| {
        "ProtocolAuthorizationMissingProtocol: role-authorized query must include protocol"
            .to_string()
    })?;
    let protocol_path = filter.protocol_path.as_deref().ok_or_else(|| {
        "ProtocolAuthorizationMissingProtocolPath: role-authorized query must include protocolPath".to_string()
    })?;
    let definition = crate::handlers::protocols::configure::fetch_protocol_definition(
        tenant,
        protocol,
        message_store,
        None,
    )
    .await
    .map_err(|err| err.to_string())?;

    let rule_set = protocol_types::get_rule_set_at_path(protocol_path, &definition.structure)
        .ok_or_else(|| {
            format!("ProtocolAuthorizationInvalidProtocolPath: {protocol_path} is not defined")
        })?;

    let invoked_role = auth_ctx
        .protocol_role()
        .ok_or_else(|| "protocolRole is required".to_string())?;

    let can = match kind {
        RecordsAuthorizationKind::Subscribe => Can::Read,
        RecordsAuthorizationKind::Count | RecordsAuthorizationKind::Query => Can::Read,
        _ => Can::Read,
    };

    resolve_query_or_subscribe_role(
        tenant,
        &auth_ctx.author,
        invoked_role,
        protocol,
        filter.context_id.as_deref(),
        can,
        rule_set,
        &definition,
        message_store,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn resolve_query_or_subscribe_role<MessageStore>(
    tenant: &str,
    author: &str,
    invoked_role: &str,
    protocol: &str,
    context_id_prefix: Option<&str>,
    can: Can,
    rule_set: &RuleSet,
    definition: &Definition,
    message_store: &MessageStore,
) -> Result<ResolvedProtocolRole, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    for action in &rule_set.actions {
        let Action::Role(action) = action else {
            continue;
        };

        if !action.can.contains(&can) || action.role != invoked_role {
            continue;
        }

        if let Some(role) = find_matching_role_record(
            tenant,
            author,
            &action.role,
            protocol,
            context_id_prefix,
            message_store,
            definition,
        )
        .await?
        {
            return Ok(role);
        }
    }

    Err("invoke role is not allowed or has no active role record".to_string())
}

pub(crate) async fn authorize_against_protocol<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    author: &str,
    kind: RecordsAuthorizationKind,
    message_store: &MessageStore,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor = records_write_descriptor(message)?;
    let protocol = descriptor.protocol.clone();
    let protocol_path = descriptor.protocol_path.clone();
    let governing_timestamp = governing_timestamp(tenant, message, message_store, author)
        .await
        .map_err(|error| error.to_string())?;
    let definition = fetch_protocol_definition(
        tenant,
        protocol.as_str(),
        message_store,
        Some(&governing_timestamp),
    )
    .await
    .map_err(|err| err.to_string())?;
    let rule_set =
        protocol_types::get_rule_set_at_path(protocol_path.as_str(), &definition.structure)
            .ok_or_else(|| {
                format!("ProtocolAuthorizationInvalidProtocolPath: {protocol_path} is not defined")
            })?;
    let chain = construct_record_chain(tenant, message, message_store).await?;
    let actions = actions_for_message_kind(tenant, message, author, kind, message_store).await?;
    authorize_actions(
        tenant,
        author,
        None,
        &actions,
        rule_set,
        &chain,
        message_store,
        Some(&definition),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_actions<MessageStore>(
    tenant: &str,
    author: &str,
    invoked_role: Option<&str>,
    actions: &[Can],
    rule_set: &RuleSet,
    record_chain: &[Message<Descriptor>],
    message_store: &MessageStore,
    definition: Option<&Definition>,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    for action in &rule_set.actions {
        match action {
            Action::Who(action) => {
                if !action.can.iter().any(|can| actions.contains(can)) {
                    continue;
                }
                match action.who {
                    Who::Anyone => return Ok(()),
                    Who::Recipient if action.of.is_none() => {
                        if record_chain
                            .last()
                            .and_then(|message| records_write_descriptor(message).ok())
                            .and_then(|descriptor| descriptor.recipient.as_deref())
                            == Some(author)
                        {
                            return Ok(());
                        }
                    }
                    Who::Author | Who::Recipient => {
                        if check_actor(
                            author,
                            &action.who,
                            action.of.as_deref(),
                            record_chain,
                            definition,
                        ) {
                            return Ok(());
                        }
                    }
                }
            }
            Action::Role(action) => {
                if !action.can.iter().any(|can| actions.contains(can)) {
                    continue;
                }
                if invoked_role == Some(action.role.as_str())
                    && matching_role_record_exists(
                        tenant,
                        author,
                        &action.role,
                        record_chain,
                        message_store,
                        definition,
                    )
                    .await?
                {
                    return Ok(());
                }
            }
        }
    }
    Err("ProtocolAuthorizationActionNotAllowed: inbound message action is not allowed".to_string())
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
    let parsed_cross_ref = protocol_types::parse_cross_protocol_ref(of);
    record_chain.iter().any(|message| {
        let Ok(descriptor) = records_write_descriptor(message) else {
            return false;
        };
        let path_matches = if let Some(parsed) = parsed_cross_ref.as_ref() {
            definition
                .and_then(|definition| definition.uses.as_ref())
                .and_then(|uses| uses.get(parsed.alias))
                .is_some_and(|protocol| {
                    descriptor.protocol == *protocol
                        && descriptor.protocol_path == parsed.protocol_path
                })
        } else {
            descriptor.protocol_path == of
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

async fn find_matching_role_record<MS>(
    tenant: &str,
    author: &str,
    role: &str,
    requested_protocol: &str,
    context_id: Option<&str>,
    message_store: &MS,
    definition: &Definition,
) -> Result<Option<ResolvedProtocolRole>, String>
where
    MS: crate::stores::MessageStore + Sync,
{
    let (role_proto, role_proto_path) =
        if let Some(parsed) = protocol_types::parse_cross_protocol_ref(role) {
            let role_proto = definition
                .uses
                .as_ref()
                .and_then(|uses| uses.get(parsed.alias))
                .ok_or_else(|| {
                    "ProtocolAuthorizationNotARole: cross-protocol role alias not found".to_string()
                })?;
            (role_proto.as_str(), parsed.protocol_path)
        } else {
            (requested_protocol, role)
        };

    let mut filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("method", string_filter(WRITE_METHOD)),
        ("protocol", string_filter(role_proto)),
        ("protocolPath", string_filter(role_proto_path)),
        ("recipient", string_filter(author)),
        ("isLatestBaseState", bool_filter(true)),
    ]);

    if let Some(context) = context_id {
        let ancestor_count = role_proto_path.split('/').count().saturating_sub(1);
        if ancestor_count > 0 {
            let context_prefix = context
                .split('/')
                .take(ancestor_count)
                .collect::<Vec<_>>()
                .join("/");

            filter.insert(
                FilterKey::Index("contextId".to_string()),
                Filter::Prefix(Value::String(context_prefix)),
            );
        }
    };

    let result = message_store
        .query(
            tenant,
            Filters::from(filter),
            None,
            Some(Pagination::with_limit(1)),
        )
        .await
        .map_err(|err| err.to_string())?;

    let Some(role_record) = result.messages.first() else {
        return Ok(None);
    };

    let role_record_id =
        record_id(role_record).ok_or_else(|| "recordId is required".to_string())?;

    Ok(Some(ResolvedProtocolRole {
        protocol: role_proto.to_string(),
        protocol_path: role_proto_path.to_string(),
        context_id_prefix: context_id.map(|s| s.to_string()),
        role_record_id,
    }))
}

pub(crate) async fn matching_role_record_exists<MessageStore>(
    tenant: &str,
    author: &str,
    role: &str,
    record_chain: &[Message<Descriptor>],
    message_store: &MessageStore,
    definition: Option<&Definition>,
) -> Result<bool, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let mut protocol: String = record_chain
        .last()
        .and_then(|message| records_write_descriptor(message).ok())
        .map(|descriptor| descriptor.protocol.clone())
        .unwrap_or_default();

    let mut protocol_path = role.to_string();
    if let Some(parsed) = protocol_types::parse_cross_protocol_ref(role) {
        protocol = definition
            .and_then(|definition| definition.uses.as_ref())
            .and_then(|uses| uses.get(parsed.alias))
            .cloned()
            .ok_or_else(|| {
                "ProtocolAuthorizationNotARole: cross-protocol role alias not found".to_string()
            })?;
        protocol_path = parsed.protocol_path.to_string();
    }
    let mut filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("method", string_filter(WRITE_METHOD)),
        ("protocol", string_filter(&protocol)),
        ("protocolPath", string_filter(&protocol_path)),
        ("recipient", string_filter(author)),
        ("isLatestBaseState", bool_filter(true)),
    ]);
    if let Some(context) = record_chain.last().and_then(context_id) {
        let ancestor_count = protocol_path.split('/').count().saturating_sub(1);
        if ancestor_count > 0 {
            let context_prefix = context
                .split('/')
                .take(ancestor_count)
                .collect::<Vec<_>>()
                .join("/");
            filter.insert(
                FilterKey::Index("contextId".to_string()),
                Filter::Prefix(Value::String(context_prefix)),
            );
        }
    }
    let result = message_store
        .query(
            tenant,
            Filters::from(filter),
            None,
            Some(Pagination::with_limit(1)),
        )
        .await
        .map_err(|err| err.to_string())?;
    Ok(!result.messages.is_empty())
}

pub(crate) async fn actions_for_message_kind<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    author: &str,
    kind: RecordsAuthorizationKind,
    message_store: &MessageStore,
) -> Result<Vec<Can>, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    match kind {
        RecordsAuthorizationKind::Write => {
            if is_initial_write(message, author)? {
                if records_write_descriptor(message)?.squash == Some(true) {
                    Ok(vec![Can::Squash, Can::Create])
                } else {
                    Ok(vec![Can::Create])
                }
            } else if let Some(record_id) = record_id(message) {
                let initial =
                    fetch_initial_write_message(tenant, &record_id, message_store).await?;
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
                let initial =
                    fetch_initial_write_message(tenant, &record_id, message_store).await?;
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
        return Ok(canonical_rfc3339(message_timestamp(message)?));
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
    Ok(canonical_rfc3339(message_timestamp(&initial)?))
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
        .query(tenant, Filters::from(filter), None, None)
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
        )
        .await
        .map_err(|err| err.to_string())?;
    result
        .messages
        .into_iter()
        .next()
        .ok_or_else(|| "RecordsWriteGetNewestWriteRecordNotFound: record not found".to_string())
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
        )
        .await
        .map(|result| result.messages.into_iter().next())
        .map_err(|err| err.to_string())
}

pub(crate) async fn existing_initial_lacks_data<DataStore>(
    newest_existing: &Option<Message<Descriptor>>,
    data_store: &DataStore,
    tenant: &str,
    record_id: &str,
    data_cid: &str,
) -> bool
where
    DataStore: crate::stores::DataStore + Sync,
{
    let Some(message) = newest_existing.as_ref() else {
        return false;
    };
    let Some(author) = extract_author(message) else {
        return false;
    };
    if !is_initial_write(message, &author).unwrap_or(false) {
        return false;
    }
    if write_fields(message)
        .ok()
        .and_then(|fields| fields.encoded_data.as_ref())
        .is_some()
    {
        return false;
    }
    data_store
        .get(tenant, record_id, data_cid)
        .await
        .map(|result| result.is_none())
        .unwrap_or(false)
}

pub(crate) fn newest_message(messages: &[Message<Descriptor>]) -> Option<Message<Descriptor>> {
    messages.iter().cloned().max_by(compare_messages)
}

pub(crate) fn compare_messages(
    left: &Message<Descriptor>,
    right: &Message<Descriptor>,
) -> Ordering {
    let left_timestamp = message_timestamp(left).ok();
    let right_timestamp = message_timestamp(right).ok();
    left_timestamp
        .cmp(&right_timestamp)
        .then_with(|| message_cid(left).ok().cmp(&message_cid(right).ok()))
}

pub(crate) fn message_timestamp(
    message: &Message<Descriptor>,
) -> Result<chrono::DateTime<chrono::Utc>, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Read(descriptor) => Ok(descriptor.message_timestamp),
            Records::Count(descriptor) => Ok(descriptor.message_timestamp),
            Records::Query(descriptor) => Ok(descriptor.message_timestamp),
            Records::Write(descriptor) => Ok(descriptor.message_timestamp),
            Records::Delete(descriptor) => Ok(descriptor.message_timestamp),
            Records::Subscribe(descriptor) => Ok(descriptor.message_timestamp),
        },
        _ => Err("MessageTimestampExpected: message timestamp is required".to_string()),
    }
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
        .query(tenant, Filters::from(filter), None, None)
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

pub(crate) fn core_protocol_error_reply<R: Default>(
    registry: &CoreProtocolRegistry,
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
    use crate::interfaces::messages::protocols::ActionRole;
    use crate::stores::{memory::MemoryMessageStore, MessageStore};
    use serde_json::json;

    const ROLE_TEST_TENANT: &str = "did:example:tenant";
    const ROLE_TEST_AUTHOR: &str = "did:example:alice";
    const ROLE_TEST_PROTOCOL: &str = "https://example.com/protocol/chat";

    fn role_rule(role: &str, can: Vec<Can>) -> RuleSet {
        RuleSet {
            actions: vec![Action::Role(ActionRole {
                role: role.to_string(),
                can,
            })],
            ..Default::default()
        }
    }

    fn role_definition(uses: Option<BTreeMap<String, String>>) -> Definition {
        Definition {
            protocol: ROLE_TEST_PROTOCOL.to_string(),
            published: false,
            uses,
            types: BTreeMap::new(),
            structure: BTreeMap::new(),
        }
    }

    async fn put_role_record(
        store: &MemoryMessageStore,
        protocol: &str,
        protocol_path: &str,
        context_id: &str,
        record_id: &str,
    ) {
        let message: Message<Descriptor> = serde_json::from_value(json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "dateCreated": "2025-01-01T00:00:00.000000Z",
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 0,
                "dataFormat": "application/json",
                "protocol": protocol,
                "protocolPath": protocol_path,
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
            ("protocol".to_string(), Value::String(protocol.to_string())),
            (
                "protocolPath".to_string(),
                Value::String(protocol_path.to_string()),
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
            .put(ROLE_TEST_TENANT, message, indexes)
            .await
            .expect("role record must be stored");
    }

    #[tokio::test]
    async fn query_role_resolution_returns_active_ordinary_role_record() {
        let store = MemoryMessageStore::default();
        put_role_record(
            &store,
            ROLE_TEST_PROTOCOL,
            "thread/participant",
            "thread-1",
            "role-record-1",
        )
        .await;

        let resolved = resolve_query_or_subscribe_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            "thread/participant",
            ROLE_TEST_PROTOCOL,
            Some("thread-1/message-1"),
            Can::Read,
            &role_rule("thread/participant", vec![Can::Read]),
            &role_definition(None),
            &store,
        )
        .await
        .expect("active role must authorize");

        assert_eq!(resolved.protocol, ROLE_TEST_PROTOCOL);
        assert_eq!(resolved.protocol_path, "thread/participant");
        assert_eq!(
            resolved.context_id_prefix.as_deref(),
            Some("thread-1/message-1")
        );
        assert_eq!(resolved.role_record_id, "role-record-1");
    }

    #[tokio::test]
    async fn query_role_resolution_rejects_missing_or_wrong_role() {
        let store = MemoryMessageStore::default();
        let definition = role_definition(None);

        let missing_record = resolve_query_or_subscribe_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            "thread/participant",
            ROLE_TEST_PROTOCOL,
            Some("thread-1/message-1"),
            Can::Read,
            &role_rule("thread/participant", vec![Can::Read]),
            &definition,
            &store,
        )
        .await;
        assert!(missing_record.is_err());

        put_role_record(
            &store,
            ROLE_TEST_PROTOCOL,
            "thread/participant",
            "thread-1",
            "role-record-1",
        )
        .await;

        let wrong_role = resolve_query_or_subscribe_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            "thread/moderator",
            ROLE_TEST_PROTOCOL,
            Some("thread-1/message-1"),
            Can::Read,
            &role_rule("thread/participant", vec![Can::Read]),
            &definition,
            &store,
        )
        .await;
        assert!(wrong_role.is_err());

        let wrong_action = resolve_query_or_subscribe_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            "thread/participant",
            ROLE_TEST_PROTOCOL,
            Some("thread-1/message-1"),
            Can::Read,
            &role_rule("thread/participant", vec![Can::Create]),
            &definition,
            &store,
        )
        .await;
        assert!(wrong_action.is_err());
    }

    #[tokio::test]
    async fn query_role_resolution_resolves_cross_protocol_role() {
        const ROLES_PROTOCOL: &str = "https://example.com/protocol/roles";

        let store = MemoryMessageStore::default();
        put_role_record(
            &store,
            ROLES_PROTOCOL,
            "team/member",
            "team-1",
            "cross-role-record",
        )
        .await;

        let definition = role_definition(Some(BTreeMap::from([(
            "roles".to_string(),
            ROLES_PROTOCOL.to_string(),
        )])));
        let resolved = resolve_query_or_subscribe_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            "roles:team/member",
            ROLE_TEST_PROTOCOL,
            Some("team-1/thread-1"),
            Can::Read,
            &role_rule("roles:team/member", vec![Can::Read]),
            &definition,
            &store,
        )
        .await
        .expect("cross-protocol role must resolve");

        assert_eq!(resolved.protocol, ROLES_PROTOCOL);
        assert_eq!(resolved.protocol_path, "team/member");
        assert_eq!(resolved.role_record_id, "cross-role-record");
    }

    #[tokio::test]
    async fn query_role_resolution_rejects_unknown_cross_protocol_alias_and_sibling_context() {
        let store = MemoryMessageStore::default();
        put_role_record(
            &store,
            ROLE_TEST_PROTOCOL,
            "thread/participant",
            "thread-1",
            "role-record-1",
        )
        .await;

        let unknown_alias = resolve_query_or_subscribe_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            "roles:team/member",
            ROLE_TEST_PROTOCOL,
            Some("team-1/thread-1"),
            Can::Read,
            &role_rule("roles:team/member", vec![Can::Read]),
            &role_definition(None),
            &store,
        )
        .await;
        assert!(unknown_alias
            .expect_err("unknown alias must fail")
            .contains("cross-protocol role alias not found"));

        let sibling_context = resolve_query_or_subscribe_role(
            ROLE_TEST_TENANT,
            ROLE_TEST_AUTHOR,
            "thread/participant",
            ROLE_TEST_PROTOCOL,
            Some("thread-2/message-1"),
            Can::Read,
            &role_rule("thread/participant", vec![Can::Read]),
            &role_definition(None),
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
                "protocol": "https://example.com/protocol/jwe",
                "protocolPath": "thread/message"
            },
            "recordId": "some-non-initial-record-id",
            "contextId": "some-context-id",
            "encryption": {
                "algorithm": "A256CTR",
                "initializationVector": initialization_vector,
                "keyEncryption": [{
                    "algorithm": "X25519-HKDF-SHA256+A256KW",
                    "keyId": "Qae4_6ZxDDA_vn260RVhSSBbdzwqIE0b2eWfSC7o50Q",
                    "derivationScheme": "protocolPath",
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
                    protocol_role: None,
                },
            ),
            permission_grant_invocation: crate::auth::jws::PermissionGrantInvocation::None,
            author_delegated_grant: None,
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
}
