//! Squash handling for records writes: the backstop that keeps stale
//! messages below the newest squash record, the commit-time transition
//! builder, and the sibling-purge sweep.

use std::collections::BTreeMap;

use crate::descriptors::{
    messages::record_id,
    records::{is_initial_write, records_write_descriptor},
    Descriptor,
};
use crate::filters::{Filter, FilterKey, Filters};
use crate::handlers::protocols::configure::fetch_protocol_definition;
use crate::handlers::records::common::{
    bool_filter, context_id, filter_map, message_cid, message_record_id, newest_message,
    parent_context_id, purge_record_messages, records_write_indexes, set_encoded_data,
    string_filter,
};

use crate::stores::{KeyValues, LatestStateMutation, LatestStateTransition};
use crate::SubtreeFilter;
use crate::{canonical_rfc3339, Message, MessageSort, Pagination, SortDirection};

use super::state::RecordsTransitionPlan;
use super::write::RecordsWriteValidationError;
use super::{RECORDS_INTERFACE, WRITE_METHOD};
use crate::errors::{DwnError, DwnErrorCode};

pub(crate) async fn enforce_squash_backstop<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
) -> Result<(), RecordsWriteValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor = records_write_descriptor(message).map_err(|error| error.to_string())?;
    let definition =
        match fetch_protocol_definition(tenant, &descriptor.protocol, message_store, None).await {
            Ok(definition) => definition,
            Err(_) => return Ok(()),
        };
    let Some(rule_set) = definition.rule_at(&descriptor.protocol_path) else {
        return Ok(());
    };
    if rule_set.squash != Some(true) {
        return Ok(());
    }

    let mut filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("method", string_filter(WRITE_METHOD)),
        ("isLatestBaseState", bool_filter(true)),
        ("protocol", string_filter(&descriptor.protocol)),
        ("protocolPath", string_filter(&descriptor.protocol_path)),
        ("squash", bool_filter(true)),
    ]);
    if let Some(parent_context) =
        context_id(message).and_then(|context| parent_context_id(&context))
    {
        if !parent_context.is_empty() {
            filter.insert(
                FilterKey::Index("contextId".to_string()),
                Filter::Subtree(SubtreeFilter {
                    subtree: parent_context,
                }),
            );
        }
    }

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
    let Some(newest_squash) = result.messages.first() else {
        return Ok(());
    };
    let newest_timestamp = newest_squash.message_timestamp();
    if descriptor.message_timestamp <= newest_timestamp {
        let squash_floor_timestamp = canonical_rfc3339(newest_timestamp);
        return Err(DwnError::new(
            DwnErrorCode::ProtocolAuthorizationSquashBackstop,
            format!(
                "incoming message timestamp '{}' is not newer than the most recent squash record timestamp '{}' at protocol path '{}'.",
                canonical_rfc3339(descriptor.message_timestamp),
                squash_floor_timestamp,
                descriptor.protocol_path
            ),
        )
        .with_info(BTreeMap::from([(
            "squashFloorTimestamp".to_string(),
            serde_json::Value::String(squash_floor_timestamp),
        )]))
        .into());
    }
    Ok(())
}

pub(crate) fn records_write_transition(
    message: &Message<Descriptor>,
    indexes: KeyValues,
    existing_messages: &[Message<Descriptor>],
    plan: &RecordsTransitionPlan,
    author: &str,
) -> Result<LatestStateTransition, String> {
    let outranked_cids = match plan {
        RecordsTransitionPlan::Apply { outranked_cids, .. } => outranked_cids.as_slice(),
        RecordsTransitionPlan::Duplicate { .. } => &[],
        RecordsTransitionPlan::Superseded { .. } => {
            return Err(
                "RecordsStateSupersededTransition: superseded write cannot be committed"
                    .to_string(),
            )
        }
    };
    let mut retains = Vec::new();
    let mut deletes = Vec::new();

    for existing in existing_messages {
        let existing_cid = message_cid(existing)?;
        if !outranked_cids.contains(&existing_cid) {
            continue;
        }
        if is_initial_write(existing, author).unwrap_or(false) {
            let mut initial_write = existing.clone();
            set_encoded_data(&mut initial_write, None)?;
            let indexes = records_write_indexes(&initial_write, author, false)?;
            retains.push(LatestStateMutation {
                message: initial_write,
                indexes,
            });
        } else {
            deletes.push(existing_cid);
        }
    }

    Ok(LatestStateTransition {
        put: LatestStateMutation {
            message: message.clone(),
            indexes,
        },
        retains,
        deletes,
    })
}

pub(crate) async fn perform_records_squash<MessageStore, DataStore>(
    message_store: &MessageStore,
    data_store: &DataStore,
    tenant: &str,
    message: &Message<Descriptor>,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    let descriptor = records_write_descriptor(message)?;
    let record_id = record_id(message)
        .ok_or_else(|| "RecordsWriteMissingRecordId: recordId is required".to_string())?;
    let mut filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("protocol", string_filter(&descriptor.protocol)),
        ("protocolPath", string_filter(&descriptor.protocol_path)),
    ]);
    if let Some(parent_context) =
        context_id(message).and_then(|context| parent_context_id(&context))
    {
        if !parent_context.is_empty() {
            filter.insert(
                FilterKey::Index("contextId".to_string()),
                Filter::Subtree(SubtreeFilter {
                    subtree: parent_context,
                }),
            );
        }
    }
    let sibling_messages = message_store
        .query(tenant, Filters::from(filter), None, None, None)
        .await
        .map_err(|err| err.to_string())?
        .messages;
    let mut by_record_id = BTreeMap::<String, Vec<Message<Descriptor>>>::new();
    for sibling in sibling_messages {
        if let Some(sibling_record_id) = message_record_id(&sibling) {
            by_record_id
                .entry(sibling_record_id)
                .or_default()
                .push(sibling);
        }
    }
    for (sibling_record_id, messages) in by_record_id {
        if sibling_record_id == record_id {
            continue;
        }
        let Some(newest) = newest_message(&messages) else {
            continue;
        };
        if newest.message_timestamp() < descriptor.message_timestamp {
            purge_record_messages(tenant, &messages, message_store, data_store).await?;
        }
    }
    Ok(())
}
