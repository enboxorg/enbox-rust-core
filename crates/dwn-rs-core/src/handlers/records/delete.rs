use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Bound;
use std::pin::Pin;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use chrono::SecondsFormat;
use futures_util::{stream, TryStreamExt};
use serde_json::{json, Value as JsonValue};

use crate::auth::JwsPublicKeyResolver;
use crate::cid::{
    generate_cid_from_json, generate_dag_pb_cid_from_bytes, generate_message_cid_from_json,
};
use crate::core_protocol::{CoreProtocolRegistry, CoreProtocolStores};
use crate::descriptors::records::CountDescriptor;
use crate::descriptors::{
    DeleteDescriptor, Descriptor, ReadDescriptor, Records, RecordsQueryDescriptor,
    RecordsWriteDescriptor, SubscribeDescriptor,
};
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::errors::EventLogError;
use crate::fields::{Fields, WriteFields};
use crate::filters::message_filters::Records as RecordsFilter;
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::interfaces::messages::protocols::{
    self as protocol_types, Action, Can, Definition, RuleSet, Who,
};
use crate::interfaces::replies::Status;
use crate::permissions::{self, AuthorizationContext};
use crate::stores::{EventLogSubscribeOptions, EventSubscription, KeyValues, SubscriptionListener};
use crate::{Message, MessageSort, Pagination, SortDirection, Value};

use super::common::*;
use super::write::perform_records_squash;
use super::{RecordsAuthorizationKind, RecordsDeleteHandler};

impl<MessageStore, DataStore, StateIndex> RecordsDeleteHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    pub async fn handle_delete(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match records_delete_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let signature = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            true,
        ) {
            Ok(Some(signature)) => signature,
            Ok(None) => {
                return DwnReply::unauthorized(
                    "AuthenticateJwsMissing: authorization signature is required",
                )
            }
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return DwnReply::bad_request(detail)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
        };

        let existing_messages =
            match fetch_record_messages(tenant, &descriptor.record_id, &self.message_store).await {
                Ok(messages) => messages,
                Err(detail) => return store_error_reply(detail),
            };
        let Some(newest_existing) = newest_message(&existing_messages) else {
            return not_found_reply();
        };
        if !can_perform_delete_against_record(&message, &newest_existing) {
            return not_found_reply();
        }
        if compare_messages(&message, &newest_existing) != Ordering::Greater {
            return conflict_reply();
        }

        let initial_write = match find_initial_write(
            &existing_messages,
            extract_author(&newest_existing)
                .as_deref()
                .unwrap_or_default(),
        )
        .or_else(|| {
            existing_messages
                .iter()
                .find(|message| records_write_descriptor(message).is_ok())
                .cloned()
        }) {
            Some(message) => message,
            None => {
                return DwnReply::unauthorized(
                    "RecordsDeleteAuthorizationFailed: initial write not found",
                )
            }
        };
        if let Err(detail) = authorize_records_delete(
            tenant,
            &message,
            &initial_write,
            &signature,
            &self.message_store,
        )
        .await
        {
            return DwnReply::unauthorized(detail);
        }

        if let Err(detail) = perform_records_delete(
            &self.message_store,
            &self.data_store,
            &self.state_index,
            tenant,
            &message,
            &existing_messages,
            &initial_write,
        )
        .await
        {
            return store_error_reply(detail);
        }
        accepted_reply()
    }
}

pub(crate) async fn perform_records_delete<MessageStore, DataStore, StateIndex>(
    message_store: &MessageStore,
    data_store: &DataStore,
    state_index: &StateIndex,
    tenant: &str,
    message: &Message<Descriptor>,
    existing_messages: &[Message<Descriptor>],
    initial_write: &Message<Descriptor>,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    let author = extract_author(message)
        .ok_or_else(|| "RecordsDeleteMissingAuthor: author is required".to_string())?;
    let indexes = records_delete_indexes(message, initial_write, &author)?;
    message_store
        .put(tenant, message.clone(), indexes.clone())
        .await
        .map_err(|err| err.to_string())?;
    let cid = message_cid(message)?;
    state_index
        .insert(tenant, &cid, indexes)
        .await
        .map_err(|err| err.to_string())?;

    let descriptor = records_delete_descriptor(message)?;
    if descriptor.prune {
        purge_record_descendants(
            tenant,
            &descriptor.record_id,
            message_store,
            data_store,
            state_index,
        )
        .await?;
    }

    for existing in existing_messages {
        if compare_messages(existing, message) == Ordering::Less {
            delete_from_data_store_if_needed(tenant, existing, message, data_store).await?;
            let old_cid = message_cid(existing)?;
            message_store
                .delete(tenant, &old_cid)
                .await
                .map_err(|err| err.to_string())?;
            state_index
                .delete(tenant, std::slice::from_ref(&old_cid))
                .await
                .map_err(|err| err.to_string())?;
            if records_write_descriptor(existing).is_ok()
                && record_id(existing) == Some(descriptor.record_id.clone())
                && is_initial_write(
                    existing,
                    extract_author(existing).as_deref().unwrap_or_default(),
                )
                .unwrap_or(false)
            {
                let mut initial = existing.clone();
                set_encoded_data(&mut initial, None)?;
                let author = extract_author(&initial).unwrap_or_default();
                let indexes = records_write_indexes(&initial, &author, false)?;
                message_store
                    .put(tenant, initial.clone(), indexes.clone())
                    .await
                    .map_err(|err| err.to_string())?;
                let new_cid = message_cid(&initial)?;
                state_index
                    .insert(tenant, &new_cid, indexes)
                    .await
                    .map_err(|err| err.to_string())?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn resume_records_delete_from_task<MessageStore, DataStore, StateIndex>(
    message_store: &MessageStore,
    data_store: &DataStore,
    state_index: &StateIndex,
    tenant: &str,
    raw_message: &JsonValue,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    let message = parse_message(raw_message)?;
    let descriptor = records_delete_descriptor(&message)?;
    let existing_messages =
        fetch_record_messages(tenant, &descriptor.record_id, message_store).await?;
    let Some(newest_existing) = newest_message(&existing_messages) else {
        return Ok(());
    };
    if !can_perform_delete_against_record(&message, &newest_existing) {
        return Ok(());
    }
    let initial_write = find_initial_write(
        &existing_messages,
        extract_author(&newest_existing)
            .as_deref()
            .unwrap_or_default(),
    )
    .or_else(|| {
        existing_messages
            .iter()
            .find(|message| records_write_descriptor(message).is_ok())
            .cloned()
    })
    .ok_or_else(|| "RecordsDeleteAuthorizationFailed: initial write not found".to_string())?;
    perform_records_delete(
        message_store,
        data_store,
        state_index,
        tenant,
        &message,
        &existing_messages,
        &initial_write,
    )
    .await
}

pub(crate) async fn resume_records_squash_from_task<MessageStore, DataStore, StateIndex>(
    message_store: &MessageStore,
    data_store: &DataStore,
    state_index: &StateIndex,
    tenant: &str,
    raw_message: &JsonValue,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    let message = parse_message(raw_message)?;
    perform_records_squash(message_store, data_store, state_index, tenant, &message).await
}
