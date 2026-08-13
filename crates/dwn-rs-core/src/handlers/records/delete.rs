use std::cmp::Ordering;
use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::{
    messages::record_id, records::records_write_descriptor, DeleteDescriptor, Descriptor,
};
use crate::dwn::{Handler, HandlerContext};
use crate::handlers::records::common::{
    authorize_records_delete, can_perform_delete_against_record, compare_messages,
    delete_from_data_store_if_needed, extract_author, fetch_record_messages, find_initial_write,
    is_initial_write, message_cid, newest_message, purge_record_descendants,
    records_delete_descriptor, records_delete_indexes, records_write_indexes, set_encoded_data,
    store_error_reply,
};
use crate::permissions::{self};
use crate::Message;
use crate::Response;

use super::write::perform_records_squash;

#[derive(Clone)]
pub struct RecordsDeleteHandler<MessageStore, DataStore, StateIndex> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MessageStore, DataStore, StateIndex> Handler
    for RecordsDeleteHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    type Reply = ();
    type Descriptor = DeleteDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = Response<Self::Reply>> + Send {
        async move {
            let HandlerContext {
                tenant,
                message,
                descriptor,
                ..
            } = ctx;

            let signature = match permissions::validate_authorization_signature(
                &message,
                self.did_resolver.as_deref(),
                true,
            )
            .await
            {
                Ok(Some(signature)) => signature,
                Ok(None) => {
                    return Response::unauthorized(
                        "AuthenticateJwsMissing: authorization signature is required".to_string(),
                    )
                }
                Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                    return Response::bad_request(detail.to_string())
                }
                Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                    return Response::unauthorized(detail.to_string())
                }
                Err(error) => return Response::bad_request(error.to_string()),
            };

            let existing_messages =
                match fetch_record_messages(tenant, &descriptor.record_id, &self.message_store)
                    .await
                {
                    Ok(messages) => messages,
                    Err(detail) => return store_error_reply(detail),
                };
            let Some(newest_existing) = newest_message(&existing_messages) else {
                return Response::not_found();
            };
            if !can_perform_delete_against_record(&message, &newest_existing) {
                return Response::not_found();
            }
            if compare_messages(&message, &newest_existing) != Ordering::Greater {
                return Response::conflict();
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
                    return Response::unauthorized(
                        "RecordsDeleteAuthorizationFailed: initial write not found".to_string(),
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
                return Response::unauthorized(detail);
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

            Response::accepted()
        }
    }
}

impl<MessageStore, DataStore, StateIndex>
    RecordsDeleteHandler<MessageStore, DataStore, StateIndex>
{
    pub fn new(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
        did_resolver: Option<Arc<dyn DidResolver>>,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
            did_resolver,
        }
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
    message: &Message<Descriptor>,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    let descriptor = records_delete_descriptor(message)?;
    let existing_messages =
        fetch_record_messages(tenant, &descriptor.record_id, message_store).await?;
    let Some(newest_existing) = newest_message(&existing_messages) else {
        return Ok(());
    };
    if !can_perform_delete_against_record(message, &newest_existing) {
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
        message,
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
    message: &Message<Descriptor>,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    perform_records_squash(message_store, data_store, state_index, tenant, message).await
}
