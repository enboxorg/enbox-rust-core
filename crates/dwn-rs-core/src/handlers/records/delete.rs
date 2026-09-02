use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::records::is_initial_write;
use crate::descriptors::{
    messages::record_id, records::records_write_descriptor, DeleteDescriptor, Descriptor,
};
use crate::dwn::{Handler, HandlerContext};
use crate::handlers::records::common::{
    authorize_records_delete, delete_from_data_store_if_needed, extract_author,
    fetch_record_messages, find_initial_write, message_cid, newest_message,
    purge_record_descendants, records_delete_descriptor, records_delete_indexes,
    records_write_indexes, set_encoded_data, store_error_reply,
};
use crate::permissions::{self};
use crate::stores::{KeyValues, LatestStateMutation, LatestStateTransition};
use crate::Message;
use crate::Response;

use super::state::{plan_records_transition, RecordsTransitionPlan};
use super::write::perform_records_squash;

#[derive(Clone)]
pub struct RecordsDeleteHandler<MessageStore, DataStore, StateIndex> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

struct PreparedRecordsDeleteTransition {
    durable: LatestStateTransition,
    cleanup_cids: Vec<String>,
}

struct RecordsDeleteExecution<'a> {
    message: &'a Message<Descriptor>,
    existing_messages: &'a [Message<Descriptor>],
    initial_write: &'a Message<Descriptor>,
    plan: &'a RecordsTransitionPlan,
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
            let transition_plan = match plan_records_transition(&message, &existing_messages) {
                Ok(plan) => plan,
                Err(detail) => return Response::bad_request(detail),
            };

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

            if matches!(
                transition_plan,
                RecordsTransitionPlan::Duplicate { .. } | RecordsTransitionPlan::Superseded { .. }
            ) {
                return Response::conflict();
            }

            if let Err(detail) = perform_records_delete(
                &self.message_store,
                &self.data_store,
                &self.state_index,
                tenant,
                RecordsDeleteExecution {
                    message: &message,
                    existing_messages: &existing_messages,
                    initial_write: &initial_write,
                    plan: &transition_plan,
                },
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

async fn perform_records_delete<MessageStore, DataStore, StateIndex>(
    message_store: &MessageStore,
    data_store: &DataStore,
    state_index: &StateIndex,
    tenant: &str,
    execution: RecordsDeleteExecution<'_>,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    let RecordsDeleteExecution {
        message,
        existing_messages,
        initial_write,
        plan,
    } = execution;
    let delete_author = extract_author(message)
        .ok_or_else(|| "RecordsDeleteMissingAuthor: author is required".to_string())?;
    let indexes = records_delete_indexes(message, initial_write, &delete_author)?;
    let PreparedRecordsDeleteTransition {
        durable,
        cleanup_cids,
    } = prepare_records_delete_transition(message, indexes.clone(), existing_messages, plan)?;
    message_store
        .commit_latest_state(tenant, durable)
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
        if cleanup_cids
            .iter()
            .any(|cid| message_cid(existing).as_deref() == Ok(cid.as_str()))
        {
            delete_from_data_store_if_needed(tenant, existing, message, data_store).await?;
        }
    }
    Ok(())
}

fn prepare_records_delete_transition(
    message: &Message<Descriptor>,
    indexes: KeyValues,
    existing_messages: &[Message<Descriptor>],
    plan: &RecordsTransitionPlan,
) -> Result<PreparedRecordsDeleteTransition, String> {
    let cleanup_cids = match plan {
        RecordsTransitionPlan::Apply { outranked_cids, .. } => outranked_cids.clone(),
        RecordsTransitionPlan::Duplicate { .. } => Vec::new(),
        RecordsTransitionPlan::Superseded { .. } => {
            return Err(
                "RecordsStateSupersededTransition: superseded delete cannot be committed"
                    .to_string(),
            )
        }
    };
    let descriptor = records_delete_descriptor(message)?;
    let mut retains = Vec::new();
    let mut deleted_cids = Vec::new();

    for existing in existing_messages {
        let existing_cid = message_cid(existing)?;
        if !cleanup_cids.contains(&existing_cid) {
            continue;
        }
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
            let initial_indexes = records_write_indexes(&initial, &author, false)?;
            retains.push(LatestStateMutation {
                message: initial,
                indexes: initial_indexes,
            });
        } else {
            deleted_cids.push(existing_cid);
        }
    }

    Ok(PreparedRecordsDeleteTransition {
        durable: LatestStateTransition {
            put: LatestStateMutation {
                message: message.clone(),
                indexes,
            },
            retains,
            deletes: deleted_cids.clone(),
        },
        cleanup_cids,
    })
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
    let plan = plan_records_transition(message, &existing_messages)?;
    if matches!(plan, RecordsTransitionPlan::Superseded { .. }) {
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
        RecordsDeleteExecution {
            message,
            existing_messages: &existing_messages,
            initial_write: &initial_write,
            plan: &plan,
        },
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
