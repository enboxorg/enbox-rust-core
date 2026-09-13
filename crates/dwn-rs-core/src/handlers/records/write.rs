use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::records::is_initial_write;
use crate::descriptors::{
    messages::record_id, records::records_write_descriptor, Descriptor, Records,
    RecordsWriteDescriptor,
};
use crate::dwn::core_protocol::CoreProtocolStores;
use crate::dwn::core_protocol::{CoreProtocolError, CoreProtocolRegistry};
use crate::dwn::{Handler, HandlerContext};
use crate::encryption::control::ControlKind;
use crate::errors::{DwnError, DwnErrorCode};
use crate::filters::Filters;
use crate::handlers::protocols::configure::ProtocolDefinitionLookupError;
use crate::handlers::records::common::{
    authorize_against_protocol, compare_messages, core_protocol_error_reply,
    delete_from_data_store_if_needed, encoded_data_bytes, filter_map, find_initial_write,
    message_cid, newest_message, records_write_indexes, store_error_reply, string_filter,
    validate_records_write_integrity, verify_immutable_properties, GoverningTimestampError,
};
use crate::handlers::records::control;
use crate::permissions::{self, AuthorizationContext};
use crate::replies::records::Write;
use crate::replies::Status;
use crate::Message;
use crate::Response;

use super::state::{plan_records_transition, RecordsTransitionPlan};
use super::{data, integrity, squash};
use super::{RecordsAuthorizationKind, RECORDS_INTERFACE};

#[derive(Clone)]
pub struct RecordsWriteHandler<MessageStore, DataStore> {
    message_store: MessageStore,
    data_store: DataStore,
    core_protocol_registry: CoreProtocolRegistry,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RecordsWriteValidationError {
    #[error(transparent)]
    Dwn(#[from] DwnError),
    #[error("{0}")]
    Detail(String),
    #[error("{0}")]
    Internal(String),
}

impl From<control::ControlValidationError> for RecordsWriteValidationError {
    /// Control admission distinguishes the same three outcomes this handler
    /// does, so the mapping is one-to-one: a record defect stays a bad request,
    /// an unavailable store stays an internal failure.
    fn from(error: control::ControlValidationError) -> Self {
        match error {
            control::ControlValidationError::Dwn(error) => Self::Dwn(error),
            control::ControlValidationError::Detail(detail) => Self::Detail(detail),
            control::ControlValidationError::Internal(detail) => Self::Internal(detail),
        }
    }
}

impl From<String> for RecordsWriteValidationError {
    fn from(detail: String) -> Self {
        Self::Detail(detail)
    }
}

impl From<GoverningTimestampError> for RecordsWriteValidationError {
    fn from(error: GoverningTimestampError) -> Self {
        match error {
            GoverningTimestampError::Dwn(error) => Self::Dwn(error),
            GoverningTimestampError::Detail(detail) => Self::Detail(detail),
        }
    }
}

impl From<ProtocolDefinitionLookupError> for RecordsWriteValidationError {
    fn from(error: ProtocolDefinitionLookupError) -> Self {
        match error {
            ProtocolDefinitionLookupError::NotFound(protocol) => Self::Dwn(DwnError::new(
                DwnErrorCode::ProtocolAuthorizationProtocolNotFound,
                format!("unable to find protocol definition for {protocol}"),
            )),
            ProtocolDefinitionLookupError::Store(detail) => Self::Internal(detail),
            ProtocolDefinitionLookupError::InvalidMessage(detail) => Self::Detail(detail),
        }
    }
}

impl<MessageStore, DataStore> Handler for RecordsWriteHandler<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    type Reply = Write;
    type Descriptor = RecordsWriteDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = Response<Self::Reply>> + Send {
        async move {
            let HandlerContext {
                tenant,
                mut message,
                descriptor,
                data,
                ..
            } = ctx;

            // Covers: DWN-REC-003
            // Exact replay is classified from the parsed message alone, before
            // authentication and before mutable protocol, role, grant, parent,
            // record-limit, or state-relative admission can reinterpret it. An
            // identical retained CID is the same bytes the store already
            // admitted, so re-resolving its signer proves nothing and must not
            // be able to turn a settled replay into a different reply when the
            // resolver is unreachable.
            let record_id = match record_id(&message) {
                Some(record_id) => record_id,
                None => {
                    return Response::bad_request(
                        "RecordsWriteMissingRecordId: recordId is required".to_string(),
                    )
                }
            };
            let existing_messages = match self.existing_record_messages(tenant, &record_id).await {
                Ok(messages) => messages,
                Err(reply) => return reply,
            };
            let transition_plan = match plan_records_transition(&message, &existing_messages) {
                Ok(plan) => plan,
                Err(detail) => return Response::bad_request(detail),
            };
            if matches!(transition_plan, RecordsTransitionPlan::Duplicate { .. }) {
                return Response::conflict();
            }

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

            if let Err(detail) = validate_records_write_integrity(&message, &signature) {
                return Response::bad_request(detail);
            }

            if let Err(error) = integrity::validate_referential_integrity(
                tenant,
                &message,
                &signature.author,
                &self.core_protocol_registry,
                &self.message_store,
            )
            .await
            {
                return match error {
                    RecordsWriteValidationError::Dwn(error) => Response::bad_request_error(error),
                    RecordsWriteValidationError::Detail(detail) => Response::bad_request(detail),
                    RecordsWriteValidationError::Internal(detail) => {
                        Response::internal_error(detail)
                    }
                };
            }

            if let Err(detail) = self
                .authorize_records_write(tenant, &message, &signature)
                .await
            {
                return Response::unauthorized(detail);
            }

            if let Err(error) = self
                .core_protocol_registry
                .pre_process_write(tenant, &message, &self.message_store)
                .await
            {
                return match error {
                    CoreProtocolError::GrantKey(error) => error.reply(),
                    CoreProtocolError::Detail(detail) => {
                        core_protocol_error_reply(&self.core_protocol_registry, detail)
                    }
                };
            }

            let incoming_is_initial = match is_initial_write(&message, &signature.author) {
                Ok(is_initial) => is_initial,
                Err(detail) => return Response::bad_request(detail),
            };

            if !incoming_is_initial {
                let Some(initial_write) = find_initial_write(&existing_messages, &signature.author)
                else {
                    return Response::bad_request_error(DwnError::new(
                        DwnErrorCode::RecordsWriteGetInitialWriteNotFound,
                        "Initial write is not found.",
                    ));
                };
                if let Err(detail) = verify_immutable_properties(&initial_write, &message) {
                    return Response::bad_request_error(detail);
                }
            }

            if let Err(error) =
                squash::enforce_squash_backstop(tenant, &message, &self.message_store).await
            {
                return match error {
                    RecordsWriteValidationError::Dwn(error) => Response::conflict_error(error),
                    RecordsWriteValidationError::Detail(detail) => {
                        Response::new(Status::new(409, detail), Write::default())
                    }
                    RecordsWriteValidationError::Internal(detail) => {
                        Response::internal_error(detail)
                    }
                };
            }

            let newest_existing = newest_message(&existing_messages);
            if matches!(transition_plan, RecordsTransitionPlan::Superseded { .. }) {
                if newest_existing.as_ref().is_some_and(|existing| {
                    matches!(
                        &existing.descriptor,
                        Descriptor::Records(records)
                            if matches!(records.as_ref(), Records::Delete(_))
                    ) && compare_messages(&message, existing).is_gt()
                }) {
                    return Response::bad_request_error(DwnError::new(
                        DwnErrorCode::RecordsWriteNotAllowedAfterDelete,
                        "RecordsWrite is not allowed after a RecordsDelete.",
                    ));
                }
                return Response::conflict();
            }

            let mut is_latest_base_state = false;
            let supplied_data = data.or_else(|| encoded_data_bytes(&message).ok().flatten());

            // A control record's data *is* its content: an audience without a
            // payload publishes no key, and a delivery without one delivers
            // nothing. Admitting it dataless would also be unrepairable —
            // resubmitting the same message with its data attached is an exact
            // replay and answers 409 — so the record would be permanently
            // stuck describing nothing.
            if supplied_data.is_none() && ControlKind::of(&message).is_some() {
                return Response::bad_request_error(DwnError::new(
                    DwnErrorCode::EncryptionControlValidateUnexpectedRecord,
                    "encryption control records must be written with their data",
                ));
            }

            if let Some(data) = supplied_data {
                if let Err(error) = data::process_message_with_data_stream(
                    tenant,
                    &mut message,
                    data,
                    &self.message_store,
                    &self.data_store,
                )
                .await
                {
                    return match error {
                        RecordsWriteValidationError::Dwn(error) => {
                            Response::bad_request_error(error)
                        }
                        RecordsWriteValidationError::Detail(detail) => {
                            Response::bad_request(detail)
                        }
                        RecordsWriteValidationError::Internal(detail) => {
                            Response::internal_error(detail)
                        }
                    };
                }
                is_latest_base_state = true;
            } else if !incoming_is_initial {
                let Some(newest_existing_write) = newest_existing
                    .as_ref()
                    .filter(|message| records_write_descriptor(message).is_ok())
                else {
                    return Response::bad_request_error(DwnError::new(
                        DwnErrorCode::RecordsWriteMissingDataInPrevious,
                        "No dataStream was provided and unable to get data from previous message",
                    ));
                };
                if let Err(error) = data::process_message_without_data_stream(
                    tenant,
                    &mut message,
                    newest_existing_write,
                    &self.data_store,
                )
                .await
                {
                    return match error {
                        RecordsWriteValidationError::Dwn(error) => {
                            Response::bad_request_error(error)
                        }
                        RecordsWriteValidationError::Detail(detail) => {
                            Response::bad_request(detail)
                        }
                        RecordsWriteValidationError::Internal(detail) => {
                            Response::internal_error(detail)
                        }
                    };
                }
                is_latest_base_state = true;
            }

            if let Err(error) = self.core_protocol_registry.validate_record(&message, None) {
                return match error {
                    CoreProtocolError::GrantKey(error) => error.reply(),
                    CoreProtocolError::Detail(detail) => {
                        core_protocol_error_reply(&self.core_protocol_registry, detail)
                    }
                };
            }

            let indexes =
                match records_write_indexes(&message, &signature.author, is_latest_base_state) {
                    Ok(indexes) => indexes,
                    Err(detail) => return Response::bad_request(detail),
                };
            let cleanup_cids = match &transition_plan {
                RecordsTransitionPlan::Apply { outranked_cids, .. } => outranked_cids.clone(),
                RecordsTransitionPlan::Duplicate { .. }
                | RecordsTransitionPlan::Superseded { .. } => Vec::new(),
            };
            let transition = match squash::records_write_transition(
                &message,
                indexes,
                &existing_messages,
                &transition_plan,
                &signature.author,
            ) {
                Ok(transition) => transition,
                Err(detail) => return Response::bad_request(detail),
            };
            if let Err(err) = self
                .message_store
                .commit_latest_state(tenant, transition)
                .await
            {
                return store_error_reply(err.to_string());
            }
            for existing in &existing_messages {
                if cleanup_cids
                    .iter()
                    .any(|cid| message_cid(existing).as_deref() == Ok(cid.as_str()))
                {
                    if let Err(detail) = delete_from_data_store_if_needed(
                        tenant,
                        existing,
                        &message,
                        &self.data_store,
                    )
                    .await
                    {
                        return store_error_reply(detail);
                    }
                }
            }

            if descriptor.squash == Some(true) {
                if let Err(detail) = squash::perform_records_squash(
                    &self.message_store,
                    &self.data_store,
                    tenant,
                    &message,
                )
                .await
                {
                    return store_error_reply(detail);
                }
            }

            if let Err(detail) = self
                .core_protocol_registry
                .post_process_write(
                    tenant,
                    &message,
                    CoreProtocolStores {
                        message_store: &self.message_store,
                        data_store: &self.data_store,
                    },
                )
                .await
            {
                return store_error_reply(detail);
            }

            if incoming_is_initial && !is_latest_base_state {
                Response::no_content()
            } else {
                Response::accepted()
            }
        }
    }
}

impl<MessageStore, DataStore> RecordsWriteHandler<MessageStore, DataStore> {
    /// Construct a handler.
    pub fn new(
        message_store: MessageStore,
        data_store: DataStore,
        did_resolver: Option<Arc<dyn DidResolver>>,
    ) -> Self {
        Self {
            message_store,
            data_store,
            core_protocol_registry: CoreProtocolRegistry::with_core_protocols(),
            did_resolver,
        }
    }
}

impl<MessageStore, DataStore> RecordsWriteHandler<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    // The error path returns the DWN reply itself; boxing it would only move the
    // allocation to every caller.
    #[allow(clippy::result_large_err)]
    async fn existing_record_messages(
        &self,
        tenant: &str,
        record_id: &str,
    ) -> Result<Vec<Message<Descriptor>>, Response<Write>> {
        let filter = filter_map([
            ("interface", string_filter(RECORDS_INTERFACE)),
            ("recordId", string_filter(record_id)),
        ]);
        self.message_store
            .query(tenant, Filters::from(filter), None, None, None)
            .await
            .map(|result| result.messages)
            .map_err(|err| store_error_reply(err.to_string()))
    }

    async fn authorize_records_write(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        auth: &AuthorizationContext,
    ) -> Result<(), String> {
        // Control writes carry their own authority question — may this actor
        // mint this role's key material — so they do not fall through to the
        // ordinary grant and protocol-action ladder.
        if let Some(kind) = ControlKind::of(message) {
            return control::authorize_write(tenant, message, kind, auth, &self.message_store)
                .await
                .map_err(|error| error.to_string());
        }
        if permissions::authorize_delegated_records_write(message, auth, &self.message_store)
            .await
            .map_err(|error| error.to_string())?
        {
            return Ok(());
        }
        if auth.author == tenant {
            return Ok(());
        }
        if permissions::authorize_records_write_with_grant_id(
            tenant,
            message,
            auth,
            &self.message_store,
        )
        .await
        .map_err(|error| error.to_string())?
        {
            return Ok(());
        }
        self.authorize_against_protocol(
            tenant,
            message,
            &auth.author,
            RecordsAuthorizationKind::Write,
        )
        .await
    }

    async fn authorize_against_protocol(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        author: &str,
        kind: RecordsAuthorizationKind,
    ) -> Result<(), String> {
        authorize_against_protocol(tenant, message, author, kind, &self.message_store).await
    }
}
