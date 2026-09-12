use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use futures_util::stream;

use crate::auth::resolver::DidResolver;
use crate::cid::generate_dag_pb_cid_from_bytes;
use crate::descriptors::records::is_initial_write;
use crate::descriptors::{
    messages::record_id,
    records::{records_write_descriptor, write_fields},
    Descriptor, Records, RecordsWriteDescriptor,
};
use crate::dwn::core_protocol::CoreProtocolStores;
use crate::dwn::core_protocol::{CoreProtocolError, CoreProtocolRegistry};
use crate::dwn::{Handler, HandlerContext};
use crate::encryption::control::ControlKind;
use crate::encryption::protocol::validate_encryption_delivery;
use crate::encryption::{
    KeyEncryption, ENCRYPTION_PROTOCOL_GRANT_KEY_PATH, ENCRYPTION_PROTOCOL_URI,
};
use crate::errors::{DwnError, DwnErrorCode};
use crate::filters::{Filter, FilterKey, Filters};
use crate::handlers::protocols::configure::{
    fetch_protocol_definition, ProtocolDefinitionLookupError,
};
use crate::handlers::records::common::{
    authorize_against_protocol, bool_filter, compare_messages, context_id,
    core_protocol_error_reply, delete_from_data_store_if_needed, encoded_data_bytes,
    fetch_newest_write, filter_map, find_initial_write, governing_timestamp, message_cid,
    message_record_id, newest_message, parent_context_id, purge_record_messages,
    records_write_indexes, set_encoded_data, store_error_reply, string_filter,
    validate_data_integrity, validate_records_write_integrity, verify_immutable_properties,
    GoverningTimestampError,
};
use crate::handlers::records::control;
use crate::interfaces::messages::protocols::{self as protocol_types};
use crate::permissions::{self, AuthorizationContext};
use crate::replies::records::Write;
use crate::replies::Status;
use crate::stores::{KeyValues, LatestStateMutation, LatestStateTransition};
use crate::Response;
use crate::SubtreeFilter;
use crate::{canonical_rfc3339, Message, MessageSort, Pagination, SortDirection};

use super::state::{plan_records_transition, RecordsTransitionPlan};
use super::{RecordsAuthorizationKind, MAX_ENCODED_DATA_SIZE, RECORDS_INTERFACE, WRITE_METHOD};

#[derive(Clone)]
pub struct RecordsWriteHandler<MessageStore, DataStore> {
    message_store: MessageStore,
    data_store: DataStore,
    core_protocol_registry: CoreProtocolRegistry,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

#[derive(Debug, thiserror::Error)]
enum RecordsWriteValidationError {
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

            if let Err(error) = self
                .validate_referential_integrity(tenant, &message, &signature.author)
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

            if let Err(error) = self.enforce_squash_backstop(tenant, &message).await {
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
                if let Err(error) = self
                    .process_message_with_data_stream(tenant, &mut message, data)
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
                if let Err(error) = self
                    .process_message_without_data_stream(
                        tenant,
                        &mut message,
                        newest_existing_write,
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
            let transition = match self.records_write_transition(
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
                if let Err(detail) =
                    perform_records_squash(&self.message_store, &self.data_store, tenant, &message)
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

    async fn process_message_with_data_stream(
        &self,
        tenant: &str,
        message: &mut Message<Descriptor>,
        data: Bytes,
    ) -> Result<(), RecordsWriteValidationError> {
        let descriptor = records_write_descriptor(message)
            .map_err(|error| error.to_string())?
            .clone();
        let actual_data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
        validate_data_integrity(
            &descriptor.data_cid,
            descriptor.data_size,
            &actual_data_cid,
            data.len() as u64,
        )?;

        // An audience record's payload is part of its admission contract: the
        // key it publishes and the seal over that key are checked here, once
        // the bytes the descriptor commits to are actually in hand.
        if let Some(kind) = ControlKind::from_protocol_path(&descriptor.protocol_path) {
            control::validate_payload(tenant, message, kind, &data, &self.message_store)
                .await
                .map_err(RecordsWriteValidationError::from)?;
        }

        if descriptor.data_size <= MAX_ENCODED_DATA_SIZE {
            // Grant-key payload validation runs where the bytes are in hand;
            // the post-processing hook below re-runs the descriptor half with
            // no data, which is what lets dataless initial writes through.
            // Only the encryption check runs here: the permissions check
            // reads back the encoded data set below, so it stays post-hoc.
            if descriptor.protocol.as_str() == ENCRYPTION_PROTOCOL_URI {
                validate_encryption_delivery(message, &data).map_err(|error| {
                    match error.code() {
                        Some(code) => {
                            RecordsWriteValidationError::Dwn(DwnError::new(code, error.detail()))
                        }
                        None => RecordsWriteValidationError::Internal(error.to_string()),
                    }
                })?;
            }
            set_encoded_data(message, Some(URL_SAFE_NO_PAD.encode(&data)))
                .map_err(RecordsWriteValidationError::from)?;
            return Ok(());
        }

        let record_id = record_id(message)
            .ok_or_else(|| "RecordsWriteMissingRecordId: recordId is required".to_string())?;
        let put_result = self
            .data_store
            .put(
                tenant,
                &record_id,
                &descriptor.data_cid,
                stream::iter(vec![data]),
            )
            .await
            .map_err(|err| RecordsWriteValidationError::Internal(err.to_string()))?;
        if put_result.data_size as u64 != descriptor.data_size {
            let _ = self
                .data_store
                .delete(tenant, &record_id, &descriptor.data_cid)
                .await;
            return Err(DwnError::new(
                DwnErrorCode::RecordsWriteDataSizeMismatch,
                format!(
                    "actual data size {} bytes does not match dataSize in descriptor: {}",
                    put_result.data_size, descriptor.data_size
                ),
            )
            .into());
        }
        set_encoded_data(message, None).map_err(RecordsWriteValidationError::from)
    }

    async fn process_message_without_data_stream(
        &self,
        tenant: &str,
        message: &mut Message<Descriptor>,
        newest_existing_write: &Message<Descriptor>,
    ) -> Result<(), RecordsWriteValidationError> {
        let descriptor = records_write_descriptor(message)
            .map_err(|error| error.to_string())?
            .clone();
        let newest_descriptor =
            records_write_descriptor(newest_existing_write).map_err(|error| error.to_string())?;
        validate_data_integrity(
            &descriptor.data_cid,
            descriptor.data_size,
            &newest_descriptor.data_cid,
            newest_descriptor.data_size,
        )?;

        if descriptor.data_size <= MAX_ENCODED_DATA_SIZE {
            let encoded_data = write_fields(newest_existing_write)
                .map_err(|error| error.to_string())?
                .encoded_data
                .clone()
                .ok_or_else(|| {
                    DwnError::new(
                        DwnErrorCode::RecordsWriteMissingEncodedDataInPrevious,
                        "No dataStream was provided and unable to get data from previous message",
                    )
                })?;
            set_encoded_data(message, Some(encoded_data))
                .map_err(RecordsWriteValidationError::from)?;
            return Ok(());
        }

        let record_id = record_id(newest_existing_write).ok_or_else(|| {
            "RecordsWriteMissingRecordId: previous recordId is required".to_string()
        })?;
        let has_data = self
            .data_store
            .get(tenant, &record_id, &descriptor.data_cid)
            .await
            .map_err(|err| err.to_string())?
            .is_some();
        if !has_data {
            return Err(DwnError::new(
                DwnErrorCode::RecordsWriteMissingDataInPrevious,
                "No dataStream was provided and unable to get data from previous message",
            )
            .into());
        }
        set_encoded_data(message, None).map_err(RecordsWriteValidationError::from)
    }

    async fn referenced_definition_for_ref_path(
        &self,
        tenant: &str,
        descriptor: &RecordsWriteDescriptor,
        definition: &protocol_types::Definition,
        governing_timestamp: &str,
    ) -> Result<Option<protocol_types::Definition>, RecordsWriteValidationError> {
        let Some(parsed) = definition.ref_position(descriptor.protocol_path.as_str()) else {
            return Ok(None);
        };
        let ref_uri = definition
            .uses
            .as_ref()
            .and_then(|uses| uses.get(parsed.alias))
            .ok_or_else(|| {
                format!(
                    "ProtocolsConfigureInvalidRefAlias: '$ref' alias '{}' at protocol path '{}' does not exist in the 'uses' map.",
                    parsed.alias, descriptor.protocol_path
                )
            })?;
        Ok(Some(
            fetch_protocol_definition(
                tenant,
                ref_uri,
                &self.message_store,
                Some(governing_timestamp),
            )
            .await?,
        ))
    }

    async fn validate_referential_integrity(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        author: &str,
    ) -> Result<(), RecordsWriteValidationError> {
        let descriptor = records_write_descriptor(message).map_err(|error| error.to_string())?;
        let protocol_path = descriptor.protocol_path.clone();

        // Control records live at virtual paths the protocol never declares, so
        // there is no type or rule set to validate them against. They are
        // admitted on their own fixed contract instead, and the application
        // encryption-policy checks below deliberately do not apply: a control
        // record's representation is fixed by its kind, not by the protocol.
        if let Some(kind) = ControlKind::from_protocol_path(&protocol_path) {
            return control::validate_referential_integrity(
                tenant,
                message,
                kind,
                author,
                &self.message_store,
            )
            .await
            .map_err(RecordsWriteValidationError::from);
        }

        let governing_timestamp =
            governing_timestamp(tenant, message, &self.message_store, author).await?;

        // check if protocol is defined in the core_protocol_registry and use that
        // definition, otherwise fetch the protocol definition from the message store
        let definition = if self.core_protocol_registry.has(&descriptor.protocol) {
            self.core_protocol_registry
                .get_definition(&descriptor.protocol)
                .ok_or_else(|| {
                    format!(
                        "ProtocolAuthorizationInvalidProtocol: {} is not defined",
                        descriptor.protocol
                    )
                })?
        } else {
            fetch_protocol_definition(
                tenant,
                &descriptor.protocol,
                &self.message_store,
                Some(&governing_timestamp),
            )
            .await?
        };
        let rule_set = definition
            .rule_at(descriptor.protocol_path.as_str())
            .ok_or_else(|| {
                format!("ProtocolAuthorizationInvalidProtocolPath: {protocol_path} is not defined")
            })?;

        // Covers: DWN-PROTO-001, DWN-PROTO-004, DWN-PROTO-005, DWN-ENC-001
        // Protocol-declared encryption representation is enforced at admission
        // against the definition governing the record timestamp. A record at
        // a `$ref` position follows the referenced protocol's type and key
        // namespace at the referenced target path; locally declared
        // descendants follow the composing type map.
        let referenced = self
            .referenced_definition_for_ref_path(
                tenant,
                descriptor,
                &definition,
                &governing_timestamp,
            )
            .await?;
        let ref_position = definition.ref_position(descriptor.protocol_path.as_str());
        let (types, type_name) = match (&referenced, &ref_position) {
            (Some(referenced), Some(position)) => (
                &referenced.types,
                position
                    .protocol_path
                    .split('/')
                    .next_back()
                    .unwrap_or_default(),
            ),
            _ => (
                &definition.types,
                descriptor
                    .protocol_path
                    .split('/')
                    .next_back()
                    .unwrap_or_default(),
            ),
        };
        let key_agreement = match (&referenced, &ref_position) {
            (Some(referenced), Some(position)) => referenced
                .rule_at(position.protocol_path)
                .and_then(|rule_set| rule_set.key_agreement.as_ref()),
            _ => rule_set.key_agreement.as_ref(),
        };
        let encryption_required = types
            .get(type_name)
            .and_then(|protocol_type| protocol_type.encryption_required)
            == Some(true);
        let fields = write_fields(message).map_err(|error| error.to_string())?;
        let has_envelope = fields.encryption.is_some();
        if encryption_required && !has_envelope {
            return Err(DwnError::new(
                DwnErrorCode::ProtocolAuthorizationEncryptionRequired,
                format!(
                    "type '{type_name}' requires encryption but message has no encryption metadata"
                ),
            )
            .into());
        }
        if !encryption_required && has_envelope {
            return Err(DwnError::new(
                DwnErrorCode::ProtocolAuthorizationEncryptionNotAllowed,
                format!(
                    "type '{type_name}' requires plaintext but message has encryption metadata"
                ),
            )
            .into());
        }
        if encryption_required {
            match key_agreement {
                Some(agreement) => {
                    let key_id = agreement.public_key_jwk.thumbprint().map_err(|error| {
                        RecordsWriteValidationError::Internal(error.to_string())
                    })?;
                    let Some(envelope) = fields.encryption.as_ref() else {
                        return Err(DwnError::new(
                            DwnErrorCode::ProtocolAuthorizationEncryptionRequired,
                            format!(
                                "type '{type_name}' requires encryption but message has no encryption metadata"
                            ),
                        )
                        .into());
                    };
                    let has_protocol_path_entry = envelope.key_encryption.iter().any(|entry| {
                        matches!(entry, KeyEncryption::ProtocolPath { key_id: id, .. } if id == &key_id)
                    });
                    if !has_protocol_path_entry {
                        return Err(DwnError::new(
                            DwnErrorCode::ProtocolAuthorizationEncryptionProtocolPathEntryMissing,
                            format!(
                                "encrypted record is missing a protocolPath keyEncryption entry for '{protocol_path}'"
                            ),
                        )
                        .into());
                    }
                }
                None => {
                    let dynamic_recipient = definition.protocol == ENCRYPTION_PROTOCOL_URI
                        && descriptor.protocol_path == ENCRYPTION_PROTOCOL_GRANT_KEY_PATH;
                    if !dynamic_recipient {
                        return Err(DwnError::new(
                            DwnErrorCode::ProtocolAuthorizationEncryptionKeyAgreementMissing,
                            format!(
                                "encrypted protocol path '{protocol_path}' has no $keyAgreement"
                            ),
                        )
                        .into());
                    }
                }
            }
        }

        if rule_set.immutable == Some(true) && !is_initial_write(message, author)? {
            return Err(DwnError::new(
                DwnErrorCode::ProtocolAuthorizationImmutableRecord,
                format!(
                    "record at protocol path '{protocol_path}' is immutable: updates are not allowed."
                ),
            )
            .into());
        }

        if let Some(size) = &rule_set.size {
            if let Some(min) = size.min {
                if descriptor.data_size < min {
                    return Err(format!(
                        "ProtocolAuthorizationInvalidDataSize: dataSize {} is smaller than minimum {}",
                        descriptor.data_size, min
                    )
                    .into());
                }
            }
            if let Some(max) = size.max {
                if descriptor.data_size > max {
                    return Err(format!(
                        "ProtocolAuthorizationInvalidDataSize: dataSize {} exceeds maximum {}",
                        descriptor.data_size, max
                    )
                    .into());
                }
            }
        }

        if descriptor.squash == Some(true)
            && (rule_set.squash != Some(true) || !is_initial_write(message, author)?)
        {
            return Err("ProtocolAuthorizationInvalidSquash: squash writes must be initial writes at a $squash path".to_string().into());
        }

        if let Some(parent_id) = &descriptor.parent_id {
            let parent = fetch_newest_write(tenant, parent_id, &self.message_store).await?;
            let parent_context = context_id(&parent).ok_or_else(|| {
                "ProtocolAuthorizationParentContextMissing: parent contextId is required"
                    .to_string()
            })?;
            let context_id = write_fields(message)
                .map_err(|error| error.to_string())?
                .context_id
                .clone()
                .ok_or_else(|| {
                    "ProtocolAuthorizationContextMissing: contextId is required".to_string()
                })?;
            if !context_id.starts_with(&format!("{parent_context}/")) {
                return Err(
                    "ProtocolAuthorizationContextMismatch: contextId must be under parent context"
                        .to_string()
                        .into(),
                );
            }
        }

        Ok(())
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

    async fn enforce_squash_backstop(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
    ) -> Result<(), RecordsWriteValidationError> {
        let descriptor = records_write_descriptor(message).map_err(|error| error.to_string())?;
        let definition = match fetch_protocol_definition(
            tenant,
            &descriptor.protocol,
            &self.message_store,
            None,
        )
        .await
        {
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

        let result = self
            .message_store
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

    fn records_write_transition(
        &self,
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
