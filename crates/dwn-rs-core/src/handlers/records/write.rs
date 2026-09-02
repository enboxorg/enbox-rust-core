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
    Descriptor, RecordsWriteDescriptor,
};
use crate::dwn::core_protocol::CoreProtocolRegistry;
use crate::dwn::core_protocol::CoreProtocolStores;
use crate::dwn::{Handler, HandlerContext};
use crate::filters::{Filter, FilterKey, Filters};
use crate::handlers::records::common::{
    authorize_against_protocol, bool_filter, context_id, core_protocol_error_reply,
    delete_from_data_store_if_needed, encoded_data_bytes, existing_initial_lacks_data,
    fetch_newest_write, filter_map, find_initial_write, governing_timestamp, message_cid,
    message_record_id, message_timestamp, newest_message, parent_context_id, purge_record_messages,
    records_write_indexes, set_encoded_data, store_error_reply, string_filter,
    validate_data_integrity, validate_records_write_integrity, verify_immutable_properties,
};
use crate::interfaces::messages::protocols::{self as protocol_types};
use crate::permissions::{self, AuthorizationContext};
use crate::replies::records::Write;
use crate::replies::Status;
use crate::stores::{KeyValues, LatestStateMutation, LatestStateTransition};
use crate::Response;
use crate::{canonical_rfc3339, Message, MessageSort, Pagination, SortDirection, Value};

use super::state::{plan_records_transition, RecordsTransitionPlan};
use super::{RecordsAuthorizationKind, MAX_ENCODED_DATA_SIZE, RECORDS_INTERFACE, WRITE_METHOD};

#[derive(Clone)]
pub struct RecordsWriteHandler<MessageStore, DataStore, StateIndex = ()> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
    core_protocol_registry: CoreProtocolRegistry,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

struct PreparedRecordsWriteTransition {
    durable: LatestStateTransition,
    retained_indexes: Vec<(String, KeyValues)>,
    deleted_cids: Vec<String>,
}

impl<MessageStore, DataStore, StateIndex> Handler
    for RecordsWriteHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
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
            let incoming_cid = match message_cid(&message) {
                Ok(cid) => cid,
                Err(detail) => return Response::bad_request(detail),
            };
            let transition_plan = match plan_records_transition(&message, &existing_messages) {
                Ok(plan) => plan,
                Err(detail) => return Response::bad_request(detail),
            };
            let has_incoming_data =
                data.is_some() || encoded_data_bytes(&message).ok().flatten().is_some();
            let completes_initial_data =
                matches!(transition_plan, RecordsTransitionPlan::Duplicate { .. })
                    && has_incoming_data
                    && existing_initial_lacks_data(
                        &existing_messages
                            .iter()
                            .find(|existing| {
                                message_cid(existing).as_deref() == Ok(incoming_cid.as_str())
                            })
                            .cloned(),
                        &self.data_store,
                        tenant,
                        &record_id,
                        &descriptor.data_cid,
                    )
                    .await;

            // Covers: DWN-REC-003
            // Exact replay is classified before mutable protocol, role, grant, parent,
            // record-limit, or state-relative admission can reinterpret it.
            if matches!(transition_plan, RecordsTransitionPlan::Duplicate { .. })
                && !completes_initial_data
            {
                return Response::conflict();
            }

            if let Err(detail) = self
                .validate_referential_integrity(tenant, &message, &signature.author)
                .await
            {
                return Response::bad_request(detail);
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
                    return Response::bad_request(
                        "RecordsWriteGetInitialWriteNotFound: Initial write is not found."
                            .to_string(),
                    );
                };
                if let Err(detail) = verify_immutable_properties(&initial_write, &message) {
                    return Response::bad_request(detail);
                }
            }

            if let Err(detail) = self.enforce_squash_backstop(tenant, &message).await {
                return Response::new(Status { code: 409, detail }, Write::default());
            }

            let newest_existing = newest_message(&existing_messages);
            if matches!(transition_plan, RecordsTransitionPlan::Superseded { .. }) {
                return Response::conflict();
            }

            let mut is_latest_base_state = false;
            if let Some(data) = data.or_else(|| encoded_data_bytes(&message).ok().flatten()) {
                if let Err(detail) = self
                    .process_message_with_data_stream(tenant, &mut message, data)
                    .await
                {
                    return Response::bad_request(detail);
                }
                is_latest_base_state = true;
            } else if !incoming_is_initial {
                let Some(newest_existing_write) = newest_existing
                    .as_ref()
                    .filter(|message| records_write_descriptor(message).is_ok())
                else {
                    return Response::bad_request("RecordsWriteMissingDataInPrevious: No dataStream was provided and unable to get data from previous message".to_string());
                };
                if let Err(detail) = self
                    .process_message_without_data_stream(
                        tenant,
                        &mut message,
                        newest_existing_write,
                    )
                    .await
                {
                    return Response::bad_request(detail);
                }
                is_latest_base_state = true;
            }

            if let Err(detail) = self.core_protocol_registry.validate_record(&message, None) {
                return core_protocol_error_reply(&self.core_protocol_registry, detail);
            }
            if let Err(detail) = self
                .core_protocol_registry
                .pre_process_write(tenant, &message, &self.message_store)
                .await
            {
                return core_protocol_error_reply(&self.core_protocol_registry, detail);
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
            let PreparedRecordsWriteTransition {
                durable,
                retained_indexes,
                deleted_cids,
            } = match self.records_write_transition(
                &message,
                indexes.clone(),
                &existing_messages,
                &transition_plan,
                &signature.author,
            ) {
                Ok(transition) => transition,
                Err(detail) => return Response::bad_request(detail),
            };
            if let Err(err) = self
                .message_store
                .commit_latest_state(tenant, durable)
                .await
            {
                return store_error_reply(err.to_string());
            }

            // StateIndex is temporary compatibility plumbing. MessageStore owns the
            // atomic durable transition and is the source of truth.
            if let Err(err) = self
                .state_index
                .insert(tenant, &incoming_cid, indexes)
                .await
            {
                return store_error_reply(err.to_string());
            }
            for (cid, indexes) in retained_indexes {
                if let Err(err) = self.state_index.insert(tenant, &cid, indexes).await {
                    return store_error_reply(err.to_string());
                }
            }
            if !deleted_cids.is_empty() {
                if let Err(err) = self.state_index.delete(tenant, &deleted_cids).await {
                    return store_error_reply(err.to_string());
                }
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
                if let Err(detail) = perform_records_squash(
                    &self.message_store,
                    &self.data_store,
                    &self.state_index,
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
                        state_index: &self.state_index,
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

impl<MessageStore, DataStore, StateIndex> RecordsWriteHandler<MessageStore, DataStore, StateIndex> {
    /// Construct a handler.
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
            core_protocol_registry: CoreProtocolRegistry::with_permissions(),
            did_resolver,
        }
    }
}

impl<MessageStore, DataStore, StateIndex> RecordsWriteHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
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
            .query(tenant, Filters::from(filter), None, None)
            .await
            .map(|result| result.messages)
            .map_err(|err| store_error_reply(err.to_string()))
    }

    async fn process_message_with_data_stream(
        &self,
        tenant: &str,
        message: &mut Message<Descriptor>,
        data: Bytes,
    ) -> Result<(), String> {
        let descriptor = records_write_descriptor(message)?.clone();
        let actual_data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
        validate_data_integrity(
            &descriptor.data_cid,
            descriptor.data_size,
            &actual_data_cid,
            data.len() as u64,
        )?;

        if descriptor.data_size <= MAX_ENCODED_DATA_SIZE {
            set_encoded_data(message, Some(URL_SAFE_NO_PAD.encode(&data)))?;
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
            .map_err(|err| err.to_string())?;
        if put_result.data_size as u64 != descriptor.data_size {
            let _ = self
                .data_store
                .delete(tenant, &record_id, &descriptor.data_cid)
                .await;
            return Err(format!(
                "RecordsWriteDataSizeMismatch: actual data size {} bytes does not match dataSize in descriptor: {}",
                put_result.data_size, descriptor.data_size
            ));
        }
        set_encoded_data(message, None)
    }

    async fn process_message_without_data_stream(
        &self,
        tenant: &str,
        message: &mut Message<Descriptor>,
        newest_existing_write: &Message<Descriptor>,
    ) -> Result<(), String> {
        let descriptor = records_write_descriptor(message)?.clone();
        let newest_descriptor = records_write_descriptor(newest_existing_write)?;
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
                .ok_or_else(|| "RecordsWriteMissingEncodedDataInPrevious: No dataStream was provided and unable to get data from previous message".to_string())?;
            set_encoded_data(message, Some(encoded_data))?;
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
            return Err("RecordsWriteMissingDataInPrevious: No dataStream was provided and unable to get data from previous message".to_string());
        }
        set_encoded_data(message, None)
    }

    async fn validate_referential_integrity(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        author: &str,
    ) -> Result<(), String> {
        let descriptor = records_write_descriptor(message)?;
        let protocol_path = descriptor.protocol_path.clone();
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
                        &descriptor.protocol
                    )
                })?
        } else {
            crate::handlers::protocols::configure::fetch_protocol_definition(
                tenant,
                &descriptor.protocol,
                &self.message_store,
                Some(&governing_timestamp),
            )
            .await
            .map_err(|err| err.to_string())?
        };
        let rule_set = protocol_types::get_rule_set_at_path(
            descriptor.protocol_path.as_str(),
            &definition.structure,
        )
        .ok_or_else(|| {
            format!("ProtocolAuthorizationInvalidProtocolPath: {protocol_path} is not defined")
        })?;

        if let Some(size) = &rule_set.size {
            if let Some(min) = size.min {
                if descriptor.data_size < min {
                    return Err(format!(
                        "ProtocolAuthorizationInvalidDataSize: dataSize {} is smaller than minimum {}",
                        descriptor.data_size, min
                    ));
                }
            }
            if let Some(max) = size.max {
                if descriptor.data_size > max {
                    return Err(format!(
                        "ProtocolAuthorizationInvalidDataSize: dataSize {} exceeds maximum {}",
                        descriptor.data_size, max
                    ));
                }
            }
        }

        if descriptor.squash == Some(true)
            && (rule_set.squash != Some(true) || !is_initial_write(message, author)?)
        {
            return Err("ProtocolAuthorizationInvalidSquash: squash writes must be initial writes at a $squash path".to_string());
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
                        .to_string(),
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
    ) -> Result<(), String> {
        let descriptor = records_write_descriptor(message)?;
        let definition = match crate::handlers::protocols::configure::fetch_protocol_definition(
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
        let Some(rule_set) =
            protocol_types::get_rule_set_at_path(&descriptor.protocol_path, &definition.structure)
        else {
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
                    Filter::Prefix(Value::String(parent_context)),
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
            )
            .await
            .map_err(|err| err.to_string())?;
        let Some(newest_squash) = result.messages.first() else {
            return Ok(());
        };
        let newest_timestamp = message_timestamp(newest_squash)?;
        if descriptor.message_timestamp <= newest_timestamp {
            return Err(format!(
                "ProtocolAuthorizationSquashBackstop: incoming message timestamp '{}' is not newer than the most recent squash record timestamp '{}' at protocol path '{}'.",
                canonical_rfc3339(descriptor.message_timestamp),
                canonical_rfc3339(newest_timestamp),
                &descriptor.protocol_path
            ));
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
    ) -> Result<PreparedRecordsWriteTransition, String> {
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
        let mut retained_indexes = Vec::new();
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
                retained_indexes.push((existing_cid, indexes.clone()));
                retains.push(LatestStateMutation {
                    message: initial_write,
                    indexes,
                });
            } else {
                deletes.push(existing_cid);
            }
        }

        Ok(PreparedRecordsWriteTransition {
            durable: LatestStateTransition {
                put: LatestStateMutation {
                    message: message.clone(),
                    indexes,
                },
                retains,
                deletes: deletes.clone(),
            },
            retained_indexes,
            deleted_cids: deletes,
        })
    }
}

pub(crate) async fn perform_records_squash<MessageStore, DataStore, StateIndex>(
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
                Filter::Prefix(Value::String(parent_context)),
            );
        }
    }
    let sibling_messages = message_store
        .query(tenant, Filters::from(filter), None, None)
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
        if message_timestamp(&newest)? < descriptor.message_timestamp {
            purge_record_messages(tenant, &messages, message_store, data_store, state_index)
                .await?;
        }
    }
    Ok(())
}
