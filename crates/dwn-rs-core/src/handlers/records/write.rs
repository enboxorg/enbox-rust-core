use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use futures_util::stream;
use serde_json::Value as JsonValue;

use crate::auth::JwsPublicKeyResolver;
use crate::cid::generate_dag_pb_cid_from_bytes;
use crate::descriptors::Descriptor;
use crate::descriptors::RecordsWriteDescriptor;
use crate::dwn::core_protocol::CoreProtocolRegistry;
use crate::dwn::core_protocol::CoreProtocolStores;
use crate::dwn::{DwnReply, HandlesDescriptor, MethodHandler, MethodHandlerRequest};
use crate::filters::{Filter, FilterKey, Filters};
use crate::handlers::records::common::{
    accepted_reply, authorize_against_protocol, bool_filter, compare_messages, conflict_reply,
    context_id, core_protocol_error_reply, delete_from_data_store_if_needed, encoded_data_bytes,
    event_log_error_reply, existing_initial_lacks_data, fetch_newest_write, filter_map,
    find_initial_write, governing_timestamp, is_initial_write, message_as_write_descriptor,
    message_cid, message_record_id, message_timestamp, newest_message, parent_context_id,
    parse_message, purge_record_messages, record_id, records_delete_descriptor,
    records_write_descriptor, records_write_event_log_indexes, records_write_indexes,
    set_encoded_data, store_error_reply, string_filter, validate_data_integrity,
    validate_records_write_integrity, verify_immutable_properties, write_fields,
};
use crate::interfaces::messages::protocols::{self as protocol_types};
use crate::permissions::{self, AuthorizationContext};
use crate::{canonical_rfc3339, Message, MessageSort, Pagination, SortDirection, Value};

use super::{RecordsAuthorizationKind, MAX_ENCODED_DATA_SIZE, RECORDS_INTERFACE, WRITE_METHOD};

#[derive(Clone)]
pub struct RecordsWriteHandler<MessageStore, DataStore, StateIndex, EventLog = ()> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
    event_log: Option<EventLog>,
    core_protocol_registry: CoreProtocolRegistry,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MessageStore, DataStore, StateIndex, EventLog> HandlesDescriptor
    for RecordsWriteHandler<MessageStore, DataStore, StateIndex, EventLog>
{
    type Descriptor = RecordsWriteDescriptor;
}

impl<MessageStore, DataStore, StateIndex, EventLog>
    RecordsWriteHandler<MessageStore, DataStore, StateIndex, EventLog>
where
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    pub fn with_public_key_resolver_and_event_log(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
        event_log: EventLog,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
            event_log: Some(event_log),
            core_protocol_registry: CoreProtocolRegistry::with_permissions(),
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }

    pub fn with_optional_resolver(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
        event_log: EventLog,
        public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
            event_log: Some(event_log),
            core_protocol_registry: CoreProtocolRegistry::with_permissions(),
            public_key_resolver,
        }
    }
}

impl<MessageStore, DataStore, StateIndex, EventLog>
    RecordsWriteHandler<MessageStore, DataStore, StateIndex, EventLog>
{
    pub fn new(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
            event_log: None,
            core_protocol_registry: CoreProtocolRegistry::with_permissions(),
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
            event_log: None,
            core_protocol_registry: CoreProtocolRegistry::with_permissions(),
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore, DataStore, StateIndex, EventLog> MethodHandler
    for RecordsWriteHandler<MessageStore, DataStore, StateIndex, EventLog>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move {
            self.handle_write(request.tenant, request.message, request.data.clone())
                .await
        })
    }
}

impl<MessageStore, DataStore, StateIndex, EventLog>
    RecordsWriteHandler<MessageStore, DataStore, StateIndex, EventLog>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    pub async fn handle_write(
        &self,
        tenant: &str,
        raw_message: &JsonValue,
        data: Option<Bytes>,
    ) -> DwnReply {
        let mut message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match records_write_descriptor(&message) {
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

        if let Err(detail) = validate_records_write_integrity(&message, &signature) {
            return DwnReply::bad_request(detail);
        }

        if let Err(detail) = self
            .validate_referential_integrity(tenant, &message, &signature.author)
            .await
        {
            return DwnReply::bad_request(detail);
        }

        if let Err(detail) = self
            .authorize_records_write(tenant, &message, &signature)
            .await
        {
            return DwnReply::unauthorized(detail);
        }

        let record_id = match record_id(&message) {
            Some(record_id) => record_id,
            None => {
                return DwnReply::bad_request("RecordsWriteMissingRecordId: recordId is required")
            }
        };
        let existing_messages = match self.existing_record_messages(tenant, &record_id).await {
            Ok(messages) => messages,
            Err(reply) => return reply,
        };

        let incoming_is_initial = match is_initial_write(&message, &signature.author) {
            Ok(is_initial) => is_initial,
            Err(detail) => return DwnReply::bad_request(detail),
        };

        if !incoming_is_initial {
            let Some(initial_write) = find_initial_write(&existing_messages, &signature.author)
            else {
                return DwnReply::bad_request(
                    "RecordsWriteGetInitialWriteNotFound: Initial write is not found.",
                );
            };
            if let Err(detail) = verify_immutable_properties(&initial_write, &message) {
                return DwnReply::bad_request(detail);
            }
        }

        if let Err(detail) = self.enforce_squash_backstop(tenant, &message).await {
            return DwnReply::new(409, detail);
        }

        let newest_existing = newest_message(&existing_messages);
        let incoming_is_newest = newest_existing
            .as_ref()
            .is_none_or(|newest| compare_messages(&message, newest) == Ordering::Greater);

        if !incoming_is_newest
            && !existing_initial_lacks_data(
                &newest_existing,
                &self.data_store,
                tenant,
                &record_id,
                &descriptor.data_cid,
            )
            .await
        {
            return conflict_reply();
        }

        if newest_existing
            .as_ref()
            .and_then(|message| records_delete_descriptor(message).ok())
            .is_some()
        {
            return DwnReply::bad_request("RecordsWriteNotAllowedAfterDelete: RecordsWrite is not allowed after a RecordsDelete.");
        }

        let mut is_latest_base_state = false;
        if let Some(data) = data.or_else(|| encoded_data_bytes(&message).ok().flatten()) {
            if let Err(detail) = self
                .process_message_with_data_stream(tenant, &mut message, data)
                .await
            {
                return DwnReply::bad_request(detail);
            }
            is_latest_base_state = true;
        } else if !incoming_is_initial {
            let Some(newest_existing_write) = newest_existing
                .as_ref()
                .filter(|message| records_write_descriptor(message).is_ok())
            else {
                return DwnReply::bad_request("RecordsWriteMissingDataInPrevious: No dataStream was provided and unable to get data from previous message");
            };
            if let Err(detail) = self
                .process_message_without_data_stream(tenant, &mut message, newest_existing_write)
                .await
            {
                return DwnReply::bad_request(detail);
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

        let indexes = match records_write_indexes(&message, &signature.author, is_latest_base_state)
        {
            Ok(indexes) => indexes,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        if let Err(err) = self
            .message_store
            .put(tenant, message.clone(), indexes.clone())
            .await
        {
            return store_error_reply(err.to_string());
        }
        let incoming_cid = match message_cid(&message) {
            Ok(cid) => cid,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        if let Err(err) = self
            .state_index
            .insert(tenant, &incoming_cid, indexes)
            .await
        {
            return store_error_reply(err.to_string());
        }

        let newest_message = if incoming_is_newest {
            message.clone()
        } else {
            newest_existing.unwrap_or_else(|| message.clone())
        };
        if let Err(detail) = self
            .delete_all_older_messages_but_keep_initial_write(
                tenant,
                &existing_messages,
                &newest_message,
                &signature.author,
            )
            .await
        {
            return store_error_reply(detail);
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

        if let Some(event_log) = &self.event_log {
            let initial_write = if incoming_is_initial {
                None
            } else {
                find_initial_write(&existing_messages, &signature.author)
                    .and_then(message_as_write_descriptor)
            };
            let indexes = match records_write_event_log_indexes(
                &message,
                &signature.author,
                is_latest_base_state,
            ) {
                Ok(indexes) => indexes,
                Err(detail) => return DwnReply::bad_request(detail),
            };
            let event = crate::events::MessageEvent {
                message: message.clone(),
                initial_write,
            };
            if let Err(err) = event_log.emit(tenant, event, indexes, &incoming_cid).await {
                return event_log_error_reply(err);
            }
        }

        if incoming_is_initial && !is_latest_base_state {
            DwnReply::new(204, "No Content")
        } else {
            accepted_reply()
        }
    }

    async fn existing_record_messages(
        &self,
        tenant: &str,
        record_id: &str,
    ) -> Result<Vec<Message<Descriptor>>, DwnReply> {
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
            let encoded_data = write_fields(newest_existing_write)?
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
        let Some(protocol) = &descriptor.protocol else {
            return Ok(());
        };
        let protocol_path = descriptor.protocol_path.as_deref().ok_or_else(|| {
            "ProtocolAuthorizationMissingProtocolPath: protocolPath is required for protocol records".to_string()
        })?;
        let governing_timestamp =
            governing_timestamp(tenant, message, &self.message_store, author).await?;
        let definition = crate::handlers::protocols::configure::fetch_protocol_definition(
            tenant,
            protocol,
            &self.message_store,
            Some(&governing_timestamp),
        )
        .await
        .map_err(|err| err.to_string())?;
        let rule_set = protocol_types::get_rule_set_at_path(protocol_path, &definition.structure)
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
            let context_id = write_fields(message)?.context_id.clone().ok_or_else(|| {
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
            .await?
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
        .await?
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
        let (Some(protocol), Some(protocol_path)) =
            (&descriptor.protocol, &descriptor.protocol_path)
        else {
            return Ok(());
        };
        let definition = match crate::handlers::protocols::configure::fetch_protocol_definition(
            tenant,
            protocol,
            &self.message_store,
            None,
        )
        .await
        {
            Ok(definition) => definition,
            Err(_) => return Ok(()),
        };
        let Some(rule_set) =
            protocol_types::get_rule_set_at_path(protocol_path, &definition.structure)
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
            ("protocol", string_filter(protocol)),
            ("protocolPath", string_filter(protocol_path)),
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
                protocol_path
            ));
        }
        Ok(())
    }

    async fn delete_all_older_messages_but_keep_initial_write(
        &self,
        tenant: &str,
        existing_messages: &[Message<Descriptor>],
        newest_message: &Message<Descriptor>,
        author: &str,
    ) -> Result<(), String> {
        for message in existing_messages {
            if compare_messages(message, newest_message) != Ordering::Less {
                continue;
            }

            delete_from_data_store_if_needed(tenant, message, newest_message, &self.data_store)
                .await?;
            let old_cid = message_cid(message)?;
            self.message_store
                .delete(tenant, &old_cid)
                .await
                .map_err(|err| err.to_string())?;
            self.state_index
                .delete(tenant, std::slice::from_ref(&old_cid))
                .await
                .map_err(|err| err.to_string())?;

            if is_initial_write(message, author).unwrap_or(false) {
                let mut initial_write = message.clone();
                set_encoded_data(&mut initial_write, None)?;
                let indexes = records_write_indexes(&initial_write, author, false)?;
                self.message_store
                    .put(tenant, initial_write.clone(), indexes.clone())
                    .await
                    .map_err(|err| err.to_string())?;
                let new_cid = message_cid(&initial_write)?;
                self.state_index
                    .insert(tenant, &new_cid, indexes)
                    .await
                    .map_err(|err| err.to_string())?;
            }
        }
        Ok(())
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
    let (Some(protocol), Some(protocol_path)) = (&descriptor.protocol, &descriptor.protocol_path)
    else {
        return Ok(());
    };
    let record_id = record_id(message)
        .ok_or_else(|| "RecordsWriteMissingRecordId: recordId is required".to_string())?;
    let mut filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("protocol", string_filter(protocol)),
        ("protocolPath", string_filter(protocol_path)),
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
