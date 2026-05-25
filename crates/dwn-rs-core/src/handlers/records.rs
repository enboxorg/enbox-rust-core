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
use crate::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
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

const RECORDS_INTERFACE: &str = "Records";
const WRITE_METHOD: &str = "Write";
const MAX_ENCODED_DATA_SIZE: u64 = 30_000;

#[derive(Clone)]
pub struct RecordsWriteHandler<MessageStore, DataStore, StateIndex> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

#[derive(Clone)]
pub struct RecordsReadHandler<MessageStore, DataStore> {
    message_store: MessageStore,
    data_store: DataStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

#[derive(Clone)]
pub struct RecordsQueryHandler<MessageStore> {
    message_store: MessageStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

#[derive(Clone)]
pub struct RecordsCountHandler<MessageStore> {
    message_store: MessageStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

#[derive(Clone)]
pub struct RecordsDeleteHandler<MessageStore, DataStore, StateIndex> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

#[derive(Clone)]
pub struct RecordsSubscribeHandler<MessageStore> {
    message_store: MessageStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

#[derive(Clone)]
pub struct RecordsEventLogSubscribeHandler<MessageStore, EventLog> {
    message_store: MessageStore,
    event_log: EventLog,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

pub struct RecordsSubscribeReply {
    pub reply: DwnReply,
    pub subscription: Option<EventSubscription>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordsAuthorizationKind {
    Write,
    Read,
    Query,
    Count,
    Delete { prune: bool },
    Subscribe,
}

impl<MessageStore, DataStore, StateIndex> RecordsWriteHandler<MessageStore, DataStore, StateIndex> {
    pub fn new(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
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
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore, DataStore> RecordsReadHandler<MessageStore, DataStore> {
    pub fn new(message_store: MessageStore, data_store: DataStore) -> Self {
        Self {
            message_store,
            data_store,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        data_store: DataStore,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            data_store,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore> RecordsQueryHandler<MessageStore> {
    pub fn new(message_store: MessageStore) -> Self {
        Self {
            message_store,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore> RecordsCountHandler<MessageStore> {
    pub fn new(message_store: MessageStore) -> Self {
        Self {
            message_store,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
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
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
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
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore> RecordsSubscribeHandler<MessageStore> {
    pub fn new(message_store: MessageStore) -> Self {
        Self {
            message_store,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore, EventLog> RecordsEventLogSubscribeHandler<MessageStore, EventLog> {
    pub fn new(message_store: MessageStore, event_log: EventLog) -> Self {
        Self {
            message_store,
            event_log,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        event_log: EventLog,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            event_log,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore, DataStore, StateIndex> MethodHandler
    for RecordsWriteHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move {
            self.handle_write(request.tenant, request.message, None)
                .await
        })
    }
}

impl<MessageStore, DataStore> MethodHandler for RecordsReadHandler<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_read(request.tenant, request.message).await })
    }
}

impl<MessageStore> MethodHandler for RecordsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_query(request.tenant, request.message).await })
    }
}

impl<MessageStore> MethodHandler for RecordsCountHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_count(request.tenant, request.message).await })
    }
}

impl<MessageStore, DataStore, StateIndex> MethodHandler
    for RecordsDeleteHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_delete(request.tenant, request.message).await })
    }
}

impl<MessageStore> MethodHandler for RecordsSubscribeHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_subscribe(request.tenant, request.message).await })
    }
}

impl<MessageStore, EventLog> MethodHandler
    for RecordsEventLogSubscribeHandler<MessageStore, EventLog>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move {
            self.handle_subscribe(request.tenant, request.message, Box::new(|_| {}))
                .await
                .reply
        })
    }
}

impl<MessageStore, DataStore, StateIndex> RecordsWriteHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
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

        if let Err(detail) = permissions::validate_permissions_record_schema(&message) {
            return DwnReply::bad_request(detail);
        }
        if let Err(detail) =
            permissions::pre_process_permissions_write(tenant, &message, &self.message_store).await
        {
            return DwnReply::bad_request(detail);
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

        if let Err(detail) = permissions::post_process_permissions_write(
            tenant,
            &message,
            &self.message_store,
            &self.data_store,
            &self.state_index,
        )
        .await
        {
            return store_error_reply(detail);
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
        let definition = super::protocols::fetch_protocol_definition(
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
            let context_id = context_id(message).ok_or_else(|| {
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
        let definition = match super::protocols::fetch_protocol_definition(
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
                descriptor.message_timestamp.to_rfc3339_opts(SecondsFormat::Micros, true),
                newest_timestamp.to_rfc3339_opts(SecondsFormat::Micros, true),
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

impl<MessageStore, DataStore> RecordsReadHandler<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    pub async fn handle_read(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match records_read_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let signature = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            false,
        ) {
            Ok(signature) => signature,
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return DwnReply::bad_request(detail)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
        };
        let mut filter =
            records_filter_to_filter_map(&descriptor.filter, descriptor.date_sort.as_ref());
        filter.insert(
            FilterKey::Index("interface".to_string()),
            string_filter(RECORDS_INTERFACE),
        );
        filter.insert(
            FilterKey::Index("isLatestBaseState".to_string()),
            bool_filter(true),
        );
        let result = match self
            .message_store
            .query(
                tenant,
                Filters::from(filter),
                Some(date_sort_to_message_sort(
                    descriptor.date_sort.as_ref(),
                    true,
                )),
                Some(Pagination::with_limit(1)),
            )
            .await
        {
            Ok(result) => result,
            Err(err) => return store_error_reply(err.to_string()),
        };
        let Some(matched_message) = result.messages.first() else {
            return not_found_reply();
        };

        if records_delete_descriptor(matched_message).is_ok() {
            let record_id = message_record_id(matched_message).unwrap_or_default();
            let initial_write = match fetch_initial_write_message(
                tenant,
                &record_id,
                &self.message_store,
            )
            .await
            {
                Ok(Some(message)) => message,
                Ok(None) => return DwnReply::bad_request(
                    "RecordsReadInitialWriteNotFound: initial write for deleted record not found",
                ),
                Err(detail) => return store_error_reply(detail),
            };
            let newest_write = fetch_newest_write(tenant, &record_id, &self.message_store)
                .await
                .unwrap_or_else(|_| initial_write.clone());
            if let Err(detail) = authorize_records_read(
                tenant,
                &message,
                signature.as_ref(),
                &newest_write,
                &self.message_store,
            )
            .await
            {
                return DwnReply::unauthorized(detail);
            }
            return DwnReply::new(404, "Not Found").with_body(
                "entry",
                json!({
                    "recordsDelete": matched_message,
                    "initialWrite": initial_write,
                }),
            );
        }

        if let Err(detail) = authorize_records_read(
            tenant,
            &message,
            signature.as_ref(),
            matched_message,
            &self.message_store,
        )
        .await
        {
            return DwnReply::unauthorized(detail);
        }

        let mut entry = serde_json::Map::new();
        let mut records_write = serde_json::to_value(matched_message).unwrap_or(JsonValue::Null);
        if let Some(encoded_data) = write_fields(matched_message)
            .ok()
            .and_then(|fields| fields.encoded_data.clone())
        {
            if let Some(object) = records_write.as_object_mut() {
                object.remove("encodedData");
            }
            entry.insert("encodedData".to_string(), JsonValue::String(encoded_data));
        } else {
            let Some(record_id) = record_id(matched_message) else {
                return DwnReply::bad_request("RecordsReadMissingRecordId: recordId is required");
            };
            let data_cid = match records_write_descriptor(matched_message) {
                Ok(descriptor) => descriptor.data_cid.clone(),
                Err(detail) => return DwnReply::bad_request(detail),
            };
            let data = match self.data_store.get(tenant, &record_id, &data_cid).await {
                Ok(Some(data)) => data,
                Ok(None) => {
                    return DwnReply::new(410, "Record data not available")
                        .with_body("entry", json!({ "recordsWrite": matched_message }))
                }
                Err(err) => return store_error_reply(err.to_string()),
            };
            let mut data_stream = data.data_stream;
            let mut bytes = Vec::new();
            loop {
                match data_stream.try_next().await {
                    Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
                    Ok(None) => break,
                    Err(err) => return store_error_reply(err.to_string()),
                }
            }
            entry.insert(
                "encodedData".to_string(),
                JsonValue::String(URL_SAFE_NO_PAD.encode(bytes)),
            );
        }
        entry.insert("recordsWrite".to_string(), records_write);

        if !is_initial_write(
            matched_message,
            extract_author(matched_message)
                .as_deref()
                .unwrap_or_default(),
        )
        .unwrap_or(false)
        {
            if let Some(record_id) = record_id(matched_message) {
                if let Ok(Some(initial_write)) =
                    fetch_initial_write_message(tenant, &record_id, &self.message_store).await
                {
                    entry.insert(
                        "initialWrite".to_string(),
                        serde_json::to_value(initial_write).unwrap(),
                    );
                }
            }
        }

        DwnReply::ok().with_body("entry", JsonValue::Object(entry))
    }
}

impl<MessageStore> RecordsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    pub async fn handle_query(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match records_query_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let signature = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            false,
        ) {
            Ok(signature) => signature,
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return DwnReply::bad_request(detail)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
        };

        let (filters, author) = match self
            .query_filters(tenant, &message, &descriptor, signature.as_ref())
            .await
        {
            Ok(result) => result,
            Err(QueryAuthorizationResult::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
        };
        let result = match self
            .message_store
            .query(
                tenant,
                filters,
                Some(date_sort_to_message_sort(
                    descriptor.date_sort.as_ref(),
                    false,
                )),
                descriptor.pagination.clone(),
            )
            .await
        {
            Ok(result) => result,
            Err(err) => return store_error_reply(err.to_string()),
        };

        let entries = attach_initial_writes(
            tenant,
            result.messages,
            &self.message_store,
            author.as_deref(),
        )
        .await;
        DwnReply::ok()
            .with_body("entries", JsonValue::Array(entries))
            .with_body(
                "cursor",
                serde_json::to_value(result.cursor).unwrap_or(JsonValue::Null),
            )
    }

    async fn query_filters(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        descriptor: &RecordsQueryDescriptor,
        signature: Option<&AuthorizationContext>,
    ) -> Result<(Filters, Option<String>), QueryAuthorizationResult> {
        if filter_includes_published_records(&descriptor.filter) && signature.is_none() {
            return Ok((
                Filters::from(published_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                )),
                None,
            ));
        }
        let signature = signature.ok_or_else(|| {
            QueryAuthorizationResult::Unauthorized(
                "AuthenticateJwsMissing: authorization signature is required".to_string(),
            )
        })?;
        let grant_authorized = permissions::authorize_records_query_or_subscribe_with_grant(
            tenant,
            message,
            &descriptor.filter,
            signature,
            &self.message_store,
        )
        .await
        .map_err(QueryAuthorizationResult::Unauthorized)?;
        if should_protocol_authorize(&signature.payload) {
            authorize_protocol_query_or_subscribe(
                tenant,
                &descriptor.filter,
                &signature.payload,
                &signature.author,
                &self.message_store,
                RecordsAuthorizationKind::Query,
            )
            .await
            .map_err(QueryAuthorizationResult::Unauthorized)?;
        }
        if signature.author == tenant {
            return Ok((
                Filters::from(owner_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                )),
                Some(signature.author.clone()),
            ));
        }
        Ok((
            Filters::from(non_owner_records_filters(
                &descriptor.filter,
                descriptor.date_sort.as_ref(),
                &signature.author,
                should_protocol_authorize(&signature.payload) || grant_authorized,
            )),
            Some(signature.author.clone()),
        ))
    }
}

impl<MessageStore> RecordsCountHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    pub async fn handle_count(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match records_count_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let signature = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            false,
        ) {
            Ok(signature) => signature,
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return DwnReply::bad_request(detail)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
        };

        let filters =
            if filter_includes_published_records(&descriptor.filter) && signature.is_none() {
                Filters::from(published_records_filter(&descriptor.filter, None))
            } else {
                let Some(signature) = signature.as_ref() else {
                    return DwnReply::unauthorized(
                        "AuthenticateJwsMissing: authorization signature is required",
                    );
                };
                let grant_authorized =
                    match permissions::authorize_records_query_or_subscribe_with_grant(
                        tenant,
                        &message,
                        &descriptor.filter,
                        signature,
                        &self.message_store,
                    )
                    .await
                    {
                        Ok(grant_authorized) => grant_authorized,
                        Err(detail) => return DwnReply::unauthorized(detail),
                    };
                if should_protocol_authorize(&signature.payload) {
                    if let Err(detail) = authorize_protocol_query_or_subscribe(
                        tenant,
                        &descriptor.filter,
                        &signature.payload,
                        &signature.author,
                        &self.message_store,
                        RecordsAuthorizationKind::Count,
                    )
                    .await
                    {
                        return DwnReply::unauthorized(detail);
                    }
                }
                if signature.author == tenant {
                    Filters::from(owner_records_filter(&descriptor.filter, None))
                } else {
                    Filters::from(non_owner_records_filters(
                        &descriptor.filter,
                        None,
                        &signature.author,
                        should_protocol_authorize(&signature.payload) || grant_authorized,
                    ))
                }
            };

        match self.message_store.count(tenant, filters, None).await {
            Ok(count) => DwnReply::ok().with_body("count", json!(count)),
            Err(err) => store_error_reply(err.to_string()),
        }
    }
}

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

impl<MessageStore> RecordsSubscribeHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    pub async fn handle_subscribe(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match records_subscribe_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return DwnReply::bad_request(detail),
        };
        if descriptor.cursor.is_some() {
            return DwnReply::not_implemented(
                "RecordsSubscribe cursor replay requires EventLog integration",
            );
        }

        let signature = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            false,
        ) {
            Ok(signature) => signature,
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return DwnReply::bad_request(detail)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
        };
        let filters =
            if filter_includes_published_records(&descriptor.filter) && signature.is_none() {
                Filters::from(published_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                ))
            } else {
                let Some(signature) = signature.as_ref() else {
                    return DwnReply::unauthorized(
                        "AuthenticateJwsMissing: authorization signature is required",
                    );
                };
                let grant_authorized =
                    match permissions::authorize_records_query_or_subscribe_with_grant(
                        tenant,
                        &message,
                        &descriptor.filter,
                        signature,
                        &self.message_store,
                    )
                    .await
                    {
                        Ok(grant_authorized) => grant_authorized,
                        Err(detail) => return DwnReply::unauthorized(detail),
                    };
                if should_protocol_authorize(&signature.payload) {
                    if let Err(detail) = authorize_protocol_query_or_subscribe(
                        tenant,
                        &descriptor.filter,
                        &signature.payload,
                        &signature.author,
                        &self.message_store,
                        RecordsAuthorizationKind::Subscribe,
                    )
                    .await
                    {
                        return DwnReply::unauthorized(detail);
                    }
                }
                if signature.author == tenant {
                    Filters::from(owner_records_filter(
                        &descriptor.filter,
                        descriptor.date_sort.as_ref(),
                    ))
                } else {
                    Filters::from(non_owner_records_filters(
                        &descriptor.filter,
                        descriptor.date_sort.as_ref(),
                        &signature.author,
                        should_protocol_authorize(&signature.payload) || grant_authorized,
                    ))
                }
            };
        let result = match self
            .message_store
            .query(
                tenant,
                filters,
                Some(date_sort_to_message_sort(
                    descriptor.date_sort.as_ref(),
                    false,
                )),
                descriptor.pagination.clone(),
            )
            .await
        {
            Ok(result) => result,
            Err(err) => return store_error_reply(err.to_string()),
        };
        let entries = attach_initial_writes(
            tenant,
            result.messages,
            &self.message_store,
            signature
                .as_ref()
                .map(|signature| signature.author.as_str()),
        )
        .await;
        DwnReply::ok()
            .with_body("entries", JsonValue::Array(entries))
            .with_body(
                "cursor",
                serde_json::to_value(result.cursor).unwrap_or(JsonValue::Null),
            )
    }
}

impl<MessageStore, EventLog> RecordsEventLogSubscribeHandler<MessageStore, EventLog>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    pub async fn handle_subscribe(
        &self,
        tenant: &str,
        raw_message: &JsonValue,
        listener: SubscriptionListener,
    ) -> RecordsSubscribeReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return records_subscribe_reply(DwnReply::bad_request(detail), None),
        };
        let descriptor = match records_subscribe_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return records_subscribe_reply(DwnReply::bad_request(detail), None),
        };

        let signature = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            false,
        ) {
            Ok(signature) => signature,
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return records_subscribe_reply(DwnReply::bad_request(detail), None)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return records_subscribe_reply(DwnReply::unauthorized(detail), None)
            }
        };

        let (event_filters, query_filters, author) = match self
            .records_subscribe_filters(tenant, &message, &descriptor, signature.as_ref())
            .await
        {
            Ok(filters) => filters,
            Err(reply) => return records_subscribe_reply(reply, None),
        };

        let subscription_id = match generate_cid_from_json(raw_message) {
            Ok(cid) => cid.to_string(),
            Err(err) => {
                return records_subscribe_reply(
                    DwnReply::bad_request(format!("RecordsSubscribeCidFailed: {err}")),
                    None,
                )
            }
        };

        let subscription = match self
            .event_log
            .subscribe(
                tenant,
                &subscription_id,
                listener,
                Some(EventLogSubscribeOptions {
                    cursor: descriptor.cursor.clone(),
                    filters: Some(event_filters),
                }),
            )
            .await
        {
            Ok(subscription) => subscription,
            Err(err) => return records_subscribe_reply(event_log_error_reply(err), None),
        };

        if descriptor.cursor.is_some() {
            let reply = DwnReply::ok()
                .with_body("subscriptionId", JsonValue::String(subscription.id.clone()));
            return records_subscribe_reply(reply, Some(subscription));
        }

        let result = match self
            .message_store
            .query(
                tenant,
                query_filters,
                Some(date_sort_to_message_sort(
                    descriptor.date_sort.as_ref(),
                    false,
                )),
                descriptor.pagination.clone(),
            )
            .await
        {
            Ok(result) => result,
            Err(err) => {
                let _ = (subscription.close)().await;
                return records_subscribe_reply(store_error_reply(err.to_string()), None);
            }
        };
        let entries = attach_initial_writes(
            tenant,
            result.messages,
            &self.message_store,
            author.as_deref(),
        )
        .await;
        let reply = DwnReply::ok()
            .with_body("subscriptionId", JsonValue::String(subscription.id.clone()))
            .with_body("entries", JsonValue::Array(entries))
            .with_body(
                "cursor",
                serde_json::to_value(result.cursor).unwrap_or(JsonValue::Null),
            );
        records_subscribe_reply(reply, Some(subscription))
    }

    async fn records_subscribe_filters(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        descriptor: &SubscribeDescriptor,
        signature: Option<&AuthorizationContext>,
    ) -> Result<(Filters, Filters, Option<String>), DwnReply> {
        if filter_includes_published_records(&descriptor.filter) && signature.is_none() {
            return Ok((
                Filters::from(published_records_event_filter(&descriptor.filter)),
                Filters::from(published_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                )),
                None,
            ));
        }

        let Some(signature) = signature else {
            return Err(DwnReply::unauthorized(
                "AuthenticateJwsMissing: authorization signature is required",
            ));
        };
        let grant_authorized = permissions::authorize_records_query_or_subscribe_with_grant(
            tenant,
            message,
            &descriptor.filter,
            signature,
            &self.message_store,
        )
        .await
        .map_err(DwnReply::unauthorized)?;
        if should_protocol_authorize(&signature.payload) {
            authorize_protocol_query_or_subscribe(
                tenant,
                &descriptor.filter,
                &signature.payload,
                &signature.author,
                &self.message_store,
                RecordsAuthorizationKind::Subscribe,
            )
            .await
            .map_err(DwnReply::unauthorized)?;
        }
        if signature.author == tenant {
            Ok((
                Filters::from(owner_records_event_filter(&descriptor.filter)),
                Filters::from(owner_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                )),
                Some(signature.author.clone()),
            ))
        } else {
            let protocol_authorized =
                should_protocol_authorize(&signature.payload) || grant_authorized;
            Ok((
                Filters::from(non_owner_records_event_filters(
                    &descriptor.filter,
                    &signature.author,
                    protocol_authorized,
                )),
                Filters::from(non_owner_records_filters(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                    &signature.author,
                    protocol_authorized,
                )),
                Some(signature.author.clone()),
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QueryAuthorizationResult {
    Unauthorized(String),
}

fn parse_message(raw_message: &JsonValue) -> Result<Message<Descriptor>, String> {
    serde_json::from_value(raw_message.clone()).map_err(|err| format!("MessageParseFailed: {err}"))
}

fn records_write_descriptor(
    message: &Message<Descriptor>,
) -> Result<&RecordsWriteDescriptor, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Write(descriptor) => Ok(descriptor),
            _ => Err("RecordsWriteDescriptorExpected: message is not RecordsWrite".to_string()),
        },
        _ => Err("RecordsWriteDescriptorExpected: message is not RecordsWrite".to_string()),
    }
}

fn records_read_descriptor(message: &Message<Descriptor>) -> Result<&ReadDescriptor, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Read(descriptor) => Ok(descriptor),
            _ => Err("RecordsReadDescriptorExpected: message is not RecordsRead".to_string()),
        },
        _ => Err("RecordsReadDescriptorExpected: message is not RecordsRead".to_string()),
    }
}

fn records_query_descriptor(
    message: &Message<Descriptor>,
) -> Result<&RecordsQueryDescriptor, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Query(descriptor) => Ok(descriptor),
            _ => Err("RecordsQueryDescriptorExpected: message is not RecordsQuery".to_string()),
        },
        _ => Err("RecordsQueryDescriptorExpected: message is not RecordsQuery".to_string()),
    }
}

fn records_count_descriptor(message: &Message<Descriptor>) -> Result<&CountDescriptor, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Count(descriptor) => Ok(descriptor),
            _ => Err("RecordsCountDescriptorExpected: message is not RecordsCount".to_string()),
        },
        _ => Err("RecordsCountDescriptorExpected: message is not RecordsCount".to_string()),
    }
}

fn records_delete_descriptor(message: &Message<Descriptor>) -> Result<&DeleteDescriptor, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Delete(descriptor) => Ok(descriptor),
            _ => Err("RecordsDeleteDescriptorExpected: message is not RecordsDelete".to_string()),
        },
        _ => Err("RecordsDeleteDescriptorExpected: message is not RecordsDelete".to_string()),
    }
}

fn records_subscribe_descriptor(
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

fn write_fields(message: &Message<Descriptor>) -> Result<&WriteFields, String> {
    match &message.fields {
        Fields::Write(fields) => Ok(fields),
        Fields::InitialWriteField(fields) => Ok(&fields.write_fields),
        _ => Err("RecordsWriteFieldsExpected: write fields are required".to_string()),
    }
}

fn write_fields_mut(message: &mut Message<Descriptor>) -> Result<&mut WriteFields, String> {
    match &mut message.fields {
        Fields::Write(fields) => Ok(fields),
        Fields::InitialWriteField(fields) => Ok(&mut fields.write_fields),
        _ => Err("RecordsWriteFieldsExpected: write fields are required".to_string()),
    }
}

fn validate_records_write_integrity(
    message: &Message<Descriptor>,
    signature: &AuthorizationContext,
) -> Result<(), String> {
    let record_id = record_id(message).ok_or_else(|| {
        "RecordsWriteValidateIntegrityRecordIdMissing: recordId is required".to_string()
    })?;
    let context_id = context_id(message).ok_or_else(|| {
        "RecordsWriteValidateIntegrityContextIdMissing: contextId is required".to_string()
    })?;
    if signature
        .payload
        .get("recordId")
        .and_then(JsonValue::as_str)
        != Some(record_id.as_str())
    {
        return Err("RecordsWriteValidateIntegrityRecordIdUnauthorized: recordId in message does not match recordId in authorization".to_string());
    }
    if signature
        .payload
        .get("contextId")
        .and_then(JsonValue::as_str)
        != Some(context_id.as_str())
    {
        return Err("RecordsWriteValidateIntegrityContextIdNotInSignerSignaturePayload: contextId in message does not match contextId in authorization".to_string());
    }

    if is_initial_write(message, &signature.author)? {
        let descriptor = records_write_descriptor(message)?;
        if descriptor.message_timestamp != descriptor.date_created {
            return Err(format!(
                "RecordsWriteValidateIntegrityDateCreatedMismatch: messageTimestamp {} must match dateCreated {} for the initial write",
                descriptor.message_timestamp.to_rfc3339_opts(SecondsFormat::Micros, true),
                descriptor.date_created.to_rfc3339_opts(SecondsFormat::Micros, true)
            ));
        }
        if descriptor.parent_id.is_none() && context_id != record_id {
            return Err("RecordsWriteValidateIntegrityContextIdMismatch: root contextId must match recordId".to_string());
        }
    }
    Ok(())
}

fn record_id(message: &Message<Descriptor>) -> Option<String> {
    write_fields(message).ok()?.record_id.clone()
}

fn context_id(message: &Message<Descriptor>) -> Option<String> {
    write_fields(message).ok()?.context_id.clone()
}

fn message_record_id(message: &Message<Descriptor>) -> Option<String> {
    record_id(message).or_else(|| {
        records_delete_descriptor(message)
            .ok()
            .map(|d| d.record_id.clone())
    })
}

fn entry_id(author: &str, descriptor: &RecordsWriteDescriptor) -> Result<String, String> {
    let mut descriptor = serde_json::to_value(descriptor).map_err(|err| err.to_string())?;
    let object = descriptor.as_object_mut().ok_or_else(|| {
        "RecordsWriteGetEntryIdInvalidDescriptor: descriptor must be an object".to_string()
    })?;
    object.insert("author".to_string(), JsonValue::String(author.to_string()));
    generate_cid_from_json(&descriptor)
        .map(|cid| cid.to_string())
        .map_err(|err| err.to_string())
}

fn is_initial_write(message: &Message<Descriptor>, author: &str) -> Result<bool, String> {
    let descriptor = records_write_descriptor(message)?;
    let Some(record_id) = record_id(message) else {
        return Ok(false);
    };
    Ok(entry_id(author, descriptor)? == record_id)
}

fn find_initial_write(
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

fn verify_immutable_properties(
    initial_write: &Message<Descriptor>,
    new_message: &Message<Descriptor>,
) -> Result<(), String> {
    let initial = records_write_descriptor(initial_write)?;
    let new = records_write_descriptor(new_message)?;
    let changed = [
        ("interface", initial.interface(), new.interface()),
        ("method", initial.method(), new.method()),
    ]
    .into_iter()
    .find(|(_, left, right)| left != right)
    .map(|(property, _, _)| property.to_string())
    .or_else(|| {
        [
            ("protocol", &initial.protocol, &new.protocol),
            ("protocolPath", &initial.protocol_path, &new.protocol_path),
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
        return Err(format!(
            "RecordsWriteImmutablePropertyChanged: {property} is an immutable property"
        ));
    }
    Ok(())
}

fn validate_data_integrity(
    expected_data_cid: &str,
    expected_data_size: u64,
    actual_data_cid: &str,
    actual_data_size: u64,
) -> Result<(), String> {
    if expected_data_cid != actual_data_cid {
        return Err(format!(
            "RecordsWriteDataCidMismatch: actual data CID {actual_data_cid} does not match dataCid in descriptor: {expected_data_cid}"
        ));
    }
    if expected_data_size != actual_data_size {
        return Err(format!(
            "RecordsWriteDataSizeMismatch: actual data size {actual_data_size} bytes does not match dataSize in descriptor: {expected_data_size}"
        ));
    }
    Ok(())
}

fn encoded_data_bytes(message: &Message<Descriptor>) -> Result<Option<Bytes>, String> {
    write_fields(message)?
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

fn set_encoded_data(
    message: &mut Message<Descriptor>,
    encoded_data: Option<String>,
) -> Result<(), String> {
    write_fields_mut(message)?.encoded_data = encoded_data;
    Ok(())
}

fn records_write_indexes(
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

fn records_delete_indexes(
    message: &Message<Descriptor>,
    initial_write: &Message<Descriptor>,
    author: &str,
) -> Result<KeyValues, String> {
    let descriptor = records_delete_descriptor(message)?;
    let initial = records_write_descriptor(initial_write)?;
    let mut indexes = descriptor_indexes(descriptor)?;
    indexes.insert("isLatestBaseState".to_string(), Value::Bool(true));
    indexes.insert("author".to_string(), Value::String(author.to_string()));
    if let Some(protocol) = &initial.protocol {
        indexes.insert("protocol".to_string(), Value::String(protocol.clone()));
    }
    if let Some(protocol_path) = &initial.protocol_path {
        indexes.insert(
            "protocolPath".to_string(),
            Value::String(protocol_path.clone()),
        );
    }
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
        Value::String(
            initial
                .date_created
                .to_rfc3339_opts(SecondsFormat::Micros, true),
        ),
    );
    if let Some(context_id) = context_id(initial_write) {
        indexes.insert("contextId".to_string(), Value::String(context_id));
    }
    Ok(indexes)
}

fn descriptor_indexes<T: serde::Serialize>(descriptor: &T) -> Result<KeyValues, String> {
    let descriptor = serde_json::to_value(descriptor).map_err(|err| err.to_string())?;
    let object = descriptor
        .as_object()
        .ok_or_else(|| "DescriptorIndexInvalid: descriptor must be an object".to_string())?;
    Ok(object
        .iter()
        .filter_map(|(key, value)| json_to_index_value(value).map(|value| (key.clone(), value)))
        .collect())
}

fn json_to_index_value(value: &JsonValue) -> Option<Value> {
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

fn records_filter_to_filter_map(
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

fn insert_string_filter(
    map: &mut BTreeMap<FilterKey, Filter<Value>>,
    key: &str,
    value: Option<&String>,
) {
    if let Some(value) = value {
        map.insert(FilterKey::Index(key.to_string()), string_filter(value));
    }
}

fn insert_bool_filter(
    map: &mut BTreeMap<FilterKey, Filter<Value>>,
    key: &str,
    value: Option<bool>,
) {
    if let Some(value) = value {
        map.insert(FilterKey::Index(key.to_string()), bool_filter(value));
    }
}

fn insert_string_vec_filter(
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

fn range_u64_filter(range: &RangeFilter<u64>) -> Filter<Value> {
    Filter::Range(match range {
        RangeFilter::Numeric(lower, upper) => {
            RangeFilter::Numeric(bound_u64_to_value(lower), bound_u64_to_value(upper))
        }
        RangeFilter::Criterion(lower, upper) => {
            RangeFilter::Criterion(bound_u64_to_value(lower), bound_u64_to_value(upper))
        }
    })
}

fn range_string_filter(range: &RangeFilter<String>) -> Filter<Value> {
    Filter::Range(match range {
        RangeFilter::Numeric(lower, upper) => {
            RangeFilter::Numeric(bound_string_to_value(lower), bound_string_to_value(upper))
        }
        RangeFilter::Criterion(lower, upper) => {
            RangeFilter::Criterion(bound_string_to_value(lower), bound_string_to_value(upper))
        }
    })
}

fn bound_u64_to_value(bound: &Bound<u64>) -> Bound<Value> {
    match bound {
        Bound::Included(value) => Bound::Included(Value::Number(*value as i64)),
        Bound::Excluded(value) => Bound::Excluded(Value::Number(*value as i64)),
        Bound::Unbounded => Bound::Unbounded,
    }
}

fn bound_string_to_value(bound: &Bound<String>) -> Bound<Value> {
    match bound {
        Bound::Included(value) => Bound::Included(Value::String(value.clone())),
        Bound::Excluded(value) => Bound::Excluded(Value::String(value.clone())),
        Bound::Unbounded => Bound::Unbounded,
    }
}

fn owner_records_filter(
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

fn owner_records_event_filter(filter: &RecordsFilter) -> BTreeMap<FilterKey, Filter<Value>> {
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

fn published_records_filter(
    filter: &RecordsFilter,
    date_sort: Option<&crate::descriptors::records::DateSort>,
) -> BTreeMap<FilterKey, Filter<Value>> {
    let mut map = owner_records_filter(filter, date_sort);
    map.insert(FilterKey::Index("published".to_string()), bool_filter(true));
    map
}

fn published_records_event_filter(filter: &RecordsFilter) -> BTreeMap<FilterKey, Filter<Value>> {
    let mut map = owner_records_event_filter(filter);
    map.insert(FilterKey::Index("published".to_string()), bool_filter(true));
    map
}

fn non_owner_records_filters(
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

fn non_owner_records_event_filters(
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

fn filter_includes_published_records(filter: &RecordsFilter) -> bool {
    filter.date_published.is_some() || filter.published != Some(false)
}

fn filter_includes_unpublished_records(filter: &RecordsFilter) -> bool {
    if filter.date_published.is_none() && filter.published.is_none() {
        return true;
    }
    filter.published == Some(false)
}

fn should_build_author_filter(filter: &RecordsFilter, author: &str) -> bool {
    filter
        .author
        .as_ref()
        .is_none_or(|authors| authors.is_empty() || authors.iter().any(|value| value == author))
}

fn should_build_recipient_filter(filter: &RecordsFilter, recipient: &str) -> bool {
    filter.recipient.as_ref().is_none_or(|recipients| {
        recipients.is_empty() || recipients.iter().any(|value| value == recipient)
    })
}

fn should_protocol_authorize(payload: &JsonValue) -> bool {
    payload
        .get("protocolRole")
        .and_then(JsonValue::as_str)
        .is_some()
}

fn date_sort_to_message_sort(
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

async fn authorize_records_read<MessageStore>(
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
        .await?
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

async fn authorize_records_delete<MessageStore>(
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
    .await?
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

async fn authorize_protocol_query_or_subscribe<MessageStore>(
    tenant: &str,
    filter: &RecordsFilter,
    payload: &JsonValue,
    author: &str,
    message_store: &MessageStore,
    kind: RecordsAuthorizationKind,
) -> Result<(), String>
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
    let definition =
        super::protocols::fetch_protocol_definition(tenant, protocol, message_store, None)
            .await
            .map_err(|err| err.to_string())?;
    let rule_set = protocol_types::get_rule_set_at_path(protocol_path, &definition.structure)
        .ok_or_else(|| {
            format!("ProtocolAuthorizationInvalidProtocolPath: {protocol_path} is not defined")
        })?;
    let can = match kind {
        RecordsAuthorizationKind::Subscribe => Can::Read,
        RecordsAuthorizationKind::Count | RecordsAuthorizationKind::Query => Can::Read,
        _ => Can::Read,
    };
    authorize_actions(
        tenant,
        author,
        payload.get("protocolRole").and_then(JsonValue::as_str),
        &[can],
        rule_set,
        &[],
        message_store,
        Some(&definition),
    )
    .await
}

async fn authorize_against_protocol<MessageStore>(
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
    let protocol = descriptor.protocol.as_deref().ok_or_else(|| {
        "ProtocolAuthorizationProtocolNotFound: protocol-based authorization requires protocol"
            .to_string()
    })?;
    let protocol_path = descriptor.protocol_path.as_deref().ok_or_else(|| {
        "ProtocolAuthorizationMissingProtocolPath: protocolPath is required".to_string()
    })?;
    let governing_timestamp = governing_timestamp(tenant, message, message_store, author).await?;
    let definition = super::protocols::fetch_protocol_definition(
        tenant,
        protocol,
        message_store,
        Some(&governing_timestamp),
    )
    .await
    .map_err(|err| err.to_string())?;
    let rule_set = protocol_types::get_rule_set_at_path(protocol_path, &definition.structure)
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
async fn authorize_actions<MessageStore>(
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

fn check_actor(
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
                    descriptor.protocol.as_deref() == Some(protocol.as_str())
                        && descriptor.protocol_path.as_deref() == Some(parsed.protocol_path)
                })
        } else {
            descriptor.protocol_path.as_deref() == Some(of)
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

async fn matching_role_record_exists<MessageStore>(
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
    let mut protocol = record_chain
        .last()
        .and_then(|message| records_write_descriptor(message).ok())
        .and_then(|descriptor| descriptor.protocol.clone())
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

async fn actions_for_message_kind<MessageStore>(
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

async fn governing_timestamp<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
    author: &str,
) -> Result<String, String>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if is_initial_write(message, author)? {
        return Ok(message_timestamp(message)?.to_rfc3339_opts(SecondsFormat::Micros, true));
    }
    let record_id = record_id(message)
        .ok_or_else(|| "RecordsWriteMissingRecordId: recordId is required".to_string())?;
    let initial = fetch_initial_write_message(tenant, &record_id, message_store)
        .await?
        .ok_or_else(|| {
            "RecordsWriteGetInitialWriteNotFound: Initial write is not found.".to_string()
        })?;
    Ok(message_timestamp(&initial)?.to_rfc3339_opts(SecondsFormat::Micros, true))
}

async fn construct_record_chain<MessageStore>(
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

async fn attach_initial_writes<MessageStore>(
    tenant: &str,
    messages: Vec<Message<Descriptor>>,
    message_store: &MessageStore,
    author_hint: Option<&str>,
) -> Vec<JsonValue>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let mut entries = Vec::new();
    for message in messages {
        let mut entry = serde_json::to_value(&message).unwrap_or(JsonValue::Null);
        let author = extract_author(&message).or_else(|| author_hint.map(str::to_string));
        let is_initial = author
            .as_deref()
            .and_then(|author| is_initial_write(&message, author).ok())
            .unwrap_or(false);
        if !is_initial {
            if let Some(record_id) = record_id(&message) {
                if let Ok(Some(initial_write)) =
                    fetch_initial_write_message(tenant, &record_id, message_store).await
                {
                    if let Some(object) = entry.as_object_mut() {
                        object.insert(
                            "initialWrite".to_string(),
                            serde_json::to_value(initial_write).unwrap_or(JsonValue::Null),
                        );
                    }
                }
            }
        }
        entries.push(entry);
    }
    entries
}

async fn fetch_record_messages<MessageStore>(
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

async fn fetch_newest_write<MessageStore>(
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

async fn fetch_initial_write_message<MessageStore>(
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

async fn existing_initial_lacks_data<DataStore>(
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

fn newest_message(messages: &[Message<Descriptor>]) -> Option<Message<Descriptor>> {
    messages.iter().cloned().max_by(compare_messages)
}

fn compare_messages(left: &Message<Descriptor>, right: &Message<Descriptor>) -> Ordering {
    let left_timestamp = message_timestamp(left).ok();
    let right_timestamp = message_timestamp(right).ok();
    left_timestamp
        .cmp(&right_timestamp)
        .then_with(|| message_cid(left).ok().cmp(&message_cid(right).ok()))
}

fn message_timestamp(
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

fn message_cid(message: &Message<Descriptor>) -> Result<String, String> {
    serde_json::to_value(message)
        .map_err(|err| err.to_string())
        .and_then(|value| generate_cid_from_json(&value).map_err(|err| err.to_string()))
        .map(|cid| cid.to_string())
}

fn extract_author(message: &Message<Descriptor>) -> Option<String> {
    permissions::message_author(message)
}

async fn delete_from_data_store_if_needed<DataStore>(
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

async fn purge_record_descendants<MessageStore, DataStore, StateIndex>(
    tenant: &str,
    record_id: &str,
    message_store: &MessageStore,
    data_store: &DataStore,
    state_index: &StateIndex,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Sync,
    DataStore: crate::stores::DataStore + Sync,
    StateIndex: crate::stores::StateIndex + Sync,
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
            state_index,
        ))
        .await?;
    }
    for messages in by_record.values() {
        purge_record_messages(tenant, messages, message_store, data_store, state_index).await?;
    }
    Ok(())
}

async fn purge_record_messages<MessageStore, DataStore, StateIndex>(
    tenant: &str,
    record_messages: &[Message<Descriptor>],
    message_store: &MessageStore,
    data_store: &DataStore,
    state_index: &StateIndex,
) -> Result<(), String>
where
    MessageStore: crate::stores::MessageStore + Sync,
    DataStore: crate::stores::DataStore + Sync,
    StateIndex: crate::stores::StateIndex + Sync,
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
    let mut cids = Vec::new();
    for message in record_messages {
        let cid = message_cid(message)?;
        message_store
            .delete(tenant, &cid)
            .await
            .map_err(|err| err.to_string())?;
        cids.push(cid);
    }
    state_index
        .delete(tenant, &cids)
        .await
        .map_err(|err| err.to_string())
}

fn can_perform_delete_against_record(
    delete_message: &Message<Descriptor>,
    newest_existing_message: &Message<Descriptor>,
) -> bool {
    let Ok(delete_descriptor) = records_delete_descriptor(delete_message) else {
        return false;
    };
    if let Ok(newest_delete) = records_delete_descriptor(newest_existing_message) {
        if !delete_descriptor.prune || newest_delete.prune {
            return false;
        }
    }
    true
}

fn parent_context_id(context_id: &str) -> Option<String> {
    context_id
        .rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .or_else(|| Some(String::new()))
}

fn string_filter(value: &str) -> Filter<Value> {
    Filter::Equal(Value::String(value.to_string()))
}

fn bool_filter(value: bool) -> Filter<Value> {
    Filter::Equal(Value::Bool(value))
}

fn filter_map<const N: usize>(
    items: [(&str, Filter<Value>); N],
) -> BTreeMap<FilterKey, Filter<Value>> {
    items
        .into_iter()
        .map(|(key, value)| (FilterKey::Index(key.to_string()), value))
        .collect()
}

fn accepted_reply() -> DwnReply {
    DwnReply::new(202, "Accepted")
}

fn conflict_reply() -> DwnReply {
    DwnReply::new(409, "Conflict")
}

fn not_found_reply() -> DwnReply {
    DwnReply::new(404, "Not Found")
}

fn store_error_reply(detail: impl Into<String>) -> DwnReply {
    DwnReply {
        status: Status {
            code: 500,
            detail: detail.into(),
        },
        body: BTreeMap::new(),
    }
}

fn records_subscribe_reply(
    reply: DwnReply,
    subscription: Option<EventSubscription>,
) -> RecordsSubscribeReply {
    RecordsSubscribeReply {
        reply,
        subscription,
    }
}

fn event_log_error_reply(error: EventLogError) -> DwnReply {
    match error {
        EventLogError::ProgressGap(gap_info) => {
            let mut error = serde_json::to_value(&*gap_info)
                .unwrap_or_else(|_| JsonValue::Object(serde_json::Map::new()));
            if let Some(error) = error.as_object_mut() {
                error.insert(
                    "code".to_string(),
                    JsonValue::String("ProgressGap".to_string()),
                );
            }
            DwnReply::new(410, "Progress token gap").with_body("error", error)
        }
        error => store_error_reply(error.to_string()),
    }
}

trait DescriptorMethod {
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
    use std::collections::BTreeMap;
    use std::sync::{Arc, RwLock};

    use futures_util::{Stream, StreamExt};

    use crate::auth::{
        Jws, JwsPrivateJwk, JwsPublicJwk, PrivateJwkSigner, StaticPublicKeyResolver,
    };
    use crate::descriptors::{ConfigureDescriptor, Protocols as ProtocolsDescriptor};
    use crate::errors::{DataStoreError, MessageStoreError, StoreError};
    use crate::events::MessageEvent;
    use crate::interfaces::messages::protocols::{ActionWho, Type};
    use crate::local::MemoryEventLog;
    use crate::state_index::MemoryStateIndex;
    use crate::stores::{
        DataStore, DataStoreGetResult, DataStorePutResult, EventLog, MessageQueryResult,
        MessageStore, StateIndex, SubscriptionMessage,
    };
    use crate::MapValue;

    use super::*;

    #[tokio::test]
    async fn records_write_read_query_and_count_published_inline_data() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();

        let write_handler = RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            state_index,
            test_resolver(),
        );
        let read_handler = RecordsReadHandler::new(message_store.clone(), data_store.clone());
        let query_handler = RecordsQueryHandler::new(message_store.clone());
        let count_handler = RecordsCountHandler::new(message_store.clone());

        let data = Bytes::from_static(b"hello world");
        let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
        let write = signed_write_message(WriteSpec {
            data_cid: data_cid.clone(),
            data_size: data.len() as u64,
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
        });
        let record_id = write["recordId"].as_str().unwrap().to_string();

        let reply = write_handler
            .handle_write("did:example:alice", &write, Some(data.clone()))
            .await;
        assert_eq!(reply.status.code, 202);

        let query = unsigned_query_message(json!({ "published": true }));
        let reply = query_handler
            .handle_query("did:example:alice", &query)
            .await;
        assert_eq!(reply.status.code, 200);
        let entries = reply.body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["encodedData"].as_str(),
            Some(URL_SAFE_NO_PAD.encode(&data).as_str())
        );

        let count = unsigned_count_message(json!({ "published": true }));
        let reply = count_handler
            .handle_count("did:example:alice", &count)
            .await;
        assert_eq!(reply.status.code, 200);
        assert_eq!(reply.body["count"], json!(1));

        let read = unsigned_read_message(json!({ "recordId": record_id }));
        let reply = read_handler.handle_read("did:example:alice", &read).await;
        assert_eq!(reply.status.code, 200);
        assert_eq!(
            reply.body["entry"]["encodedData"].as_str(),
            Some(URL_SAFE_NO_PAD.encode(&data).as_str())
        );
    }

    #[tokio::test]
    async fn records_write_update_without_data_copies_previous_inline_data_and_keeps_initial() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let handler = RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store,
            state_index,
            test_resolver(),
        );

        let data = Bytes::from_static(b"version one");
        let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
        let initial = signed_write_message(WriteSpec {
            data_cid: data_cid.clone(),
            data_size: data.len() as u64,
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
        });
        let record_id = initial["recordId"].as_str().unwrap().to_string();
        let context_id = initial["contextId"].as_str().unwrap().to_string();
        assert_eq!(
            handler
                .handle_write("did:example:alice", &initial, Some(data.clone()))
                .await
                .status
                .code,
            202
        );

        let update = signed_write_message(WriteSpec {
            record_id: Some(record_id.clone()),
            context_id: Some(context_id),
            data_cid,
            data_size: data.len() as u64,
            date_created: "2025-01-01T00:00:00.000000Z".to_string(),
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
        });
        let reply = handler
            .handle_write("did:example:alice", &update, None)
            .await;
        assert_eq!(reply.status.code, 202);

        let stored = fetch_record_messages("did:example:alice", &record_id, &message_store)
            .await
            .unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(
            stored
                .iter()
                .filter(|message| write_fields(message)
                    .ok()
                    .and_then(|fields| fields.encoded_data.as_ref())
                    .is_some())
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn records_write_rejects_older_conflicting_write() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let handler = RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store,
            state_index,
            test_resolver(),
        );

        let data = Bytes::from_static(b"newest");
        let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
        let initial = signed_write_message(WriteSpec {
            data_cid: data_cid.clone(),
            data_size: data.len() as u64,
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:10:00.000000Z")
        });
        let record_id = initial["recordId"].as_str().unwrap().to_string();
        let context_id = initial["contextId"].as_str().unwrap().to_string();
        assert_eq!(
            handler
                .handle_write("did:example:alice", &initial, Some(data.clone()))
                .await
                .status
                .code,
            202
        );

        let older = signed_write_message(WriteSpec {
            record_id: Some(record_id),
            context_id: Some(context_id),
            data_cid,
            data_size: data.len() as u64,
            date_created: "2025-01-01T00:10:00.000000Z".to_string(),
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:09:00.000000Z")
        });
        let reply = handler
            .handle_write("did:example:alice", &older, Some(data))
            .await;
        assert_eq!(reply.status.code, 409);
    }

    #[tokio::test]
    async fn records_read_returns_gone_when_external_data_is_missing() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let handler = RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            state_index,
            test_resolver(),
        );
        let read_handler = RecordsReadHandler::new(message_store.clone(), data_store.clone());

        let data = Bytes::from(vec![7u8; (MAX_ENCODED_DATA_SIZE + 1) as usize]);
        let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
        let write = signed_write_message(WriteSpec {
            data_cid: data_cid.clone(),
            data_size: data.len() as u64,
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
        });
        let record_id = write["recordId"].as_str().unwrap().to_string();
        assert_eq!(
            handler
                .handle_write("did:example:alice", &write, Some(data))
                .await
                .status
                .code,
            202
        );
        data_store
            .delete("did:example:alice", &record_id, &data_cid)
            .await
            .unwrap();

        let reply = read_handler
            .handle_read(
                "did:example:alice",
                &unsigned_read_message(json!({ "recordId": record_id })),
            )
            .await;
        assert_eq!(reply.status.code, 410);
    }

    #[tokio::test]
    async fn records_delete_prune_purges_descendant_records() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let write_handler = RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            state_index.clone(),
            test_resolver(),
        );
        let delete_handler = RecordsDeleteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            state_index,
            test_resolver(),
        );

        let data = Bytes::from_static(b"parent");
        let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
        let parent = signed_write_message(WriteSpec {
            data_cid,
            data_size: data.len() as u64,
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
        });
        let parent_record_id = parent["recordId"].as_str().unwrap().to_string();
        let parent_context_id = parent["contextId"].as_str().unwrap().to_string();
        assert_eq!(
            write_handler
                .handle_write("did:example:alice", &parent, Some(data))
                .await
                .status
                .code,
            202
        );

        let child_data = Bytes::from_static(b"child");
        let child_data_cid = generate_dag_pb_cid_from_bytes(&child_data).to_string();
        let child = signed_write_message(WriteSpec {
            parent_id: Some(parent_record_id.clone()),
            parent_context_id: Some(parent_context_id),
            data_cid: child_data_cid,
            data_size: child_data.len() as u64,
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
        });
        let child_record_id = child["recordId"].as_str().unwrap().to_string();
        assert_eq!(
            write_handler
                .handle_write("did:example:alice", &child, Some(child_data))
                .await
                .status
                .code,
            202
        );

        let delete = signed_delete_message(&parent_record_id, true, "2025-01-01T00:02:00.000000Z");
        let reply = delete_handler
            .handle_delete("did:example:alice", &delete)
            .await;
        assert_eq!(reply.status.code, 202);

        let child_messages =
            fetch_record_messages("did:example:alice", &child_record_id, &message_store)
                .await
                .unwrap();
        assert!(child_messages.is_empty());
    }

    #[tokio::test]
    async fn records_write_squash_purges_older_sibling_records_and_sets_backstop() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();
        put_squash_protocol("did:example:alice", &message_store).await;
        let handler = RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            state_index,
            test_resolver(),
        );

        let old_data = Bytes::from_static(b"old note");
        let old = signed_write_message(WriteSpec {
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path: Some("note".to_string()),
            data_cid: generate_dag_pb_cid_from_bytes(&old_data).to_string(),
            data_size: old_data.len() as u64,
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
        });
        let old_record_id = old["recordId"].as_str().unwrap().to_string();
        assert_eq!(
            handler
                .handle_write("did:example:alice", &old, Some(old_data))
                .await
                .status
                .code,
            202
        );

        let squash_data = Bytes::from_static(b"snapshot");
        let squash = signed_write_message(WriteSpec {
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path: Some("note".to_string()),
            data_cid: generate_dag_pb_cid_from_bytes(&squash_data).to_string(),
            data_size: squash_data.len() as u64,
            published: Some(true),
            squash: Some(true),
            ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
        });
        assert_eq!(
            handler
                .handle_write("did:example:alice", &squash, Some(squash_data))
                .await
                .status
                .code,
            202
        );
        assert!(
            fetch_record_messages("did:example:alice", &old_record_id, &message_store)
                .await
                .unwrap()
                .is_empty()
        );

        let late_old_data = Bytes::from_static(b"late old");
        let late_old = signed_write_message(WriteSpec {
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path: Some("note".to_string()),
            data_cid: generate_dag_pb_cid_from_bytes(&late_old_data).to_string(),
            data_size: late_old_data.len() as u64,
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:00:30.000000Z")
        });
        let reply = handler
            .handle_write("did:example:alice", &late_old, Some(late_old_data))
            .await;
        assert_eq!(reply.status.code, 409);
    }

    #[tokio::test]
    async fn records_write_accepts_permission_grant_id_and_enforces_publication_condition() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();
        put_notes_protocol_without_actions("did:example:alice", &message_store).await;

        let handler = RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store,
            state_index,
            test_resolver(),
        );

        let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"},"conditions":{"publication":"Required"}}"#);
        let grant = signed_write_message(WriteSpec {
            protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
            protocol_path: Some(permissions::PERMISSIONS_GRANT_PATH.to_string()),
            recipient: Some("did:example:bob".to_string()),
            tags: Some(MapValue::from([(
                "protocol".to_string(),
                Value::String("http://example.com/notes".to_string()),
            )])),
            data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
            data_size: grant_data.len() as u64,
            data_format: "application/json".to_string(),
            ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
        });
        let grant_id = grant["recordId"].as_str().unwrap().to_string();
        assert_eq!(
            handler
                .handle_write("did:example:alice", &grant, Some(grant_data.clone()))
                .await
                .status
                .code,
            202
        );
        let unpublished_data = Bytes::from_static(b"unpublished note");
        let unpublished = signed_write_message(WriteSpec {
            author: "did:example:bob".to_string(),
            signer: bob_signer(),
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path: Some("note".to_string()),
            data_cid: generate_dag_pb_cid_from_bytes(&unpublished_data).to_string(),
            data_size: unpublished_data.len() as u64,
            permission_grant_id: Some(grant_id.clone()),
            ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
        });
        let reply = handler
            .handle_write("did:example:alice", &unpublished, Some(unpublished_data))
            .await;
        assert_eq!(reply.status.code, 401);
        assert!(reply
            .status
            .detail
            .contains("RecordsGrantAuthorizationConditionPublicationRequired"));

        let published_data = Bytes::from_static(b"published note");
        let published = signed_write_message(WriteSpec {
            author: "did:example:bob".to_string(),
            signer: bob_signer(),
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path: Some("note".to_string()),
            data_cid: generate_dag_pb_cid_from_bytes(&published_data).to_string(),
            data_size: published_data.len() as u64,
            published: Some(true),
            permission_grant_id: Some(grant_id),
            ..WriteSpec::new("2025-01-01T00:02:00.000000Z")
        });
        let reply = handler
            .handle_write("did:example:alice", &published, Some(published_data))
            .await;
        assert_eq!(reply.status.code, 202);
    }

    #[tokio::test]
    async fn records_write_accepts_embedded_author_delegated_grant() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();
        put_notes_protocol_without_actions("did:example:alice", &message_store).await;

        let handler = RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store,
            state_index,
            test_resolver(),
        );

        let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"},"delegated":true}"#);
        let grant = signed_write_message(WriteSpec {
            protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
            protocol_path: Some(permissions::PERMISSIONS_GRANT_PATH.to_string()),
            recipient: Some("did:example:bob".to_string()),
            tags: Some(MapValue::from([(
                "protocol".to_string(),
                Value::String("http://example.com/notes".to_string()),
            )])),
            data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
            data_size: grant_data.len() as u64,
            data_format: "application/json".to_string(),
            ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
        });
        assert_eq!(
            handler
                .handle_write("did:example:alice", &grant, Some(grant_data.clone()))
                .await
                .status
                .code,
            202
        );
        let mut delegated_grant = grant.clone();
        delegated_grant["encodedData"] = JsonValue::String(URL_SAFE_NO_PAD.encode(&grant_data));

        let note_data = Bytes::from_static(b"delegated note");
        let note = signed_write_message(WriteSpec {
            author: "did:example:alice".to_string(),
            signer: bob_signer(),
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path: Some("note".to_string()),
            data_cid: generate_dag_pb_cid_from_bytes(&note_data).to_string(),
            data_size: note_data.len() as u64,
            ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
        });
        let note = with_author_delegated_grant(note, &delegated_grant, bob_signer());
        let reply = handler
            .handle_write("did:example:alice", &note, Some(note_data))
            .await;
        assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    }

    #[tokio::test]
    async fn permissions_revocation_cleans_grant_authorized_messages() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();
        put_notes_protocol_without_actions("did:example:alice", &message_store).await;

        let handler = RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            state_index,
            test_resolver(),
        );

        let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"}}"#);
        let grant = signed_write_message(WriteSpec {
            protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
            protocol_path: Some(permissions::PERMISSIONS_GRANT_PATH.to_string()),
            recipient: Some("did:example:bob".to_string()),
            tags: Some(MapValue::from([(
                "protocol".to_string(),
                Value::String("http://example.com/notes".to_string()),
            )])),
            data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
            data_size: grant_data.len() as u64,
            data_format: "application/json".to_string(),
            ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
        });
        let grant_id = grant["recordId"].as_str().unwrap().to_string();
        assert_eq!(
            handler
                .handle_write("did:example:alice", &grant, Some(grant_data))
                .await
                .status
                .code,
            202
        );

        let note_data = Bytes::from_static(b"revoked note");
        let note = signed_write_message(WriteSpec {
            author: "did:example:bob".to_string(),
            signer: bob_signer(),
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path: Some("note".to_string()),
            data_cid: generate_dag_pb_cid_from_bytes(&note_data).to_string(),
            data_size: note_data.len() as u64,
            permission_grant_id: Some(grant_id.clone()),
            ..WriteSpec::new("2025-01-01T00:05:00.000000Z")
        });
        let note_record_id = note["recordId"].as_str().unwrap().to_string();
        assert_eq!(
            handler
                .handle_write("did:example:alice", &note, Some(note_data))
                .await
                .status
                .code,
            202
        );

        let revoke_data = Bytes::from_static(br#"{"description":"revoke"}"#);
        let revocation = signed_write_message(WriteSpec {
            protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
            protocol_path: Some(permissions::PERMISSIONS_REVOCATION_PATH.to_string()),
            parent_id: Some(grant_id.clone()),
            parent_context_id: Some(grant_id.clone()),
            tags: Some(MapValue::from([(
                "protocol".to_string(),
                Value::String("http://example.com/notes".to_string()),
            )])),
            data_cid: generate_dag_pb_cid_from_bytes(&revoke_data).to_string(),
            data_size: revoke_data.len() as u64,
            data_format: "application/json".to_string(),
            ..WriteSpec::new("2025-01-01T00:04:00.000000Z")
        });
        assert_eq!(
            handler
                .handle_write("did:example:alice", &revocation, Some(revoke_data))
                .await
                .status
                .code,
            202
        );

        assert!(
            fetch_record_messages("did:example:alice", &note_record_id, &message_store)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn records_event_log_subscribe_replays_from_cursor_and_sends_eose() {
        let mut message_store = TestMessageStore::default();
        let mut event_log = MemoryEventLog::default();
        message_store.open().await.unwrap();
        event_log.open().await.unwrap();

        let note = stored_note_message("2025-01-01T00:01:00.000000Z");
        let first = event_log
            .emit(
                "did:example:alice",
                MessageEvent {
                    message: note.clone(),
                    initial_write: None,
                },
                record_event_indexes("http://example.com/notes", "Write"),
                "first-cid",
            )
            .await
            .unwrap()
            .unwrap();
        event_log
            .emit(
                "did:example:alice",
                MessageEvent {
                    message: note,
                    initial_write: None,
                },
                record_event_indexes("http://example.com/notes", "Write"),
                "second-cid",
            )
            .await
            .unwrap();

        let delivered = Arc::new(RwLock::new(Vec::new()));
        let delivered_for_listener = delivered.clone();
        let handler = RecordsEventLogSubscribeHandler::with_public_key_resolver(
            message_store,
            event_log,
            test_resolver(),
        );
        let request = signed_records_subscribe_message(
            RecordsFilter {
                protocol: Some("http://example.com/notes".to_string()),
                ..Default::default()
            },
            Some(first),
            "2025-01-01T00:10:00.000000Z",
        );

        let result = handler
            .handle_subscribe(
                "did:example:alice",
                &request,
                Box::new(move |message| delivered_for_listener.write().unwrap().push(message)),
            )
            .await;
        assert_eq!(
            result.reply.status.code, 200,
            "{}",
            result.reply.status.detail
        );
        assert!(!result.reply.body.contains_key("entries"));
        assert_eq!(
            result.reply.body["subscriptionId"],
            result.subscription.as_ref().unwrap().id
        );
        let delivered = delivered.read().unwrap();
        assert_eq!(delivered.len(), 2);
        match &delivered[0] {
            SubscriptionMessage::Event { cursor, .. } => {
                assert_eq!(cursor.position, "2");
                assert_eq!(cursor.message_cid, "second-cid");
            }
            other => panic!("expected event, got {other:?}"),
        }
        match &delivered[1] {
            SubscriptionMessage::Eose { cursor } => {
                assert_eq!(cursor.position, "2");
                assert_eq!(cursor.message_cid, "second-cid");
            }
            other => panic!("expected eose, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn records_event_log_subscribe_maps_progress_gap_to_410() {
        let message_store = TestMessageStore::default();
        let mut event_log = MemoryEventLog::new(1);
        event_log.open().await.unwrap();

        let note = stored_note_message("2025-01-01T00:01:00.000000Z");
        let mut old_cursor = event_log
            .emit(
                "did:example:alice",
                MessageEvent {
                    message: note.clone(),
                    initial_write: None,
                },
                record_event_indexes("http://example.com/notes", "Write"),
                "first-cid",
            )
            .await
            .unwrap()
            .unwrap();
        old_cursor.position = "0".to_string();
        event_log
            .emit(
                "did:example:alice",
                MessageEvent {
                    message: note,
                    initial_write: None,
                },
                record_event_indexes("http://example.com/notes", "Write"),
                "second-cid",
            )
            .await
            .unwrap();

        let handler = RecordsEventLogSubscribeHandler::with_public_key_resolver(
            message_store,
            event_log,
            test_resolver(),
        );
        let request = signed_records_subscribe_message(
            RecordsFilter {
                protocol: Some("http://example.com/notes".to_string()),
                ..Default::default()
            },
            Some(old_cursor),
            "2025-01-01T00:10:00.000000Z",
        );

        let result = handler
            .handle_subscribe("did:example:alice", &request, Box::new(|_| {}))
            .await;
        assert_eq!(result.reply.status.code, 410);
        assert_eq!(result.reply.body["error"]["code"], "ProgressGap");
        assert_eq!(result.reply.body["error"]["reason"], "token_too_old");
        assert!(result.subscription.is_none());
    }

    #[tokio::test]
    async fn records_event_log_subscribe_without_cursor_returns_snapshot_and_live_subscription() {
        let mut message_store = TestMessageStore::default();
        let mut event_log = MemoryEventLog::default();
        message_store.open().await.unwrap();
        event_log.open().await.unwrap();

        let note = stored_note_message("2025-01-01T00:01:00.000000Z");
        let indexes = records_write_indexes(&note, "did:example:alice", true).unwrap();
        message_store
            .put("did:example:alice", note.clone(), indexes)
            .await
            .unwrap();

        let delivered = Arc::new(RwLock::new(Vec::new()));
        let delivered_for_listener = delivered.clone();
        let handler = RecordsEventLogSubscribeHandler::with_public_key_resolver(
            message_store,
            event_log.clone(),
            test_resolver(),
        );
        let request = signed_records_subscribe_message(
            RecordsFilter {
                protocol: Some("http://example.com/notes".to_string()),
                ..Default::default()
            },
            None,
            "2025-01-01T00:10:00.000000Z",
        );

        let result = handler
            .handle_subscribe(
                "did:example:alice",
                &request,
                Box::new(move |message| delivered_for_listener.write().unwrap().push(message)),
            )
            .await;
        assert_eq!(
            result.reply.status.code, 200,
            "{}",
            result.reply.status.detail
        );
        assert_eq!(result.reply.body["entries"].as_array().unwrap().len(), 1);
        assert!(result.subscription.is_some());

        event_log
            .emit(
                "did:example:alice",
                MessageEvent {
                    message: note,
                    initial_write: None,
                },
                record_event_indexes("http://example.com/notes", "Write"),
                "live-cid",
            )
            .await
            .unwrap();
        let delivered = delivered.read().unwrap();
        assert_eq!(delivered.len(), 1);
        assert!(matches!(delivered[0], SubscriptionMessage::Event { .. }));
    }

    #[test]
    fn generic_records_descriptor_deserializes_by_method() {
        let count = json!({
            "interface": "Records",
            "method": "Count",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z",
            "filter": { "published": true }
        });
        let descriptor: Descriptor = serde_json::from_value(count).unwrap();
        assert!(matches!(
            descriptor,
            Descriptor::Records(records) if matches!(records.as_ref(), Records::Count(_))
        ));

        let query = json!({
            "interface": "Records",
            "method": "Query",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z",
            "filter": { "published": true }
        });
        let descriptor: Descriptor = serde_json::from_value(query).unwrap();
        assert!(matches!(
            descriptor,
            Descriptor::Records(records) if matches!(records.as_ref(), Records::Query(_))
        ));
    }

    #[derive(Clone)]
    struct WriteSpec {
        author: String,
        signer: PrivateJwkSigner,
        timestamp: String,
        date_created: String,
        record_id: Option<String>,
        context_id: Option<String>,
        parent_id: Option<String>,
        parent_context_id: Option<String>,
        protocol: Option<String>,
        protocol_path: Option<String>,
        recipient: Option<String>,
        tags: Option<MapValue>,
        data_cid: String,
        data_size: u64,
        data_format: String,
        published: Option<bool>,
        permission_grant_id: Option<String>,
        squash: Option<bool>,
    }

    impl WriteSpec {
        fn new(timestamp: &str) -> Self {
            Self {
                author: "did:example:alice".to_string(),
                signer: test_signer(),
                timestamp: timestamp.to_string(),
                date_created: timestamp.to_string(),
                record_id: None,
                context_id: None,
                parent_id: None,
                parent_context_id: None,
                protocol: None,
                protocol_path: None,
                recipient: None,
                tags: None,
                data_cid: generate_dag_pb_cid_from_bytes([]).to_string(),
                data_size: 0,
                data_format: "text/plain".to_string(),
                published: None,
                permission_grant_id: None,
                squash: None,
            }
        }
    }

    fn signed_write_message(spec: WriteSpec) -> JsonValue {
        let descriptor = RecordsWriteDescriptor {
            protocol: spec.protocol,
            protocol_path: spec.protocol_path,
            recipient: spec.recipient,
            schema: None,
            tags: spec.tags,
            parent_id: spec.parent_id.clone(),
            data_cid: spec.data_cid,
            data_size: spec.data_size,
            date_created: parse_time(&spec.date_created),
            message_timestamp: parse_time(&spec.timestamp),
            published: spec.published,
            date_published: spec.published.map(|_| parse_time(&spec.timestamp)),
            data_format: spec.data_format,
            permission_grant_id: spec.permission_grant_id.clone(),
            squash: spec.squash,
        };
        let record_id = spec
            .record_id
            .clone()
            .unwrap_or_else(|| entry_id(&spec.author, &descriptor).unwrap());
        let context_id = spec.context_id.unwrap_or_else(|| {
            spec.parent_context_id
                .filter(|context| !context.is_empty())
                .map(|parent| format!("{parent}/{record_id}"))
                .unwrap_or_else(|| record_id.clone())
        });
        let descriptor_json = serde_json::to_value(&descriptor).unwrap();
        let signature_payload = payload_with_permission_grant(
            &record_id,
            &context_id,
            spec.permission_grant_id.as_deref(),
        );
        let signature = signature_for_descriptor(&descriptor_json, signature_payload, spec.signer);
        json!({
            "descriptor": descriptor_json,
            "recordId": record_id,
            "contextId": context_id,
            "authorization": { "signature": signature }
        })
    }

    fn with_author_delegated_grant(
        mut message: JsonValue,
        grant: &JsonValue,
        signer: PrivateJwkSigner,
    ) -> JsonValue {
        let grant_message: Message<Descriptor> = serde_json::from_value(grant.clone()).unwrap();
        let grant_cid = message_cid(&grant_message).unwrap();
        let descriptor_json = message["descriptor"].clone();
        let signature = signature_for_descriptor(
            &descriptor_json,
            json!({
                "recordId": message["recordId"].as_str().unwrap(),
                "contextId": message["contextId"].as_str().unwrap(),
                "delegatedGrantId": grant_cid,
            }),
            signer,
        );
        message["authorization"] = json!({
            "signature": signature,
            "authorDelegatedGrant": grant,
        });
        message
    }

    fn signed_delete_message(record_id: &str, prune: bool, timestamp: &str) -> JsonValue {
        let descriptor = DeleteDescriptor {
            message_timestamp: parse_time(timestamp),
            record_id: record_id.to_string(),
            prune,
        };
        let descriptor_json = serde_json::to_value(&descriptor).unwrap();
        let signature = signature_for_descriptor(&descriptor_json, json!({}), test_signer());
        json!({
            "descriptor": descriptor_json,
            "authorization": { "signature": signature }
        })
    }

    fn stored_note_message(timestamp: &str) -> Message<Descriptor> {
        serde_json::from_value(signed_write_message(WriteSpec {
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path: Some("note".to_string()),
            ..WriteSpec::new(timestamp)
        }))
        .unwrap()
    }

    fn record_event_indexes(protocol: &str, method: &str) -> KeyValues {
        KeyValues::from([
            (
                "interface".to_string(),
                Value::String(RECORDS_INTERFACE.to_string()),
            ),
            ("method".to_string(), Value::String(method.to_string())),
            ("protocol".to_string(), Value::String(protocol.to_string())),
        ])
    }

    fn signed_records_subscribe_message(
        filter: RecordsFilter,
        cursor: Option<crate::stores::ProgressToken>,
        timestamp: &str,
    ) -> JsonValue {
        let descriptor = SubscribeDescriptor {
            message_timestamp: parse_time(timestamp),
            filter,
            date_sort: None,
            pagination: None,
            cursor,
        };
        let descriptor_json = serde_json::to_value(&descriptor).unwrap();
        let signature = signature_for_descriptor(&descriptor_json, json!({}), test_signer());
        json!({
            "descriptor": descriptor_json,
            "authorization": { "signature": signature }
        })
    }

    fn unsigned_query_message(filter: JsonValue) -> JsonValue {
        json!({
            "descriptor": {
                "interface": "Records",
                "method": "Query",
                "messageTimestamp": "2025-01-01T00:10:00.000000Z",
                "filter": filter
            }
        })
    }

    fn unsigned_count_message(filter: JsonValue) -> JsonValue {
        json!({
            "descriptor": {
                "interface": "Records",
                "method": "Count",
                "messageTimestamp": "2025-01-01T00:10:00.000000Z",
                "filter": filter
            }
        })
    }

    fn unsigned_read_message(filter: JsonValue) -> JsonValue {
        json!({
            "descriptor": {
                "interface": "Records",
                "method": "Read",
                "messageTimestamp": "2025-01-01T00:10:00.000000Z",
                "filter": filter
            }
        })
    }

    async fn put_squash_protocol(tenant: &str, message_store: &TestMessageStore) {
        let definition = Definition {
            protocol: "http://example.com/notes".to_string(),
            published: true,
            uses: None,
            types: BTreeMap::from([(
                "note".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["text/plain".to_string()]),
                    encryption_required: None,
                },
            )]),
            structure: BTreeMap::from([(
                "note".to_string(),
                RuleSet {
                    squash: Some(true),
                    actions: vec![Action::Who(ActionWho {
                        who: Who::Anyone,
                        of: None,
                        can: vec![Can::Create, Can::Read, Can::Squash],
                    })],
                    ..Default::default()
                },
            )]),
        };
        let descriptor = ConfigureDescriptor {
            message_timestamp: parse_time("2024-12-31T00:00:00.000000Z"),
            definition,
            permission_grant_id: None,
        };
        let message = Message {
            descriptor: Descriptor::Protocols(Box::new(ProtocolsDescriptor::Configure(descriptor))),
            fields: Fields::Write(WriteFields::default()),
        };
        let indexes = BTreeMap::from([
            (
                "interface".to_string(),
                Value::String("Protocols".to_string()),
            ),
            ("method".to_string(), Value::String("Configure".to_string())),
            (
                "protocol".to_string(),
                Value::String("http://example.com/notes".to_string()),
            ),
            ("published".to_string(), Value::Bool(true)),
            ("isLatestBaseState".to_string(), Value::Bool(true)),
            (
                "messageTimestamp".to_string(),
                Value::String("2024-12-31T00:00:00.000000Z".to_string()),
            ),
        ]);
        message_store.put(tenant, message, indexes).await.unwrap();
    }

    async fn put_notes_protocol_without_actions(tenant: &str, message_store: &TestMessageStore) {
        let definition = Definition {
            protocol: "http://example.com/notes".to_string(),
            published: false,
            uses: None,
            types: BTreeMap::from([(
                "note".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["text/plain".to_string()]),
                    encryption_required: None,
                },
            )]),
            structure: BTreeMap::from([("note".to_string(), RuleSet::default())]),
        };
        let descriptor = ConfigureDescriptor {
            message_timestamp: parse_time("2024-12-31T00:00:00.000000Z"),
            definition,
            permission_grant_id: None,
        };
        let message = Message {
            descriptor: Descriptor::Protocols(Box::new(ProtocolsDescriptor::Configure(descriptor))),
            fields: Fields::Write(WriteFields::default()),
        };
        let indexes = BTreeMap::from([
            (
                "interface".to_string(),
                Value::String("Protocols".to_string()),
            ),
            ("method".to_string(), Value::String("Configure".to_string())),
            (
                "protocol".to_string(),
                Value::String("http://example.com/notes".to_string()),
            ),
            ("published".to_string(), Value::Bool(false)),
            ("isLatestBaseState".to_string(), Value::Bool(true)),
            (
                "messageTimestamp".to_string(),
                Value::String("2024-12-31T00:00:00.000000Z".to_string()),
            ),
        ]);
        message_store.put(tenant, message, indexes).await.unwrap();
    }

    fn signature_for_descriptor(
        descriptor: &JsonValue,
        extra_payload: JsonValue,
        signer: PrivateJwkSigner,
    ) -> Jws {
        let mut payload = extra_payload.as_object().cloned().unwrap_or_default();
        payload.insert(
            "descriptorCid".to_string(),
            JsonValue::String(generate_cid_from_json(descriptor).unwrap().to_string()),
        );
        Jws::create_general(
            serde_json::to_vec(&JsonValue::Object(payload))
                .unwrap()
                .as_slice(),
            &[signer],
        )
        .unwrap()
    }

    fn payload_with_permission_grant(
        record_id: &str,
        context_id: &str,
        permission_grant_id: Option<&str>,
    ) -> JsonValue {
        let mut payload = serde_json::Map::from_iter([
            (
                "recordId".to_string(),
                JsonValue::String(record_id.to_string()),
            ),
            (
                "contextId".to_string(),
                JsonValue::String(context_id.to_string()),
            ),
        ]);
        if let Some(permission_grant_id) = permission_grant_id {
            payload.insert(
                "permissionGrantId".to_string(),
                JsonValue::String(permission_grant_id.to_string()),
            );
        }
        JsonValue::Object(payload)
    }

    fn parse_time(value: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn test_signer() -> PrivateJwkSigner {
        signer_for("did:example:alice")
    }

    fn bob_signer() -> PrivateJwkSigner {
        signer_for("did:example:bob")
    }

    fn signer_for(did: &str) -> PrivateJwkSigner {
        let key_id = format!("{did}#key1");
        PrivateJwkSigner::new(
            &key_id,
            "EdDSA",
            JwsPrivateJwk {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                d: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string(),
                x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
                y: None,
                kid: Some(key_id.clone()),
                alg: Some("EdDSA".to_string()),
            },
        )
    }

    fn test_resolver() -> StaticPublicKeyResolver {
        StaticPublicKeyResolver::new(BTreeMap::from([
            (
                "did:example:alice#key1".to_string(),
                test_public_jwk("did:example:alice#key1"),
            ),
            (
                "did:example:bob#key1".to_string(),
                test_public_jwk("did:example:bob#key1"),
            ),
        ]))
    }

    fn test_public_jwk(key_id: &str) -> JwsPublicJwk {
        JwsPublicJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
            y: None,
            kid: Some(key_id.to_string()),
            alg: Some("EdDSA".to_string()),
        }
    }

    #[derive(Clone, Default)]
    struct TestMessageStore {
        rows: Arc<RwLock<Vec<TestMessageRow>>>,
    }

    #[derive(Clone)]
    struct TestMessageRow {
        tenant: String,
        cid: String,
        message: Message<Descriptor>,
        indexes: KeyValues,
    }

    impl MessageStore for TestMessageStore {
        async fn open(&mut self) -> Result<(), MessageStoreError> {
            Ok(())
        }

        async fn close(&mut self) {}

        fn put(
            &self,
            tenant: &str,
            message: Message<Descriptor>,
            indexes: KeyValues,
        ) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
            let rows = self.rows.clone();
            let tenant = tenant.to_string();
            async move {
                let cid = message_cid(&message).map_err(test_store_error)?;
                rows.write()
                    .unwrap()
                    .retain(|row| row.tenant != tenant || row.cid != cid);
                rows.write().unwrap().push(TestMessageRow {
                    tenant,
                    cid,
                    message,
                    indexes,
                });
                Ok(())
            }
        }

        fn get(
            &self,
            tenant: &str,
            cid: &str,
        ) -> impl Future<Output = Result<Option<Message<Descriptor>>, MessageStoreError>> + Send
        {
            let rows = self.rows.clone();
            let tenant = tenant.to_string();
            let cid = cid.to_string();
            async move {
                Ok(rows
                    .read()
                    .unwrap()
                    .iter()
                    .find(|row| row.tenant == tenant && row.cid == cid)
                    .map(|row| row.message.clone()))
            }
        }

        fn query(
            &self,
            tenant: &str,
            filters: Filters,
            sort: Option<MessageSort>,
            pagination: Option<Pagination>,
        ) -> impl Future<Output = Result<MessageQueryResult, MessageStoreError>> + Send {
            let rows = self.rows.clone();
            let tenant = tenant.to_string();
            async move {
                let mut rows = rows
                    .read()
                    .unwrap()
                    .iter()
                    .filter(|row| {
                        row.tenant == tenant && matches_filters(&row.indexes, filters.clone())
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if let Some(sort) = sort {
                    let (property, direction) = match sort {
                        MessageSort::DateCreated(direction) => ("dateCreated", direction),
                        MessageSort::DatePublished(direction) => ("datePublished", direction),
                        MessageSort::Timestamp(direction) => ("messageTimestamp", direction),
                    };
                    rows.sort_by(|left, right| {
                        let order = value_string(left.indexes.get(property))
                            .cmp(&value_string(right.indexes.get(property)))
                            .then_with(|| left.cid.cmp(&right.cid));
                        match direction {
                            SortDirection::Ascending => order,
                            SortDirection::Descending => order.reverse(),
                        }
                    });
                }
                if let Some(limit) = pagination.and_then(|pagination| pagination.limit) {
                    rows.truncate(limit as usize);
                }
                Ok(MessageQueryResult {
                    messages: rows.into_iter().map(|row| row.message).collect(),
                    cursor: None,
                })
            }
        }

        async fn count(
            &self,
            tenant: &str,
            filters: Filters,
            sort: Option<MessageSort>,
        ) -> Result<u64, MessageStoreError> {
            Ok(self
                .query(tenant, filters, sort, None)
                .await?
                .messages
                .len() as u64)
        }

        fn delete(
            &self,
            tenant: &str,
            cid: &str,
        ) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
            let rows = self.rows.clone();
            let tenant = tenant.to_string();
            let cid = cid.to_string();
            async move {
                rows.write()
                    .unwrap()
                    .retain(|row| row.tenant != tenant || row.cid != cid);
                Ok(())
            }
        }

        fn clear(&self) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
            let rows = self.rows.clone();
            async move {
                rows.write().unwrap().clear();
                Ok(())
            }
        }
    }

    type TestDataKey = (String, String, String);
    type TestDataValues = Arc<RwLock<BTreeMap<TestDataKey, Bytes>>>;

    #[derive(Clone, Default)]
    struct TestDataStore {
        values: TestDataValues,
    }

    impl DataStore for TestDataStore {
        async fn open(&mut self) -> Result<(), DataStoreError> {
            Ok(())
        }

        async fn close(&mut self) {}

        fn put<T: Stream<Item = Bytes> + Send + Unpin>(
            &self,
            tenant: &str,
            record_id: &str,
            data_cid: &str,
            mut data_stream: T,
        ) -> impl Future<Output = Result<DataStorePutResult, DataStoreError>> + Send {
            let values = self.values.clone();
            let key = (
                tenant.to_string(),
                record_id.to_string(),
                data_cid.to_string(),
            );
            async move {
                let mut bytes = Vec::new();
                while let Some(chunk) = data_stream.next().await {
                    bytes.extend_from_slice(&chunk);
                }
                let bytes = Bytes::from(bytes);
                let data_size = bytes.len();
                values.write().unwrap().insert(key, bytes);
                Ok(DataStorePutResult { data_size })
            }
        }

        fn get(
            &self,
            tenant: &str,
            record_id: &str,
            data_cid: &str,
        ) -> impl Future<Output = Result<Option<DataStoreGetResult>, DataStoreError>> + Send
        {
            let values = self.values.clone();
            let key = (
                tenant.to_string(),
                record_id.to_string(),
                data_cid.to_string(),
            );
            async move {
                Ok(values.read().unwrap().get(&key).cloned().map(|bytes| {
                    let data_size = bytes.len();
                    DataStoreGetResult {
                        data_size,
                        data_stream: Box::pin(stream::iter(vec![Ok(bytes)])),
                    }
                }))
            }
        }

        fn delete(
            &self,
            tenant: &str,
            record_id: &str,
            data_cid: &str,
        ) -> impl Future<Output = Result<(), DataStoreError>> + Send {
            let values = self.values.clone();
            let key = (
                tenant.to_string(),
                record_id.to_string(),
                data_cid.to_string(),
            );
            async move {
                values.write().unwrap().remove(&key);
                Ok(())
            }
        }

        fn clear(&self) -> impl Future<Output = Result<(), DataStoreError>> + Send {
            let values = self.values.clone();
            async move {
                values.write().unwrap().clear();
                Ok(())
            }
        }
    }

    fn matches_filters(indexes: &KeyValues, filters: Filters) -> bool {
        let mut has_filter_set = false;
        for filter_set in filters {
            has_filter_set = true;
            if filter_set.into_iter().all(|(key, filter)| match key {
                FilterKey::Index(index) => indexes
                    .get(&index)
                    .is_some_and(|value| matches_filter(value, &filter)),
                FilterKey::Tag(_) => false,
            }) {
                return true;
            }
        }
        !has_filter_set
    }

    fn matches_filter(value: &Value, filter: &Filter<Value>) -> bool {
        match filter {
            Filter::Equal(expected) => value == expected,
            Filter::OneOf(values) => values.iter().any(|expected| value == expected),
            Filter::Prefix(prefix) => {
                value_string(Some(value)).starts_with(&value_string(Some(prefix)))
            }
            Filter::Range(RangeFilter::Numeric(lower, upper))
            | Filter::Range(RangeFilter::Criterion(lower, upper)) => {
                matches_lower_bound(value, lower) && matches_upper_bound(value, upper)
            }
        }
    }

    fn matches_lower_bound(value: &Value, bound: &Bound<Value>) -> bool {
        match bound {
            Bound::Included(bound) => value_string(Some(value)) >= value_string(Some(bound)),
            Bound::Excluded(bound) => value_string(Some(value)) > value_string(Some(bound)),
            Bound::Unbounded => true,
        }
    }

    fn matches_upper_bound(value: &Value, bound: &Bound<Value>) -> bool {
        match bound {
            Bound::Included(bound) => value_string(Some(value)) <= value_string(Some(bound)),
            Bound::Excluded(bound) => value_string(Some(value)) < value_string(Some(bound)),
            Bound::Unbounded => true,
        }
    }

    fn value_string(value: Option<&Value>) -> String {
        match value {
            Some(Value::String(value)) => value.clone(),
            Some(Value::Bool(value)) => value.to_string(),
            Some(value) => value.to_string(),
            None => String::new(),
        }
    }

    fn test_store_error(error: String) -> MessageStoreError {
        MessageStoreError::StoreError(StoreError::InternalException(error))
    }
}
