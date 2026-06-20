use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::auth::JwsPublicKeyResolver;
use crate::dwn::core_protocol::CoreProtocolRegistry;
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::stores::EventSubscription;

mod common;
mod count;
mod delete;
mod query;
mod read;
mod subscribe;
mod write;

#[cfg(test)]
mod tests;

pub(crate) const RECORDS_INTERFACE: &str = "Records";
pub(crate) const WRITE_METHOD: &str = "Write";
pub(crate) const MAX_ENCODED_DATA_SIZE: u64 = 30_000;

#[derive(Clone)]
pub struct RecordsWriteHandler<MessageStore, DataStore, StateIndex, EventLog = ()> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
    event_log: Option<EventLog>,
    core_protocol_registry: CoreProtocolRegistry,
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

pub(crate) use delete::{resume_records_delete_from_task, resume_records_squash_from_task};
