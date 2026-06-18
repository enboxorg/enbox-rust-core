use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::auth::JwsPublicKeyResolver;
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::stores::EventSubscription;

mod common;
mod read;
mod subscribe;
mod sync;

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct MessagesSubscribeHandler<MessageStore, EventLog> {
    message_store: MessageStore,
    event_log: EventLog,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

pub struct SubscribeReply {
    pub reply: DwnReply,
    pub subscription: Option<EventSubscription>,
}

#[derive(Clone)]
pub struct MessagesSyncHandler<MessageStore, DataStore, StateIndex> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

#[derive(Clone)]
pub struct MessagesReadHandler<MessageStore, DataStore> {
    message_store: MessageStore,
    data_store: DataStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MessageStore, DataStore> MessagesReadHandler<MessageStore, DataStore> {
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

impl<MessageStore, DataStore> MethodHandler for MessagesReadHandler<MessageStore, DataStore>
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
