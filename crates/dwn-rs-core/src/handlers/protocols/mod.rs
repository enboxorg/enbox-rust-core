use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Bound;
use std::pin::Pin;
use std::sync::Arc;

use chrono::SecondsFormat;
use serde_json::Value as JsonValue;

use crate::auth::JwsPublicKeyResolver;
use crate::core_protocol::CoreProtocolRegistry;
use crate::descriptors::{ConfigureDescriptor, Descriptor, Protocols};
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::interfaces::messages::protocols::{self as protocol_types, Definition, RuleSet};
use crate::interfaces::replies::Status;
use crate::permissions;
use crate::stores::KeyValues;
use crate::{Message, MessageSort, Pagination, SortDirection, Value};

const PROTOCOLS_INTERFACE: &str = "Protocols";
const CONFIGURE_METHOD: &str = "Configure";

mod common;
mod configure;
mod query;

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct ProtocolsConfigureHandler<MessageStore, StateIndex> {
    message_store: MessageStore,
    state_index: StateIndex,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

#[derive(Clone)]
pub struct ProtocolsQueryHandler<MessageStore> {
    message_store: MessageStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolDefinitionLookupError {
    #[error("ProtocolAuthorizationProtocolNotFound: unable to find protocol definition for {0}")]
    NotFound(String),
    #[error("{0}")]
    Store(String),
    #[error("{0}")]
    InvalidMessage(String),
}

impl<MessageStore, StateIndex> ProtocolsConfigureHandler<MessageStore, StateIndex> {
    pub fn new(message_store: MessageStore, state_index: StateIndex) -> Self {
        Self {
            message_store,
            state_index,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        state_index: StateIndex,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            state_index,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore> ProtocolsQueryHandler<MessageStore> {
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

pub async fn fetch_protocol_definition<MessageStore>(
    tenant: &str,
    protocol_uri: &str,
    message_store: &MessageStore,
    message_timestamp: Option<&str>,
) -> Result<Definition, ProtocolDefinitionLookupError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if let Some(definition) = CoreProtocolRegistry::with_permissions().get_definition(protocol_uri)
    {
        return Ok(definition);
    }

    let filters = common::protocol_definition_lookup_filters(protocol_uri, message_timestamp);
    let result = message_store
        .query(
            tenant,
            filters,
            Some(MessageSort::Timestamp(SortDirection::Descending)),
            Some(Pagination::with_limit(1)),
        )
        .await
        .map_err(|err| ProtocolDefinitionLookupError::Store(err.to_string()))?;

    let Some(message) = result.messages.first() else {
        return Err(ProtocolDefinitionLookupError::NotFound(
            protocol_uri.to_string(),
        ));
    };

    common::protocols_configure_descriptor(message)
        .map(|descriptor| descriptor.definition.clone())
        .map_err(ProtocolDefinitionLookupError::InvalidMessage)
}

impl<MessageStore, StateIndex> MethodHandler for ProtocolsConfigureHandler<MessageStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_configure(request.tenant, request.message).await })
    }
}

impl<MessageStore> MethodHandler for ProtocolsQueryHandler<MessageStore>
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
