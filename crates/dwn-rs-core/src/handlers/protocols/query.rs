use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::auth::JwsPublicKeyResolver;
use crate::descriptors::ProtocolQueryDescriptor;
use crate::dwn::{DwnReply, HandlerContext};
use crate::filters::{Filter, FilterKey, Filters};
use crate::{permissions, Handler};
use crate::{MessageSort, SortDirection, Value};

const PROTOCOLS_INTERFACE: &str = "Protocols";
const CONFIGURE_METHOD: &str = "Configure";

#[derive(Clone)]
pub struct ProtocolsQueryHandler<MessageStore> {
    message_store: MessageStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MessageStore> ProtocolsQueryHandler<MessageStore> {
    pub fn new(
        message_store: MessageStore,
        public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
    ) -> Self {
        Self {
            message_store,
            public_key_resolver,
        }
    }
}

impl<MessageStore> Handler for ProtocolsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    type Descriptor = ProtocolQueryDescriptor;

    fn handle<'a>(
        &'a self,
        ctx: HandlerContext<'a, Self::Descriptor>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move {
            let HandlerContext {
                tenant,
                raw_message,
                message,
                descriptor,
                ..
            } = ctx;

            let include_private = if raw_message.get("authorization").is_some() {
                match permissions::validate_authorization_signature(
                    raw_message,
                    self.public_key_resolver.as_deref(),
                    false,
                ) {
                    Ok(Some(authorization)) => {
                        match permissions::authorize_protocols_query(
                            tenant,
                            &message,
                            &authorization,
                            &self.message_store,
                        )
                        .await
                        {
                            Ok(include_private) => include_private,
                            Err(detail) => return DwnReply::unauthorized(detail),
                        }
                    }
                    Ok(None) => false,
                    Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                        return DwnReply::bad_request(detail)
                    }
                    Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                        return DwnReply::unauthorized(detail)
                    }
                }
            } else {
                false
            };

            let mut filters = BTreeMap::new();
            filters.insert(
                FilterKey::Index("interface".to_string()),
                Filter::Equal(Value::String(PROTOCOLS_INTERFACE.to_string())),
            );
            filters.insert(
                FilterKey::Index("method".to_string()),
                Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
            );
            filters.insert(
                FilterKey::Index("isLatestBaseState".to_string()),
                Filter::Equal(Value::Bool(true)),
            );
            if !include_private {
                filters.insert(
                    FilterKey::Index("published".to_string()),
                    Filter::Equal(Value::Bool(true)),
                );
            }
            if let Some(filter) = &descriptor.filter {
                if let Some(protocol) = &filter.protocol {
                    filters.insert(
                        FilterKey::Index("protocol".to_string()),
                        Filter::Equal(Value::String(protocol.clone())),
                    );
                }
            }

            let result = match self
                .message_store
                .query(
                    tenant,
                    Filters::from(filters),
                    Some(MessageSort::Timestamp(SortDirection::Ascending)),
                    None,
                )
                .await
            {
                Ok(result) => result,
                Err(err) => return store_error_reply(err.to_string()),
            };

            let entries = match serde_json::to_value(result.messages) {
                Ok(entries) => entries,
                Err(err) => return DwnReply::bad_request(err.to_string()),
            };
            DwnReply::new(200, "OK").with_body("entries", entries)
        })
    }
}

use super::common::*;
