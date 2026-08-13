use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::ProtocolQueryDescriptor;
use crate::dwn::HandlerContext;
use crate::filters::{Filter, FilterKey, Filters};
use crate::replies::protocols::Query;
use crate::{permissions, Handler, Response};
use crate::{MessageSort, SortDirection, Value};

const PROTOCOLS_INTERFACE: &str = "Protocols";
const CONFIGURE_METHOD: &str = "Configure";

#[derive(Clone)]
pub struct ProtocolsQueryHandler<MessageStore> {
    message_store: MessageStore,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MessageStore> ProtocolsQueryHandler<MessageStore> {
    pub fn new(message_store: MessageStore, did_resolver: Option<Arc<dyn DidResolver>>) -> Self {
        Self {
            message_store,
            did_resolver,
        }
    }
}

impl<MessageStore> Handler for ProtocolsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    type Reply = Query;
    type Descriptor = ProtocolQueryDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = Response<Self::Reply>> + Send {
        async move {
            let HandlerContext {
                tenant,
                raw_message,
                message,
                descriptor,
                ..
            } = ctx;

            let include_private = if raw_message.get("authorization").is_some() {
                match permissions::validate_authorization_signature(
                    &message,
                    self.did_resolver.as_deref(),
                    false,
                )
                .await
                {
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
                            Err(detail) => return Response::unauthorized(detail.to_string()),
                        }
                    }
                    Ok(None) => false,
                    Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                        return Response::bad_request(detail.to_string())
                    }
                    Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                        return Response::unauthorized(detail)
                    }
                    Err(error) => return Response::bad_request(error.to_string()),
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

            Response::ok().with_reply(Query {
                entries: Some(result.messages),
            })
        }
    }
}

use super::common::*;
