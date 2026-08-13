use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::RecordsCountDescriptor;
use crate::dwn::{Handler, HandlerContext};
use crate::filters::Filters;
use crate::handlers::records::common::{
    authorize_protocol_query_or_subscribe, filter_includes_published_records,
    non_owner_records_filters, owner_records_filter, published_records_filter,
    should_protocol_authorize, store_error_reply,
};
use crate::permissions::{self};
use crate::replies::records::Count;
use crate::Response;

use super::RecordsAuthorizationKind;

#[derive(Clone)]
pub struct RecordsCountHandler<MessageStore> {
    message_store: MessageStore,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MessageStore> Handler for RecordsCountHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    type Descriptor = RecordsCountDescriptor;

    type Reply = Count;
    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = Response<Self::Reply>> + Send {
        async move {
            let HandlerContext {
                tenant,
                message,
                descriptor,
                ..
            } = ctx;

            let signature = match permissions::validate_authorization_signature(
                &message,
                self.did_resolver.as_deref(),
                false,
            )
            .await
            {
                Ok(signature) => signature,
                Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                    return Response::bad_request(detail.to_string())
                }
                Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                    return Response::unauthorized(detail)
                }
                Err(error) => return Response::bad_request(error.to_string()),
            };

            let filters = if filter_includes_published_records(&descriptor.filter)
                && signature.is_none()
            {
                Filters::from(published_records_filter(&descriptor.filter, None))
            } else {
                let Some(signature) = signature.as_ref() else {
                    return Response::unauthorized(
                        "AuthenticateJwsMissing: authorization signature is required".to_string(),
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
                        Err(detail) => return Response::unauthorized(detail.to_string()),
                    };
                if should_protocol_authorize(signature) {
                    if let Err(detail) = authorize_protocol_query_or_subscribe(
                        tenant,
                        &descriptor.filter,
                        signature,
                        &self.message_store,
                        RecordsAuthorizationKind::Count,
                    )
                    .await
                    {
                        return Response::unauthorized(detail);
                    }
                }
                if signature.author == tenant {
                    Filters::from(owner_records_filter(&descriptor.filter, None))
                } else {
                    Filters::from(non_owner_records_filters(
                        &descriptor.filter,
                        None,
                        &signature.author,
                        should_protocol_authorize(signature) || grant_authorized,
                    ))
                }
            };

            match self.message_store.count(tenant, filters, None).await {
                Ok(count) => Response::ok().with_reply(Count { count: Some(count) }),
                Err(err) => store_error_reply(err.to_string()),
            }
        }
    }
}

impl<MessageStore> RecordsCountHandler<MessageStore> {
    pub fn new(message_store: MessageStore, did_resolver: Option<Arc<dyn DidResolver>>) -> Self {
        Self {
            message_store,
            did_resolver,
        }
    }
}
