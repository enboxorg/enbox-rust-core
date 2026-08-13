use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::permissions::errors::PermissionError;
use crate::permissions::{self, AuthorizationContext, AuthorizationValidationError};
use crate::replies::messages::Query;
use crate::stores::MessageStore;
use crate::{descriptors, replies, Descriptor, Handler, HandlerContext, Message, Response};

#[derive(Clone)]
pub struct MessagesQueryHandler<MessageStore> {
    message_store: MessageStore,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MS> Handler for MessagesQueryHandler<MS>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    type Reply = Query;
    type Descriptor = descriptors::MessagesQueryDescriptor;

    async fn handle(
        &self,
        ctx: crate::HandlerContext<'_, Self::Descriptor>,
    ) -> replies::Response<Self::Reply> {
        let HandlerContext {
            tenant,
            message,
            descriptor,
            ..
        } = ctx;

        let authorization = match crate::permissions::validate_authorization_signature(
            &message,
            self.did_resolver.as_deref(),
            true,
        )
        .await
        {
            Ok(Some(authorization)) => authorization,
            Ok(None) => {
                return Response::unauthorized(
                    "MessagesQueryMissingAuthorization: authorization is required",
                )
            }
            Err(err) => match err {
                AuthorizationValidationError::BadRequest(detail) => {
                    return Response::bad_request(format!(
                        "MessagesQueryInvalidAuthorization: {}",
                        detail
                    ));
                }
                AuthorizationValidationError::Unauthorized(detail) => {
                    return Response::unauthorized(format!(
                        "MessagesQueryInvalidAuthorization: {}",
                        detail
                    ));
                }
                err => {
                    return Response::bad_request(format!(
                        "MessagesQueryInvalidAuthorization: {}",
                        err
                    ));
                }
            },
        };

        if let Err(details) = self
            .authorize_messages_query(tenant, &message, &descriptor, &authorization)
            .await
        {
            return Response::unauthorized(details.to_string());
        }

        todo!()
    }
}

impl<MS> MessagesQueryHandler<MS>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    pub fn new(message_store: MS, did_resolver: Option<Arc<dyn DidResolver>>) -> Self {
        Self {
            message_store,
            did_resolver,
        }
    }

    async fn authorize_messages_query(
        &self,
        tenant: &str,
        incoming_message: &Message<Descriptor>,
        descriptor: &descriptors::MessagesQueryDescriptor,
        auth: &AuthorizationContext,
    ) -> Result<(), PermissionError> {
        if auth.author == tenant {
            return Ok(());
        }

        permissions::authorize_messages_subscribe_and_query(
            tenant,
            incoming_message,
            &descriptor.filters,
            auth,
            &self.message_store,
        )
        .await
    }
}
