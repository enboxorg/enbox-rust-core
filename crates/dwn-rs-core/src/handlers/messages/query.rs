use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::handlers::messages::authorization::{
    authorize_query_or_subscribe, MessageAuthorizationKind, QueryAuthorization,
};
use crate::permissions::AuthorizationValidationError;
use crate::replies::messages::Query;
use crate::stores::{MessageStore, ReplicationFeedReader};
use crate::{descriptors, replies, Handler, HandlerContext, Response};

#[derive(Clone)]
pub struct MessagesQueryHandler<MS, RS> {
    message_store: MS,
    did_resolver: Option<Arc<dyn DidResolver>>,
    replication_feed_reader: Option<RS>,
}

impl<MS, RS> Handler for MessagesQueryHandler<MS, RS>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
    RS: ReplicationFeedReader + Clone + Send + Sync + 'static,
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

        let auth_context = match crate::permissions::validate_authorization_signature(
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

        let authorization = match authorize_query_or_subscribe(
            tenant,
            &message,
            &descriptor.filters,
            &auth_context,
            &self.message_store,
            MessageAuthorizationKind::Query,
        )
        .await
        {
            Ok(authorization) => QueryAuthorization::from(authorization),
            Err(details) => {
                return Response::unauthorized(details.to_string());
            }
        };

        if self.replication_feed_reader.is_none() {
            return Response::not_implemented("replication feed not supported");
        }

        Response::not_implemented("replication feed not supported")
    }
}

impl<MS, RS> MessagesQueryHandler<MS, RS>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    pub fn new(
        message_store: MS,
        replication_feed_reader: Option<RS>,
        did_resolver: Option<Arc<dyn DidResolver>>,
    ) -> Self {
        Self {
            message_store,
            did_resolver,
            replication_feed_reader,
        }
    }
}
