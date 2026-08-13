use std::future::Future;
use std::sync::Arc;

use super::RecordsAuthorizationKind;
use crate::auth::resolver::DidResolver;
use crate::descriptors::Descriptor;
use crate::descriptors::RecordsQueryDescriptor;
use crate::dwn::{Handler, HandlerContext};
use crate::filters::Filters;
use crate::handlers::records::common::{
    attach_initial_writes, authorize_protocol_query_or_subscribe, date_sort_to_message_sort,
    filter_includes_published_records, non_owner_records_filters, owner_records_filter,
    published_records_filter, should_protocol_authorize, store_error_reply,
    QueryAuthorizationResult,
};
use crate::permissions::{self, AuthorizationContext};
use crate::replies::records::Query;
use crate::Message;
use crate::Response;

#[derive(Clone)]
pub struct RecordsQueryHandler<MessageStore> {
    message_store: MessageStore,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MessageStore> Handler for RecordsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    type Reply = Query;
    type Descriptor = RecordsQueryDescriptor;

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
                    return Response::unauthorized(detail.to_string())
                }
                Err(error) => return Response::bad_request(error.to_string()),
            };

            let (filters, author) = match self
                .query_filters(tenant, &message, &descriptor, signature.as_ref())
                .await
            {
                Ok(result) => result,
                Err(QueryAuthorizationResult::Unauthorized(detail)) => {
                    return Response::unauthorized(detail)
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

            Response::ok().with_reply(Query {
                entries: Some(entries),
                cursor: result.cursor,
                error: None,
            })
        }
    }
}

impl<MessageStore> RecordsQueryHandler<MessageStore> {
    pub fn new(message_store: MessageStore, did_resolver: Option<Arc<dyn DidResolver>>) -> Self {
        Self {
            message_store,
            did_resolver,
        }
    }
}

impl<MessageStore> RecordsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
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
        .map_err(|error| QueryAuthorizationResult::Unauthorized(error.to_string()))?;
        if should_protocol_authorize(signature) {
            authorize_protocol_query_or_subscribe(
                tenant,
                &descriptor.filter,
                signature,
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
                should_protocol_authorize(signature) || grant_authorized,
            )),
            Some(signature.author.clone()),
        ))
    }
}
