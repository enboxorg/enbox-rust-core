use std::future::Future;
use std::sync::Arc;

use serde_json::Value as JsonValue;

use super::RecordsAuthorizationKind;
use crate::auth::JwsPublicKeyResolver;
use crate::descriptors::Descriptor;
use crate::descriptors::RecordsQueryDescriptor;
use crate::dwn::DwnReply;
use crate::dwn::{Handler, HandlerContext};
use crate::filters::Filters;
use crate::handlers::records::common::{
    attach_initial_writes, authorize_protocol_query_or_subscribe, date_sort_to_message_sort,
    filter_includes_published_records, non_owner_records_filters, owner_records_filter,
    published_records_filter, should_protocol_authorize, store_error_reply,
    QueryAuthorizationResult,
};
use crate::permissions::{self, AuthorizationContext};
use crate::Message;

#[derive(Clone)]
pub struct RecordsQueryHandler<MessageStore> {
    message_store: MessageStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MessageStore> Handler for RecordsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    type Descriptor = RecordsQueryDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = DwnReply> + Send {
        async move {
            let HandlerContext {
                tenant,
                raw_message,
                message,
                descriptor,
                ..
            } = ctx;

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
    }
}

impl<MessageStore> RecordsQueryHandler<MessageStore> {
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
