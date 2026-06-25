use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::json;

use crate::auth::JwsPublicKeyResolver;
use crate::descriptors::RecordsCountDescriptor;
use crate::dwn::{DwnReply, Handler, HandlerContext};
use crate::filters::Filters;
use crate::handlers::records::common::{
    authorize_protocol_query_or_subscribe, filter_includes_published_records,
    non_owner_records_filters, owner_records_filter, published_records_filter,
    should_protocol_authorize, store_error_reply,
};
use crate::permissions::{self};

use super::RecordsAuthorizationKind;

#[derive(Clone)]
pub struct RecordsCountHandler<MessageStore> {
    message_store: MessageStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MessageStore> Handler for RecordsCountHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    type Descriptor = RecordsCountDescriptor;

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

            let filters =
                if filter_includes_published_records(&descriptor.filter) && signature.is_none() {
                    Filters::from(published_records_filter(&descriptor.filter, None))
                } else {
                    let Some(signature) = signature.as_ref() else {
                        return DwnReply::unauthorized(
                            "AuthenticateJwsMissing: authorization signature is required",
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
                            Err(detail) => return DwnReply::unauthorized(detail),
                        };
                    if should_protocol_authorize(&signature.payload) {
                        if let Err(detail) = authorize_protocol_query_or_subscribe(
                            tenant,
                            &descriptor.filter,
                            &signature.payload,
                            &signature.author,
                            &self.message_store,
                            RecordsAuthorizationKind::Count,
                        )
                        .await
                        {
                            return DwnReply::unauthorized(detail);
                        }
                    }
                    if signature.author == tenant {
                        Filters::from(owner_records_filter(&descriptor.filter, None))
                    } else {
                        Filters::from(non_owner_records_filters(
                            &descriptor.filter,
                            None,
                            &signature.author,
                            should_protocol_authorize(&signature.payload) || grant_authorized,
                        ))
                    }
                };

            match self.message_store.count(tenant, filters, None).await {
                Ok(count) => DwnReply::ok().with_body("count", json!(count)),
                Err(err) => store_error_reply(err.to_string()),
            }
        })
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

    pub fn with_optional_resolver(
        message_store: MessageStore,
        public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
    ) -> Self {
        Self {
            message_store,
            public_key_resolver,
        }
    }
}
