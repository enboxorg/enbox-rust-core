use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::canonical_rfc3339;
use crate::descriptors::RecordsCountDescriptor;
use crate::dwn::{Handler, HandlerContext};
use crate::filters::context::validate_nested_protocol_path_scope;
use crate::handlers::records::common::{resolve_record_limit_policy, store_error_reply};
use crate::handlers::records::visibility::{authorize_collection, collection_filters, PlanMode};
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

            if let Err(reason) = validate_nested_protocol_path_scope(&descriptor.filter, false) {
                return Response::bad_request(format!(
                    "RecordsCountNestedProtocolPathContextIdInvalid: {reason}"
                ));
            }

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

            let auth = match authorize_collection(
                tenant,
                &message,
                &descriptor.filter,
                signature.as_ref(),
                &self.message_store,
                &canonical_rfc3339(descriptor.message_timestamp),
                RecordsAuthorizationKind::Count,
            )
            .await
            {
                Ok(auth) => auth,
                Err(detail) => return Response::unauthorized(detail),
            };
            let filters = collection_filters(&auth, &descriptor.filter, None, PlanMode::Snapshot);
            let record_limit = match resolve_record_limit_policy(
                tenant,
                &descriptor.filter,
                &self.message_store,
                &canonical_rfc3339(descriptor.message_timestamp),
            )
            .await
            {
                Ok(policy) => policy,
                Err(detail) => return store_error_reply(detail),
            };

            match self
                .message_store
                .count(tenant, filters, None, record_limit)
                .await
            {
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
