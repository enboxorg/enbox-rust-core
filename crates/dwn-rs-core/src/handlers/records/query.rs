use std::future::Future;
use std::sync::Arc;

use super::RecordsAuthorizationKind;
use crate::auth::resolver::DidResolver;
use crate::canonical_rfc3339;
use crate::descriptors::Descriptor;
use crate::descriptors::RecordsQueryDescriptor;
use crate::dwn::{Handler, HandlerContext};
use crate::filters::context::validate_nested_protocol_path_scope;
use crate::filters::Filters;
use crate::handlers::records::common::{
    attach_initial_writes, date_sort_to_message_sort, published_sort_name,
    resolve_record_limit_policy, store_error_reply, QueryAuthorizationResult,
};
use crate::handlers::records::control;
use crate::handlers::records::visibility::{authorize_collection, collection_filters, PlanMode};
use crate::permissions::{self, AuthorizationContext};
use crate::replies::records::Query;
use crate::stores::write_resolver::InitialWriteResolver;
use crate::stores::write_resolver::MessageStoreInitialWriteResolver;
use crate::Message;
use crate::Pagination;
use crate::Response;

#[derive(Clone)]
pub struct RecordsQueryHandler<MessageStore> {
    message_store: Arc<MessageStore>,
    did_resolver: Option<Arc<dyn DidResolver>>,
    write_resolver: Arc<dyn InitialWriteResolver>,
}

impl<MessageStore> Handler for RecordsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Send + Sync + 'static,
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

            if descriptor.filter.published == Some(false) {
                if let Some(sort_name) = published_sort_name(&descriptor.date_sort) {
                    return Response::bad_request(format!(
                        "RecordsQueryParseFilterPublishedSortInvalid: queries must not filter for `published:false` and sort by {sort_name}"
                    ));
                }
            }

            if let Err(reason) = validate_nested_protocol_path_scope(&descriptor.filter, false) {
                return Response::bad_request(format!(
                    "RecordsQueryNestedProtocolPathContextIdInvalid: {reason}"
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
                    return Response::unauthorized(detail.to_string())
                }
                Err(error) => return Response::bad_request(error.to_string()),
            };

            let (filters, _) = match self
                .query_filters(tenant, &message, &descriptor, signature.as_ref())
                .await
            {
                Ok(result) => result,
                Err(QueryAuthorizationResult::Unauthorized(detail)) => {
                    return Response::unauthorized(detail)
                }
            };
            let record_limit = match resolve_record_limit_policy(
                tenant,
                &descriptor.filter,
                self.message_store.as_ref(),
                &canonical_rfc3339(descriptor.message_timestamp),
            )
            .await
            {
                Ok(policy) => policy,
                Err(detail) => return store_error_reply(detail),
            };
            // Projection and visibility both remove records, so one storage
            // page is not one reply page. Keep fetching until the requested
            // limit is met or the store runs out.
            let sort = date_sort_to_message_sort(descriptor.date_sort.as_ref(), false);
            let limit = descriptor.pagination.as_ref().and_then(|page| page.limit);
            let start_cursor = descriptor
                .pagination
                .as_ref()
                .and_then(|page| page.cursor.clone());
            let mut first_page = true;
            let (messages, cursor) = match control::collect_visible_page(
                tenant,
                &message,
                signature.as_ref(),
                &descriptor.filter,
                limit,
                self.message_store.as_ref(),
                |cursor, remaining| {
                    let filters = filters.clone();
                    let record_limit = record_limit.clone();
                    let cursor = if first_page {
                        first_page = false;
                        start_cursor.clone()
                    } else {
                        cursor
                    };
                    async move {
                        let result = self
                            .message_store
                            .query(
                                tenant,
                                filters,
                                Some(sort),
                                Some(Pagination {
                                    cursor,
                                    limit: remaining.or(limit),
                                }),
                                record_limit,
                            )
                            .await
                            .map_err(|err| err.to_string())?;
                        Ok((result.messages, result.cursor))
                    }
                },
            )
            .await
            {
                Ok(page) => page,
                Err(control::ControlValidationError::Internal(detail)) => {
                    return store_error_reply(detail)
                }
                Err(error) => return Response::unauthorized(error.to_string()),
            };

            let entries =
                match attach_initial_writes(tenant, messages, self.write_resolver.as_ref()).await {
                    Ok(entries) => entries,
                    Err(err) => {
                        return store_error_reply(format!("failed to attach initial writes: {err}"))
                    }
                };

            Response::ok().with_reply(Query {
                entries: Some(entries),
                cursor,
                error: None,
            })
        }
    }
}

impl<MessageStore> RecordsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Send + Sync + 'static,
{
    pub fn new(message_store: MessageStore, did_resolver: Option<Arc<dyn DidResolver>>) -> Self {
        let message_store = Arc::new(message_store);
        Self {
            message_store: message_store.clone(),
            did_resolver,
            write_resolver: Arc::new(MessageStoreInitialWriteResolver::new(message_store)),
        }
    }
}

impl<MessageStore> RecordsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Send + Sync + 'static,
{
    async fn query_filters(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        descriptor: &RecordsQueryDescriptor,
        signature: Option<&AuthorizationContext>,
    ) -> Result<(Filters, Option<String>), QueryAuthorizationResult> {
        let auth = authorize_collection(
            tenant,
            message,
            &descriptor.filter,
            signature,
            self.message_store.as_ref(),
            &canonical_rfc3339(descriptor.message_timestamp),
            RecordsAuthorizationKind::Query,
        )
        .await
        .map_err(QueryAuthorizationResult::Unauthorized)?;
        let author = auth.author.clone();
        Ok((
            collection_filters(
                &auth,
                &descriptor.filter,
                descriptor.date_sort.as_ref(),
                PlanMode::Snapshot,
            ),
            author,
        ))
    }
}
