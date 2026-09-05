use std::future::Future;
use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::auth::resolver::DidResolver;
use crate::canonical_rfc3339;
use crate::cid::generate_cid_from_json;
use crate::descriptors::{Descriptor, SubscribeDescriptor};
use crate::dwn::{Handler, HandlerContext};
use crate::filters::context::validate_nested_protocol_path_scope;
use crate::filters::Filters;
use crate::handlers::records::common::{
    attach_initial_writes, date_sort_to_message_sort, event_log_error_reply,
    records_subscribe_descriptor, records_subscribe_reply, resolve_record_limit_policy,
    store_error_reply,
};
use crate::handlers::records::visibility::{authorize_collection, collection_filters, PlanMode};
use crate::permissions::{self, AuthorizationContext};
use crate::replies::records::Subscribe;
use crate::stores::write_resolver::{InitialWriteResolver, MessageStoreInitialWriteResolver};
use crate::stores::EventSubscription;
use crate::stores::{EventLogSubscribeOptions, SubscriptionListener};
use crate::validation::{ingest_message, ingress_rejection};
use crate::Message;
use crate::Response;

use super::RecordsAuthorizationKind;

#[derive(Clone)]
pub struct RecordsSubscribeHandler<MessageStore> {
    message_store: Arc<MessageStore>,
    did_resolver: Option<Arc<dyn DidResolver>>,
    write_resolver: Arc<dyn InitialWriteResolver>,
}

impl<MessageStore> Handler for RecordsSubscribeHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Send + Sync + 'static,
{
    type Reply = Subscribe;
    type Descriptor = SubscribeDescriptor;

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

            if descriptor.cursor.is_some() {
                return Response::not_implemented(
                    "RecordsSubscribe cursor replay requires EventLog integration".to_string(),
                );
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
            // Bounded path-wide Subscribe may omit nested scope when the initial
            // page is explicitly capped and no slash-role is invoked; mirrors
            // `RecordsSubscribe.parse` at the parity baseline.
            let allow_bounded_path_wide = descriptor.cursor.is_none()
                && descriptor
                    .pagination
                    .as_ref()
                    .and_then(|pagination| pagination.limit)
                    .is_some_and(|limit| limit > 0)
                && signature
                    .as_ref()
                    .and_then(|signature| signature.protocol_role())
                    .is_none_or(|role| !role.contains('/'));
            if let Err(reason) =
                validate_nested_protocol_path_scope(&descriptor.filter, allow_bounded_path_wide)
            {
                return Response::bad_request(format!(
                    "RecordsSubscribeNestedProtocolPathContextIdInvalid: {reason}"
                ));
            }
            let auth = match authorize_collection(
                tenant,
                &message,
                &descriptor.filter,
                signature.as_ref(),
                self.message_store.as_ref(),
                &canonical_rfc3339(descriptor.message_timestamp),
                RecordsAuthorizationKind::Subscribe,
            )
            .await
            {
                Ok(auth) => auth,
                Err(detail) => return Response::unauthorized(detail),
            };
            let filters = collection_filters(
                &auth,
                &descriptor.filter,
                descriptor.date_sort.as_ref(),
                PlanMode::Snapshot,
            );
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
                    record_limit,
                )
                .await
            {
                Ok(result) => result,
                Err(err) => return store_error_reply(err.to_string()),
            };
            let entries =
                match attach_initial_writes(tenant, result.messages, self.write_resolver.as_ref())
                    .await
                {
                    Ok(entries) => entries,
                    Err(err) => {
                        return store_error_reply(format!(
                            "failed to attach initial writes: {err}"
                        ));
                    }
                };
            Response::ok().with_reply(Subscribe {
                subscription_id: None,
                entries: Some(entries.clone()),
                cursor: result.cursor,
                error: None,
            })
        }
    }
}

pub struct RecordsSubscribeReply {
    pub reply: Response<Subscribe>,
    pub subscription: Option<EventSubscription>,
}

impl<MessageStore> RecordsSubscribeHandler<MessageStore>
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

#[derive(Clone)]
pub struct RecordsEventLogSubscribeHandler<MessageStore, EventLog> {
    message_store: Arc<MessageStore>,
    event_log: EventLog,
    did_resolver: Option<Arc<dyn DidResolver>>,
    write_resolver: Arc<dyn InitialWriteResolver>,
}

impl<MessageStore, EventLog> RecordsEventLogSubscribeHandler<MessageStore, EventLog>
where
    MessageStore: crate::stores::MessageStore + Send + Sync + 'static,
{
    pub fn new(
        message_store: MessageStore,
        event_log: EventLog,
        did_resolver: Option<Arc<dyn DidResolver>>,
    ) -> Self {
        let message_store = Arc::new(message_store);
        Self {
            message_store: message_store.clone(),
            event_log,
            did_resolver,
            write_resolver: Arc::new(MessageStoreInitialWriteResolver::new(message_store)),
        }
    }
}

impl<MessageStore, EventLog> RecordsEventLogSubscribeHandler<MessageStore, EventLog>
where
    MessageStore: crate::stores::MessageStore + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    pub async fn handle_subscribe(
        &self,
        tenant: &str,
        raw_message: &JsonValue,
        listener: SubscriptionListener,
    ) -> RecordsSubscribeReply {
        // The WebSocket/native subscribe entry point admits messages through the same ingress
        // as `Dwn::process_message`, not a private fork of it.
        let message = match ingest_message(raw_message) {
            Ok((_, message)) => message,
            Err(error) => return records_subscribe_reply(ingress_rejection(error), None),
        };
        let descriptor = match records_subscribe_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return records_subscribe_reply(Response::bad_request(detail), None),
        };

        let signature = match permissions::validate_authorization_signature(
            &message,
            self.did_resolver.as_deref(),
            false,
        )
        .await
        {
            Ok(signature) => signature,
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return records_subscribe_reply(Response::bad_request(detail.to_string()), None)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return records_subscribe_reply(Response::unauthorized(detail.to_string()), None)
            }
            Err(error) => {
                return records_subscribe_reply(Response::bad_request(error.to_string()), None)
            }
        };

        // Same nested-scope contract as the snapshot handler: bounded
        // path-wide subscriptions may omit scope when the initial page is
        // explicitly capped and no slash-role is invoked.
        let allow_bounded_path_wide = descriptor.cursor.is_none()
            && descriptor
                .pagination
                .as_ref()
                .and_then(|pagination| pagination.limit)
                .is_some_and(|limit| limit > 0)
            && signature
                .as_ref()
                .and_then(|signature| signature.protocol_role())
                .is_none_or(|role| !role.contains('/'));
        if let Err(reason) =
            validate_nested_protocol_path_scope(&descriptor.filter, allow_bounded_path_wide)
        {
            return records_subscribe_reply(
                Response::bad_request(format!(
                    "RecordsSubscribeNestedProtocolPathContextIdInvalid: {reason}"
                )),
                None,
            );
        }

        let (event_filters, query_filters, _) = match self
            .records_subscribe_filters(tenant, &message, &descriptor, signature.as_ref())
            .await
        {
            Ok(filters) => filters,
            Err(reply) => return records_subscribe_reply(reply, None),
        };

        let subscription_id = match generate_cid_from_json(raw_message) {
            Ok(cid) => cid.to_string(),
            Err(err) => {
                return records_subscribe_reply(
                    Response::bad_request(format!("RecordsSubscribeCidFailed: {err}")),
                    None,
                )
            }
        };

        let subscription = match self
            .event_log
            .subscribe(
                tenant,
                &subscription_id,
                listener,
                Some(EventLogSubscribeOptions {
                    cursor: descriptor.cursor.clone(),
                    filters: Some(event_filters),
                }),
            )
            .await
        {
            Ok(subscription) => subscription,
            Err(err) => return records_subscribe_reply(event_log_error_reply(err), None),
        };

        if descriptor.cursor.is_some() {
            let reply = Response::ok().with_reply(Subscribe {
                subscription_id: Some(subscription.id.clone()),
                entries: None,
                cursor: None,
                error: None,
            });
            return records_subscribe_reply(reply, Some(subscription));
        }

        let record_limit = match resolve_record_limit_policy(
            tenant,
            &descriptor.filter,
            self.message_store.as_ref(),
            &canonical_rfc3339(descriptor.message_timestamp),
        )
        .await
        {
            Ok(policy) => policy,
            Err(detail) => {
                let _ = (subscription.close)().await;
                return records_subscribe_reply(store_error_reply(detail), None);
            }
        };
        let result = match self
            .message_store
            .query(
                tenant,
                query_filters,
                Some(date_sort_to_message_sort(
                    descriptor.date_sort.as_ref(),
                    false,
                )),
                descriptor.pagination.clone(),
                record_limit,
            )
            .await
        {
            Ok(result) => result,
            Err(err) => {
                let _ = (subscription.close)().await;
                return records_subscribe_reply(store_error_reply(err.to_string()), None);
            }
        };
        let entries = match attach_initial_writes(
            tenant,
            result.messages,
            self.write_resolver.as_ref(),
        )
        .await
        {
            Ok(entries) => entries,
            Err(err) => {
                let _ = (subscription.close)().await;
                return records_subscribe_reply(
                    store_error_reply(format!("failed to attach initial writes: {err}")),
                    None,
                );
            }
        };
        let reply = Response::ok().with_reply(Subscribe {
            subscription_id: Some(subscription.id.clone()),
            entries: Some(entries.clone()),
            cursor: result.cursor.clone(),
            error: None,
        });

        records_subscribe_reply(reply, Some(subscription))
    }

    // The error path returns the DWN reply itself; boxing it would only move the
    // allocation to every caller.
    #[allow(clippy::result_large_err)]
    async fn records_subscribe_filters(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        descriptor: &SubscribeDescriptor,
        signature: Option<&AuthorizationContext>,
    ) -> Result<(Filters, Filters, Option<String>), Response<Subscribe>> {
        // One authorization serves both projections: the event set for live
        // delivery and the snapshot set for the initial page.
        let auth = authorize_collection(
            tenant,
            message,
            &descriptor.filter,
            signature,
            self.message_store.as_ref(),
            &canonical_rfc3339(descriptor.message_timestamp),
            RecordsAuthorizationKind::Subscribe,
        )
        .await
        .map_err(Response::unauthorized)?;
        let author = auth.author.clone();
        Ok((
            collection_filters(&auth, &descriptor.filter, None, PlanMode::Event),
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
