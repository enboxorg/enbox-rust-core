use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::auth::JwsPublicKeyResolver;
use crate::cid::generate_cid_from_json;
use crate::descriptors::{Descriptor, SubscribeDescriptor};
use crate::dwn::{DwnReply, Handler, HandlerContext, MethodHandler, MethodHandlerRequest};
use crate::filters::Filters;
use crate::handlers::records::common::{
    attach_initial_writes, authorize_protocol_query_or_subscribe, date_sort_to_message_sort,
    event_log_error_reply, filter_includes_published_records, non_owner_records_event_filters,
    non_owner_records_filters, owner_records_event_filter, owner_records_filter, parse_message,
    published_records_event_filter, published_records_filter, records_subscribe_descriptor,
    records_subscribe_reply, should_protocol_authorize, store_error_reply,
};
use crate::permissions::{self, AuthorizationContext};
use crate::stores::EventSubscription;
use crate::stores::{EventLogSubscribeOptions, SubscriptionListener};
use crate::Message;

use super::RecordsAuthorizationKind;

#[derive(Clone)]
pub struct RecordsSubscribeHandler<MessageStore> {
    message_store: MessageStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MessageStore> Handler for RecordsSubscribeHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    type Descriptor = SubscribeDescriptor;

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

            if descriptor.cursor.is_some() {
                return DwnReply::not_implemented(
                    "RecordsSubscribe cursor replay requires EventLog integration",
                );
            }

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
                    Filters::from(published_records_filter(
                        &descriptor.filter,
                        descriptor.date_sort.as_ref(),
                    ))
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
                            RecordsAuthorizationKind::Subscribe,
                        )
                        .await
                        {
                            return DwnReply::unauthorized(detail);
                        }
                    }
                    if signature.author == tenant {
                        Filters::from(owner_records_filter(
                            &descriptor.filter,
                            descriptor.date_sort.as_ref(),
                        ))
                    } else {
                        Filters::from(non_owner_records_filters(
                            &descriptor.filter,
                            descriptor.date_sort.as_ref(),
                            &signature.author,
                            should_protocol_authorize(&signature.payload) || grant_authorized,
                        ))
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
                signature
                    .as_ref()
                    .map(|signature| signature.author.as_str()),
            )
            .await;
            DwnReply::ok()
                .with_body("entries", JsonValue::Array(entries))
                .with_body(
                    "cursor",
                    serde_json::to_value(result.cursor).unwrap_or(JsonValue::Null),
                )
        })
    }
}

pub struct RecordsSubscribeReply {
    pub reply: DwnReply,
    pub subscription: Option<EventSubscription>,
}

impl<MessageStore> RecordsSubscribeHandler<MessageStore> {
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

#[derive(Clone)]
pub struct RecordsEventLogSubscribeHandler<MessageStore, EventLog> {
    message_store: MessageStore,
    event_log: EventLog,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MessageStore, EventLog> MethodHandler
    for RecordsEventLogSubscribeHandler<MessageStore, EventLog>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move {
            self.handle_subscribe(request.tenant, request.message, Box::new(|_| {}))
                .await
                .reply
        })
    }
}

impl<MessageStore, EventLog> RecordsEventLogSubscribeHandler<MessageStore, EventLog> {
    pub fn new(message_store: MessageStore, event_log: EventLog) -> Self {
        Self {
            message_store,
            event_log,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        event_log: EventLog,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            event_log,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore, EventLog> RecordsEventLogSubscribeHandler<MessageStore, EventLog>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    pub async fn handle_subscribe(
        &self,
        tenant: &str,
        raw_message: &JsonValue,
        listener: SubscriptionListener,
    ) -> RecordsSubscribeReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return records_subscribe_reply(DwnReply::bad_request(detail), None),
        };
        let descriptor = match records_subscribe_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return records_subscribe_reply(DwnReply::bad_request(detail), None),
        };

        let signature = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            false,
        ) {
            Ok(signature) => signature,
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return records_subscribe_reply(DwnReply::bad_request(detail), None)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return records_subscribe_reply(DwnReply::unauthorized(detail), None)
            }
        };

        let (event_filters, query_filters, author) = match self
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
                    DwnReply::bad_request(format!("RecordsSubscribeCidFailed: {err}")),
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
            let reply = DwnReply::ok()
                .with_body("subscriptionId", JsonValue::String(subscription.id.clone()));
            return records_subscribe_reply(reply, Some(subscription));
        }

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
            )
            .await
        {
            Ok(result) => result,
            Err(err) => {
                let _ = (subscription.close)().await;
                return records_subscribe_reply(store_error_reply(err.to_string()), None);
            }
        };
        let entries = attach_initial_writes(
            tenant,
            result.messages,
            &self.message_store,
            author.as_deref(),
        )
        .await;
        let reply = DwnReply::ok()
            .with_body("subscriptionId", JsonValue::String(subscription.id.clone()))
            .with_body("entries", JsonValue::Array(entries))
            .with_body(
                "cursor",
                serde_json::to_value(result.cursor).unwrap_or(JsonValue::Null),
            );
        records_subscribe_reply(reply, Some(subscription))
    }

    async fn records_subscribe_filters(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        descriptor: &SubscribeDescriptor,
        signature: Option<&AuthorizationContext>,
    ) -> Result<(Filters, Filters, Option<String>), DwnReply> {
        if filter_includes_published_records(&descriptor.filter) && signature.is_none() {
            return Ok((
                Filters::from(published_records_event_filter(&descriptor.filter)),
                Filters::from(published_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                )),
                None,
            ));
        }

        let Some(signature) = signature else {
            return Err(DwnReply::unauthorized(
                "AuthenticateJwsMissing: authorization signature is required",
            ));
        };
        let grant_authorized = permissions::authorize_records_query_or_subscribe_with_grant(
            tenant,
            message,
            &descriptor.filter,
            signature,
            &self.message_store,
        )
        .await
        .map_err(DwnReply::unauthorized)?;
        if should_protocol_authorize(&signature.payload) {
            authorize_protocol_query_or_subscribe(
                tenant,
                &descriptor.filter,
                &signature.payload,
                &signature.author,
                &self.message_store,
                RecordsAuthorizationKind::Subscribe,
            )
            .await
            .map_err(DwnReply::unauthorized)?;
        }
        if signature.author == tenant {
            Ok((
                Filters::from(owner_records_event_filter(&descriptor.filter)),
                Filters::from(owner_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                )),
                Some(signature.author.clone()),
            ))
        } else {
            let protocol_authorized =
                should_protocol_authorize(&signature.payload) || grant_authorized;
            Ok((
                Filters::from(non_owner_records_event_filters(
                    &descriptor.filter,
                    &signature.author,
                    protocol_authorized,
                )),
                Filters::from(non_owner_records_filters(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                    &signature.author,
                    protocol_authorized,
                )),
                Some(signature.author.clone()),
            ))
        }
    }
}
