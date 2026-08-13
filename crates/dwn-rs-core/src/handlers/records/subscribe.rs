use std::future::Future;
use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::auth::resolver::DidResolver;
use crate::cid::generate_cid_from_json;
use crate::descriptors::{Descriptor, SubscribeDescriptor};
use crate::dwn::{Handler, HandlerContext};
use crate::filters::Filters;
use crate::handlers::records::common::{
    attach_initial_writes, authorize_protocol_query_or_subscribe, date_sort_to_message_sort,
    event_log_error_reply, filter_includes_published_records, non_owner_records_event_filters,
    non_owner_records_filters, owner_records_event_filter, owner_records_filter, parse_message,
    published_records_event_filter, published_records_filter, records_subscribe_descriptor,
    records_subscribe_reply, should_protocol_authorize, store_error_reply,
};
use crate::permissions::{self, AuthorizationContext};
use crate::replies::records::Subscribe;
use crate::stores::EventSubscription;
use crate::stores::{EventLogSubscribeOptions, SubscriptionListener};
use crate::validation::validate_message;
use crate::Message;
use crate::Response;

use super::RecordsAuthorizationKind;

#[derive(Clone)]
pub struct RecordsSubscribeHandler<MessageStore> {
    message_store: MessageStore,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MessageStore> Handler for RecordsSubscribeHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
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
            let filters = if filter_includes_published_records(&descriptor.filter)
                && signature.is_none()
            {
                Filters::from(published_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                ))
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
                        RecordsAuthorizationKind::Subscribe,
                    )
                    .await
                    {
                        return Response::unauthorized(detail);
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
                        should_protocol_authorize(signature) || grant_authorized,
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

impl<MessageStore> RecordsSubscribeHandler<MessageStore> {
    pub fn new(message_store: MessageStore, did_resolver: Option<Arc<dyn DidResolver>>) -> Self {
        Self {
            message_store,
            did_resolver,
        }
    }
}

#[derive(Clone)]
pub struct RecordsEventLogSubscribeHandler<MessageStore, EventLog> {
    message_store: MessageStore,
    event_log: EventLog,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MessageStore, EventLog> RecordsEventLogSubscribeHandler<MessageStore, EventLog> {
    pub fn new(
        message_store: MessageStore,
        event_log: EventLog,
        did_resolver: Option<Arc<dyn DidResolver>>,
    ) -> Self {
        Self {
            message_store,
            event_log,
            did_resolver,
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
        if validate_message(raw_message).is_err() {
            return records_subscribe_reply(
                Response::bad_request(
                    "RecordsSubscribeValidationFailed: invalid message".to_string(),
                ),
                None,
            );
        }
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return records_subscribe_reply(Response::bad_request(detail), None),
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
        let reply = Response::ok().with_reply(Subscribe {
            subscription_id: Some(subscription.id.clone()),
            entries: Some(entries.clone()),
            cursor: result.cursor.clone(),
            error: None,
        });

        records_subscribe_reply(reply, Some(subscription))
    }

    async fn records_subscribe_filters(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        descriptor: &SubscribeDescriptor,
        signature: Option<&AuthorizationContext>,
    ) -> Result<(Filters, Filters, Option<String>), Response<Subscribe>> {
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
            return Err(Response::unauthorized(
                "AuthenticateJwsMissing: authorization signature is required".to_string(),
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
        .map_err(|err| Response::unauthorized(err.to_string()))?;
        if should_protocol_authorize(signature) {
            authorize_protocol_query_or_subscribe(
                tenant,
                &descriptor.filter,
                signature,
                &self.message_store,
                RecordsAuthorizationKind::Subscribe,
            )
            .await
            .map_err(Response::unauthorized)?;
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
            let protocol_authorized = should_protocol_authorize(signature) || grant_authorized;
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
