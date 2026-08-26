use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::{Descriptor, MessagesSubscribeDescriptor};
use crate::dwn::HandlerContext;
use crate::handlers::messages::authorization::{
    authorize_query_or_subscribe, MessageAuthorizationKind, QueryAuthorization,
};
use crate::permissions::{self};
use crate::replies::messages;
use crate::stores::{EventLogSubscribeOptions, EventSubscription, SubscriptionListener};
use crate::Message;
use crate::{Handler, Response};

use super::common::*;

#[derive(Clone)]
pub struct MessagesSubscribeHandler<MessageStore, EventLog> {
    message_store: MessageStore,
    event_log: EventLog,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

pub struct SubscribeReply {
    pub reply: Response<messages::Subscription>,
    /// The live subscription handle from the store-driven path. The one-shot request handler reads
    /// only `reply`, so this is unread within the lib build (it is exercised by tests and mirrors
    /// [`super::super::records::RecordsSubscribeReply`], whose handle is consumed by the desktop
    /// websocket runtime).
    #[allow(dead_code)]
    pub subscription: Option<EventSubscription>,
}

impl<MessageStore, EventLog> Handler for MessagesSubscribeHandler<MessageStore, EventLog>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    type Reply = messages::Subscription;
    type Descriptor = MessagesSubscribeDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = Response<messages::Subscription>> + Send {
        // `handle_subscribe` is shared with the store-driven subscription path (which supplies a
        // real listener), so it stays an inherent method and re-parses internally. Here we drive it
        // with a no-op listener for the one-shot request path.
        async move {
            self.handle_subscribe(ctx.tenant, &ctx.message, Box::new(|_| {}))
                .await
                .reply
        }
    }
}

impl<MessageStore, EventLog> MessagesSubscribeHandler<MessageStore, EventLog> {
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

impl<MessageStore, EventLog> MessagesSubscribeHandler<MessageStore, EventLog>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
{
    pub async fn handle_subscribe(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        listener: SubscriptionListener,
    ) -> SubscribeReply {
        let descriptor = match messages_subscribe_descriptor(message) {
            Ok(descriptor) => descriptor,
            Err(detail) => return subscribe_reply(Response::bad_request(detail.to_string()), None),
        };

        let auth_context = match permissions::validate_authorization_signature(
            message,
            self.did_resolver.as_deref(),
            true,
        )
        .await
        {
            Ok(Some(authorization)) => authorization,
            Ok(None) => {
                return subscribe_reply(
                    Response::unauthorized(
                        "MessagesSubscribeAuthorizationFailed: message failed authorization"
                            .to_string(),
                    ),
                    None,
                )
            }
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return subscribe_reply(Response::bad_request(detail.to_string()), None)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return subscribe_reply(Response::unauthorized(detail.to_string()), None)
            }
            Err(error) => return subscribe_reply(Response::bad_request(error.to_string()), None),
        };

        let authorization = match authorize_query_or_subscribe(
            tenant,
            message,
            &descriptor.filters,
            &auth_context,
            &self.message_store,
            MessageAuthorizationKind::Subscribe,
        )
        .await
        {
            Ok(authorization) => QueryAuthorization::from(authorization),
            Err(details) => {
                return subscribe_reply(
                    Response::unauthorized(format!(
                        "MessagesSubscribeAuthorizationFailed: {details}"
                    )),
                    None,
                );
            }
        };

        let subscription_id = match message.cid() {
            Ok(cid) => cid.to_string(),
            Err(err) => {
                return subscribe_reply(
                    Response::bad_request(format!("MessagesSubscribeCidFailed: {err}")),
                    None,
                )
            }
        };

        let filters = messages_filters_to_filters(&descriptor.filters, authorization.include_shadow_filters);
        let subscription = match self
            .event_log
            .subscribe(
                tenant,
                &subscription_id,
                listener,
                Some(EventLogSubscribeOptions {
                    cursor: descriptor.cursor.clone(),
                    filters,
                }),
            )
            .await
        {
            Ok(subscription) => subscription,
            Err(err) => return subscribe_reply(event_log_error_reply(err), None),
        };
        let reply = Response::ok().with_reply(messages::Subscription {
            subscription_id: Some(subscription.id.clone()),
            ..Default::default()
        });
        subscribe_reply(reply, Some(subscription))
    }

}
