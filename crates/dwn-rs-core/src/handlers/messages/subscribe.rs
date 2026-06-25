use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::auth::JwsPublicKeyResolver;
use crate::cid::generate_cid_from_json;
use crate::descriptors::{Descriptor, MessagesSubscribeDescriptor};
use crate::dwn::{DwnReply, HandlerContext};
use crate::permissions::{self};
use crate::stores::{EventLogSubscribeOptions, EventSubscription, SubscriptionListener};
use crate::Handler;
use crate::Message;

use super::common::*;

#[derive(Clone)]
pub struct MessagesSubscribeHandler<MessageStore, EventLog> {
    message_store: MessageStore,
    event_log: EventLog,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

pub struct SubscribeReply {
    pub reply: DwnReply,
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
    type Descriptor = MessagesSubscribeDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = DwnReply> + Send {
        // `handle_subscribe` is shared with the store-driven subscription path (which supplies a
        // real listener), so it stays an inherent method and re-parses internally. Here we drive it
        // with a no-op listener for the one-shot request path.
        async move {
            self.handle_subscribe(ctx.tenant, ctx.raw_message, Box::new(|_| {}))
                .await
                .reply
        }
    }
}

impl<MessageStore, EventLog> MessagesSubscribeHandler<MessageStore, EventLog> {
    pub fn new(
        message_store: MessageStore,
        event_log: EventLog,
        public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
    ) -> Self {
        Self {
            message_store,
            event_log,
            public_key_resolver,
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
        raw_message: &JsonValue,
        listener: SubscriptionListener,
    ) -> SubscribeReply {
        let message = match parse_message(raw_message, "MessagesSubscribeParseFailed") {
            Ok(message) => message,
            Err(detail) => return subscribe_reply(DwnReply::bad_request(detail), None),
        };
        let descriptor = match messages_subscribe_descriptor(&message) {
            Ok(descriptor) => descriptor,
            Err(detail) => return subscribe_reply(DwnReply::bad_request(detail), None),
        };

        let authorization = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            true,
        ) {
            Ok(Some(authorization)) => authorization,
            Ok(None) => {
                return subscribe_reply(
                    DwnReply::unauthorized(
                        "MessagesSubscribeAuthorizationFailed: message failed authorization",
                    ),
                    None,
                )
            }
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return subscribe_reply(DwnReply::bad_request(detail), None)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return subscribe_reply(DwnReply::unauthorized(detail), None)
            }
        };

        if let Err(detail) = self
            .authorize_messages_subscribe(tenant, &message, descriptor, &authorization)
            .await
        {
            return subscribe_reply(DwnReply::unauthorized(detail), None);
        }

        let subscription_id = match generate_cid_from_json(raw_message) {
            Ok(cid) => cid.to_string(),
            Err(err) => {
                return subscribe_reply(
                    DwnReply::bad_request(format!("MessagesSubscribeCidFailed: {err}")),
                    None,
                )
            }
        };
        let filters = messages_filters_to_filters(&descriptor.filters);
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
        let reply =
            DwnReply::ok().with_body("subscriptionId", JsonValue::String(subscription.id.clone()));
        subscribe_reply(reply, Some(subscription))
    }

    async fn authorize_messages_subscribe(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        descriptor: &MessagesSubscribeDescriptor,
        authorization: &permissions::AuthorizationContext,
    ) -> Result<(), String> {
        if authorization.author == tenant {
            return Ok(());
        }
        let protocols = descriptor
            .filters
            .iter()
            .filter_map(|filter| filter.protocol.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        permissions::authorize_messages_subscribe_or_sync(
            tenant,
            message,
            &protocols,
            authorization,
            &self.message_store,
        )
        .await
        .map_err(|detail| format!("MessagesSubscribeAuthorizationFailed: {detail}"))
    }
}
