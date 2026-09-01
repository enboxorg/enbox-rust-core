use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use chrono::Utc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::records::{records_write_descriptor, strip_encoded_data, write_fields};
use crate::descriptors::{
    Descriptor, MessageDescriptor, Messages, MessagesSubscribeDescriptor, Records,
    RecordsWriteDescriptor as WriteDescriptor,
};
use crate::dwn::HandlerContext;
use crate::events::MessageEvent;
use crate::filters::matches_filters;
use crate::filters::{Filter, FilterKey, Filters};
use crate::handlers::guarded_subscription::{
    create_guarded_subscription, DeliveryDecision, GuardedSubscription,
};
use crate::handlers::messages::authorization::{
    authorize_query_or_subscribe, MessageAuthorizationKind, MessagesAuthorization,
};
use crate::handlers::messages::query::query_fingerprint_scopes;
use crate::handlers::records::common::message_record_id;
use crate::permissions::{self};
use crate::replies::messages;
use crate::stores::replication_feed_reader::build_token;
use crate::stores::{
    EventLogSubscribeOptions, EventSubscription, MessageStore, ReplicationFeedReader,
    SubscriptionError, SubscriptionErrorCode, SubscriptionListener, SubscriptionMessage,
};
use crate::{Handler, Response, Value};
use crate::{MapValue, Message};

use super::common::*;

#[derive(Clone)]
pub struct MessagesSubscribeHandler<MessageStore, EventLog, FeedReader> {
    message_store: MessageStore,
    event_log: EventLog,
    replication_feed_reader: Option<FeedReader>,
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

impl<MessageStore, EventLog, FeedReader> Handler
    for MessagesSubscribeHandler<MessageStore, EventLog, FeedReader>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
    FeedReader: ReplicationFeedReader + Clone + Send + Sync + 'static,
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

impl<MessageStore, EventLog, FeedReader>
    MessagesSubscribeHandler<MessageStore, EventLog, FeedReader>
{
    pub fn new(
        message_store: MessageStore,
        event_log: EventLog,
        replication_feed_reader: Option<FeedReader>,
        did_resolver: Option<Arc<dyn DidResolver>>,
    ) -> Self {
        Self {
            message_store,
            event_log,
            replication_feed_reader,
            did_resolver,
        }
    }
}

impl<MessageStore, EventLog, FeedReader>
    MessagesSubscribeHandler<MessageStore, EventLog, FeedReader>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    EventLog: crate::stores::EventLog + Clone + Send + Sync + 'static,
    FeedReader: ReplicationFeedReader + Clone + Send + Sync + 'static,
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
            Ok(authorization) => authorization,
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

        let caller_filters = messages_filters_to_filters(
            &descriptor.filters,
            authorization.include_shadow_filters(),
        );
        let filters = subscription_filters(caller_filters.clone(), &authorization);
        let (guarded_listener, guard) = guarded_subscription_listener(
            tenant.to_string(),
            message.clone(),
            descriptor.filters.clone(),
            caller_filters,
            auth_context,
            authorization.clone(),
            self.message_store.clone(),
            listener,
        );
        let subscription = match self
            .event_log
            .subscribe(
                tenant,
                &subscription_id,
                guarded_listener,
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
        guard.install_close(subscription.close.clone()).await;
        guard.flush().await;
        let mut reply = messages::Subscription {
            subscription_id: Some(subscription.id.clone()),
            role_record_id: authorization.role_record_id().map(str::to_string),
            ..Default::default()
        };
        if authorization.role_record_id().is_none() {
            if let Ok(Some((head, fingerprint))) =
                self.feed_snapshot(tenant, &descriptor.filters).await
            {
                reply.head = Some(head);
                reply.fingerprint = fingerprint;
            }
        }
        subscribe_reply(Response::ok().with_reply(reply), Some(subscription))
    }

    /// Captures a post-installation feed head and its canonical scope fingerprint. Snapshot
    /// failure is best-effort because returning an error after subscription installation would
    /// orphan a live listener.
    async fn feed_snapshot(
        &self,
        tenant: &str,
        filters: &[crate::message_filters::Messages],
    ) -> Result<Option<(crate::ProgressToken, Option<String>)>, crate::errors::EventLogError> {
        let Some(reader) = &self.replication_feed_reader else {
            return Ok(None);
        };

        let head = match reader.log_bounds(tenant).await? {
            Some((_, latest)) => latest,
            None => {
                let epoch = reader.epoch().await?;
                build_token(tenant, &epoch, 0, None)
            }
        };
        let fingerprint = match query_fingerprint_scopes(filters) {
            Some(scopes) => Some(reader.fingerprint(tenant, &scopes).await?.hex()),
            None => None,
        };
        Ok(Some((head, fingerprint)))
    }
}

#[allow(clippy::too_many_arguments)]
fn guarded_subscription_listener<MS>(
    tenant: String,
    request: Message<Descriptor>,
    signed_filters: Vec<crate::message_filters::Messages>,
    caller_filters: Option<Filters>,
    auth_context: permissions::AuthorizationContext,
    authorization: MessagesAuthorization,
    message_store: MS,
    listener: SubscriptionListener,
) -> (SubscriptionListener, GuardedSubscription)
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    create_guarded_subscription(listener, move |message| {
        let tenant = tenant.clone();
        let request = request.clone();
        let signed_filters = signed_filters.clone();
        let caller_filters = caller_filters.clone();
        let auth_context = auth_context.clone();
        let authorization = authorization.clone();
        let message_store = message_store.clone();
        async move {
            let SubscriptionMessage::Event { cursor, .. } = &message else {
                return DeliveryDecision::Forward(message);
            };
            let cursor = cursor.clone();

            if let Err(detail) = authorize_delivery(
                &tenant,
                &request,
                &signed_filters,
                &auth_context,
                &authorization,
                &message_store,
            )
            .await
            {
                return DeliveryDecision::Fail {
                    cursor,
                    error: SubscriptionError {
                        code: SubscriptionErrorCode::DeliveryAuthorizationFailed,
                        detail,
                    },
                };
            }

            if is_internal_role_wake(&message, &authorization)
                && !event_matches_caller_filters(&message, caller_filters.as_ref())
            {
                return DeliveryDecision::Suppress;
            }

            if authorization.metadata_only() {
                match to_metadata_only(message) {
                    Ok(message) => DeliveryDecision::Forward(message),
                    Err(detail) => DeliveryDecision::Fail {
                        cursor,
                        error: SubscriptionError {
                            code: SubscriptionErrorCode::DeliveryFailed,
                            detail,
                        },
                    },
                }
            } else {
                DeliveryDecision::Forward(message)
            }
        }
    })
}

async fn authorize_delivery<MS>(
    tenant: &str,
    request: &Message<Descriptor>,
    filters: &[crate::message_filters::Messages],
    auth_context: &permissions::AuthorizationContext,
    expected: &MessagesAuthorization,
    message_store: &MS,
) -> Result<(), String>
where
    MS: MessageStore + Clone + Send + Sync + 'static,
{
    if matches!(expected, MessagesAuthorization::Owner) {
        return Ok(());
    }

    // Signature authentication happened when the subscription opened. This projection changes
    // only the effective authorization time consumed by the grant validators.
    let mut delivery_request = request.clone();
    let Descriptor::Messages(messages) = &mut delivery_request.descriptor else {
        return Err("MessagesSubscribe descriptor expected during delivery".to_string());
    };
    let Messages::Subscribe(descriptor) = messages.as_mut() else {
        return Err("MessagesSubscribe descriptor expected during delivery".to_string());
    };
    descriptor.message_timestamp = Utc::now();

    let current = authorize_query_or_subscribe(
        tenant,
        &delivery_request,
        filters,
        auth_context,
        message_store,
        MessageAuthorizationKind::Subscribe,
    )
    .await
    .map_err(|error| error.to_string())?;

    match (expected, current) {
        (MessagesAuthorization::Grant { .. }, MessagesAuthorization::Grant { .. }) => Ok(()),
        (MessagesAuthorization::Role(expected), MessagesAuthorization::Role(current))
            if expected.resolved_role == current.resolved_role =>
        {
            Ok(())
        }
        _ => Err("subscription authorization changed during delivery".to_string()),
    }
}

fn is_internal_role_wake(
    message: &SubscriptionMessage,
    authorization: &MessagesAuthorization,
) -> bool {
    let Some(role_record_id) = authorization.role_record_id() else {
        return false;
    };
    let SubscriptionMessage::Event { event, .. } = message else {
        return false;
    };
    message_record_id(&event.message).as_deref() == Some(role_record_id)
        || event
            .initial_write
            .as_ref()
            .and_then(|write| message_record_id(&write.clone().into()))
            .as_deref()
            == Some(role_record_id)
}

fn event_matches_caller_filters(message: &SubscriptionMessage, filters: Option<&Filters>) -> bool {
    let SubscriptionMessage::Event { event, .. } = message else {
        return false;
    };
    let indexes = event_indexes(event);
    matches_filters(&indexes, filters)
}

fn event_indexes(event: &MessageEvent<Descriptor>) -> MapValue {
    let mut indexes = MapValue::new();
    indexes.insert(
        "interface".to_string(),
        Value::String(event.message.descriptor.interface().to_string()),
    );
    indexes.insert(
        "method".to_string(),
        Value::String(event.message.descriptor.method().to_string()),
    );

    let write = match &event.message.descriptor {
        Descriptor::Records(records) if matches!(records.as_ref(), Records::Write(_)) => {
            Some(event.message.clone())
        }
        Descriptor::Records(records) if matches!(records.as_ref(), Records::Delete(_)) => {
            event.initial_write.clone().map(Into::into)
        }
        _ => None,
    };
    if let Some(write) = write {
        if let Ok(descriptor) = records_write_descriptor(&write) {
            indexes.insert(
                "protocol".to_string(),
                Value::String(descriptor.protocol.clone()),
            );
            indexes.insert(
                "protocolPath".to_string(),
                Value::String(descriptor.protocol_path.clone()),
            );
        }
        if let Ok(fields) = write_fields(&write) {
            if let Some(context_id) = &fields.context_id {
                indexes.insert("contextId".to_string(), Value::String(context_id.clone()));
            }
        }
    }
    if let Ok(descriptor) = serde_json::to_value(&event.message.descriptor) {
        if let Some(timestamp) = descriptor.get("messageTimestamp").and_then(|v| v.as_str()) {
            indexes.insert(
                "messageTimestamp".to_string(),
                Value::String(timestamp.to_string()),
            );
        }
    }
    indexes
}

fn to_metadata_only(mut message: SubscriptionMessage) -> Result<SubscriptionMessage, String> {
    let SubscriptionMessage::Event {
        event,
        encoded_data,
        ..
    } = &mut message
    else {
        return Ok(message);
    };

    *encoded_data = None;
    if matches!(event.message.descriptor, Descriptor::Records(_)) {
        strip_encoded_data(&mut event.message).map_err(|error| error.to_string())?;
    }
    if let Some(initial_write) = &mut event.initial_write {
        let mut generic: Message<Descriptor> = initial_write.clone().into();
        strip_encoded_data(&mut generic).map_err(|error| error.to_string())?;
        *initial_write =
            Message::<WriteDescriptor>::try_from(generic).map_err(|error| error.to_string())?;
    }
    Ok(message)
}

fn subscription_filters(
    caller_filters: Option<Filters>,
    authorization: &MessagesAuthorization,
) -> Option<Filters> {
    let Some(role_record_id) = authorization.role_record_id() else {
        return caller_filters;
    };

    let mut filters = caller_filters
        .map(IntoIterator::into_iter)
        .map(Iterator::collect::<Vec<_>>)
        .unwrap_or_default();
    filters.push(BTreeMap::from([
        (
            FilterKey::Index("interface".to_string()),
            Filter::Equal(Value::String("Records".to_string())),
        ),
        (
            FilterKey::Index("recordId".to_string()),
            Filter::Equal(Value::String(role_record_id.to_string())),
        ),
    ]));

    Some(Filters::from(filters))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::messages::authorization::MessagesRoleAuthorization;
    use crate::handlers::records::common::ResolvedProtocolRole;
    use crate::stores::replication_feed_reader::build_token;

    const PROTOCOL: &str = "https://example.com/chat";
    const ROLE_PATH: &str = "thread/participant";
    const CONTEXT: &str = "thread-1";
    const FILTER_CONTEXT: &str = "thread-1/message-1";
    const ROLE_ID: &str = "role-record-1";

    fn role_authorization(metadata_only: bool) -> MessagesAuthorization {
        MessagesAuthorization::Role(MessagesRoleAuthorization {
            author: "did:example:bob".to_string(),
            metadata_only,
            resolved_role: ResolvedProtocolRole {
                protocol: PROTOCOL.to_string(),
                protocol_path: ROLE_PATH.to_string(),
                context_id_prefix: Some(FILTER_CONTEXT.to_string()),
                role_record_id: ROLE_ID.to_string(),
            },
        })
    }

    fn role_write() -> Message<Descriptor> {
        serde_json::from_value(serde_json::json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": "2026-01-01T00:00:00.000000Z",
                "dateCreated": "2026-01-01T00:00:00.000000Z",
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 3,
                "dataFormat": "text/plain",
                "protocol": PROTOCOL,
                "protocolPath": ROLE_PATH,
                "recipient": "did:example:bob"
            },
            "recordId": ROLE_ID,
            "contextId": CONTEXT,
            "encodedData": "YWJj"
        }))
        .unwrap()
    }

    fn event_message() -> SubscriptionMessage {
        SubscriptionMessage::Event {
            cursor: build_token("did:example:alice", "epoch", 1, Some("cid-1")),
            event: Box::new(MessageEvent {
                message: role_write(),
                initial_write: None,
            }),
            seq: Some("1".to_string()),
            message_cid: Some("cid-1".to_string()),
            is_latest_base_state: Some(true),
            protocol: Some(PROTOCOL.to_string()),
            encoded_data: Some("YWJj".to_string()),
        }
    }

    fn subscribe_request() -> Message<Descriptor> {
        serde_json::from_value(serde_json::json!({
            "descriptor": {
                "interface": "Messages",
                "method": "Subscribe",
                "messageTimestamp": "2026-01-01T00:00:00.000000Z",
                "filters": [{
                    "interface": "Records",
                    "protocol": PROTOCOL,
                    "protocolPath": "thread/message",
                    "contextIdPrefix": "thread-1/message-1"
                }]
            }
        }))
        .unwrap()
    }

    #[test]
    fn role_subscription_adds_an_internal_record_wake_filter() {
        let caller = Filters::from(BTreeMap::from([(
            FilterKey::Index("protocol".to_string()),
            Filter::Equal(Value::String(PROTOCOL.to_string())),
        )]));

        let filters = subscription_filters(Some(caller), &role_authorization(false)).unwrap();
        let filters = filters.into_iter().collect::<Vec<_>>();
        assert_eq!(filters.len(), 2);
        assert_eq!(
            filters[1].get(&FilterKey::Index("recordId".to_string())),
            Some(&Filter::Equal(Value::String(ROLE_ID.to_string())))
        );
    }

    #[test]
    fn metadata_projection_removes_detached_and_inline_data() {
        let projected = to_metadata_only(event_message()).unwrap();
        let SubscriptionMessage::Event {
            event,
            encoded_data,
            ..
        } = projected
        else {
            panic!("event expected");
        };
        assert!(encoded_data.is_none());
        assert!(serde_json::to_value(&event.message)
            .unwrap()
            .get("encodedData")
            .is_none());
    }

    #[test]
    fn role_wake_is_forwarded_only_when_it_matches_the_signed_filters() {
        let event = event_message();
        let authorization = role_authorization(false);
        assert!(is_internal_role_wake(&event, &authorization));

        let matching = messages_filters_to_filters(
            &[crate::message_filters::Messages {
                interface: Some("Records".to_string()),
                protocol: Some(PROTOCOL.to_string()),
                protocol_path: Some(ROLE_PATH.to_string()),
                context_id_prefix: Some(CONTEXT.to_string()),
                ..Default::default()
            }],
            false,
        );
        assert!(event_matches_caller_filters(&event, matching.as_ref()));

        let nonmatching = messages_filters_to_filters(
            &[crate::message_filters::Messages {
                interface: Some("Records".to_string()),
                protocol: Some(PROTOCOL.to_string()),
                protocol_path: Some("thread/message".to_string()),
                context_id_prefix: Some(CONTEXT.to_string()),
                ..Default::default()
            }],
            false,
        );
        assert!(!event_matches_caller_filters(&event, nonmatching.as_ref()));
    }

    #[tokio::test]
    async fn role_delivery_rejects_after_the_resolved_role_record_disappears() {
        use crate::handlers::messages::authorization::tests::{
            exact_filter, role_authorization as auth_context, role_record, role_store, TENANT,
        };

        let (store, _) = role_store().await;
        let request = subscribe_request();
        let filters = vec![exact_filter("thread/message")];
        let auth_context = auth_context();
        let expected = authorize_query_or_subscribe(
            TENANT,
            &request,
            &filters,
            &auth_context,
            &store,
            MessageAuthorizationKind::Subscribe,
        )
        .await
        .expect("active role must authorize subscription");

        authorize_delivery(TENANT, &request, &filters, &auth_context, &expected, &store)
            .await
            .expect("active role must authorize delivery");

        let role_cid = role_record().cid().unwrap().to_string();
        store.delete(TENANT, &role_cid).await.unwrap();
        assert!(
            authorize_delivery(TENANT, &request, &filters, &auth_context, &expected, &store,)
                .await
                .is_err()
        );
    }
}
