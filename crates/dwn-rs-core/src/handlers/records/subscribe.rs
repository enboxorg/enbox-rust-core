use std::future::Future;
use std::sync::Arc;

use chrono::Utc;
use serde_json::Value as JsonValue;

use crate::auth::resolver::DidResolver;
use crate::canonical_rfc3339;
use crate::cid::generate_cid_from_json;
use crate::descriptors::{Descriptor, Records, SubscribeDescriptor};
use crate::dwn::{Handler, HandlerContext};
use crate::filters::context::validate_nested_protocol_path_scope;
use crate::filters::message_filters::Records as RecordsFilter;
use crate::filters::Filters;
use crate::handlers::guarded_subscription::{
    create_guarded_subscription, DeliveryDecision, GuardedSubscription,
};
use crate::handlers::records::common::{
    attach_initial_writes, authorize_protocol_query_or_subscribe, bool_filter,
    date_sort_to_message_sort, event_log_error_reply, filter_map, message_record_id,
    message_record_limit_policy, records_subscribe_descriptor, records_subscribe_reply,
    resolve_record_limit_policy, should_protocol_authorize, store_error_reply, string_filter,
};
use crate::handlers::records::control;
use crate::handlers::records::visibility::{authorize_collection, collection_filters, PlanMode};
use crate::permissions::{
    self,
    errors::{GrantError, PermissionError},
    AuthorizationContext,
};
use crate::replies::records::Subscribe;
use crate::stores::write_resolver::{InitialWriteResolver, MessageStoreInitialWriteResolver};
use crate::stores::EventSubscription;
use crate::stores::{
    EventLogSubscribeOptions, SubscriptionError, SubscriptionErrorCode, SubscriptionListener,
    SubscriptionMessage,
};
use crate::validation::{ingest_message, ingress_rejection};
use crate::Message;
use crate::Pagination;
use crate::Response;

use super::{RecordsAuthorizationKind, RECORDS_INTERFACE, WRITE_METHOD};

/// Mutable authority retained from subscription open for delivery-time
/// revalidation. Open-time policy stays pinned to the signed request
/// timestamp; grant validity and role membership are rechecked at now.
#[derive(Clone)]
pub(crate) struct DeliveryAuthorization {
    pub(crate) message: Message<Descriptor>,
    pub(crate) filter: RecordsFilter,
    pub(crate) auth_ctx: AuthorizationContext,
    pub(crate) grant_valid_at_open: bool,
    pub(crate) role_invoked: bool,
    pub(crate) request_timestamp: String,
}

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
            // A snapshot is a collection page and refills like one: projection
            // and visibility both remove records, so one storage page is not
            // one reply page.
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
                |cursor| {
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
                                Some(Pagination { cursor, limit }),
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
                        return store_error_reply(format!(
                            "failed to attach initial writes: {err}"
                        ));
                    }
                };
            Response::ok().with_reply(Subscribe {
                subscription_id: None,
                entries: Some(entries.clone()),
                cursor,
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

/// Whether a subscription's authority can mutate after open and therefore
/// needs delivery-time revalidation: invoked grants, invoked roles, and
/// embedded author-delegated grants. Everything else is immutable.
fn needs_delivery_reauth(signature: &AuthorizationContext) -> bool {
    signature.permission_grant_id().is_some()
        || should_protocol_authorize(signature)
        || signature.author_delegated_grant.is_some()
}

/// Restamps a retained subscribe request with the delivery timestamp so
/// grant time-window checks run at now rather than at open.
fn delivery_message_at_now(message: &Message<Descriptor>) -> Result<Message<Descriptor>, String> {
    let mut message = message.clone();
    let Descriptor::Records(records) = &mut message.descriptor else {
        return Err("RecordsSubscribe descriptor expected during delivery".to_string());
    };
    let Records::Subscribe(descriptor) = records.as_mut() else {
        return Err("RecordsSubscribe descriptor expected during delivery".to_string());
    };
    descriptor.message_timestamp = Utc::now();
    Ok(message)
}

/// Revalidates mutable subscription authority at delivery time. Grant
/// validity is checked at now (expiry and revocation included); role
/// membership is re-resolved against the definition pinned to the signed
/// request timestamp, never newest. Immutable paths need no recheck.
pub(crate) async fn authorize_records_delivery<MessageStore>(
    tenant: &str,
    auth: &DeliveryAuthorization,
    message_store: &MessageStore,
) -> Result<(), SubscriptionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let authorize_failed = |detail: &str| SubscriptionError {
        code: SubscriptionErrorCode::RecordsDeliveryAuthorizationFailed,
        detail: detail.to_string(),
    };
    let delivery_message =
        delivery_message_at_now(&auth.message).map_err(|detail| SubscriptionError {
            code: SubscriptionErrorCode::RecordsDeliveryAuthorizationFailed,
            detail,
        })?;
    match permissions::authorize_records_query_or_subscribe_with_grant(
        tenant,
        &delivery_message,
        &auth.filter,
        &auth.auth_ctx,
        message_store,
    )
    .await
    {
        // A grant that activates after open is retryable; every other
        // delivery authorization failure is terminal. Activation after open
        // requires a future-dated request, so this branch is nearly dead.
        Err(PermissionError::InvalidGrant(GrantError::NotActive)) => {
            return Err(SubscriptionError {
                code: SubscriptionErrorCode::RecordsDeliveryFailed,
                detail: "subscription delivery authorization check failed".to_string(),
            });
        }
        Err(_) => {
            return Err(authorize_failed(
                "subscription authorization failed during delivery",
            ));
        }
        Ok(valid) => {
            if auth.grant_valid_at_open && !valid {
                return Err(authorize_failed(
                    "subscription authorization failed during delivery",
                ));
            }
        }
    }
    if auth.role_invoked {
        authorize_protocol_query_or_subscribe(
            tenant,
            &auth.filter,
            &auth.auth_ctx,
            message_store,
            &auth.request_timestamp,
            RecordsAuthorizationKind::Subscribe,
        )
        .await
        .map_err(|_| authorize_failed("subscription authorization failed during delivery"))?;
    }
    Ok(())
}

/// Checks one live write event against its current occupant population.
/// Deletes and non-write events skip occupancy. Projection failures are
/// terminal; non-occupants are silently suppressed.
async fn project_write_occupancy<MessageStore>(
    tenant: &str,
    write: &Message<Descriptor>,
    request_timestamp: &str,
    message_store: &MessageStore,
) -> Result<bool, SubscriptionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let projection_failed = || SubscriptionError {
        code: SubscriptionErrorCode::RecordsProjectionFailed,
        detail: "record-limit occupancy projection failed during delivery".to_string(),
    };
    let policy = message_record_limit_policy(tenant, write, message_store, request_timestamp)
        .await
        .map_err(|_| projection_failed())?;
    let Some(policy) = policy else {
        return Ok(true);
    };
    let Some(record_id) = message_record_id(write) else {
        return Err(projection_failed());
    };
    let occupant_filter = filter_map([
        ("interface", string_filter(RECORDS_INTERFACE)),
        ("method", string_filter(WRITE_METHOD)),
        ("isLatestBaseState", bool_filter(true)),
        ("protocol", string_filter(&policy.protocol)),
        ("protocolPath", string_filter(&policy.protocol_path)),
        ("recordId", string_filter(&record_id)),
    ]);
    let count = message_store
        .count(tenant, Filters::from(occupant_filter), None, Some(policy))
        .await
        .map_err(|_| projection_failed())?;
    Ok(count > 0)
}

/// Wraps a raw event-log listener with serialized delivery projection:
/// mutable reauthorization, then per-write occupancy, in feed order.
#[allow(clippy::too_many_arguments)]
fn create_records_delivery_guard<MessageStore>(
    listener: SubscriptionListener,
    tenant: String,
    request_timestamp: String,
    delivery_auth: Option<DeliveryAuthorization>,
    // The subscribe request and its requester, so live events answer to the
    // same control visibility the snapshot applied. Without them a subscriber
    // would receive, as it arrives, exactly what its own snapshot hid.
    request: Message<Descriptor>,
    signature: Option<AuthorizationContext>,
    // The caller's own filter, so a subscriber that pinned one stored key keeps
    // receiving that key rather than whichever becomes current.
    records_filter: RecordsFilter,
    message_store: Arc<MessageStore>,
) -> (SubscriptionListener, GuardedSubscription)
where
    MessageStore: crate::stores::MessageStore + Send + Sync + 'static,
{
    create_guarded_subscription(listener, move |message| {
        let tenant = tenant.clone();
        let request_timestamp = request_timestamp.clone();
        let delivery_auth = delivery_auth.clone();
        let request = request.clone();
        let signature = signature.clone();
        let records_filter = records_filter.clone();
        let message_store = message_store.clone();
        async move {
            let SubscriptionMessage::Event { cursor, event, .. } = &message else {
                return DeliveryDecision::Forward(message);
            };
            let cursor = cursor.clone();

            if let Some(auth) = delivery_auth.as_ref() {
                if let Err(error) =
                    authorize_records_delivery(&tenant, auth, message_store.as_ref()).await
                {
                    return DeliveryDecision::Fail { cursor, error };
                }
            }

            if let Descriptor::Records(records) = &event.message.descriptor {
                if matches!(records.as_ref(), Records::Write(_)) {
                    // Events are re-projected at delivery, not at open: an
                    // audience that has since stopped being current must stop
                    // being delivered.
                    // A projection or visibility lookup that *fails* is not a
                    // record the subscriber may not see. Suppressing it would
                    // present a store outage as a successfully filtered event
                    // and leave the stream running as though nothing were
                    // wrong, so it ends the subscription instead.
                    let control_failed = |detail: String| DeliveryDecision::Fail {
                        cursor: cursor.clone(),
                        error: SubscriptionError {
                            code: SubscriptionErrorCode::RecordsDeliveryFailed,
                            detail,
                        },
                    };

                    let projected = match control::project_current_audiences(
                        &tenant,
                        Some(&records_filter),
                        vec![event.message.clone()],
                        message_store.as_ref(),
                    )
                    .await
                    {
                        Ok(projected) => projected,
                        Err(error) => return control_failed(error.to_string()),
                    };
                    // Superseded: no longer the current audience for its scope.
                    let Some(write) = projected.into_iter().next() else {
                        return DeliveryDecision::Suppress;
                    };

                    // Live events answer to the same control visibility as the
                    // snapshot, so a subscriber cannot receive as it arrives
                    // what a query would have hidden.
                    match control::filter_visible_controls(
                        &tenant,
                        &request,
                        signature.as_ref(),
                        Some(&records_filter),
                        vec![write.clone()],
                        message_store.as_ref(),
                    )
                    .await
                    {
                        Ok(visible) if visible.is_empty() => return DeliveryDecision::Suppress,
                        Ok(_) => {}
                        Err(error) => return control_failed(error.to_string()),
                    }
                    match project_write_occupancy(
                        &tenant,
                        &write,
                        &request_timestamp,
                        message_store.as_ref(),
                    )
                    .await
                    {
                        Ok(true) => {}
                        Ok(false) => return DeliveryDecision::Suppress,
                        Err(error) => return DeliveryDecision::Fail { cursor, error },
                    }
                }
            }

            DeliveryDecision::Forward(message)
        }
    })
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

        let (event_filters, query_filters, _, delivery_auth) = match self
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

        // Guard live delivery with mutable reauthorization and occupancy
        // projection before the event log sees the listener, so no event can
        // slip through unprojected.
        let (guarded_listener, guard) = create_records_delivery_guard(
            listener,
            tenant.to_string(),
            canonical_rfc3339(descriptor.message_timestamp),
            delivery_auth,
            message.clone(),
            signature.clone(),
            descriptor.filter.clone(),
            self.message_store.clone(),
        );
        let subscription = match self
            .event_log
            .subscribe(
                tenant,
                &subscription_id,
                guarded_listener,
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
        guard.install_close(subscription.close.clone()).await;
        // Drain events enqueued during subscribe before the snapshot query,
        // so already-committed events are projected before initial results.
        guard.flush().await;

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
        let messages = match control::project_current_audiences(
            tenant,
            Some(&descriptor.filter),
            result.messages,
            self.message_store.as_ref(),
        )
        .await
        {
            Ok(messages) => messages,
            Err(error) => {
                let _ = (subscription.close)().await;
                return records_subscribe_reply(store_error_reply(error.to_string()), None);
            }
        };
        let messages = match control::filter_visible_controls(
            tenant,
            &message,
            signature.as_ref(),
            Some(&descriptor.filter),
            messages,
            self.message_store.as_ref(),
        )
        .await
        {
            Ok(messages) => messages,
            Err(error) => {
                let _ = (subscription.close)().await;
                return records_subscribe_reply(store_error_reply(error.to_string()), None);
            }
        };
        let entries =
            match attach_initial_writes(tenant, messages, self.write_resolver.as_ref()).await {
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
    ) -> Result<
        (
            Filters,
            Filters,
            Option<String>,
            Option<DeliveryAuthorization>,
        ),
        Response<Subscribe>,
    > {
        // One authorization serves both projections: the event set for live
        // delivery and the snapshot set for the initial page.
        let request_timestamp = canonical_rfc3339(descriptor.message_timestamp);
        let auth = authorize_collection(
            tenant,
            message,
            &descriptor.filter,
            signature,
            self.message_store.as_ref(),
            &request_timestamp,
            RecordsAuthorizationKind::Subscribe,
        )
        .await
        .map_err(Response::unauthorized)?;
        let author = auth.author.clone();
        // Retain mutable authority for delivery-time revalidation. Paths
        // authorized immutably (owner, published, author, recipient) need
        // no recheck. Invoked grants, invoked roles, and embedded
        // author-delegated grants can all mutate after open.
        let delivery_auth = match signature {
            Some(signature) if needs_delivery_reauth(signature) => Some(DeliveryAuthorization {
                message: message.clone(),
                filter: descriptor.filter.clone(),
                auth_ctx: signature.clone(),
                grant_valid_at_open: auth.grant_authorized,
                role_invoked: should_protocol_authorize(signature),
                request_timestamp,
            }),
            _ => None,
        };
        Ok((
            collection_filters(&auth, &descriptor.filter, None, PlanMode::Event),
            collection_filters(
                &auth,
                &descriptor.filter,
                descriptor.date_sort.as_ref(),
                PlanMode::Snapshot,
            ),
            author,
            delivery_auth,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jws::{AuthorizationPayloadData, PermissionGrantInvocation};
    use crate::permissions::{
        PermissionGrant, PermissionScope, RecordsMethod, RecordsScope, VerifiedAuthorizationPayload,
    };

    fn auth_ctx(
        permission_grant_id: Option<String>,
        protocol_role: Option<String>,
        delegated_grant: Option<PermissionGrant>,
    ) -> AuthorizationContext {
        AuthorizationContext {
            signer: "did:example:bob".to_string(),
            author: "did:example:alice".to_string(),
            payload: VerifiedAuthorizationPayload::Generic(AuthorizationPayloadData {
                descriptor_cid: String::new(),
                delegated_grant_id: None,
                permission_grant_id: permission_grant_id.clone(),
                permission_grant_ids: None,
                protocol_role,
            }),
            permission_grant_invocation: permission_grant_id
                .map(PermissionGrantInvocation::Single)
                .unwrap_or(PermissionGrantInvocation::None),
            author_delegated_grant: delegated_grant,
            owner: None,
        }
    }

    fn delegated_grant() -> PermissionGrant {
        PermissionGrant {
            id: "delegated-grant-1".to_string(),
            grantor: "did:example:alice".to_string(),
            grantee: "did:example:bob".to_string(),
            date_granted: crate::testing::parse_time("2025-01-01T00:00:00.000000Z"),
            date_expires: crate::testing::parse_time("2030-01-01T00:00:00.000000Z"),
            delegated: Some(true),
            scope: PermissionScope::Records(RecordsScope {
                method: RecordsMethod::Read,
                protocol: "http://example.com/notes".to_string(),
                selector: None,
            }),
            conditions: None,
            connect_session: None,
        }
    }

    // Covers: DWN-AUTH-005
    #[test]
    fn delivery_reauth_retained_for_mutable_authority_only() {
        assert!(!needs_delivery_reauth(&auth_ctx(None, None, None)));
        assert!(needs_delivery_reauth(&auth_ctx(
            Some("grant-1".to_string()),
            None,
            None
        )));
        assert!(needs_delivery_reauth(&auth_ctx(
            None,
            Some("thread/participant".to_string()),
            None
        )));
        assert!(needs_delivery_reauth(&auth_ctx(
            None,
            None,
            Some(delegated_grant())
        )));
    }
}
