use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Bound;
use std::pin::Pin;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use chrono::SecondsFormat;
use futures_util::{stream, TryStreamExt};
use serde_json::{json, Value as JsonValue};

use crate::auth::JwsPublicKeyResolver;
use crate::cid::{
    generate_cid_from_json, generate_dag_pb_cid_from_bytes, generate_message_cid_from_json,
};
use crate::core_protocol::{CoreProtocolRegistry, CoreProtocolStores};
use crate::descriptors::records::CountDescriptor;
use crate::descriptors::{
    DeleteDescriptor, Descriptor, ReadDescriptor, Records, RecordsQueryDescriptor,
    RecordsWriteDescriptor, SubscribeDescriptor,
};
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::errors::EventLogError;
use crate::fields::{Fields, WriteFields};
use crate::filters::message_filters::Records as RecordsFilter;
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::interfaces::messages::protocols::{
    self as protocol_types, Action, Can, Definition, RuleSet, Who,
};
use crate::interfaces::replies::Status;
use crate::permissions::{self, AuthorizationContext};
use crate::stores::{EventLogSubscribeOptions, EventSubscription, KeyValues, SubscriptionListener};
use crate::{Message, MessageSort, Pagination, SortDirection, Value};

use super::common::*;
use super::{RecordsAuthorizationKind, RecordsCountHandler};

impl<MessageStore> RecordsCountHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    pub async fn handle_count(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match records_count_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return DwnReply::bad_request(detail),
        };
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
    }
}
