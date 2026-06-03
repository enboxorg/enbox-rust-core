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
use super::{RecordsAuthorizationKind, RecordsQueryHandler};

impl<MessageStore> RecordsQueryHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    pub async fn handle_query(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match records_query_descriptor(&message) {
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

        let (filters, author) = match self
            .query_filters(tenant, &message, &descriptor, signature.as_ref())
            .await
        {
            Ok(result) => result,
            Err(QueryAuthorizationResult::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
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
            author.as_deref(),
        )
        .await;
        DwnReply::ok()
            .with_body("entries", JsonValue::Array(entries))
            .with_body(
                "cursor",
                serde_json::to_value(result.cursor).unwrap_or(JsonValue::Null),
            )
    }

    async fn query_filters(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        descriptor: &RecordsQueryDescriptor,
        signature: Option<&AuthorizationContext>,
    ) -> Result<(Filters, Option<String>), QueryAuthorizationResult> {
        if filter_includes_published_records(&descriptor.filter) && signature.is_none() {
            return Ok((
                Filters::from(published_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                )),
                None,
            ));
        }
        let signature = signature.ok_or_else(|| {
            QueryAuthorizationResult::Unauthorized(
                "AuthenticateJwsMissing: authorization signature is required".to_string(),
            )
        })?;
        let grant_authorized = permissions::authorize_records_query_or_subscribe_with_grant(
            tenant,
            message,
            &descriptor.filter,
            signature,
            &self.message_store,
        )
        .await
        .map_err(QueryAuthorizationResult::Unauthorized)?;
        if should_protocol_authorize(&signature.payload) {
            authorize_protocol_query_or_subscribe(
                tenant,
                &descriptor.filter,
                &signature.payload,
                &signature.author,
                &self.message_store,
                RecordsAuthorizationKind::Query,
            )
            .await
            .map_err(QueryAuthorizationResult::Unauthorized)?;
        }
        if signature.author == tenant {
            return Ok((
                Filters::from(owner_records_filter(
                    &descriptor.filter,
                    descriptor.date_sort.as_ref(),
                )),
                Some(signature.author.clone()),
            ));
        }
        Ok((
            Filters::from(non_owner_records_filters(
                &descriptor.filter,
                descriptor.date_sort.as_ref(),
                &signature.author,
                should_protocol_authorize(&signature.payload) || grant_authorized,
            )),
            Some(signature.author.clone()),
        ))
    }
}
