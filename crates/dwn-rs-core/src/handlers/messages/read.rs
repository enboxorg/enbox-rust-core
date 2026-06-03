use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::SecondsFormat;
use futures_util::TryStreamExt;
use k256::sha2::{Digest, Sha256};
use serde_json::Value as JsonValue;

use crate::auth::JwsPublicKeyResolver;
use crate::cid::generate_cid_from_json;
use crate::descriptors::{
    Descriptor, Messages, MessagesSubscribeDescriptor, MessagesSyncDescriptor, Records,
};
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::errors::EventLogError;
use crate::filters::message_filters::Messages as MessagesFilter;
use crate::filters::{Filter, FilterKey, Filters};
use crate::interfaces::messages::descriptors::messages::{ReadDescriptor, SyncAction};
use crate::permissions::{self, AuthorizationContext};
use crate::stores::{EventLogSubscribeOptions, EventSubscription, StateHash, SubscriptionListener};
use crate::{Fields, Message};

const MAX_SYNC_DEPTH: usize = 256;
const MAX_INLINE_DATA_SIZE: u64 = 30_000;

static DEFAULT_HASHES: OnceLock<Vec<StateHash>> = OnceLock::new();

use super::common::*;
use super::MessagesReadHandler;
impl<MessageStore, DataStore> MessagesReadHandler<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    pub async fn handle_read(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message, "MessagesReadParseFailed") {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match messages_read_descriptor(&message) {
            Ok(descriptor) => descriptor,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let message_cid = match descriptor.message_cid.as_ref() {
            Some(message_cid) => message_cid.to_string(),
            None => {
                return DwnReply::bad_request(
                    "MessagesReadMissingMessageCid: descriptor.messageCid is required",
                )
            }
        };

        let authorization = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            true,
        ) {
            Ok(Some(authorization)) => authorization,
            Ok(None) => {
                return DwnReply::unauthorized(
                    "MessagesReadAuthorizationFailed: message failed authorization",
                )
            }
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return DwnReply::bad_request(detail)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
        };

        let stored_message = match self.message_store.get(tenant, &message_cid).await {
            Ok(Some(message)) => message,
            Ok(None) => return DwnReply::new(404, "Not Found"),
            Err(err) => return store_error_reply(err.to_string()),
        };

        if let Err(detail) = self
            .authorize_messages_read(tenant, &message, &authorization, &stored_message)
            .await
        {
            return DwnReply::unauthorized(detail);
        }

        let mut message_json =
            match serde_json::to_value(&stored_message).map_err(|err| err.to_string()) {
                Ok(value) => value,
                Err(detail) => return store_error_reply(detail),
            };
        let inline_data = strip_encoded_data(&mut message_json);
        let encoded_data = match inline_data {
            Some(encoded_data) => Some(encoded_data),
            None => self
                .external_read_data(tenant, &stored_message)
                .await
                .unwrap_or(None),
        };

        let mut entry = serde_json::Map::new();
        entry.insert("messageCid".to_string(), JsonValue::String(message_cid));
        entry.insert("message".to_string(), message_json);
        if let Some(encoded_data) = encoded_data {
            entry.insert("encodedData".to_string(), JsonValue::String(encoded_data));
        }

        DwnReply::ok().with_body("entry", JsonValue::Object(entry))
    }

    async fn authorize_messages_read(
        &self,
        tenant: &str,
        incoming_message: &Message<Descriptor>,
        authorization: &AuthorizationContext,
        stored_message: &Message<Descriptor>,
    ) -> Result<(), String> {
        if authorization.author == tenant {
            return Ok(());
        }
        if authorization.payload.get("permissionGrantId").is_some() {
            return permissions::authorize_messages_read(
                tenant,
                incoming_message,
                stored_message,
                authorization,
                &self.message_store,
            )
            .await;
        }
        Err("MessagesReadAuthorizationFailed: protocol message failed authorization".to_string())
    }

    async fn external_read_data(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
    ) -> Result<Option<String>, String> {
        let Some((record_id, data_cid, data_size)) = records_write_data_reference(message) else {
            return Ok(None);
        };
        if data_size > MAX_INLINE_DATA_SIZE {
            return Ok(None);
        }
        let Some(data) = self
            .data_store
            .get(tenant, &record_id, &data_cid)
            .await
            .map_err(|err| err.to_string())?
        else {
            return Ok(None);
        };

        let mut stream = data.data_stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.try_next().await.map_err(|err| err.to_string())? {
            bytes.extend_from_slice(&chunk);
            if bytes.len() as u64 > MAX_INLINE_DATA_SIZE {
                return Ok(None);
            }
        }
        Ok(Some(URL_SAFE_NO_PAD.encode(bytes)))
    }
}
