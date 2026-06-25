use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::TryStreamExt;
use serde_json::Value as JsonValue;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::auth::JwsPublicKeyResolver;
use crate::descriptors::Descriptor;
use crate::descriptors::MessagesReadDescriptor;
use crate::dwn::{DwnReply, HandlerContext};
use crate::permissions::{self, AuthorizationContext};
use crate::Handler;
use crate::Message;

use super::common::*;

const MAX_INLINE_DATA_SIZE: u64 = 30_000;

#[derive(Clone)]
pub struct MessagesReadHandler<MessageStore, DataStore> {
    message_store: MessageStore,
    data_store: DataStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MS, DS> Handler for MessagesReadHandler<MS, DS>
where
    MS: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DS: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    type Descriptor = MessagesReadDescriptor;

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
            entry.insert(
                "messageCid".to_string(),
                JsonValue::String(message_cid.to_owned()),
            );
            entry.insert("message".to_string(), message_json);
            if let Some(encoded_data) = encoded_data {
                entry.insert("encodedData".to_string(), JsonValue::String(encoded_data));
            }

            DwnReply::ok().with_body("entry", JsonValue::Object(entry))
        })
    }
}

impl<MessageStore, DataStore> MessagesReadHandler<MessageStore, DataStore> {
    pub fn new(
        message_store: MessageStore,
        data_store: DataStore,
        public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
    ) -> Self {
        Self {
            message_store,
            data_store,
            public_key_resolver,
        }
    }
}

impl<MessageStore, DataStore> MessagesReadHandler<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
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
