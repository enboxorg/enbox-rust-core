use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::TryStreamExt;
use serde_json::Value as JsonValue;
use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::{
    records::strip_encoded_data, Descriptor, MessagesReadDescriptor, Records,
};
use crate::dwn::{DwnReply, HandlerContext};
use crate::permissions::{self, AuthorizationContext, MessagesReadGrantAccess};
use crate::Handler;
use crate::Message;

use super::common::*;

const MAX_INLINE_DATA_SIZE: u64 = 30_000;

#[derive(Clone)]
pub struct MessagesReadHandler<MessageStore, DataStore> {
    message_store: MessageStore,
    data_store: DataStore,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MS, DS> Handler for MessagesReadHandler<MS, DS>
where
    MS: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DS: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    type Descriptor = MessagesReadDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = DwnReply> + Send {
        async move {
            let HandlerContext {
                tenant,
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
                &message,
                self.did_resolver.as_deref(),
                true,
            )
            .await
            {
                Ok(Some(authorization)) => authorization,
                Ok(None) => {
                    return DwnReply::unauthorized(
                        "MessagesReadAuthorizationFailed: message failed authorization",
                    )
                }
                Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                    return DwnReply::unauthorized(detail)
                }
                Err(error) => return DwnReply::bad_request(error),
            };

            let mut stored_message = match self.message_store.get(tenant, &message_cid).await {
                Ok(Some(message)) => message,
                Ok(None) => return DwnReply::new(404, "Not Found"),
                Err(err) => return store_error_reply(err.to_string()),
            };

            let grant_access = match self
                .authorize_messages_read(tenant, &message, &authorization, &stored_message)
                .await
            {
                Ok(access) => access,
                Err(detail) => return DwnReply::unauthorized(detail),
            };

            let inline_data = if matches!(
                &stored_message.descriptor,
                Descriptor::Records(records) if matches!(records.as_ref(), Records::Write(_))
            ) {
                match strip_encoded_data(&mut stored_message) {
                    Ok(encoded_data) => encoded_data,
                    Err(error) => return store_error_reply(error.to_string()),
                }
            } else {
                None
            };
            let message_json =
                match serde_json::to_value(&stored_message).map_err(|err| err.to_string()) {
                    Ok(value) => value,
                    Err(detail) => return store_error_reply(detail),
                };
            let encoded_data = match grant_access {
                MessagesReadGrantAccess::MetadataOnly => None,
                MessagesReadGrantAccess::Full => match inline_data {
                    Some(encoded_data) => Some(encoded_data),
                    None => self
                        .external_read_data(tenant, &stored_message)
                        .await
                        .unwrap_or(None),
                },
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
        }
    }
}

impl<MessageStore, DataStore> MessagesReadHandler<MessageStore, DataStore> {
    pub fn new(
        message_store: MessageStore,
        data_store: DataStore,
        did_resolver: Option<Arc<dyn DidResolver>>,
    ) -> Self {
        Self {
            message_store,
            data_store,
            did_resolver,
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
    ) -> Result<MessagesReadGrantAccess, String> {
        if authorization.author == tenant {
            return Ok(MessagesReadGrantAccess::Full);
        }
        if authorization.permission_grant_ids().is_some() {
            return permissions::authorize_messages_read(
                tenant,
                incoming_message,
                stored_message,
                authorization,
                &self.message_store,
            )
            .await
            .map_err(|error| error.to_string());
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
