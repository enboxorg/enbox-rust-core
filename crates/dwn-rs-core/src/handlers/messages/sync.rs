use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::TryStreamExt;
use serde_json::Value as JsonValue;

use crate::auth::JwsPublicKeyResolver;
use crate::descriptors::{Descriptor, MessagesSyncDescriptor};
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::interfaces::messages::descriptors::messages::SyncAction;
use crate::permissions::{self};
use crate::stores::StateHash;
use crate::Message;

const MAX_SYNC_DEPTH: usize = 256;
const MAX_INLINE_DATA_SIZE: u64 = 30_000;

use super::common::*;
use super::MessagesSyncHandler;
impl<MessageStore, DataStore, StateIndex> MessagesSyncHandler<MessageStore, DataStore, StateIndex> {
    pub fn new(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }

    pub fn with_optional_resolver(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
        public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
            public_key_resolver,
        }
    }
}

impl<MessageStore, DataStore, StateIndex> MethodHandler
    for MessagesSyncHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_sync(request.tenant, request.message).await })
    }
}

impl<MessageStore, DataStore, StateIndex> MessagesSyncHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    pub async fn handle_sync(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message, "MessagesSyncParseFailed") {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match messages_sync_descriptor(&message) {
            Ok(descriptor) => descriptor,
            Err(detail) => return DwnReply::bad_request(detail),
        };

        if let Err(detail) = validate_sync_descriptor(descriptor) {
            return DwnReply::bad_request(detail);
        }

        let authorization = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            true,
        ) {
            Ok(Some(authorization)) => authorization,
            Ok(None) => {
                return DwnReply::unauthorized(
                    "MessagesSyncAuthorizationFailed: message failed authorization",
                )
            }
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return DwnReply::bad_request(detail)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
        };

        if let Err(detail) = self
            .authorize_messages_sync(tenant, &message, descriptor, &authorization)
            .await
        {
            return DwnReply::unauthorized(detail);
        }

        match descriptor.action {
            SyncAction::Root => self.handle_root(tenant, descriptor).await,
            SyncAction::Subtree => self.handle_subtree(tenant, descriptor).await,
            SyncAction::Leaves => self.handle_leaves(tenant, descriptor).await,
            SyncAction::Diff => self.handle_diff(tenant, descriptor).await,
        }
    }

    async fn authorize_messages_sync(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        descriptor: &MessagesSyncDescriptor,
        authorization: &permissions::AuthorizationContext,
    ) -> Result<(), String> {
        if authorization.author == tenant {
            return Ok(());
        }
        let protocols = descriptor.protocol.iter().cloned().collect::<Vec<String>>();
        permissions::authorize_messages_subscribe_or_sync(
            tenant,
            message,
            &protocols,
            authorization,
            &self.message_store,
        )
        .await
        .map_err(|detail| format!("MessagesSyncAuthorizationFailed: {detail}"))
    }

    async fn handle_root(&self, tenant: &str, descriptor: &MessagesSyncDescriptor) -> DwnReply {
        let root = match descriptor.protocol.as_deref() {
            Some(protocol) => self.state_index.get_protocol_root(tenant, protocol).await,
            None => self.state_index.get_root(tenant).await,
        };
        match root {
            Ok(root) => DwnReply::ok().with_body("root", JsonValue::String(state_hash_hex(&root))),
            Err(err) => store_error_reply(err.to_string()),
        }
    }

    async fn handle_subtree(&self, tenant: &str, descriptor: &MessagesSyncDescriptor) -> DwnReply {
        let prefix = match parse_bit_prefix(descriptor.prefix.as_deref().unwrap_or_default()) {
            Ok(prefix) => prefix,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let hash = match descriptor.protocol.as_deref() {
            Some(protocol) => {
                self.state_index
                    .get_protocol_subtree_hash(tenant, protocol, &prefix)
                    .await
            }
            None => self.state_index.get_subtree_hash(tenant, &prefix).await,
        };
        match hash {
            Ok(hash) => DwnReply::ok().with_body("hash", JsonValue::String(state_hash_hex(&hash))),
            Err(err) => store_error_reply(err.to_string()),
        }
    }

    async fn handle_leaves(&self, tenant: &str, descriptor: &MessagesSyncDescriptor) -> DwnReply {
        let prefix = match parse_bit_prefix(descriptor.prefix.as_deref().unwrap_or_default()) {
            Ok(prefix) => prefix,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        match self
            .leaves(tenant, descriptor.protocol.as_deref(), &prefix)
            .await
        {
            Ok(entries) => DwnReply::ok().with_body(
                "entries",
                JsonValue::Array(entries.into_iter().map(JsonValue::String).collect()),
            ),
            Err(detail) => store_error_reply(detail),
        }
    }

    async fn handle_diff(&self, tenant: &str, descriptor: &MessagesSyncDescriptor) -> DwnReply {
        let depth = usize::from(descriptor.depth.unwrap_or_default());
        let client_hashes = descriptor.hashes.as_ref().cloned().unwrap_or_default();
        let default_hash = match default_hash_hex(depth) {
            Ok(hash) => hash,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let server_hashes = match self
            .collect_subtree_hashes(tenant, descriptor.protocol.as_deref(), depth)
            .await
        {
            Ok(hashes) => hashes,
            Err(detail) => return store_error_reply(detail),
        };

        let mut all_prefixes = BTreeSet::new();
        for (prefix, hash) in &client_hashes {
            if hash != &default_hash {
                all_prefixes.insert(prefix.clone());
            }
        }
        all_prefixes.extend(server_hashes.keys().cloned());

        let mut only_remote_cids = Vec::new();
        let mut only_local = Vec::new();
        for prefix in all_prefixes {
            let client_hash = client_hashes.get(&prefix).map(String::as_str);
            let server_hash = server_hashes.get(&prefix).map(String::as_str);

            if client_hash == server_hash {
                continue;
            }
            if server_hash.is_none() {
                only_local.push(prefix);
                continue;
            }

            let bit_prefix = match parse_bit_prefix(&prefix) {
                Ok(prefix) => prefix,
                Err(detail) => return DwnReply::bad_request(detail),
            };
            match self
                .leaves(tenant, descriptor.protocol.as_deref(), &bit_prefix)
                .await
            {
                Ok(leaves) => only_remote_cids.extend(leaves),
                Err(detail) => return store_error_reply(detail),
            }
            if client_hash.is_some() {
                only_local.push(prefix);
            }
        }

        let only_remote = match self.build_diff_entries(tenant, &only_remote_cids).await {
            Ok(entries) => entries,
            Err(detail) => return store_error_reply(detail),
        };

        DwnReply::ok()
            .with_body("onlyRemote", JsonValue::Array(only_remote))
            .with_body(
                "onlyLocal",
                JsonValue::Array(only_local.into_iter().map(JsonValue::String).collect()),
            )
    }

    async fn collect_subtree_hashes(
        &self,
        tenant: &str,
        protocol: Option<&str>,
        depth: usize,
    ) -> Result<BTreeMap<String, String>, String> {
        if depth > MAX_SYNC_DEPTH {
            return Err(format!(
                "MessagesSyncInvalidDepth: depth must be <= {MAX_SYNC_DEPTH}, got {depth}"
            ));
        }

        let mut hashes = BTreeMap::new();
        let mut stack = vec![String::new()];
        while let Some(prefix) = stack.pop() {
            let bits = parse_bit_prefix(&prefix)?;
            let hash = self.subtree_hash(tenant, protocol, &bits).await?;
            if hash == default_hash(bits.len())? {
                continue;
            }
            if prefix.len() >= depth {
                hashes.insert(prefix, state_hash_hex(&hash));
                continue;
            }
            stack.push(format!("{prefix}1"));
            stack.push(format!("{prefix}0"));
        }
        Ok(hashes)
    }

    async fn subtree_hash(
        &self,
        tenant: &str,
        protocol: Option<&str>,
        prefix: &[bool],
    ) -> Result<StateHash, String> {
        match protocol {
            Some(protocol) => {
                self.state_index
                    .get_protocol_subtree_hash(tenant, protocol, prefix)
                    .await
            }
            None => self.state_index.get_subtree_hash(tenant, prefix).await,
        }
        .map_err(|err| err.to_string())
    }

    async fn leaves(
        &self,
        tenant: &str,
        protocol: Option<&str>,
        prefix: &[bool],
    ) -> Result<Vec<String>, String> {
        match protocol {
            Some(protocol) => {
                self.state_index
                    .get_protocol_leaves(tenant, protocol, prefix)
                    .await
            }
            None => self.state_index.get_leaves(tenant, prefix).await,
        }
        .map_err(|err| err.to_string())
    }

    async fn build_diff_entries(
        &self,
        tenant: &str,
        message_cids: &[String],
    ) -> Result<Vec<JsonValue>, String> {
        let mut entries = Vec::new();
        for message_cid in message_cids {
            let Some(message) = self
                .message_store
                .get(tenant, message_cid)
                .await
                .map_err(|err| err.to_string())?
            else {
                continue;
            };

            let mut message_json = serde_json::to_value(&message).map_err(|err| err.to_string())?;
            let inline_data = strip_encoded_data(&mut message_json);

            let encoded_data = match inline_data {
                Some(encoded_data) => Some(encoded_data),
                None => self.external_inline_data(tenant, &message).await?,
            };

            let mut entry = serde_json::Map::new();
            entry.insert(
                "messageCid".to_string(),
                JsonValue::String(message_cid.clone()),
            );
            entry.insert("message".to_string(), message_json);
            if let Some(encoded_data) = encoded_data {
                entry.insert("encodedData".to_string(), JsonValue::String(encoded_data));
            }
            entries.push(JsonValue::Object(entry));
        }
        Ok(entries)
    }

    async fn external_inline_data(
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
