use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::TryStreamExt;
use k256::sha2::{Digest, Sha256};
use serde_json::Value as JsonValue;

use crate::auth::GeneralJwsPublicKeyResolver;
use crate::descriptors::{Descriptor, Messages, MessagesSyncDescriptor, Records};
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::interfaces::messages::descriptors::messages::SyncAction;
use crate::permissions;
use crate::stores::{EnboxDataStore, EnboxMessageStore, EnboxStateIndex, StateHash};
use crate::{Fields, Message};

const MAX_SYNC_DEPTH: usize = 256;
const MAX_INLINE_DATA_SIZE: u64 = 30_000;

static DEFAULT_HASHES: OnceLock<Vec<StateHash>> = OnceLock::new();

#[derive(Clone)]
pub struct MessagesSyncHandler<MessageStore, DataStore, StateIndex> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
    public_key_resolver: Option<Arc<dyn GeneralJwsPublicKeyResolver + Send + Sync>>,
}

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
        public_key_resolver: impl GeneralJwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore, DataStore, StateIndex> MethodHandler
    for MessagesSyncHandler<MessageStore, DataStore, StateIndex>
where
    MessageStore: EnboxMessageStore + Clone + Send + Sync + 'static,
    DataStore: EnboxDataStore + Clone + Send + Sync + 'static,
    StateIndex: EnboxStateIndex + Clone + Send + Sync + 'static,
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
    MessageStore: EnboxMessageStore + Clone + Send + Sync + 'static,
    DataStore: EnboxDataStore + Clone + Send + Sync + 'static,
    StateIndex: EnboxStateIndex + Clone + Send + Sync + 'static,
{
    pub async fn handle_sync(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
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

fn parse_message(raw_message: &JsonValue) -> Result<Message<Descriptor>, String> {
    serde_json::from_value(raw_message.clone())
        .map_err(|err| format!("MessagesSyncParseFailed: {err}"))
}

fn messages_sync_descriptor(
    message: &Message<Descriptor>,
) -> Result<&MessagesSyncDescriptor, String> {
    match &message.descriptor {
        Descriptor::Messages(messages) => match messages.as_ref() {
            Messages::Sync(descriptor) => Ok(descriptor),
            _ => Err("MessagesSyncParseFailed: expected MessagesSync descriptor".to_string()),
        },
        _ => Err("MessagesSyncParseFailed: expected MessagesSync descriptor".to_string()),
    }
}

fn validate_sync_descriptor(descriptor: &MessagesSyncDescriptor) -> Result<(), String> {
    match descriptor.action {
        SyncAction::Root => Ok(()),
        SyncAction::Subtree | SyncAction::Leaves => {
            let prefix = descriptor.prefix.as_deref().ok_or_else(|| {
                "MessagesSyncInvalidPrefix: prefix is required for subtree and leaves actions"
                    .to_string()
            })?;
            parse_bit_prefix(prefix).map(|_| ())
        }
        SyncAction::Diff => {
            let depth = descriptor.depth.ok_or_else(|| {
                "MessagesSyncInvalidDepth: depth is required for diff action".to_string()
            })?;
            let depth = usize::from(depth);
            if depth > MAX_SYNC_DEPTH {
                return Err(format!(
                    "MessagesSyncInvalidDepth: depth must be <= {MAX_SYNC_DEPTH}, got {depth}"
                ));
            }
            let hashes = descriptor.hashes.as_ref().ok_or_else(|| {
                "MessagesSyncInvalidHashes: hashes are required for diff action".to_string()
            })?;
            for prefix in hashes.keys() {
                parse_bit_prefix(prefix)?;
                if prefix.len() != depth {
                    return Err(format!(
                        "MessagesSyncInvalidPrefix: diff prefix length must equal depth {depth}, got {}",
                        prefix.len()
                    ));
                }
            }
            Ok(())
        }
    }
}

fn parse_bit_prefix(prefix: &str) -> Result<Vec<bool>, String> {
    if prefix.len() > MAX_SYNC_DEPTH {
        return Err(format!(
            "MessagesSyncInvalidPrefix: length must be <= {MAX_SYNC_DEPTH}, got {}",
            prefix.len()
        ));
    }
    let mut bits = Vec::with_capacity(prefix.len());
    for byte in prefix.bytes() {
        match byte {
            b'0' => bits.push(false),
            b'1' => bits.push(true),
            _ => {
                return Err(format!(
                    "MessagesSyncInvalidPrefix: must contain only '0' and '1' characters, got: {prefix}"
                ))
            }
        }
    }
    Ok(bits)
}

fn strip_encoded_data(message: &mut JsonValue) -> Option<String> {
    message
        .as_object_mut()?
        .remove("encodedData")?
        .as_str()
        .map(str::to_string)
}

fn records_write_data_reference(message: &Message<Descriptor>) -> Option<(String, String, u64)> {
    let descriptor = match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Write(descriptor) => descriptor,
            _ => return None,
        },
        _ => return None,
    };
    let record_id = match &message.fields {
        Fields::Write(fields) => fields.record_id.clone(),
        Fields::InitialWriteField(fields) => fields.write_fields.record_id.clone(),
        _ => None,
    }?;
    Some((record_id, descriptor.data_cid.clone(), descriptor.data_size))
}

fn default_hash_hex(depth: usize) -> Result<String, String> {
    default_hash(depth).map(|hash| state_hash_hex(&hash))
}

fn default_hash(depth: usize) -> Result<StateHash, String> {
    if depth > MAX_SYNC_DEPTH {
        return Err(format!(
            "MessagesSyncInvalidDepth: depth must be <= {MAX_SYNC_DEPTH}, got {depth}"
        ));
    }
    Ok(default_hashes()[depth])
}

fn default_hashes() -> &'static [StateHash] {
    DEFAULT_HASHES
        .get_or_init(|| {
            let mut hashes = vec![[0u8; 32]; MAX_SYNC_DEPTH + 1];
            for depth in (0..MAX_SYNC_DEPTH).rev() {
                hashes[depth] = hash_children(&hashes[depth + 1], &hashes[depth + 1]);
            }
            hashes
        })
        .as_slice()
}

fn hash_children(left: &StateHash, right: &StateHash) -> StateHash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn state_hash_hex(hash: &StateHash) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn store_error_reply(detail: String) -> DwnReply {
    DwnReply::new(500, detail)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, RwLock};

    use bytes::Bytes;
    use futures_util::stream;
    use serde_json::json;

    use crate::auth::{
        GeneralJws, GeneralJwsPrivateJwk, GeneralJwsPublicJwk, PrivateJwkSigner,
        StaticPublicKeyResolver,
    };
    use crate::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
    use crate::descriptors::{MessagesSyncDescriptor, RecordsWriteDescriptor};
    use crate::errors::{DataStoreError, MessageStoreError};
    use crate::interfaces::messages::descriptors::messages::SyncAction;
    use crate::state_index::MemoryStateIndex;
    use crate::stores::{
        EnboxDataStoreGetResult, EnboxDataStorePutResult, EnboxMessageQueryResult,
    };
    use crate::{MapValue, Value};

    use super::*;

    #[tokio::test]
    async fn messages_sync_diff_returns_remote_messages_and_inline_data() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore;
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();

        let (cid, stored_message) = records_write_with_inline_data();
        message_store
            .insert("did:example:alice", &cid, stored_message.clone())
            .await;
        state_index
            .insert(
                "did:example:alice",
                &cid,
                MapValue::from([(
                    "protocol".to_string(),
                    Value::String("http://example.com/notes".to_string()),
                )]),
            )
            .await
            .unwrap();

        let handler = MessagesSyncHandler::with_public_key_resolver(
            message_store,
            data_store,
            state_index,
            test_resolver(),
        );
        let request = signed_sync_message(SyncSpec {
            action: SyncAction::Diff,
            protocol: Some("http://example.com/notes".to_string()),
            depth: Some(0),
            hashes: Some(BTreeMap::new()),
            signer: test_signer(),
            permission_grant_id: None,
            ..SyncSpec::new("2025-01-01T00:10:00.000000Z")
        });

        let reply = handler.handle_sync("did:example:alice", &request).await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        let only_remote = reply.body["onlyRemote"].as_array().unwrap();
        assert_eq!(only_remote.len(), 1);
        assert_eq!(only_remote[0]["messageCid"], cid);
        assert_eq!(only_remote[0]["encodedData"], "aGVsbG8");
        assert!(only_remote[0]["message"].get("encodedData").is_none());
        assert!(reply.body["onlyLocal"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn messages_sync_accepts_messages_read_grant_for_protocol_scope() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore;
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();

        let grant = permission_grant_message("grant-sync-1", Some("http://example.com/notes"));
        message_store
            .insert("did:example:alice", "grant-sync-1", grant)
            .await;
        let handler = MessagesSyncHandler::with_public_key_resolver(
            message_store,
            data_store,
            state_index,
            test_resolver(),
        );
        let request = signed_sync_message(SyncSpec {
            action: SyncAction::Root,
            protocol: Some("http://example.com/notes".to_string()),
            signer: bob_signer(),
            permission_grant_id: Some("grant-sync-1".to_string()),
            ..SyncSpec::new("2025-01-01T00:10:00.000000Z")
        });

        let reply = handler.handle_sync("did:example:alice", &request).await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        assert!(reply.body["root"].as_str().is_some());
    }

    #[tokio::test]
    async fn messages_sync_rejects_protocol_scoped_grant_for_unscoped_sync() {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore;
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        state_index.open().await.unwrap();

        let grant = permission_grant_message("grant-sync-2", Some("http://example.com/notes"));
        message_store
            .insert("did:example:alice", "grant-sync-2", grant)
            .await;
        let handler = MessagesSyncHandler::with_public_key_resolver(
            message_store,
            data_store,
            state_index,
            test_resolver(),
        );
        let request = signed_sync_message(SyncSpec {
            action: SyncAction::Root,
            signer: bob_signer(),
            permission_grant_id: Some("grant-sync-2".to_string()),
            ..SyncSpec::new("2025-01-01T00:10:00.000000Z")
        });

        let reply = handler.handle_sync("did:example:alice", &request).await;
        assert_eq!(reply.status.code, 401);
        assert!(reply
            .status
            .detail
            .contains("MessagesGrantAuthorizationMismatchedProtocol"));
    }

    fn records_write_with_inline_data() -> (String, Message<Descriptor>) {
        let data = Bytes::from_static(b"hello");
        let descriptor = RecordsWriteDescriptor {
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path: Some("note".to_string()),
            recipient: None,
            schema: None,
            tags: None,
            parent_id: None,
            data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
            data_size: data.len() as u64,
            date_created: parse_time("2025-01-01T00:00:00.000000Z"),
            message_timestamp: parse_time("2025-01-01T00:00:00.000000Z"),
            published: None,
            date_published: None,
            data_format: "text/plain".to_string(),
            permission_grant_id: None,
            squash: None,
        };
        let wire_message = json!({
            "descriptor": descriptor,
            "recordId": "record-1",
            "contextId": "record-1"
        });
        let cid = generate_cid_from_json(&wire_message).unwrap().to_string();
        let stored_message = json!({
            "descriptor": wire_message["descriptor"].clone(),
            "recordId": "record-1",
            "contextId": "record-1",
            "encodedData": URL_SAFE_NO_PAD.encode(data),
        });
        (cid, serde_json::from_value(stored_message).unwrap())
    }

    fn permission_grant_message(grant_id: &str, protocol: Option<&str>) -> Message<Descriptor> {
        let scope = match protocol {
            Some(protocol) => json!({
                "interface": "Messages",
                "method": "Read",
                "protocol": protocol,
            }),
            None => json!({
                "interface": "Messages",
                "method": "Read",
            }),
        };
        let data = serde_json::to_vec(&json!({
            "dateExpires": "2025-02-01T00:00:00.000000Z",
            "scope": scope,
        }))
        .unwrap();
        let descriptor = RecordsWriteDescriptor {
            protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
            protocol_path: Some(permissions::PERMISSIONS_GRANT_PATH.to_string()),
            recipient: Some("did:example:bob".to_string()),
            schema: None,
            tags: protocol.map(|protocol| {
                MapValue::from([("protocol".to_string(), Value::String(protocol.to_string()))])
            }),
            parent_id: None,
            data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
            data_size: data.len() as u64,
            date_created: parse_time("2025-01-01T00:00:00.000000Z"),
            message_timestamp: parse_time("2025-01-01T00:00:00.000000Z"),
            published: None,
            date_published: None,
            data_format: "application/json".to_string(),
            permission_grant_id: None,
            squash: None,
        };
        let descriptor_json = serde_json::to_value(&descriptor).unwrap();
        let payload = json!({
            "recordId": grant_id,
            "contextId": grant_id,
            "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
        });
        let signature = GeneralJws::create(
            serde_json::to_vec(&payload).unwrap().as_slice(),
            &[test_signer()],
        )
        .unwrap();
        serde_json::from_value(json!({
            "descriptor": descriptor_json,
            "recordId": grant_id,
            "contextId": grant_id,
            "authorization": { "signature": signature },
            "encodedData": URL_SAFE_NO_PAD.encode(data),
        }))
        .unwrap()
    }

    #[derive(Clone)]
    struct SyncSpec {
        timestamp: String,
        action: SyncAction,
        protocol: Option<String>,
        prefix: Option<String>,
        permission_grant_id: Option<String>,
        hashes: Option<BTreeMap<String, String>>,
        depth: Option<u16>,
        signer: PrivateJwkSigner,
    }

    impl SyncSpec {
        fn new(timestamp: &str) -> Self {
            Self {
                timestamp: timestamp.to_string(),
                action: SyncAction::Root,
                protocol: None,
                prefix: None,
                permission_grant_id: None,
                hashes: None,
                depth: None,
                signer: test_signer(),
            }
        }
    }

    fn signed_sync_message(spec: SyncSpec) -> JsonValue {
        let descriptor = MessagesSyncDescriptor {
            message_timestamp: parse_time(&spec.timestamp),
            action: spec.action,
            protocol: spec.protocol,
            prefix: spec.prefix,
            permission_grant_id: spec.permission_grant_id.clone(),
            hashes: spec.hashes,
            depth: spec.depth,
        };
        let descriptor_json = serde_json::to_value(&descriptor).unwrap();
        let mut payload = serde_json::Map::from_iter([(
            "descriptorCid".to_string(),
            JsonValue::String(
                generate_cid_from_json(&descriptor_json)
                    .unwrap()
                    .to_string(),
            ),
        )]);
        if let Some(permission_grant_id) = spec.permission_grant_id {
            payload.insert(
                "permissionGrantId".to_string(),
                JsonValue::String(permission_grant_id),
            );
        }
        let signature = GeneralJws::create(
            serde_json::to_vec(&JsonValue::Object(payload))
                .unwrap()
                .as_slice(),
            &[spec.signer],
        )
        .unwrap();
        json!({
            "descriptor": descriptor_json,
            "authorization": { "signature": signature },
        })
    }

    fn parse_time(value: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn test_signer() -> PrivateJwkSigner {
        signer_for("did:example:alice")
    }

    fn bob_signer() -> PrivateJwkSigner {
        signer_for("did:example:bob")
    }

    fn signer_for(did: &str) -> PrivateJwkSigner {
        let key_id = format!("{did}#key1");
        PrivateJwkSigner::new(
            &key_id,
            "EdDSA",
            GeneralJwsPrivateJwk {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                d: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string(),
                x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
                y: None,
                kid: Some(key_id.clone()),
                alg: Some("EdDSA".to_string()),
            },
        )
    }

    fn test_resolver() -> StaticPublicKeyResolver {
        StaticPublicKeyResolver::new(BTreeMap::from([
            (
                "did:example:alice#key1".to_string(),
                test_public_jwk("did:example:alice#key1"),
            ),
            (
                "did:example:bob#key1".to_string(),
                test_public_jwk("did:example:bob#key1"),
            ),
        ]))
    }

    fn test_public_jwk(key_id: &str) -> GeneralJwsPublicJwk {
        GeneralJwsPublicJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
            y: None,
            kid: Some(key_id.to_string()),
            alg: Some("EdDSA".to_string()),
        }
    }

    #[derive(Clone, Default)]
    struct TestMessageStore {
        rows: Arc<RwLock<TestMessageRows>>,
    }

    type TestMessageRows = BTreeMap<(String, String), Message<Descriptor>>;

    impl TestMessageStore {
        async fn insert(&self, tenant: &str, cid: &str, message: Message<Descriptor>) {
            self.rows
                .write()
                .unwrap()
                .insert((tenant.to_string(), cid.to_string()), message);
        }
    }

    impl EnboxMessageStore for TestMessageStore {
        async fn open(&mut self) -> Result<(), MessageStoreError> {
            Ok(())
        }

        async fn close(&mut self) {}

        async fn put(
            &self,
            tenant: &str,
            message: Message<Descriptor>,
            _indexes: MapValue,
        ) -> Result<(), MessageStoreError> {
            let cid = generate_cid_from_json(&serde_json::to_value(&message).unwrap())
                .map_err(test_message_store_error)?
                .to_string();
            self.insert(tenant, &cid, message).await;
            Ok(())
        }

        async fn get(
            &self,
            tenant: &str,
            cid: &str,
        ) -> Result<Option<Message<Descriptor>>, MessageStoreError> {
            Ok(self
                .rows
                .read()
                .unwrap()
                .get(&(tenant.to_string(), cid.to_string()))
                .cloned())
        }

        async fn query(
            &self,
            tenant: &str,
            filters: crate::filters::Filters,
            _sort: Option<crate::MessageSort>,
            _pagination: Option<crate::Pagination>,
        ) -> Result<EnboxMessageQueryResult, MessageStoreError> {
            let record_id = filters.into_iter().find_map(|filter| {
                filter
                    .get(&crate::filters::FilterKey::Index("recordId".to_string()))
                    .and_then(|filter| match filter {
                        crate::filters::Filter::Equal(Value::String(value)) => Some(value.clone()),
                        _ => None,
                    })
            });
            let messages = self
                .rows
                .read()
                .unwrap()
                .iter()
                .filter(|((row_tenant, cid), _)| {
                    row_tenant == tenant && Some(cid.as_str()) == record_id.as_deref()
                })
                .map(|(_, message)| message.clone())
                .collect();
            Ok(EnboxMessageQueryResult {
                messages,
                cursor: None,
            })
        }

        async fn count(
            &self,
            _tenant: &str,
            _filters: crate::filters::Filters,
            _sort: Option<crate::MessageSort>,
        ) -> Result<u64, MessageStoreError> {
            Ok(0)
        }

        async fn delete(&self, _tenant: &str, _cid: &str) -> Result<(), MessageStoreError> {
            Ok(())
        }

        async fn clear(&self) -> Result<(), MessageStoreError> {
            self.rows.write().unwrap().clear();
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct TestDataStore;

    impl EnboxDataStore for TestDataStore {
        async fn open(&mut self) -> Result<(), DataStoreError> {
            Ok(())
        }

        async fn close(&mut self) {}

        async fn put<T: futures_util::Stream<Item = Bytes> + Send + Unpin>(
            &self,
            _tenant: &str,
            _record_id: &str,
            _data_cid: &str,
            _data_stream: T,
        ) -> Result<EnboxDataStorePutResult, DataStoreError> {
            Ok(EnboxDataStorePutResult { data_size: 0 })
        }

        async fn get(
            &self,
            _tenant: &str,
            _record_id: &str,
            _data_cid: &str,
        ) -> Result<Option<EnboxDataStoreGetResult>, DataStoreError> {
            Ok(Some(EnboxDataStoreGetResult {
                data_size: 0,
                data_stream: Box::pin(stream::iter(Vec::<Result<Bytes, std::io::Error>>::new())),
            }))
        }

        async fn delete(
            &self,
            _tenant: &str,
            _record_id: &str,
            _data_cid: &str,
        ) -> Result<(), DataStoreError> {
            Ok(())
        }

        async fn clear(&self) -> Result<(), DataStoreError> {
            Ok(())
        }
    }

    fn test_message_store_error(err: impl std::fmt::Display) -> MessageStoreError {
        MessageStoreError::StoreError(crate::errors::StoreError::InternalException(
            err.to_string(),
        ))
    }
}
