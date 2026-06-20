//! Production [`SyncEndpoint`](crate::sync::SyncEndpoint) implementations for local
//! stores and remote `@enbox/dwn-server` peers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};

use crate::canonical_rfc3339;
use crate::dwn::DwnReply;
use crate::interfaces::messages::descriptors::messages::SyncAction;
use crate::interfaces::replies::Status;
use crate::runtime::desktop::server::{DwnProcessMessage, PROCESS_MESSAGE_METHOD};
use crate::stores::{DataStore, MessageStore, StateHash, StateIndex};
use crate::sync::{
    MessagesSyncDiff, SyncEndpoint, SyncError, SyncFuture, SyncHashes, SyncMessageEntry,
    SyncResult, SyncScope,
};

const MAX_SYNC_DEPTH: usize = 16;

static DEFAULT_HASHES: OnceLock<Vec<StateHash>> = OnceLock::new();

/// Returns true when an applied sync message should be treated as success (TS parity).
pub fn is_sync_apply_success(status_code: i32, message: &JsonValue) -> bool {
    match status_code {
        200 | 202 | 204 | 409 => true,
        404 => message_method(message) == Some("Delete"),
        _ => false,
    }
}

fn message_method(message: &JsonValue) -> Option<&str> {
    message
        .get("descriptor")
        .and_then(|descriptor| descriptor.get("method"))
        .and_then(JsonValue::as_str)
}

/// Builds signed MessagesSync requests for remote HTTP peers.
pub trait SyncRequestAuthorizer: Clone + Send + Sync + 'static {
    fn authorize_sync<'a>(
        &'a self,
        tenant: &'a str,
        scope: &'a SyncScope,
        action: SyncAction,
        prefix: Option<&'a str>,
        depth: Option<u8>,
        hashes: Option<SyncHashes>,
    ) -> SyncFuture<'a, JsonValue>;
}

/// In-process sync endpoint backed by local store traits.
pub struct DirectSyncEndpoint<D, MS, DS, SI> {
    applier: Arc<D>,
    message_store: MS,
    data_store: DS,
    state_index: SI,
}

impl<D, MS, DS, SI> Clone for DirectSyncEndpoint<D, MS, DS, SI>
where
    MS: Clone,
    DS: Clone,
    SI: Clone,
{
    fn clone(&self) -> Self {
        Self {
            applier: self.applier.clone(),
            message_store: self.message_store.clone(),
            data_store: self.data_store.clone(),
            state_index: self.state_index.clone(),
        }
    }
}

impl<D, MS, DS, SI> DirectSyncEndpoint<D, MS, DS, SI> {
    pub fn new(applier: D, message_store: MS, data_store: DS, state_index: SI) -> Self {
        Self {
            applier: Arc::new(applier),
            message_store,
            data_store,
            state_index,
        }
    }

    pub fn from_arc(applier: Arc<D>, message_store: MS, data_store: DS, state_index: SI) -> Self {
        Self {
            applier,
            message_store,
            data_store,
            state_index,
        }
    }
}

impl<D, MS, DS, SI> SyncEndpoint for DirectSyncEndpoint<D, MS, DS, SI>
where
    D: DwnProcessMessage + Send + Sync + 'static,
    MS: MessageStore + Clone + Send + Sync + 'static,
    DS: DataStore + Clone + Send + Sync + 'static,
    SI: StateIndex + Clone + Send + Sync + 'static,
{
    fn root<'a>(&'a self, tenant: &'a str, scope: &'a SyncScope) -> SyncFuture<'a, String> {
        let state_index = self.state_index.clone();
        let scope = scope.clone();
        Box::pin(async move {
            let root = match scope.protocol_uri() {
                Some(protocol) => state_index.get_protocol_root(tenant, protocol).await,
                None => state_index.get_root(tenant).await,
            }
            .map_err(|err| SyncError::transient("StateIndexRootFailed", err.to_string()))?;
            Ok(state_hash_hex(&root))
        })
    }

    fn subtree_hashes<'a>(
        &'a self,
        tenant: &'a str,
        scope: &'a SyncScope,
        depth: u8,
    ) -> SyncFuture<'a, SyncHashes> {
        let state_index = self.state_index.clone();
        let scope = scope.clone();
        Box::pin(async move {
            collect_subtree_hashes(&state_index, tenant, scope.protocol_uri(), depth)
                .await
                .map_err(|detail| SyncError::transient("SubtreeHashCollectionFailed", detail))
        })
    }

    fn diff<'a>(
        &'a self,
        tenant: &'a str,
        scope: &'a SyncScope,
        depth: u8,
        hashes: SyncHashes,
    ) -> SyncFuture<'a, MessagesSyncDiff> {
        let message_store = self.message_store.clone();
        let data_store = self.data_store.clone();
        let state_index = self.state_index.clone();
        let scope = scope.clone();
        Box::pin(async move {
            compute_diff(
                &state_index,
                &message_store,
                &data_store,
                tenant,
                scope.protocol_uri(),
                depth,
                hashes,
            )
            .await
            .map_err(|detail| SyncError::transient("MessagesSyncDiffFailed", detail))
        })
    }

    fn apply<'a>(&'a self, tenant: &'a str, entry: SyncMessageEntry) -> SyncFuture<'a, ()> {
        let applier = self.applier.clone();
        let tenant = tenant.to_string();
        Box::pin(async move {
            let reply = if let Some(encoded_data) = entry.encoded_data.as_deref() {
                let data = URL_SAFE_NO_PAD
                    .decode(encoded_data)
                    .map_err(|err| SyncError::permanent("SyncApplyInvalidData", err.to_string()))?;
                applier
                    .process_message_with_data(
                        &tenant,
                        entry.message.clone(),
                        Some(bytes::Bytes::from(data)),
                    )
                    .await
            } else {
                applier
                    .process_message(&tenant, entry.message.clone())
                    .await
            };
            if is_sync_apply_success(reply.status.code, &entry.message) {
                Ok(())
            } else {
                Err(map_apply_error(reply))
            }
        })
    }
}

/// Remote sync endpoint that speaks `@enbox/dwn-server` JSON-RPC over HTTP.
#[derive(Clone)]
pub struct HttpSyncEndpoint<A> {
    url: String,
    client: reqwest::Client,
    authorizer: A,
}

impl<A> HttpSyncEndpoint<A>
where
    A: SyncRequestAuthorizer,
{
    pub fn new(url: impl Into<String>, authorizer: A) -> SyncResult<Self> {
        let client = reqwest::Client::builder()
            .user_agent(format!("enbox-sync-endpoint/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| SyncError::permanent("HttpClientBuildFailed", err.to_string()))?;
        Ok(Self {
            url: url.into(),
            client,
            authorizer,
        })
    }

    pub fn with_client(url: impl Into<String>, client: reqwest::Client, authorizer: A) -> Self {
        Self {
            url: url.into(),
            client,
            authorizer,
        }
    }

    async fn process_message(&self, tenant: &str, message: JsonValue) -> SyncResult<DwnReply> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": ulid::Ulid::new().to_string(),
            "method": PROCESS_MESSAGE_METHOD,
            "params": {
                "target": tenant,
                "message": message,
            }
        });
        let response = self
            .client
            .post(&self.url)
            .header("dwn-request", request.to_string())
            .send()
            .await
            .map_err(|err| SyncError::transient("HttpTransportFailed", err.to_string()))?;
        if !response.status().is_success() {
            return Err(SyncError::transient(
                "HttpTransportFailed",
                format!("remote server returned HTTP {}", response.status()),
            ));
        }

        let payload = if let Some(header) = response.headers().get("dwn-response") {
            header
                .to_str()
                .map_err(|err| SyncError::permanent("HttpResponseInvalid", err.to_string()))?
                .to_string()
        } else {
            response
                .text()
                .await
                .map_err(|err| SyncError::transient("HttpTransportFailed", err.to_string()))?
        };
        let envelope: JsonValue = serde_json::from_str(&payload)
            .map_err(|err| SyncError::permanent("HttpResponseInvalid", err.to_string()))?;
        if let Some(error) = envelope.get("error") {
            return Err(SyncError::transient("JsonRpcError", error.to_string()));
        }
        let reply = envelope.pointer("/result/reply").cloned().ok_or_else(|| {
            SyncError::permanent("HttpResponseInvalid", "missing result.reply".to_string())
        })?;
        parse_http_dwn_reply(reply)
    }

    async fn sync_action(
        &self,
        tenant: &str,
        scope: &SyncScope,
        action: SyncAction,
        prefix: Option<&str>,
        depth: Option<u8>,
        hashes: Option<SyncHashes>,
    ) -> SyncResult<DwnReply> {
        let message = self
            .authorizer
            .authorize_sync(tenant, scope, action, prefix, depth, hashes)
            .await?;
        self.process_message(tenant, message).await
    }
}

impl<A> SyncEndpoint for HttpSyncEndpoint<A>
where
    A: SyncRequestAuthorizer,
{
    fn root<'a>(&'a self, tenant: &'a str, scope: &'a SyncScope) -> SyncFuture<'a, String> {
        let this = self.clone();
        let scope = scope.clone();
        Box::pin(async move {
            let reply = this
                .sync_action(tenant, &scope, SyncAction::Root, None, None, None)
                .await?;
            reply_root(reply)
        })
    }

    fn subtree_hashes<'a>(
        &'a self,
        tenant: &'a str,
        scope: &'a SyncScope,
        depth: u8,
    ) -> SyncFuture<'a, SyncHashes> {
        let this = self.clone();
        let scope = scope.clone();
        Box::pin(async move { collect_subtree_hashes_via_http(&this, tenant, &scope, depth).await })
    }

    fn diff<'a>(
        &'a self,
        tenant: &'a str,
        scope: &'a SyncScope,
        depth: u8,
        hashes: SyncHashes,
    ) -> SyncFuture<'a, MessagesSyncDiff> {
        let this = self.clone();
        let scope = scope.clone();
        Box::pin(async move {
            let reply = this
                .sync_action(
                    tenant,
                    &scope,
                    SyncAction::Diff,
                    None,
                    Some(depth),
                    Some(hashes),
                )
                .await?;
            MessagesSyncDiff::from_reply(reply)
        })
    }

    fn apply<'a>(&'a self, tenant: &'a str, entry: SyncMessageEntry) -> SyncFuture<'a, ()> {
        let this = self.clone();
        let tenant = tenant.to_string();
        Box::pin(async move {
            let reply = this.process_message(&tenant, entry.message.clone()).await?;
            if is_sync_apply_success(reply.status.code, &entry.message) {
                Ok(())
            } else {
                Err(map_apply_error(reply))
            }
        })
    }
}

async fn collect_subtree_hashes_via_http<A: SyncRequestAuthorizer>(
    endpoint: &HttpSyncEndpoint<A>,
    tenant: &str,
    scope: &SyncScope,
    depth: u8,
) -> SyncResult<SyncHashes> {
    if usize::from(depth) > MAX_SYNC_DEPTH {
        return Err(SyncError::permanent(
            "MessagesSyncInvalidDepth",
            format!("depth must be <= {MAX_SYNC_DEPTH}, got {depth}"),
        ));
    }
    let default_hash_hex = default_hash_hex(usize::from(depth))
        .map_err(|detail| SyncError::permanent("MessagesSyncInvalidDepth", detail))?;
    let mut hashes = BTreeMap::new();
    let mut stack = vec![String::new()];
    while let Some(prefix) = stack.pop() {
        let reply = endpoint
            .sync_action(
                tenant,
                scope,
                SyncAction::Subtree,
                Some(prefix.as_str()),
                None,
                None,
            )
            .await?;
        let hash = reply_root(reply)?;
        if hash == default_hash_hex {
            continue;
        }
        if prefix.len() >= usize::from(depth) {
            hashes.insert(prefix, hash);
            continue;
        }
        stack.push(format!("{prefix}1"));
        stack.push(format!("{prefix}0"));
    }
    Ok(hashes)
}

fn parse_http_dwn_reply(reply: JsonValue) -> SyncResult<DwnReply> {
    if reply.get("body").is_some() {
        let status: Status =
            serde_json::from_value(reply.get("status").cloned().unwrap_or(JsonValue::Null))
                .map_err(|err| SyncError::permanent("HttpResponseInvalid", err.to_string()))?;
        let mut body = BTreeMap::new();
        if let Some(object) = reply.get("body").and_then(JsonValue::as_object) {
            for (key, value) in object {
                body.insert(key.clone(), value.clone());
            }
        }
        return Ok(DwnReply { status, body });
    }
    serde_json::from_value(reply)
        .map_err(|err| SyncError::permanent("HttpResponseInvalid", err.to_string()))
}

fn reply_root(reply: DwnReply) -> SyncResult<String> {
    if !(200..300).contains(&reply.status.code) {
        return Err(SyncError::transient(
            "MessagesSyncFailed",
            reply.status.detail,
        ));
    }
    reply
        .body
        .get("root")
        .or_else(|| reply.body.get("hash"))
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            SyncError::permanent(
                "MessagesSyncReplyInvalid",
                "missing root/hash in MessagesSync reply".to_string(),
            )
        })
}

fn map_apply_error(reply: DwnReply) -> SyncError {
    let retryable = reply.status.code >= 500;
    SyncError::new(
        "SyncApplyFailed",
        format!("{}: {}", reply.status.code, reply.status.detail),
        retryable,
    )
}

async fn collect_subtree_hashes<SI: StateIndex + Clone>(
    state_index: &SI,
    tenant: &str,
    protocol: Option<&str>,
    depth: u8,
) -> Result<SyncHashes, String> {
    if usize::from(depth) > MAX_SYNC_DEPTH {
        return Err(format!(
            "MessagesSyncInvalidDepth: depth must be <= {MAX_SYNC_DEPTH}, got {depth}"
        ));
    }
    let mut hashes = BTreeMap::new();
    let mut stack = vec![String::new()];
    while let Some(prefix) = stack.pop() {
        let bits = parse_bit_prefix(&prefix)?;
        let hash = subtree_hash(state_index, tenant, protocol, &bits)
            .await
            .map_err(|err| err.to_string())?;
        if hash == empty_subtree_hash(bits.len())? {
            continue;
        }
        if prefix.len() >= usize::from(depth) {
            hashes.insert(prefix, state_hash_hex(&hash));
            continue;
        }
        stack.push(format!("{prefix}1"));
        stack.push(format!("{prefix}0"));
    }
    Ok(hashes)
}

async fn compute_diff<MS, DS, SI>(
    state_index: &SI,
    message_store: &MS,
    data_store: &DS,
    tenant: &str,
    protocol: Option<&str>,
    depth: u8,
    client_hashes: SyncHashes,
) -> Result<MessagesSyncDiff, String>
where
    MS: MessageStore + Clone,
    DS: DataStore + Clone,
    SI: StateIndex + Clone,
{
    let depth = usize::from(depth);
    let default_empty_hash = default_hash_hex(depth)?;
    let server_hashes = collect_subtree_hashes(state_index, tenant, protocol, depth as u8).await?;
    let mut all_prefixes = BTreeSet::new();
    for (prefix, hash) in &client_hashes {
        if hash != &default_empty_hash {
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
        let bit_prefix = parse_bit_prefix(&prefix)?;
        only_remote_cids.extend(
            leaves(state_index, tenant, protocol, &bit_prefix)
                .await
                .map_err(|err| err.to_string())?,
        );
        if client_hash.is_some() {
            only_local.push(prefix);
        }
    }

    let mut only_remote = Vec::new();
    for message_cid in only_remote_cids {
        only_remote.push(build_diff_entry(message_store, data_store, tenant, &message_cid).await?);
    }
    Ok(MessagesSyncDiff {
        only_remote,
        only_local,
    })
}

async fn subtree_hash<SI: StateIndex>(
    state_index: &SI,
    tenant: &str,
    protocol: Option<&str>,
    prefix: &[bool],
) -> Result<StateHash, crate::errors::StoreError> {
    match protocol {
        Some(protocol) => {
            state_index
                .get_protocol_subtree_hash(tenant, protocol, prefix)
                .await
        }
        None => state_index.get_subtree_hash(tenant, prefix).await,
    }
}

async fn leaves<SI: StateIndex>(
    state_index: &SI,
    tenant: &str,
    protocol: Option<&str>,
    prefix: &[bool],
) -> Result<Vec<String>, crate::errors::StoreError> {
    match protocol {
        Some(protocol) => {
            state_index
                .get_protocol_leaves(tenant, protocol, prefix)
                .await
        }
        None => state_index.get_leaves(tenant, prefix).await,
    }
}

async fn build_diff_entry<MS, DS>(
    message_store: &MS,
    data_store: &DS,
    tenant: &str,
    message_cid: &str,
) -> Result<SyncMessageEntry, String>
where
    MS: MessageStore + Clone,
    DS: DataStore + Clone,
{
    let Some(message) = message_store
        .get(tenant, message_cid)
        .await
        .map_err(|err| err.to_string())?
    else {
        return Err(format!("missing message for cid {message_cid}"));
    };
    let mut message_json = serde_json::to_value(&message).map_err(|err| err.to_string())?;
    let inline_data = strip_encoded_data(&mut message_json);
    let encoded_data = match inline_data {
        Some(encoded_data) => Some(encoded_data),
        None => external_inline_data(data_store, tenant, &message).await?,
    };
    Ok(SyncMessageEntry {
        message_cid: message_cid.to_string(),
        message: message_json,
        encoded_data,
    })
}

async fn external_inline_data<DS: DataStore>(
    data_store: &DS,
    tenant: &str,
    message: &crate::Message<crate::Descriptor>,
) -> Result<Option<String>, String> {
    use crate::interfaces::messages::descriptors::general::Records as RecordsDescriptor;
    use crate::Descriptor;
    use crate::Fields;

    const MAX_INLINE_DATA_SIZE: u64 = 102_400;
    let descriptor = match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            RecordsDescriptor::Write(descriptor) => descriptor,
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };
    let record_id = match &message.fields {
        Fields::Write(fields) => fields.record_id.clone(),
        Fields::InitialWriteField(fields) => fields.write_fields.record_id.clone(),
        _ => None,
    };
    let Some(record_id) = record_id else {
        return Ok(None);
    };
    if descriptor.data_size > MAX_INLINE_DATA_SIZE {
        return Ok(None);
    }
    let Some(data) = data_store
        .get(tenant, &record_id, &descriptor.data_cid)
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

fn strip_encoded_data(message: &mut JsonValue) -> Option<String> {
    message
        .as_object_mut()?
        .remove("encodedData")?
        .as_str()
        .map(str::to_string)
}

fn parse_bit_prefix(prefix: &str) -> Result<Vec<bool>, String> {
    if prefix.len() > MAX_SYNC_DEPTH {
        return Err(format!(
            "MessagesSyncInvalidPrefix: length must be <= {MAX_SYNC_DEPTH}, got {}",
            prefix.len()
        ));
    }
    prefix
        .bytes()
        .map(|byte| match byte {
            b'0' => Ok(false),
            b'1' => Ok(true),
            _ => Err(format!(
                "MessagesSyncInvalidPrefix: must contain only '0' and '1' characters, got: {prefix}"
            )),
        })
        .collect()
}

fn empty_subtree_hash(depth: usize) -> Result<StateHash, String> {
    if depth > MAX_SYNC_DEPTH {
        return Err(format!(
            "MessagesSyncInvalidDepth: depth must be <= {MAX_SYNC_DEPTH}, got {depth}"
        ));
    }
    Ok(default_hashes()[depth])
}

fn default_hash_hex(depth: usize) -> Result<String, String> {
    empty_subtree_hash(depth).map(|hash| state_hash_hex(&hash))
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

/// Signs MessagesSync requests using a local JWK signer and optional grant id.
#[derive(Clone)]
pub struct JwsSyncAuthorizer {
    signer: crate::auth::PrivateJwkSigner,
    permission_grant_id: Option<String>,
}

impl JwsSyncAuthorizer {
    pub fn new(signer: crate::auth::PrivateJwkSigner) -> Self {
        Self {
            signer,
            permission_grant_id: None,
        }
    }

    pub fn with_permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    fn timestamp() -> DateTime<Utc> {
        Utc::now()
    }
}

impl SyncRequestAuthorizer for JwsSyncAuthorizer {
    fn authorize_sync<'a>(
        &'a self,
        _tenant: &'a str,
        scope: &'a SyncScope,
        action: SyncAction,
        prefix: Option<&'a str>,
        depth: Option<u8>,
        hashes: Option<SyncHashes>,
    ) -> SyncFuture<'a, JsonValue> {
        let signer = self.signer.clone();
        let permission_grant_id = self.permission_grant_id.clone();
        let scope = scope.clone();
        Box::pin(async move {
            let descriptor = build_messages_sync_descriptor(
                action,
                scope.protocol_uri(),
                prefix,
                permission_grant_id.as_deref(),
                depth,
                hashes.as_ref(),
                canonical_rfc3339(Self::timestamp()).as_str(),
            )?;
            sign_descriptor_message(&signer, descriptor, permission_grant_id.as_deref())
        })
    }
}

fn build_messages_sync_descriptor(
    action: SyncAction,
    protocol: Option<&str>,
    prefix: Option<&str>,
    permission_grant_id: Option<&str>,
    depth: Option<u8>,
    hashes: Option<&SyncHashes>,
    message_timestamp: &str,
) -> SyncResult<JsonValue> {
    let mut descriptor = serde_json::Map::new();
    descriptor.insert("interface".into(), JsonValue::String("Messages".into()));
    descriptor.insert("method".into(), JsonValue::String("Sync".into()));
    descriptor.insert(
        "messageTimestamp".into(),
        JsonValue::String(message_timestamp.to_string()),
    );
    descriptor.insert(
        "action".into(),
        serde_json::to_value(action)
            .map_err(|err| SyncError::permanent("SyncMessageBuildFailed", err.to_string()))?,
    );
    if let Some(protocol) = protocol {
        descriptor.insert("protocol".into(), JsonValue::String(protocol.to_string()));
    }
    if let Some(prefix) = prefix {
        descriptor.insert("prefix".into(), JsonValue::String(prefix.to_string()));
    }
    if let Some(permission_grant_id) = permission_grant_id {
        descriptor.insert(
            "permissionGrantId".into(),
            JsonValue::String(permission_grant_id.to_string()),
        );
    }
    if let Some(depth) = depth {
        descriptor.insert("depth".into(), JsonValue::from(depth));
    }
    if let Some(hashes) = hashes {
        descriptor.insert(
            "hashes".into(),
            serde_json::to_value(hashes)
                .map_err(|err| SyncError::permanent("SyncMessageBuildFailed", err.to_string()))?,
        );
    }
    Ok(JsonValue::Object(descriptor))
}

fn sign_descriptor_message(
    signer: &crate::auth::PrivateJwkSigner,
    descriptor: JsonValue,
    permission_grant_id: Option<&str>,
) -> SyncResult<JsonValue> {
    use crate::auth::Jws;
    use crate::cid::generate_cid_from_json;

    let mut payload = json!({
        "descriptorCid": generate_cid_from_json(&descriptor)
            .map_err(|err| SyncError::permanent("SyncMessageBuildFailed", err.to_string()))?
            .to_string(),
    });
    if let Some(permission_grant_id) = permission_grant_id {
        payload["permissionGrantId"] = JsonValue::String(permission_grant_id.to_string());
    }
    let signature = Jws::create_general(
        serde_json::to_vec(&payload)
            .map_err(|err| SyncError::permanent("SyncMessageBuildFailed", err.to_string()))?
            .as_slice(),
        std::slice::from_ref(signer),
    )
    .map_err(|err| SyncError::permanent("SyncMessageBuildFailed", err.to_string()))?;
    Ok(json!({
        "descriptor": descriptor,
        "authorization": { "signature": signature },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_success_matches_typescript_semantics() {
        let write = json!({ "descriptor": { "method": "Write" } });
        assert!(is_sync_apply_success(202, &write));
        assert!(is_sync_apply_success(409, &write));
        let delete = json!({ "descriptor": { "method": "Delete" } });
        assert!(is_sync_apply_success(404, &delete));
        assert!(!is_sync_apply_success(404, &write));
    }
}
