//! Production [`SyncEndpoint`] implementations for local
//! stores and remote `@enbox/dwn-server` peers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};

use crate::auth::Authorization;
use crate::descriptors::messages::SyncParameters;
use crate::descriptors::{
    records::strip_encoded_data, Descriptor, MessagesSyncDescriptor, Records,
};
use crate::descriptors::{MessageDescriptor, DELETE};
use crate::errors::DwnErrorCode;
use crate::interfaces::messages::descriptors::messages::SyncAction;
use crate::replies::messages::{self};
use crate::replies::Status;
use crate::runtime::desktop::server::{DwnProcessMessage, PROCESS_MESSAGE_METHOD};
use crate::stores::{DataStore, MessageStore, StateHash, StateIndex};
use crate::sync::{
    MessagesSyncDiff, SyncEndpoint, SyncError, SyncFuture, SyncHashes, SyncMessageEntry,
    SyncResult, SyncScope,
};
use crate::{Message, Response};

const MAX_SYNC_DEPTH: usize = 16;

static DEFAULT_HASHES: OnceLock<Vec<StateHash>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationApplyOutcome {
    Applied,
    Duplicate,
    Superseded,
    Incomplete,
    Invalid,
    Deferred,
}

pub fn classify_apply_reply(
    status: &Status,
    message: &Message<Descriptor>,
    already_stored: bool,
) -> ReplicationApplyOutcome {
    // A pre-existing CID only refines the handler's ordinary conflict response.
    // It must never turn a fresh validation or authorization failure into a duplicate.
    if already_stored && status.code == 409 {
        return ReplicationApplyOutcome::Duplicate;
    }
    match status.code {
        200 | 202 | 204 => ReplicationApplyOutcome::Applied,
        409 => ReplicationApplyOutcome::Superseded,
        404 if message.descriptor.method() == DELETE => ReplicationApplyOutcome::Incomplete,
        code if code >= 500 => ReplicationApplyOutcome::Deferred,
        _ => match status
            .error_code
            .as_deref()
            .and_then(|code| DwnErrorCode::try_from(code).ok())
        {
            Some(DwnErrorCode::GeneralJwsVerifierGetPublicKeyNotFound) => {
                ReplicationApplyOutcome::Deferred
            }
            Some(DwnErrorCode::RecordsWriteNotAllowedAfterDelete) => {
                ReplicationApplyOutcome::Superseded
            }
            Some(code) if code.is_missing_dependency() => ReplicationApplyOutcome::Incomplete,
            _ => ReplicationApplyOutcome::Invalid,
        },
    }
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
    ) -> SyncFuture<'a, Message<MessagesSyncDescriptor>>;
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
        let message_store = self.message_store.clone();
        let tenant = tenant.to_string();
        Box::pin(async move {
            let actual_cid = entry.message.cid().map_err(|error| {
                SyncError::permanent("SyncApplyMessageCidFailed", error.to_string())
            })?;
            if actual_cid.to_string() != entry.message_cid {
                return Err(SyncError::permanent(
                    "SyncApplyMessageCidMismatch",
                    format!(
                        "entry messageCid '{}' does not match message CID '{actual_cid}'",
                        entry.message_cid
                    ),
                ));
            }
            let already_stored = message_store
                .get(&tenant, &actual_cid.to_string())
                .await
                .map_err(|error| {
                    SyncError::transient("SyncApplyStoreReadFailed", error.to_string())
                })?
                .is_some();
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
            match classify_apply_reply(&reply.status, &entry.message, already_stored) {
                ReplicationApplyOutcome::Applied
                | ReplicationApplyOutcome::Duplicate
                | ReplicationApplyOutcome::Superseded => Ok(()),
                outcome => Err(map_apply_error(reply.status, outcome)),
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

#[derive(Serialize)]
struct MessageSyncWire<'a> {
    descriptor: &'a MessagesSyncDescriptor,
    authorization: &'a Authorization,
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

    async fn send_process_message<M>(&self, tenant: &str, message: &M) -> SyncResult<JsonValue>
    where
        M: Serialize,
    {
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
        Ok(reply)
    }

    async fn process_sync_message(
        &self,
        tenant: &str,
        message: Message<MessagesSyncDescriptor>,
    ) -> SyncResult<Response<messages::Sync>> {
        let wire_message = MessageSyncWire {
            descriptor: &message.descriptor,
            authorization: &message.fields,
        };
        parse_http_messages_sync_reply(self.send_process_message(tenant, &wire_message).await?)
    }

    async fn process_apply_message(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
    ) -> SyncResult<Status> {
        parse_http_reply_status(self.send_process_message(tenant, message).await?)
    }

    async fn sync_action(
        &self,
        tenant: &str,
        scope: &SyncScope,
        action: SyncAction,
        prefix: Option<&str>,
        depth: Option<u8>,
        hashes: Option<SyncHashes>,
    ) -> SyncResult<Response<messages::Sync>> {
        let message = self
            .authorizer
            .authorize_sync(tenant, scope, action, prefix, depth, hashes)
            .await?;

        self.process_sync_message(tenant, message).await
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
            let status = this.process_apply_message(&tenant, &entry.message).await?;
            match classify_apply_reply(&status, &entry.message, false) {
                ReplicationApplyOutcome::Applied
                | ReplicationApplyOutcome::Duplicate
                | ReplicationApplyOutcome::Superseded => Ok(()),
                outcome => Err(map_apply_error(status, outcome)),
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

fn parse_http_messages_sync_reply(reply: JsonValue) -> SyncResult<Response<messages::Sync>> {
    let status = parse_http_reply_status(reply.clone())?;
    let body = reply.get("body").cloned().unwrap_or(reply);
    let sync = if body.is_null() {
        messages::Sync::default()
    } else {
        serde_json::from_value(body)
            .map_err(|err| SyncError::permanent("MessagesSyncReplyInvalid", err.to_string()))?
    };
    Ok(Response::new(status, sync))
}

fn parse_http_reply_status(reply: JsonValue) -> SyncResult<Status> {
    serde_json::from_value(reply.get("status").cloned().ok_or_else(|| {
        SyncError::permanent("HttpResponseInvalid", "missing reply status".to_string())
    })?)
    .map_err(|err| SyncError::permanent("HttpResponseInvalid", err.to_string()))
}

fn reply_root(resp: Response<messages::Sync>) -> SyncResult<String> {
    if !(200..300).contains(&resp.status.code) {
        return Err(SyncError::transient(
            "MessagesSyncFailed",
            resp.status.detail,
        ));
    }

    resp.reply.root.or(resp.reply.hash).ok_or_else(|| {
        SyncError::permanent(
            "MessagesSyncReplyInvalid",
            "missing root/hash in MessagesSync reply".to_string(),
        )
    })
}

fn map_apply_error(status: Status, outcome: ReplicationApplyOutcome) -> SyncError {
    let retryable = matches!(
        outcome,
        ReplicationApplyOutcome::Incomplete | ReplicationApplyOutcome::Deferred
    );
    SyncError::new(
        status.error_code.as_deref().unwrap_or("SyncApplyFailed"),
        format!("{}: {}", status.code, status.detail),
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
    let Some(mut message) = message_store
        .get(tenant, message_cid)
        .await
        .map_err(|err| err.to_string())?
    else {
        return Err(format!("missing message for cid {message_cid}"));
    };
    let inline_data = if matches!(
        &message.descriptor,
        Descriptor::Records(records) if matches!(records.as_ref(), Records::Write(_))
    ) {
        strip_encoded_data(&mut message).map_err(|error| error.to_string())?
    } else {
        None
    };
    let encoded_data = match inline_data {
        Some(encoded_data) => Some(encoded_data),
        None => external_inline_data(data_store, tenant, &message).await?,
    };
    Ok(SyncMessageEntry {
        message_cid: message_cid.to_string(),
        message,
        encoded_data,
    })
}

async fn external_inline_data<DS: DataStore>(
    data_store: &DS,
    tenant: &str,
    message: &crate::Message<crate::Descriptor>,
) -> Result<Option<String>, String> {
    use crate::interfaces::messages::descriptors::Records as RecordsDescriptor;
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
    ) -> SyncFuture<'a, Message<MessagesSyncDescriptor>> {
        let signer = self.signer.clone();
        let permission_grant_id = self.permission_grant_id.clone();
        let scope = scope.clone();
        Box::pin(async move {
            let parameters = SyncParameters {
                message_timestamp: Self::timestamp(),
                action,
                protocol: scope.protocol_uri().map(|s| s.to_string()),
                prefix: prefix.map(|s| s.to_string()),
                permission_grant_ids: permission_grant_id.map(|s| vec![s]),
                hashes,
                depth: depth.map(|d| d as u16),
            };

            let message = Message::<MessagesSyncDescriptor>::create(parameters, Some(signer))
                .await
                .map_err(|err| SyncError::permanent("SyncRequestSigningFailed", err.to_string()));

            message
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::Fields;

    use super::*;
    use crate::errors::DwnError;

    #[test]
    fn apply_reply_classification_preserves_semantic_outcomes() {
        // Covers: DWN-SYNC-002, DWN-AUTH-006
        let write = Message::new(
            Descriptor::Records(Box::new(Records::Write(Default::default()))),
            Fields::Write(Default::default()),
        )
        .unwrap();
        assert_eq!(
            classify_apply_reply(&Status::new(202, "Accepted"), &write, false),
            ReplicationApplyOutcome::Applied
        );
        assert_eq!(
            classify_apply_reply(&Status::new(409, "Conflict"), &write, false),
            ReplicationApplyOutcome::Superseded
        );
        assert_eq!(
            classify_apply_reply(&Status::new(409, "Conflict"), &write, true),
            ReplicationApplyOutcome::Duplicate
        );
        assert_eq!(
            classify_apply_reply(&Status::new(401, "Unauthorized"), &write, true),
            ReplicationApplyOutcome::Invalid
        );

        let delete = Message::new(
            Descriptor::Records(Box::new(Records::Delete(Default::default()))),
            Fields::default(),
        )
        .unwrap();
        assert_eq!(
            classify_apply_reply(&Status::new(404, "Not Found"), &delete, false),
            ReplicationApplyOutcome::Incomplete
        );
        assert_eq!(
            classify_apply_reply(&Status::new(404, "Not Found"), &write, false),
            ReplicationApplyOutcome::Invalid
        );
    }

    #[test]
    fn apply_reply_classification_uses_structured_error_code() {
        // Covers: DWN-SYNC-002
        let write = Message::new(
            Descriptor::Records(Box::new(Records::Write(Default::default()))),
            Fields::Write(Default::default()),
        )
        .unwrap();
        let missing = Status::from_error(
            400,
            DwnError::new(
                DwnErrorCode::RecordsWriteGetInitialWriteNotFound,
                "Initial write is not found.",
            ),
        );
        assert_eq!(
            classify_apply_reply(&missing, &write, false),
            ReplicationApplyOutcome::Incomplete
        );
        let error = map_apply_error(missing, ReplicationApplyOutcome::Incomplete);
        assert_eq!(error.code, "RecordsWriteGetInitialWriteNotFound");
        assert!(error.retryable);

        let terminal_write = Status::from_error(
            400,
            DwnError::new(
                DwnErrorCode::RecordsWriteNotAllowedAfterDelete,
                "RecordsWrite is not allowed after a RecordsDelete.",
            ),
        );
        assert_eq!(
            classify_apply_reply(&terminal_write, &write, false),
            ReplicationApplyOutcome::Superseded
        );

        let immutable_permission = Status::from_error(
            400,
            DwnError::new(
                DwnErrorCode::ProtocolAuthorizationImmutableRecord,
                "permission records cannot be updated",
            ),
        );
        assert_eq!(
            classify_apply_reply(&immutable_permission, &write, false),
            ReplicationApplyOutcome::Invalid
        );
        let error = map_apply_error(immutable_permission, ReplicationApplyOutcome::Invalid);
        assert_eq!(error.code, "ProtocolAuthorizationImmutableRecord");
        assert!(!error.retryable);
    }
}
