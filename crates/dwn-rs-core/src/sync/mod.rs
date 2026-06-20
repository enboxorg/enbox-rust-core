pub mod endpoint;
pub mod ledger;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::sync::RwLock;
use ulid::Ulid;

use crate::dwn::DwnReply;
use crate::events::MessageEvent;
use crate::stores::{ProgressToken, SubscriptionMessage};
use crate::sync::ledger::{MemorySyncLedger, SyncLedger};
use crate::Descriptor;

pub type SyncResult<T> = Result<T, SyncError>;
pub type SyncFuture<'a, T> = Pin<Box<dyn Future<Output = SyncResult<T>> + Send + 'a>>;
pub type SyncHashes = BTreeMap<String, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncError {
    pub code: String,
    pub detail: String,
    pub retryable: bool,
}

impl SyncError {
    pub fn new(code: impl Into<String>, detail: impl Into<String>, retryable: bool) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
            retryable,
        }
    }

    pub fn permanent(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(code, detail, false)
    }

    pub fn transient(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(code, detail, true)
    }

    pub fn progress_gap(detail: impl Into<String>) -> Self {
        Self::transient("ProgressGap", detail)
    }

    pub fn lock_poisoned<E: Display>(err: E) -> Self {
        Self::transient(
            "SyncLockPoisoned",
            format!("sync engine lock poisoned: {err}"),
        )
    }
}

impl Display for SyncError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for SyncError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncDirection {
    Pull,
    Push,
    Bidirectional,
}

impl SyncDirection {
    fn includes_pull(self) -> bool {
        matches!(self, Self::Pull | Self::Bidirectional)
    }

    fn includes_push(self) -> bool {
        matches!(self, Self::Push | Self::Bidirectional)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncMode {
    Poll,
    Live,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum SyncScope {
    Full,
    Protocol { protocol: String },
}

impl SyncScope {
    pub fn protocol(protocol: impl Into<String>) -> Self {
        Self::Protocol {
            protocol: protocol.into(),
        }
    }

    pub fn protocol_uri(&self) -> Option<&str> {
        match self {
            Self::Full => None,
            Self::Protocol { protocol } => Some(protocol),
        }
    }

    pub fn id(&self) -> String {
        match self {
            Self::Full => "global".to_string(),
            Self::Protocol { protocol } => format!("protocol:{protocol}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "values")]
pub enum SyncProtocols {
    All,
    Protocols(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncIdentityOptions {
    pub did: String,
    pub protocols: SyncProtocols,
    pub delegate_did: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncConnectivity {
    pub online: bool,
    pub expensive: bool,
    pub roaming: bool,
    pub background_restricted: bool,
    pub power_save: bool,
    pub allow_metered: bool,
    pub allow_roaming: bool,
    pub preferred_max_bytes: Option<u64>,
}

impl Default for SyncConnectivity {
    fn default() -> Self {
        Self {
            online: true,
            expensive: false,
            roaming: false,
            background_restricted: false,
            power_save: false,
            allow_metered: true,
            allow_roaming: false,
            preferred_max_bytes: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncOnceRequest {
    pub tenant: String,
    pub remote: String,
    pub direction: SyncDirection,
    pub protocol: Option<String>,
    pub max_records: Option<usize>,
    pub max_bytes: Option<u64>,
    pub connectivity: SyncConnectivity,
    pub reason: Option<String>,
}

impl SyncOnceRequest {
    pub fn new(
        tenant: impl Into<String>,
        remote: impl Into<String>,
        direction: SyncDirection,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            remote: remote.into(),
            direction,
            protocol: None,
            max_records: None,
            max_bytes: None,
            connectivity: SyncConnectivity::default(),
            reason: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartSyncParams {
    pub tenant: String,
    pub remote: String,
    pub mode: SyncMode,
    pub interval_ms: Option<u64>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusQuery {
    pub tenant: String,
    pub remote: Option<String>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncRunStatus {
    Completed,
    Partial,
    NoConnectivity,
    AlreadyRunning,
    Failed,
    Repairing,
    DegradedPoll,
    Started,
    Stopped,
    /// The native deadline elapsed before the run finished. Durable
    /// checkpoints (if any) remain in [`SyncOnceResult::checkpoints`] so
    /// the next call can resume.
    DeadlineExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncCheckpoint {
    pub key: String,
    pub tenant: String,
    pub remote: String,
    pub scope_id: String,
    pub direction: SyncDirection,
    pub local_root: Option<String>,
    pub remote_root: Option<String>,
    pub pending_pull_prefixes: Vec<String>,
    pub pending_push_prefixes: Vec<String>,
    pub pull_cursor: Option<ProgressToken>,
    pub push_cursor: Option<ProgressToken>,
    pub records_pulled: u64,
    pub records_pushed: u64,
    pub bytes_downloaded: u64,
    pub bytes_uploaded: u64,
    pub last_error: Option<SyncError>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncOnceResult {
    pub status: SyncRunStatus,
    pub checkpoints: Vec<SyncCheckpoint>,
    pub records_pulled: u64,
    pub records_pushed: u64,
    pub bytes_downloaded: u64,
    pub bytes_uploaded: u64,
    pub next_recommended_delay_ms: Option<u64>,
    pub error: Option<SyncError>,
}

impl SyncOnceResult {
    fn new(status: SyncRunStatus) -> Self {
        Self {
            status,
            checkpoints: Vec::new(),
            records_pulled: 0,
            records_pushed: 0,
            bytes_downloaded: 0,
            bytes_uploaded: 0,
            next_recommended_delay_ms: None,
            error: None,
        }
    }

    fn absorb(&mut self, other: SyncOnceResult) {
        self.records_pulled += other.records_pulled;
        self.records_pushed += other.records_pushed;
        self.bytes_downloaded += other.bytes_downloaded;
        self.bytes_uploaded += other.bytes_uploaded;
        self.checkpoints.extend(other.checkpoints);
        if other.status != SyncRunStatus::Completed {
            self.status = other.status;
        }
        if other.error.is_some() {
            self.error = other.error;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeadLetterCategory {
    PullApply,
    PushApply,
    Authorization,
    Permanent,
    Transient,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetterEntry {
    pub id: String,
    pub tenant: String,
    pub remote: String,
    pub scope_id: String,
    pub message_cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<SyncMessageEntry>,
    pub category: DeadLetterCategory,
    pub error: SyncError,
    pub attempts: u32,
    pub last_attempt_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncHealthSummary {
    pub tenant: String,
    pub remote: Option<String>,
    pub checkpoints: Vec<SyncCheckpoint>,
    pub dead_letters: Vec<DeadLetterEntry>,
    pub active_live_links: Vec<String>,
    pub last_status: Option<SyncRunStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncMessageEntry {
    #[serde(rename = "messageCid")]
    pub message_cid: String,
    pub message: JsonValue,
    #[serde(rename = "encodedData", skip_serializing_if = "Option::is_none")]
    pub encoded_data: Option<String>,
}

impl SyncMessageEntry {
    pub fn from_subscription_event(
        cursor: &ProgressToken,
        event: &MessageEvent<Descriptor>,
    ) -> Self {
        Self {
            message_cid: cursor.message_cid.clone(),
            message: serde_json::to_value(&event.message).unwrap_or(JsonValue::Null),
            encoded_data: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagesSyncDiff {
    pub only_remote: Vec<SyncMessageEntry>,
    pub only_local: Vec<String>,
}

impl MessagesSyncDiff {
    pub fn from_reply(reply: DwnReply) -> SyncResult<Self> {
        if !(200..300).contains(&reply.status.code) {
            return Err(SyncError::transient(
                "MessagesSyncFailed",
                reply.status.detail,
            ));
        }
        let only_remote = reply
            .body
            .get("onlyRemote")
            .cloned()
            .unwrap_or_else(|| JsonValue::Array(Vec::new()));
        let only_local = reply
            .body
            .get("onlyLocal")
            .cloned()
            .unwrap_or_else(|| JsonValue::Array(Vec::new()));
        Ok(Self {
            only_remote: serde_json::from_value(only_remote)
                .map_err(|err| SyncError::permanent("MessagesSyncReplyInvalid", err.to_string()))?,
            only_local: serde_json::from_value(only_local)
                .map_err(|err| SyncError::permanent("MessagesSyncReplyInvalid", err.to_string()))?,
        })
    }
}

pub trait SyncEndpoint: Clone + Send + Sync + 'static {
    fn root<'a>(&'a self, tenant: &'a str, scope: &'a SyncScope) -> SyncFuture<'a, String>;

    fn subtree_hashes<'a>(
        &'a self,
        tenant: &'a str,
        scope: &'a SyncScope,
        depth: u8,
    ) -> SyncFuture<'a, SyncHashes>;

    fn diff<'a>(
        &'a self,
        tenant: &'a str,
        scope: &'a SyncScope,
        depth: u8,
        hashes: SyncHashes,
    ) -> SyncFuture<'a, MessagesSyncDiff>;

    fn apply<'a>(&'a self, tenant: &'a str, entry: SyncMessageEntry) -> SyncFuture<'a, ()>;
}

#[derive(Clone)]
pub struct NativeSyncEngine<Local, Remote, L = MemorySyncLedger> {
    local: Local,
    remote: Remote,
    state: Arc<RwLock<SyncEngineState>>,
    ledger: L,
    diff_depth: u8,
}

#[derive(Debug, Default)]
struct SyncEngineState {
    identities: BTreeMap<String, SyncIdentityOptions>,
    checkpoints: BTreeMap<String, SyncCheckpoint>,
    running: BTreeSet<String>,
    live_links: BTreeSet<String>,
    dead_letters: Vec<DeadLetterEntry>,
    echo_cache: BTreeMap<String, DateTime<Utc>>,
    last_status: BTreeMap<String, SyncRunStatus>,
}

impl<Local, Remote, L> NativeSyncEngine<Local, Remote, L>
where
    Local: SyncEndpoint,
    Remote: SyncEndpoint,
    L: SyncLedger,
{
    pub fn new(local: Local, remote: Remote) -> Self
    where
        L: Default,
    {
        Self::with_ledger(local, remote, L::default())
    }

    pub async fn open(local: Local, remote: Remote, ledger: L) -> Result<Self, SyncError> {
        let engine = Self::with_ledger(local, remote, ledger);
        engine.restore().await?;
        Ok(engine)
    }

    pub fn with_ledger(local: Local, remote: Remote, ledger: L) -> Self {
        let engine_state = SyncEngineState::default();

        Self {
            local,
            remote,
            state: Arc::new(RwLock::new(engine_state)),
            ledger,
            diff_depth: 16,
        }
    }

    pub async fn restore(&self) -> Result<&Self, SyncError> {
        let mut engine_state = self.state.write().await;

        if let Ok(snapshot) = self.ledger.load().await {
            engine_state.checkpoints = snapshot.checkpoints;
            engine_state.dead_letters = snapshot.dead_letters;
            engine_state.echo_cache = snapshot.echo_cache;
            engine_state.last_status = snapshot.last_status;
        }

        Ok(self)
    }

    pub fn with_diff_depth(mut self, diff_depth: u8) -> Self {
        self.diff_depth = diff_depth;
        self
    }

    pub async fn register_identity(&self, options: SyncIdentityOptions) -> SyncResult<()> {
        validate_identity_options(&options)?;
        let mut state = self.state.write().await;
        if state.identities.contains_key(&options.did) {
            return Err(SyncError::permanent(
                "SyncIdentityAlreadyRegistered",
                format!("Identity with DID {} is already registered", options.did),
            ));
        }
        state.identities.insert(options.did.clone(), options);
        Ok(())
    }

    pub async fn update_identity(&self, options: SyncIdentityOptions) -> SyncResult<()> {
        validate_identity_options(&options)?;
        let mut state = self.state.write().await;
        if !state.identities.contains_key(&options.did) {
            return Err(SyncError::permanent(
                "SyncIdentityNotRegistered",
                format!("Identity with DID {} is not registered", options.did),
            ));
        }
        state.identities.insert(options.did.clone(), options);
        Ok(())
    }

    pub async fn unregister_identity(&self, did: &str) -> SyncResult<()> {
        let mut state = self.state.write().await;
        if state.identities.remove(did).is_none() {
            return Err(SyncError::permanent(
                "SyncIdentityNotRegistered",
                format!("Identity with DID {did} is not registered"),
            ));
        }
        Ok(())
    }

    pub async fn identity(&self, did: &str) -> Option<SyncIdentityOptions> {
        self.state.read().await.identities.get(did).cloned()
    }

    pub async fn sync_once(&self, request: SyncOnceRequest) -> SyncOnceResult {
        if let Some(error) = connectivity_error(&request.connectivity) {
            let mut result = SyncOnceResult::new(SyncRunStatus::NoConnectivity);
            result.error = Some(error);
            return result;
        }

        let operation_key = operation_key(&request.tenant, &request.remote, request.direction);
        if !self.begin_operation(&operation_key).await {
            return SyncOnceResult::new(SyncRunStatus::AlreadyRunning);
        }

        let result = self.sync_once_unlocked(request).await;
        self.end_operation(&operation_key, result.status.clone())
            .await;
        result
    }

    pub async fn start_sync(&self, params: StartSyncParams) -> SyncOnceResult {
        let link_key = live_link_key(&params.tenant, &params.remote, params.protocol.as_deref());
        self.state.write().await.live_links.insert(link_key);
        let mut request =
            SyncOnceRequest::new(params.tenant, params.remote, SyncDirection::Bidirectional);
        request.protocol = params.protocol;
        request.reason = Some(match params.mode {
            SyncMode::Poll => "poll_start".to_string(),
            SyncMode::Live => "live_start".to_string(),
        });
        let mut result = self.sync_once(request).await;
        if result.status == SyncRunStatus::Completed {
            result.status = SyncRunStatus::Started;
        }
        result
    }

    pub async fn stop_sync(&self, tenant: &str, remote: Option<&str>) -> SyncRunStatus {
        let mut state = self.state.write().await;
        state.live_links.retain(|link| {
            if let Some(remote) = remote {
                !link.starts_with(&format!("{tenant}|{remote}|"))
            } else {
                !link.starts_with(&format!("{tenant}|"))
            }
        });
        SyncRunStatus::Stopped
    }

    /// Poll-based SMT reconciliation (TS `SyncEngineLevel.sync()` in poll/degraded mode).
    pub async fn poll_reconcile(&self, mut request: SyncOnceRequest) -> SyncOnceResult {
        request.direction = SyncDirection::Pull;
        request.reason = Some("poll_reconcile".to_string());
        self.sync_once(request).await
    }

    /// Transition a live link to degraded poll after subscription loss (TS `enterDegradedPoll`).
    pub async fn enter_degraded_poll(
        &self,
        tenant: &str,
        remote: &str,
        protocol: Option<&str>,
    ) -> SyncOnceResult {
        let link_key = live_link_key(tenant, remote, protocol);
        let status_key = format!("{tenant}|{remote}");
        let mut state = self.state.write().await;
        state.live_links.remove(&link_key);
        state
            .last_status
            .insert(status_key.clone(), SyncRunStatus::DegradedPoll);
        drop(state);
        let _ = self
            .ledger
            .set_last_status(&status_key, SyncRunStatus::DegradedPoll)
            .await;
        let mut result = SyncOnceResult::new(SyncRunStatus::DegradedPoll);
        result.next_recommended_delay_ms = Some(DEGRADED_POLL_INTERVAL_MS);
        result
    }

    /// Close live subscriptions and run one poll reconciliation pass.
    pub async fn reconcile_after_live_disconnect(
        &self,
        request: SyncOnceRequest,
    ) -> SyncOnceResult {
        self.enter_degraded_poll(
            &request.tenant,
            &request.remote,
            request.protocol.as_deref(),
        )
        .await;
        self.poll_reconcile(request).await
    }

    pub async fn sync_status(&self, query: SyncStatusQuery) -> SyncHealthSummary {
        let state = self.state.read().await;
        let scope_filter = query.protocol.as_deref().map(|protocol| {
            SyncScope::Protocol {
                protocol: protocol.to_string(),
            }
            .id()
        });
        let checkpoints = state
            .checkpoints
            .values()
            .filter(|checkpoint| checkpoint.tenant == query.tenant)
            .filter(|checkpoint| {
                query
                    .remote
                    .as_ref()
                    .is_none_or(|remote| checkpoint.remote == *remote)
            })
            .filter(|checkpoint| {
                scope_filter
                    .as_ref()
                    .is_none_or(|scope| checkpoint.scope_id == *scope)
            })
            .cloned()
            .collect::<Vec<_>>();
        let dead_letters = state
            .dead_letters
            .iter()
            .filter(|entry| entry.tenant == query.tenant)
            .filter(|entry| {
                query
                    .remote
                    .as_ref()
                    .is_none_or(|remote| entry.remote == *remote)
            })
            .filter(|entry| {
                scope_filter
                    .as_ref()
                    .is_none_or(|scope| entry.scope_id == *scope)
            })
            .cloned()
            .collect::<Vec<_>>();
        let active_live_links = state
            .live_links
            .iter()
            .filter(|link| link.starts_with(&format!("{}|", query.tenant)))
            .filter(|link| {
                query
                    .remote
                    .as_ref()
                    .is_none_or(|remote| link.starts_with(&format!("{}|{}|", query.tenant, remote)))
            })
            .cloned()
            .collect::<Vec<_>>();
        let status_key = query
            .remote
            .as_ref()
            .map(|remote| format!("{}|{}", query.tenant, remote))
            .unwrap_or_else(|| query.tenant.clone());
        SyncHealthSummary {
            tenant: query.tenant,
            remote: query.remote,
            checkpoints,
            dead_letters,
            active_live_links,
            last_status: state.last_status.get(&status_key).cloned(),
        }
    }

    pub async fn dead_letters(&self, tenant: &str, remote: Option<&str>) -> Vec<DeadLetterEntry> {
        self.state
            .read()
            .await
            .dead_letters
            .iter()
            .filter(|entry| entry.tenant == tenant)
            .filter(|entry| remote.is_none_or(|remote| entry.remote == remote))
            .cloned()
            .collect()
    }

    pub async fn clear_dead_letter(&self, id: &str) -> bool {
        let removed = self.ledger.remove_dead_letter(id).await.unwrap_or(false);
        if removed {
            let mut state = self.state.write().await;
            state.dead_letters.retain(|entry| entry.id != id);
        }

        removed
    }

    pub async fn retry_dead_letter(&self, id: &str) -> SyncOnceResult {
        let Some(dead_letter) = self
            .state
            .read()
            .await
            .dead_letters
            .iter()
            .find(|entry| entry.id == id)
            .cloned()
        else {
            return failed_result(SyncError::permanent(
                "DeadLetterNotFound",
                format!("Dead letter {id} was not found"),
            ));
        };

        if !dead_letter.error.retryable {
            return failed_result(SyncError::permanent(
                "DeadLetterNotRetryable",
                format!("Dead letter {id} is not retryable"),
            ));
        }

        let Some(entry) = dead_letter.entry.clone() else {
            return failed_result(SyncError::permanent(
                "DeadLetterRetryUnavailable",
                format!("Dead letter {id} does not retain a sync message entry"),
            ));
        };
        let scope = match scope_from_id(&dead_letter.scope_id) {
            Ok(scope) => scope,
            Err(error) => return failed_result(error),
        };
        let direction = match dead_letter.category {
            DeadLetterCategory::PullApply => SyncDirection::Pull,
            DeadLetterCategory::PushApply => SyncDirection::Push,
            _ => {
                return failed_result(SyncError::permanent(
                    "DeadLetterRetryUnsupported",
                    format!("Dead letter {id} category is not retryable"),
                ));
            }
        };
        let operation_key = operation_key(&dead_letter.tenant, &dead_letter.remote, direction);
        if !self.begin_operation(&operation_key).await {
            return SyncOnceResult::new(SyncRunStatus::AlreadyRunning);
        }

        let entry_bytes = entry.encoded_data_bytes();
        let retry_result = match direction {
            SyncDirection::Pull => self.local.apply(&dead_letter.tenant, entry.clone()).await,
            SyncDirection::Push => self.remote.apply(&dead_letter.tenant, entry.clone()).await,
            SyncDirection::Bidirectional => unreachable!("dead-letter retry chooses one direction"),
        };
        let result = match retry_result {
            Ok(()) => {
                let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
                let checkpoint = match direction {
                    SyncDirection::Pull => {
                        result.records_pulled = 1;
                        result.bytes_downloaded = entry_bytes;
                        self.remember_echo(
                            &dead_letter.tenant,
                            &dead_letter.remote,
                            &entry.message_cid,
                        )
                        .await;
                        self.update_checkpoint(
                            &dead_letter.tenant,
                            &dead_letter.remote,
                            &scope,
                            SyncDirection::Pull,
                            |checkpoint| {
                                checkpoint.records_pulled += 1;
                                checkpoint.bytes_downloaded += entry_bytes;
                                checkpoint.last_error = None;
                            },
                        )
                        .await
                    }
                    SyncDirection::Push => {
                        result.records_pushed = 1;
                        result.bytes_uploaded = entry_bytes;
                        self.update_checkpoint(
                            &dead_letter.tenant,
                            &dead_letter.remote,
                            &scope,
                            SyncDirection::Push,
                            |checkpoint| {
                                checkpoint.records_pushed += 1;
                                checkpoint.bytes_uploaded += entry_bytes;
                                checkpoint.last_error = None;
                            },
                        )
                        .await
                    }
                    SyncDirection::Bidirectional => {
                        unreachable!("dead-letter retry chooses one direction")
                    }
                };
                self.clear_dead_letter(&dead_letter.id).await;
                result.checkpoints.push(checkpoint);
                result
            }
            Err(error) => {
                self.update_dead_letter_failure(&dead_letter.id, error.clone())
                    .await;
                failed_result(error)
            }
        };
        self.end_operation(&operation_key, result.status.clone())
            .await;
        result
    }

    pub async fn handle_remote_subscription_message(
        &self,
        tenant: &str,
        remote: &str,
        scope: SyncScope,
        message: SubscriptionMessage,
    ) -> SyncOnceResult {
        match message {
            SubscriptionMessage::Event { cursor, event } => {
                if let Err(error) = self
                    .validate_pull_cursor(tenant, remote, &scope, &cursor)
                    .await
                {
                    return self
                        .handle_progress_gap(tenant, remote, scope, error.detail)
                        .await;
                }
                let entry = SyncMessageEntry::from_subscription_event(&cursor, &event);
                let bytes = entry.encoded_data_bytes();
                let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
                match self.local.apply(tenant, entry.clone()).await {
                    Ok(()) => {
                        result.records_pulled = 1;
                        result.bytes_downloaded = bytes;
                        self.remember_echo(tenant, remote, &entry.message_cid).await;
                        let checkpoint = self
                            .update_checkpoint(
                                tenant,
                                remote,
                                &scope,
                                SyncDirection::Pull,
                                |checkpoint| {
                                    checkpoint.pull_cursor = Some(cursor);
                                    checkpoint.records_pulled += 1;
                                    checkpoint.bytes_downloaded += bytes;
                                    checkpoint.last_error = None;
                                },
                            )
                            .await;
                        result.checkpoints.push(checkpoint);
                    }
                    Err(error) => {
                        self.record_dead_letter(
                            tenant,
                            remote,
                            &scope,
                            Some(entry),
                            DeadLetterCategory::PullApply,
                            error.clone(),
                        )
                        .await;
                        result.status = SyncRunStatus::Failed;
                        result.error = Some(error);
                    }
                }
                result
            }
            SubscriptionMessage::Eose { cursor } => {
                let checkpoint = self
                    .update_checkpoint(tenant, remote, &scope, SyncDirection::Pull, |checkpoint| {
                        checkpoint.pull_cursor = Some(cursor)
                    })
                    .await;
                let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
                result.checkpoints.push(checkpoint);
                result
            }
        }
    }

    pub async fn handle_local_subscription_message(
        &self,
        tenant: &str,
        remote: &str,
        scope: SyncScope,
        message: SubscriptionMessage,
    ) -> SyncOnceResult {
        match message {
            SubscriptionMessage::Event { cursor, event } => {
                if self
                    .should_suppress_echo(tenant, remote, &cursor.message_cid)
                    .await
                {
                    let checkpoint = self
                        .update_checkpoint(
                            tenant,
                            remote,
                            &scope,
                            SyncDirection::Push,
                            |checkpoint| checkpoint.push_cursor = Some(cursor),
                        )
                        .await;
                    let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
                    result.checkpoints.push(checkpoint);
                    return result;
                }
                let entry = SyncMessageEntry::from_subscription_event(&cursor, &event);
                let bytes = entry.encoded_data_bytes();
                let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
                match self.remote.apply(tenant, entry.clone()).await {
                    Ok(()) => {
                        result.records_pushed = 1;
                        result.bytes_uploaded = bytes;
                        let checkpoint = self
                            .update_checkpoint(
                                tenant,
                                remote,
                                &scope,
                                SyncDirection::Push,
                                |checkpoint| {
                                    checkpoint.push_cursor = Some(cursor);
                                    checkpoint.records_pushed += 1;
                                    checkpoint.bytes_uploaded += bytes;
                                    checkpoint.last_error = None;
                                },
                            )
                            .await;
                        result.checkpoints.push(checkpoint);
                    }
                    Err(error) => {
                        self.record_dead_letter(
                            tenant,
                            remote,
                            &scope,
                            Some(entry),
                            DeadLetterCategory::PushApply,
                            error.clone(),
                        )
                        .await;
                        result.status = SyncRunStatus::Failed;
                        result.error = Some(error);
                    }
                }
                result
            }
            SubscriptionMessage::Eose { cursor } => {
                let checkpoint = self
                    .update_checkpoint(tenant, remote, &scope, SyncDirection::Push, |checkpoint| {
                        checkpoint.push_cursor = Some(cursor)
                    })
                    .await;
                let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
                result.checkpoints.push(checkpoint);
                result
            }
        }
    }

    pub async fn handle_progress_gap(
        &self,
        tenant: &str,
        remote: &str,
        scope: SyncScope,
        detail: impl Into<String>,
    ) -> SyncOnceResult {
        let error = SyncError::progress_gap(detail.into());
        let checkpoint = self
            .update_checkpoint(tenant, remote, &scope, SyncDirection::Pull, |checkpoint| {
                checkpoint.last_error = Some(error.clone())
            })
            .await;
        let mut state = self.state.write().await;
        let status_key = format!("{tenant}|{remote}");
        state
            .last_status
            .insert(status_key.clone(), SyncRunStatus::Repairing);
        let _ = self
            .ledger
            .set_last_status(&status_key, SyncRunStatus::Repairing)
            .await;
        drop(state);
        let mut result = SyncOnceResult::new(SyncRunStatus::Repairing);
        result.error = Some(error);
        result.checkpoints.push(checkpoint);
        result.next_recommended_delay_ms = Some(0);
        result
    }

    async fn sync_once_unlocked(&self, request: SyncOnceRequest) -> SyncOnceResult {
        let identity = match self.identity(&request.tenant).await {
            Some(identity) => identity,
            None => {
                let mut result = SyncOnceResult::new(SyncRunStatus::Failed);
                result.error = Some(SyncError::permanent(
                    "SyncIdentityNotRegistered",
                    format!("Identity with DID {} is not registered", request.tenant),
                ));
                return result;
            }
        };
        let scopes = match scopes_for_request(&identity, request.protocol.as_deref()) {
            Ok(scopes) => scopes,
            Err(error) => {
                let mut result = SyncOnceResult::new(SyncRunStatus::Failed);
                result.error = Some(error);
                return result;
            }
        };

        let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
        for scope in scopes {
            let scope_result = self.sync_scope(&request, &scope).await;
            let terminal = matches!(
                scope_result.status,
                SyncRunStatus::Failed | SyncRunStatus::Partial | SyncRunStatus::Repairing
            );
            result.absorb(scope_result);
            if terminal {
                break;
            }
        }
        result
    }

    async fn sync_scope(&self, request: &SyncOnceRequest, scope: &SyncScope) -> SyncOnceResult {
        let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
        if request.direction.includes_pull() {
            let pull_result = self.sync_pull_scope(request, scope).await;
            let terminal = pull_result.status != SyncRunStatus::Completed;
            result.absorb(pull_result);
            if terminal {
                return result;
            }
        }
        if request.direction.includes_push() {
            result.absorb(self.sync_push_scope(request, scope).await);
        }
        result
    }

    async fn sync_pull_scope(
        &self,
        request: &SyncOnceRequest,
        scope: &SyncScope,
    ) -> SyncOnceResult {
        let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
        let local_root = match self.local.root(&request.tenant, scope).await {
            Ok(root) => root,
            Err(error) => return failed_result(error),
        };
        let remote_root = match self.remote.root(&request.tenant, scope).await {
            Ok(root) => root,
            Err(error) => return failed_result(error),
        };
        if local_root == remote_root {
            let checkpoint = self
                .update_checkpoint(
                    &request.tenant,
                    &request.remote,
                    scope,
                    SyncDirection::Pull,
                    |checkpoint| {
                        checkpoint.local_root = Some(local_root.clone());
                        checkpoint.remote_root = Some(remote_root.clone());
                        checkpoint.pending_pull_prefixes.clear();
                        checkpoint.last_error = None;
                    },
                )
                .await;
            result.checkpoints.push(checkpoint);
            return result;
        }

        let local_hashes = match self
            .local
            .subtree_hashes(&request.tenant, scope, self.diff_depth)
            .await
        {
            Ok(hashes) => hashes,
            Err(error) => return failed_result(error),
        };
        let diff = match self
            .remote
            .diff(&request.tenant, scope, self.diff_depth, local_hashes)
            .await
        {
            Ok(diff) => diff,
            Err(error) => return failed_result(error),
        };

        let mut applied = 0usize;
        let mut bytes = 0u64;
        for entry in sort_diff_entries_topologically(diff.only_remote) {
            if request
                .max_records
                .is_some_and(|max_records| applied >= max_records)
            {
                result.status = SyncRunStatus::Partial;
                break;
            }
            if request
                .max_bytes
                .is_some_and(|max_bytes| bytes + entry.encoded_data_bytes() > max_bytes)
            {
                result.status = SyncRunStatus::Partial;
                break;
            }
            let message_cid = entry.message_cid.clone();
            let entry_bytes = entry.encoded_data_bytes();
            match self.local.apply(&request.tenant, entry.clone()).await {
                Ok(()) => {
                    applied += 1;
                    bytes += entry_bytes;
                    self.remember_echo(&request.tenant, &request.remote, &message_cid)
                        .await;
                }
                Err(error) => {
                    self.record_dead_letter(
                        &request.tenant,
                        &request.remote,
                        scope,
                        Some(entry),
                        DeadLetterCategory::PullApply,
                        error.clone(),
                    )
                    .await;
                    return failed_result(error);
                }
            }
        }

        result.records_pulled += applied as u64;
        result.bytes_downloaded += bytes;
        let checkpoint = self
            .update_checkpoint(
                &request.tenant,
                &request.remote,
                scope,
                SyncDirection::Pull,
                |checkpoint| {
                    checkpoint.local_root = Some(local_root);
                    checkpoint.remote_root = Some(remote_root);
                    checkpoint.pending_push_prefixes = diff.only_local;
                    checkpoint.records_pulled += applied as u64;
                    checkpoint.bytes_downloaded += bytes;
                    checkpoint.last_error = None;
                },
            )
            .await;
        result.checkpoints.push(checkpoint);
        result
    }

    async fn sync_push_scope(
        &self,
        request: &SyncOnceRequest,
        scope: &SyncScope,
    ) -> SyncOnceResult {
        let mut result = SyncOnceResult::new(SyncRunStatus::Completed);
        let local_root = match self.local.root(&request.tenant, scope).await {
            Ok(root) => root,
            Err(error) => return failed_result(error),
        };
        let remote_root = match self.remote.root(&request.tenant, scope).await {
            Ok(root) => root,
            Err(error) => return failed_result(error),
        };
        if local_root == remote_root {
            let checkpoint = self
                .update_checkpoint(
                    &request.tenant,
                    &request.remote,
                    scope,
                    SyncDirection::Push,
                    |checkpoint| {
                        checkpoint.local_root = Some(local_root.clone());
                        checkpoint.remote_root = Some(remote_root.clone());
                        checkpoint.pending_push_prefixes.clear();
                        checkpoint.last_error = None;
                    },
                )
                .await;
            result.checkpoints.push(checkpoint);
            return result;
        }

        let remote_hashes = match self
            .remote
            .subtree_hashes(&request.tenant, scope, self.diff_depth)
            .await
        {
            Ok(hashes) => hashes,
            Err(error) => return failed_result(error),
        };
        let diff = match self
            .local
            .diff(&request.tenant, scope, self.diff_depth, remote_hashes)
            .await
        {
            Ok(diff) => diff,
            Err(error) => return failed_result(error),
        };

        let mut pushed = 0usize;
        let mut bytes = 0u64;
        for entry in sort_diff_entries_topologically(diff.only_remote) {
            if self
                .should_suppress_echo(&request.tenant, &request.remote, &entry.message_cid)
                .await
            {
                continue;
            }
            if request
                .max_records
                .is_some_and(|max_records| pushed >= max_records)
            {
                result.status = SyncRunStatus::Partial;
                break;
            }
            if request
                .max_bytes
                .is_some_and(|max_bytes| bytes + entry.encoded_data_bytes() > max_bytes)
            {
                result.status = SyncRunStatus::Partial;
                break;
            }
            let entry_bytes = entry.encoded_data_bytes();
            match self.remote.apply(&request.tenant, entry.clone()).await {
                Ok(()) => {
                    pushed += 1;
                    bytes += entry_bytes;
                }
                Err(error) => {
                    self.record_dead_letter(
                        &request.tenant,
                        &request.remote,
                        scope,
                        Some(entry),
                        DeadLetterCategory::PushApply,
                        error.clone(),
                    )
                    .await;
                    return failed_result(error);
                }
            }
        }

        result.records_pushed += pushed as u64;
        result.bytes_uploaded += bytes;
        let checkpoint = self
            .update_checkpoint(
                &request.tenant,
                &request.remote,
                scope,
                SyncDirection::Push,
                |checkpoint| {
                    checkpoint.local_root = Some(local_root);
                    checkpoint.remote_root = Some(remote_root);
                    checkpoint.pending_pull_prefixes = diff.only_local;
                    checkpoint.records_pushed += pushed as u64;
                    checkpoint.bytes_uploaded += bytes;
                    checkpoint.last_error = None;
                },
            )
            .await;
        result.checkpoints.push(checkpoint);
        result
    }

    async fn begin_operation(&self, operation_key: &str) -> bool {
        let mut state = self.state.write().await;
        if state.running.contains(operation_key) {
            return false;
        }
        state.running.insert(operation_key.to_string());
        true
    }

    async fn end_operation(&self, operation_key: &str, status: SyncRunStatus) {
        let mut state = self.state.write().await;
        state.running.remove(operation_key);
        if let Some((tenant, remote, _)) = split_operation_key(operation_key) {
            let status_key = format!("{tenant}|{remote}");
            state.last_status.insert(status_key.clone(), status.clone());
            drop(state);
            if let Err(error) = self.ledger.set_last_status(&status_key, status).await {
                tracing::warn!(%error, %status_key, "failed to persist sync run status to ledger");
            }
        }
    }

    async fn update_checkpoint(
        &self,
        tenant: &str,
        remote: &str,
        scope: &SyncScope,
        direction: SyncDirection,
        update: impl FnOnce(&mut SyncCheckpoint),
    ) -> SyncCheckpoint {
        let key = checkpoint_key(tenant, remote, scope, direction);
        let mut state = self.state.write().await;
        let checkpoint = state
            .checkpoints
            .entry(key.clone())
            .or_insert_with(|| SyncCheckpoint {
                key: key.clone(),
                tenant: tenant.to_string(),
                remote: remote.to_string(),
                scope_id: scope.id(),
                direction,
                local_root: None,
                remote_root: None,
                pending_pull_prefixes: Vec::new(),
                pending_push_prefixes: Vec::new(),
                pull_cursor: None,
                push_cursor: None,
                records_pulled: 0,
                records_pushed: 0,
                bytes_downloaded: 0,
                bytes_uploaded: 0,
                last_error: None,
                updated_at: Utc::now(),
            });
        update(checkpoint);
        checkpoint.updated_at = Utc::now();
        let checkpoint = checkpoint.clone();
        drop(state);
        if let Err(error) = self.ledger.upsert_checkpoint(&checkpoint).await {
            tracing::warn!(%error, key = %checkpoint.key, "failed to persist sync checkpoint to ledger");
        }
        checkpoint
    }

    async fn record_dead_letter(
        &self,
        tenant: &str,
        remote: &str,
        scope: &SyncScope,
        entry: Option<SyncMessageEntry>,
        category: DeadLetterCategory,
        error: SyncError,
    ) {
        let message_cid = entry.as_ref().map(|entry| entry.message_cid.clone());
        let dead_letter = DeadLetterEntry {
            id: Ulid::new().to_string(),
            tenant: tenant.to_string(),
            remote: remote.to_string(),
            scope_id: scope.id(),
            message_cid,
            entry,
            category,
            error,
            attempts: 1,
            last_attempt_at: Utc::now(),
        };
        self.state
            .write()
            .await
            .dead_letters
            .push(dead_letter.clone());
        if let Err(error) = self.ledger.insert_dead_letter(&dead_letter).await {
            tracing::warn!(%error, id = %dead_letter.id, "failed to persist dead-letter to ledger");
        }
    }

    async fn update_dead_letter_failure(&self, id: &str, error: SyncError) {
        let mut state = self.state.write().await;
        if let Some(entry) = state.dead_letters.iter_mut().find(|entry| entry.id == id) {
            entry.error = error.clone();
            entry.attempts += 1;
            entry.last_attempt_at = Utc::now();
            if let Err(error) = self.ledger.update_dead_letter(entry).await {
                tracing::warn!(%error, id = %entry.id, "failed to update dead-letter in ledger");
            }
        }
    }

    async fn remember_echo(&self, tenant: &str, remote: &str, message_cid: &str) {
        let key = echo_key(tenant, remote, message_cid);
        let now = Utc::now();
        self.state.write().await.echo_cache.insert(key.clone(), now);
        if let Err(error) = self.ledger.remember_echo(&key, now).await {
            tracing::warn!(%error, %key, "failed to persist echo marker to ledger");
        }
    }

    async fn should_suppress_echo(&self, tenant: &str, remote: &str, message_cid: &str) -> bool {
        let key = echo_key(tenant, remote, message_cid);
        match self.ledger.contains_echo(&key).await {
            Ok(v) => v,
            Err(_) => self.state.read().await.echo_cache.contains_key(&key),
        }
    }

    async fn validate_pull_cursor(
        &self,
        tenant: &str,
        remote: &str,
        scope: &SyncScope,
        cursor: &ProgressToken,
    ) -> SyncResult<()> {
        let key = checkpoint_key(tenant, remote, scope, SyncDirection::Pull);
        let Some(previous) = self
            .state
            .read()
            .await
            .checkpoints
            .get(&key)
            .and_then(|checkpoint| checkpoint.pull_cursor.clone())
        else {
            return Ok(());
        };
        if previous.stream_id != cursor.stream_id || previous.epoch != cursor.epoch {
            return Err(SyncError::progress_gap(
                "subscription cursor domain changed",
            ));
        }
        let previous_position = previous.position.parse::<u64>().unwrap_or_default();
        let cursor_position = cursor.position.parse::<u64>().unwrap_or_default();
        if cursor_position < previous_position {
            return Err(SyncError::progress_gap(
                "subscription cursor moved backwards",
            ));
        }
        Ok(())
    }
}

pub fn validate_identity_options(options: &SyncIdentityOptions) -> SyncResult<()> {
    if options.did.is_empty() {
        return Err(SyncError::permanent(
            "SyncIdentityInvalid",
            "did is required",
        ));
    }
    if let SyncProtocols::Protocols(protocols) = &options.protocols {
        if protocols.is_empty() || protocols.iter().any(|protocol| protocol.is_empty()) {
            return Err(SyncError::permanent(
                "SyncIdentityInvalidProtocols",
                "protocols must be 'all' or a non-empty protocol list",
            ));
        }
    }
    Ok(())
}

fn scopes_for_request(
    identity: &SyncIdentityOptions,
    protocol: Option<&str>,
) -> SyncResult<Vec<SyncScope>> {
    if let Some(protocol) = protocol {
        if protocol.is_empty() {
            return Err(SyncError::permanent(
                "SyncScopeInvalid",
                "protocol must not be empty",
            ));
        }
        return Ok(vec![SyncScope::protocol(protocol)]);
    }
    match &identity.protocols {
        SyncProtocols::All => Ok(vec![SyncScope::Full]),
        SyncProtocols::Protocols(protocols) => {
            Ok(protocols.iter().cloned().map(SyncScope::protocol).collect())
        }
    }
}

fn scope_from_id(scope_id: &str) -> SyncResult<SyncScope> {
    if scope_id == SyncScope::Full.id() {
        return Ok(SyncScope::Full);
    }
    if let Some(protocol) = scope_id.strip_prefix("protocol:") {
        if !protocol.is_empty() {
            return Ok(SyncScope::protocol(protocol));
        }
    }
    Err(SyncError::permanent(
        "SyncScopeInvalid",
        format!("Invalid sync scope id {scope_id}"),
    ))
}

fn connectivity_error(connectivity: &SyncConnectivity) -> Option<SyncError> {
    if !connectivity.online || connectivity.background_restricted {
        return Some(SyncError::transient(
            "NoConnectivity",
            "network is unavailable or background work is restricted",
        ));
    }
    if connectivity.expensive && !connectivity.allow_metered {
        return Some(SyncError::transient(
            "NoConnectivity",
            "metered network is not allowed",
        ));
    }
    if connectivity.roaming && !connectivity.allow_roaming {
        return Some(SyncError::transient(
            "NoConnectivity",
            "roaming network is not allowed",
        ));
    }
    None
}

fn failed_result(error: SyncError) -> SyncOnceResult {
    let mut result = SyncOnceResult::new(SyncRunStatus::Failed);
    result.error = Some(error);
    result
}

fn sort_diff_entries_topologically(entries: Vec<SyncMessageEntry>) -> Vec<SyncMessageEntry> {
    let mut pending = entries;
    let mut sorted = Vec::new();
    while !pending.is_empty() {
        let remaining_record_ids = pending
            .iter()
            .filter_map(entry_record_id)
            .collect::<BTreeSet<_>>();
        let mut next_index = None;
        for (index, entry) in pending.iter().enumerate() {
            let parent_is_pending = entry_parent_id(entry)
                .as_ref()
                .is_some_and(|parent_id| remaining_record_ids.contains(parent_id));
            if !parent_is_pending {
                next_index = Some(index);
                break;
            }
        }
        match next_index {
            Some(index) => sorted.push(pending.remove(index)),
            None => {
                pending.sort_by(|left, right| left.message_cid.cmp(&right.message_cid));
                sorted.extend(pending);
                break;
            }
        }
    }
    sorted
}

fn entry_record_id(entry: &SyncMessageEntry) -> Option<String> {
    entry
        .message
        .get("recordId")
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            entry
                .message
                .get("descriptor")
                .and_then(|descriptor| descriptor.get("recordId"))
                .and_then(JsonValue::as_str)
                .map(ToString::to_string)
        })
}

fn entry_parent_id(entry: &SyncMessageEntry) -> Option<String> {
    entry
        .message
        .get("descriptor")
        .and_then(|descriptor| descriptor.get("parentId"))
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
}

impl SyncMessageEntry {
    fn encoded_data_bytes(&self) -> u64 {
        self.encoded_data
            .as_ref()
            .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            .map(|bytes| bytes.len() as u64)
            .unwrap_or_default()
    }
}

fn operation_key(tenant: &str, remote: &str, direction: SyncDirection) -> String {
    format!("{tenant}|{remote}|{direction:?}")
}

fn split_operation_key(operation_key: &str) -> Option<(&str, &str, &str)> {
    let mut parts = operation_key.splitn(3, '|');
    Some((parts.next()?, parts.next()?, parts.next()?))
}

fn checkpoint_key(
    tenant: &str,
    remote: &str,
    scope: &SyncScope,
    direction: SyncDirection,
) -> String {
    format!("{tenant}|{remote}|{}|{direction:?}", scope.id())
}

/// Minimum degraded-poll interval in milliseconds (TS uses 15–30s with jitter).
const DEGRADED_POLL_INTERVAL_MS: u64 = 15_000;

fn live_link_key(tenant: &str, remote: &str, protocol: Option<&str>) -> String {
    let scope = protocol
        .map(|protocol| SyncScope::protocol(protocol).id())
        .unwrap_or_else(|| SyncScope::Full.id());
    format!("{tenant}|{remote}|{scope}")
}

fn echo_key(tenant: &str, remote: &str, message_cid: &str) -> String {
    format!("{tenant}|{remote}|{message_cid}")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, RwLock};

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde_json::json;

    use crate::events::MessageEvent;
    use crate::stores::ProgressToken;
    use crate::{Descriptor, Fields, Message};

    use super::*;

    #[tokio::test]
    async fn sync_once_bidirectional_pulls_then_pushes_topologically() {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        local.set_root("local-root");
        remote.set_root("remote-root");
        local.set_hashes(BTreeMap::from([(
            "0".to_string(),
            "local-hash".to_string(),
        )]));
        remote.set_hashes(BTreeMap::from([(
            "0".to_string(),
            "remote-hash".to_string(),
        )]));
        remote.set_diff(MessagesSyncDiff {
            only_remote: vec![child_entry(), parent_entry()],
            only_local: vec!["10".to_string()],
        });
        local.set_diff(MessagesSyncDiff {
            only_remote: vec![local_entry()],
            only_local: Vec::new(),
        });
        let engine = engine(local.clone(), remote.clone()).await;

        let result = engine
            .sync_once(SyncOnceRequest::new(
                "did:example:alice",
                "https://remote.example",
                SyncDirection::Bidirectional,
            ))
            .await;

        assert_eq!(result.status, SyncRunStatus::Completed);
        assert_eq!(result.records_pulled, 2);
        assert_eq!(result.records_pushed, 1);
        assert_eq!(
            local.applied_cids(),
            vec!["parent-cid".to_string(), "child-cid".to_string()]
        );
        assert_eq!(remote.applied_cids(), vec!["local-cid".to_string()]);
        let status = engine
            .sync_status(SyncStatusQuery {
                tenant: "did:example:alice".to_string(),
                remote: Some("https://remote.example".to_string()),
                protocol: None,
            })
            .await;
        assert_eq!(status.dead_letters.len(), 0);
        assert!(status
            .checkpoints
            .iter()
            .any(|checkpoint| checkpoint.pending_push_prefixes == vec!["10"]));
    }

    #[tokio::test]
    async fn sync_once_records_dead_letter_on_apply_failure() {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        local.set_root("local-root");
        remote.set_root("remote-root");
        remote.set_diff(MessagesSyncDiff {
            only_remote: vec![parent_entry()],
            only_local: Vec::new(),
        });
        local.fail_apply("parent-cid");
        let engine = engine(local.clone(), remote).await;

        let result = engine
            .sync_once(SyncOnceRequest::new(
                "did:example:alice",
                "https://remote.example",
                SyncDirection::Pull,
            ))
            .await;

        assert_eq!(result.status, SyncRunStatus::Failed);
        let dead_letters = engine.dead_letters("did:example:alice", None).await;
        assert_eq!(dead_letters.len(), 1);
        assert_eq!(dead_letters[0].message_cid.as_deref(), Some("parent-cid"));
        assert_eq!(
            dead_letters[0].entry.as_ref().unwrap().message_cid,
            "parent-cid"
        );
        assert_eq!(dead_letters[0].category, DeadLetterCategory::PullApply);
    }

    #[tokio::test]
    async fn retry_dead_letter_reapplies_retained_entry_and_clears_failure() {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        local.set_root("local-root");
        remote.set_root("remote-root");
        remote.set_diff(MessagesSyncDiff {
            only_remote: vec![parent_entry()],
            only_local: Vec::new(),
        });
        local.fail_apply("parent-cid");
        let engine = engine(local.clone(), remote).await;
        let result = engine
            .sync_once(SyncOnceRequest::new(
                "did:example:alice",
                "https://remote.example",
                SyncDirection::Pull,
            ))
            .await;
        assert_eq!(result.status, SyncRunStatus::Failed);
        let dead_letter = &engine.dead_letters("did:example:alice", None).await[0];

        local.allow_apply("parent-cid");
        let retry = engine.retry_dead_letter(&dead_letter.id).await;

        assert_eq!(retry.status, SyncRunStatus::Completed);
        assert_eq!(retry.records_pulled, 1);
        assert_eq!(retry.bytes_downloaded, b"parent".len() as u64);
        assert_eq!(local.applied_cids(), vec!["parent-cid".to_string()]);
        assert!(engine
            .dead_letters("did:example:alice", None)
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn remote_subscription_event_applies_and_advances_cursor() {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        let engine = engine(local.clone(), remote).await;
        let cursor = token("remote-stream", "1", "event-cid");

        let result = engine
            .handle_remote_subscription_message(
                "did:example:alice",
                "https://remote.example",
                SyncScope::Full,
                SubscriptionMessage::Event {
                    cursor: cursor.clone(),
                    event: Box::new(MessageEvent {
                        message: empty_message(),
                        initial_write: None,
                    }),
                },
            )
            .await;

        assert_eq!(result.status, SyncRunStatus::Completed);
        assert_eq!(local.applied_cids(), vec!["event-cid".to_string()]);
        assert_eq!(result.checkpoints[0].pull_cursor, Some(cursor));
    }

    #[tokio::test]
    async fn local_subscription_event_skips_recently_pulled_echo() {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        let engine = engine(local, remote.clone()).await;
        let cursor = token("remote-stream", "1", "same-cid");
        let event = SubscriptionMessage::Event {
            cursor: cursor.clone(),
            event: Box::new(MessageEvent {
                message: empty_message(),
                initial_write: None,
            }),
        };

        engine
            .handle_remote_subscription_message(
                "did:example:alice",
                "https://remote.example",
                SyncScope::Full,
                event,
            )
            .await;
        let result = engine
            .handle_local_subscription_message(
                "did:example:alice",
                "https://remote.example",
                SyncScope::Full,
                SubscriptionMessage::Event {
                    cursor,
                    event: Box::new(MessageEvent {
                        message: empty_message(),
                        initial_write: None,
                    }),
                },
            )
            .await;

        assert_eq!(result.status, SyncRunStatus::Completed);
        assert!(remote.applied_cids().is_empty());
    }

    #[tokio::test]
    async fn poll_reconcile_runs_pull_only_sync() {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        local.set_root("local-root");
        remote.set_root("remote-root");
        remote.set_diff(MessagesSyncDiff {
            only_remote: vec![parent_entry()],
            only_local: Vec::new(),
        });
        let engine = engine(local.clone(), remote).await;

        let result = engine
            .poll_reconcile(SyncOnceRequest::new(
                "did:example:alice",
                "https://remote.example",
                SyncDirection::Bidirectional,
            ))
            .await;

        assert_eq!(result.status, SyncRunStatus::Completed);
        assert_eq!(result.records_pulled, 1);
        assert_eq!(local.applied_cids(), vec!["parent-cid".to_string()]);
    }

    #[tokio::test]
    async fn enter_degraded_poll_clears_live_link_and_sets_status() {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        local.set_root("local-root");
        remote.set_root("remote-root");
        let engine = engine(local, remote).await;
        engine
            .start_sync(StartSyncParams {
                tenant: "did:example:alice".to_string(),
                remote: "https://remote.example".to_string(),
                mode: SyncMode::Live,
                interval_ms: None,
                protocol: None,
            })
            .await;

        let result = engine
            .enter_degraded_poll("did:example:alice", "https://remote.example", None)
            .await;

        assert_eq!(result.status, SyncRunStatus::DegradedPoll);
        assert_eq!(
            result.next_recommended_delay_ms,
            Some(DEGRADED_POLL_INTERVAL_MS)
        );
        let status = engine
            .sync_status(SyncStatusQuery {
                tenant: "did:example:alice".to_string(),
                remote: Some("https://remote.example".to_string()),
                protocol: None,
            })
            .await;
        assert_eq!(status.last_status, Some(SyncRunStatus::DegradedPoll));
        assert!(status.active_live_links.is_empty());
    }

    #[tokio::test]
    async fn reconcile_after_live_disconnect_polls_without_duplicating_live_applied_record() {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        local.set_root("local-root");
        remote.set_root("remote-root");
        let live_entry = parent_entry();
        remote.set_diff(MessagesSyncDiff {
            only_remote: vec![live_entry.clone(), child_entry()],
            only_local: Vec::new(),
        });
        let engine = engine(local.clone(), remote.clone()).await;
        let cursor = token("remote-stream", "1", "parent-cid");

        engine
            .handle_remote_subscription_message(
                "did:example:alice",
                "https://remote.example",
                SyncScope::Full,
                SubscriptionMessage::Event {
                    cursor: cursor.clone(),
                    event: Box::new(MessageEvent {
                        message: empty_message(),
                        initial_write: None,
                    }),
                },
            )
            .await;
        assert_eq!(local.applied_cids(), vec!["parent-cid".to_string()]);

        // Simulate SMT state after the live-delivered record converged locally.
        local.set_root("local-root-after-live");
        remote.set_diff(MessagesSyncDiff {
            only_remote: vec![child_entry()],
            only_local: Vec::new(),
        });

        let reconcile = engine
            .reconcile_after_live_disconnect(SyncOnceRequest::new(
                "did:example:alice",
                "https://remote.example",
                SyncDirection::Pull,
            ))
            .await;

        assert_eq!(reconcile.status, SyncRunStatus::Completed);
        assert_eq!(
            reconcile.records_pulled, 1,
            "poll should apply only the record missed by live path"
        );
        assert_eq!(
            local.applied_cids(),
            vec!["parent-cid".to_string(), "child-cid".to_string()]
        );
    }

    #[tokio::test]
    async fn progress_gap_marks_repairing_and_keeps_dead_letters_visible() {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        let engine = engine(local, remote).await;

        let result = engine
            .handle_progress_gap(
                "did:example:alice",
                "https://remote.example",
                SyncScope::Full,
                "token_too_old",
            )
            .await;

        assert_eq!(result.status, SyncRunStatus::Repairing);
        assert_eq!(result.error.as_ref().unwrap().code, "ProgressGap");
        assert_eq!(
            result.checkpoints[0].last_error.as_ref().unwrap().detail,
            "token_too_old"
        );
    }

    #[tokio::test]
    async fn identity_protocols_must_be_explicit_and_non_empty() {
        let engine = engine(MockEndpoint::default(), MockEndpoint::default()).await;
        let result = engine
            .register_identity(SyncIdentityOptions {
                did: "did:example:alice".to_string(),
                protocols: SyncProtocols::Protocols(Vec::new()),
                delegate_did: None,
            })
            .await;

        assert_eq!(result.unwrap_err().code, "SyncIdentityInvalidProtocols");
    }

    async fn engine(
        local: MockEndpoint,
        remote: MockEndpoint,
    ) -> NativeSyncEngine<MockEndpoint, MockEndpoint> {
        let engine = NativeSyncEngine::new(local, remote).with_diff_depth(2);
        engine
            .register_identity(SyncIdentityOptions {
                did: "did:example:alice".to_string(),
                protocols: SyncProtocols::All,
                delegate_did: None,
            })
            .await
            .unwrap();
        engine
    }

    #[derive(Clone, Default)]
    struct MockEndpoint {
        state: Arc<RwLock<MockEndpointState>>,
    }

    #[derive(Default)]
    struct MockEndpointState {
        root: String,
        hashes: BTreeMap<String, String>,
        diff: MessagesSyncDiff,
        applied: Vec<SyncMessageEntry>,
        fail_apply: BTreeSet<String>,
    }

    impl MockEndpoint {
        fn set_root(&self, root: &str) {
            self.state.write().unwrap().root = root.to_string();
        }

        fn set_hashes(&self, hashes: BTreeMap<String, String>) {
            self.state.write().unwrap().hashes = hashes;
        }

        fn set_diff(&self, diff: MessagesSyncDiff) {
            self.state.write().unwrap().diff = diff;
        }

        fn fail_apply(&self, cid: &str) {
            self.state
                .write()
                .unwrap()
                .fail_apply
                .insert(cid.to_string());
        }

        fn allow_apply(&self, cid: &str) {
            self.state.write().unwrap().fail_apply.remove(cid);
        }

        fn applied_cids(&self) -> Vec<String> {
            self.state
                .read()
                .unwrap()
                .applied
                .iter()
                .map(|entry| entry.message_cid.clone())
                .collect()
        }
    }

    impl SyncEndpoint for MockEndpoint {
        fn root<'a>(
            &'a self,
            _tenant: &'a str,
            _scope: &'a SyncScope,
        ) -> Pin<Box<dyn Future<Output = SyncResult<String>> + Send + 'a>> {
            Box::pin(async move { Ok(self.state.read().unwrap().root.clone()) })
        }

        fn subtree_hashes<'a>(
            &'a self,
            _tenant: &'a str,
            _scope: &'a SyncScope,
            _depth: u8,
        ) -> Pin<Box<dyn Future<Output = SyncResult<BTreeMap<String, String>>> + Send + 'a>>
        {
            Box::pin(async move { Ok(self.state.read().unwrap().hashes.clone()) })
        }

        fn diff<'a>(
            &'a self,
            _tenant: &'a str,
            _scope: &'a SyncScope,
            _depth: u8,
            _hashes: BTreeMap<String, String>,
        ) -> Pin<Box<dyn Future<Output = SyncResult<MessagesSyncDiff>> + Send + 'a>> {
            Box::pin(async move { Ok(self.state.read().unwrap().diff.clone()) })
        }

        fn apply<'a>(
            &'a self,
            _tenant: &'a str,
            entry: SyncMessageEntry,
        ) -> Pin<Box<dyn Future<Output = SyncResult<()>> + Send + 'a>> {
            Box::pin(async move {
                let mut state = self.state.write().unwrap();
                if state.fail_apply.contains(&entry.message_cid) {
                    return Err(SyncError::transient(
                        "ApplyFailed",
                        format!("failed to apply {}", entry.message_cid),
                    ));
                }
                state.applied.push(entry);
                Ok(())
            })
        }
    }

    fn parent_entry() -> SyncMessageEntry {
        SyncMessageEntry {
            message_cid: "parent-cid".to_string(),
            message: json!({
                "descriptor": {
                    "interface": "Records",
                    "method": "Write"
                },
                "recordId": "parent-record"
            }),
            encoded_data: Some(URL_SAFE_NO_PAD.encode(b"parent")),
        }
    }

    fn child_entry() -> SyncMessageEntry {
        SyncMessageEntry {
            message_cid: "child-cid".to_string(),
            message: json!({
                "descriptor": {
                    "interface": "Records",
                    "method": "Write",
                    "parentId": "parent-record"
                },
                "recordId": "child-record"
            }),
            encoded_data: Some(URL_SAFE_NO_PAD.encode(b"child")),
        }
    }

    fn local_entry() -> SyncMessageEntry {
        SyncMessageEntry {
            message_cid: "local-cid".to_string(),
            message: json!({
                "descriptor": {
                    "interface": "Records",
                    "method": "Write"
                },
                "recordId": "local-record"
            }),
            encoded_data: None,
        }
    }

    fn token(stream: &str, position: &str, message_cid: &str) -> ProgressToken {
        ProgressToken {
            stream_id: stream.to_string(),
            epoch: "epoch".to_string(),
            position: position.to_string(),
            message_cid: message_cid.to_string(),
        }
    }

    fn empty_message() -> Message<Descriptor> {
        Message {
            descriptor: serde_json::from_value(json!({
                "interface": "Records",
                "method": "Write",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "dataCid": "bafybeigdyrzt5sfp7udm7hu76fin73tazj24zpxtenqecq7z2xdha2f7mm",
                "dataSize": 0,
                "dateCreated": "2025-01-01T00:00:00.000000Z",
                "dataFormat": "text/plain"
            }))
            .unwrap(),
            fields: Fields::Write(Default::default()),
        }
    }
}
