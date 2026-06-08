//! UniFFI facade for mobile and other foreign-language Enbox integrations.
//!
//! This crate exposes a small, stable boundary over the native Rust DWN core.
//! Internal crates remain idiomatic Rust; DTO translation happens here.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use dwn_rs_core::agent::{
    derive_agent_keys, AgentIdentityInitializeRequest, AgentIdentityService,
    DeterministicDidJwkProvider, MemoryDidResolverCache, MemoryKeyManager, PortableDid,
};
use dwn_rs_core::auth::{JwsPrivateJwk, PrivateJwkSigner, StaticPublicKeyResolver};
use dwn_rs_core::connect::{
    create_delegate_grant, create_grant_revocation, create_permission_request, derive_context_key,
    derive_delegate_keys, load_delegate_context_keys, load_delegate_decryption_keys,
    save_delegate_context_keys, save_delegate_decryption_keys, DelegateContextKey,
    DelegateDecryptionKey,
};
use dwn_rs_core::mobile::MobileInitializeRequest;
use dwn_rs_core::protocols::Definition;
use dwn_rs_core::setup::{
    inject_protocol_encryption, install_protocol_if_needed, push_protocol_if_needed,
    register_with_dwn_endpoints, run_restore_flow, TenantRegistrationRequest,
};
use dwn_rs_core::sync::{
    SyncCheckpoint, SyncConnectivity, SyncDirection, SyncIdentityOptions, SyncOnceRequest,
    SyncOnceResult, SyncRunStatus,
};
use dwn_rs_core::sync_endpoint::JwsSyncAuthorizer;
use dwn_rs_core::sync_ledger::SyncLedger;
use dwn_rs_stores::{SqliteNativeDwn, SqliteSecretStore};
use serde::{Deserialize, Serialize};

pub mod connect;
pub mod http_registration;
pub mod setup;
use connect::{
    DelegateGrantInput, DeriveContextKeyInput, DeriveDelegateKeysInput, GrantRevocationInput,
    PermissionRequestInput,
};
use http_registration::HttpTenantRegistrationClient;
use setup::{signer_from_portable_did, HttpDwnProtocolEndpoint, LocalDwnProtocolEndpoint};

uniffi::setup_scaffolding!();

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnboxRuntimeStatus {
    pub initialized: bool,
    pub locked: bool,
    pub database_path: Option<String>,
    /// Host-provided device identifier, set by `initialize_runtime`.
    pub device_id: Option<String>,
    /// iOS App Group / Android shared user id, when the host provides one.
    pub app_group: Option<String>,
    /// Whether the host has enabled background sync wake hooks.
    pub background_refresh_enabled: bool,
    /// Last reason supplied to `unlock_with_reason`. Cleared on `lock()`.
    pub last_unlock_reason: Option<String>,
    /// IDs of background tasks currently checked out via
    /// `begin_background_task`. Sorted for deterministic comparison.
    pub active_background_tasks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnboxSyncStatus {
    pub in_progress: bool,
    pub last_status: String,
    pub last_error_code: Option<String>,
    pub last_error_detail: Option<String>,
    pub records_pulled: u64,
    pub records_pushed: u64,
    pub last_pull_cursor_json: Option<String>,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum EnboxError {
    #[error("DWN processing failed: {detail}")]
    Dwn { detail: String },
    #[error("JSON error: {detail}")]
    Json { detail: String },
    #[error("Store error: {detail}")]
    Store { detail: String },
    #[error("Sync error: {detail}")]
    Sync { detail: String },
    #[error("Agent identity error ({code}): {detail}")]
    Agent { code: String, detail: String },
    #[error("Core is not initialized")]
    NotInitialized,
    #[error("Vault is locked")]
    Locked,
    #[error("Sync is already in progress")]
    SyncInProgress,
    #[error("Sync signer is not configured")]
    SyncSignerMissing,
    #[error("Operation was cancelled")]
    Cancelled,
    #[error("Operation deadline exceeded")]
    DeadlineExceeded,
}

impl From<dwn_rs_core::agent::AgentIdentityError> for EnboxError {
    fn from(err: dwn_rs_core::agent::AgentIdentityError) -> Self {
        EnboxError::Agent {
            code: err.code,
            detail: err.detail,
        }
    }
}

struct CoreState {
    locked: bool,
    database_path: Option<String>,
    node: Option<Arc<SqliteNativeDwn>>,
    secret_store: Option<SqliteSecretStore>,
    sync_signer: Option<PrivateJwkSigner>,
    sync_in_progress: bool,
    last_sync: Option<SyncOnceResult>,
    last_sync_tenant: Option<String>,
    last_sync_remote: Option<String>,
    device_id: Option<String>,
    app_group: Option<String>,
    background_refresh_enabled: bool,
    last_unlock_reason: Option<String>,
    active_background_tasks: BTreeSet<String>,
}

type AgentService = AgentIdentityService<
    DeterministicDidJwkProvider,
    MemoryKeyManager,
    SqliteSecretStore,
    MemoryDidResolverCache,
>;

#[derive(uniffi::Object)]
pub struct EnboxCore {
    runtime: tokio::runtime::Runtime,
    state: Arc<Mutex<CoreState>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SyncSignerConfig {
    key_id: String,
    algorithm: String,
    private_jwk: JwsPrivateJwk,
}

/// Which `SqliteNativeDwn` HTTP entry point a sync invocation should
/// dispatch to. Kept private; `sync_once` and `poll_reconcile` are the
/// only callers.
#[derive(Debug, Clone, Copy)]
enum SyncBackend {
    SyncOnce,
    PollReconcile,
}

/// Optional filter for `list_pending_scopes` and `resume_pending`. A
/// missing field matches everything; supplying `protocol: null`
/// explicitly is treated identically to omitting it.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct FfiPendingScopesQuery {
    tenant: String,
    remote: Option<String>,
    protocol: Option<String>,
    direction: Option<SyncDirection>,
}

/// JSON entry returned by `list_pending_scopes`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FfiPendingScope {
    tenant: String,
    remote: String,
    /// Protocol URI when scoped, or `None` for the global scope.
    protocol: Option<String>,
    direction: SyncDirection,
    pending_pull_count: usize,
    pending_push_count: usize,
    /// True when either cursor still has more pages to fetch.
    has_cursor: bool,
    records_pulled: u64,
    records_pushed: u64,
    bytes_downloaded: u64,
    bytes_uploaded: u64,
}

impl FfiPendingScope {
    fn from_checkpoint(checkpoint: &SyncCheckpoint) -> Self {
        Self {
            tenant: checkpoint.tenant.clone(),
            remote: checkpoint.remote.clone(),
            protocol: protocol_from_scope_id(&checkpoint.scope_id),
            direction: checkpoint.direction,
            pending_pull_count: checkpoint.pending_pull_prefixes.len(),
            pending_push_count: checkpoint.pending_push_prefixes.len(),
            has_cursor: checkpoint.pull_cursor.is_some() || checkpoint.push_cursor.is_some(),
            records_pulled: checkpoint.records_pulled,
            records_pushed: checkpoint.records_pushed,
            bytes_downloaded: checkpoint.bytes_downloaded,
            bytes_uploaded: checkpoint.bytes_uploaded,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FfiResumePendingRequest {
    tenant: String,
    /// Native deadline budget for the entire resume batch (not per
    /// scope). Scopes that didn't get a turn stay pending in the
    /// ledger.
    deadline_ms: Option<u64>,
    connectivity: Option<SyncConnectivity>,
    remote: Option<String>,
    protocol: Option<String>,
    direction: Option<SyncDirection>,
    max_records: Option<usize>,
    max_bytes: Option<u64>,
    reason: Option<String>,
    /// Optional signer override; falls back to the configured
    /// `sync_signer` when omitted.
    signer: Option<SyncSignerConfig>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FfiResumePendingResult {
    attempted: usize,
    results: Vec<SyncOnceResult>,
    deadline_exceeded: bool,
}

/// Map a `SyncCheckpoint.scope_id` (`global` or `protocol:<uri>`) back
/// to the optional protocol filter used by [`SyncOnceRequest`].
fn protocol_from_scope_id(scope_id: &str) -> Option<String> {
    scope_id.strip_prefix("protocol:").map(str::to_string)
}

/// True when a checkpoint still has unfinished work (pending prefixes
/// to apply or a cursor to keep paging).
fn checkpoint_is_pending(checkpoint: &SyncCheckpoint) -> bool {
    !checkpoint.pending_pull_prefixes.is_empty()
        || !checkpoint.pending_push_prefixes.is_empty()
        || checkpoint.pull_cursor.is_some()
        || checkpoint.push_cursor.is_some()
}

/// Apply the `tenant` / `remote` / `protocol` / `direction` filter from
/// a `FfiPendingScopesQuery` to a single ledger checkpoint.
fn matches_scope_filter(checkpoint: &SyncCheckpoint, query: &FfiPendingScopesQuery) -> bool {
    if checkpoint.tenant != query.tenant {
        return false;
    }
    if let Some(remote) = query.remote.as_deref() {
        if checkpoint.remote != remote {
            return false;
        }
    }
    if let Some(direction) = query.direction {
        if checkpoint.direction != direction {
            return false;
        }
    }
    if let Some(protocol) = query.protocol.as_deref() {
        match protocol_from_scope_id(&checkpoint.scope_id) {
            Some(scope_protocol) if scope_protocol == protocol => {}
            _ => return false,
        }
    }
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FfiSyncOnceRequest {
    tenant: String,
    remote: String,
    #[serde(default = "default_sync_direction")]
    direction: SyncDirection,
    protocol: Option<String>,
    max_records: Option<usize>,
    max_bytes: Option<u64>,
    signer: Option<SyncSignerConfig>,
    /// Native deadline in milliseconds; when set, the sync run is wrapped
    /// in a [`tokio::time::timeout`] and returns a
    /// `SyncRunStatus::DeadlineExceeded` result if the budget elapses.
    /// Durable checkpoints written before the timeout are preserved so a
    /// follow-up call resumes from the same point.
    deadline_ms: Option<u64>,
    /// Caller-supplied connectivity snapshot. Omitting it keeps the
    /// permissive default (`online=true`, `allow_metered=true`,
    /// `allow_roaming=false`) so existing callers see no behaviour change.
    connectivity: Option<SyncConnectivity>,
    /// Caller-supplied reason label (`push_notification`, `periodic`,
    /// `manual`, `repair`, `startup_resume`, ...). Recorded for telemetry
    /// in the resulting checkpoints.
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FfiSyncStatusQuery {
    tenant: String,
    remote: Option<String>,
    protocol: Option<String>,
}

fn default_sync_direction() -> SyncDirection {
    SyncDirection::Bidirectional
}

#[uniffi::export]
impl EnboxCore {
    #[uniffi::constructor]
    pub fn open_in_memory() -> Result<Arc<Self>, EnboxError> {
        Self::open_with_resolver(":memory:", StaticPublicKeyResolver::default())
    }

    /// Open a durable SQLite-backed DWN at `database_path`.
    #[uniffi::constructor]
    pub fn open(database_path: String) -> Result<Arc<Self>, EnboxError> {
        Self::open_with_resolver(database_path, StaticPublicKeyResolver::default())
    }

    pub fn lock(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.locked = true;
            state.last_unlock_reason = None;
        }
    }

    /// Mark the vault unlocked without recording a reason. Prefer
    /// [`Self::unlock_with_reason`] from mobile hosts so audit logs can
    /// distinguish user-initiated unlocks from background-task wakes.
    pub fn unlock(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.locked = false;
        }
    }

    /// Mark the vault unlocked and record `reason` on the runtime status.
    ///
    /// Mirrors `MobileBiometricVault::unlock(reason)` in `dwn-rs-core`:
    /// Rust does not perform the biometric check itself, so the host
    /// must call this only after a successful platform prompt (Face ID,
    /// Touch ID, BiometricPrompt, ...).
    pub fn unlock_with_reason(&self, reason: String) -> Result<(), EnboxError> {
        let mut state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        state.locked = false;
        state.last_unlock_reason = Some(reason);
        Ok(())
    }

    /// Record host-supplied runtime metadata (`device_id`, `app_group`,
    /// optional override `database_path`, and `background_refresh_enabled`).
    ///
    /// `request_json` must match [`dwn_rs_core::mobile::MobileInitializeRequest`]
    /// (camelCase: `deviceId`, `appGroup`, `databasePath`,
    /// `backgroundRefreshEnabled`). Calling this does **not** open or
    /// migrate the SQLite database — use [`Self::open`] for that.
    pub fn initialize_runtime(
        &self,
        request_json: String,
    ) -> Result<EnboxRuntimeStatus, EnboxError> {
        let request: MobileInitializeRequest =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let mut state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        state.device_id = Some(request.device_id);
        state.app_group = request.app_group;
        if let Some(database_path) = request.database_path {
            state.database_path = Some(database_path);
        }
        state.background_refresh_enabled = request.background_refresh_enabled;
        Ok(status_from_state(&state))
    }

    /// Register a background task id on the runtime status. Returns
    /// `true` if the id was newly inserted, `false` if it was already
    /// active (matching `dwn-sdk-js` / `MobileCore::track_background_task`
    /// idempotency semantics expected by WorkManager and BGTaskScheduler).
    pub fn begin_background_task(&self, task_id: String) -> Result<bool, EnboxError> {
        let mut state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        Ok(state.active_background_tasks.insert(task_id))
    }

    /// Remove a previously registered background task id. Returns `true`
    /// if the id was present, `false` if it was unknown. Safe to call
    /// from a `defer`-style cleanup path (e.g. iOS `BGTask` expiration
    /// handler) even if the task already completed normally.
    pub fn end_background_task(&self, task_id: String) -> Result<bool, EnboxError> {
        let mut state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        Ok(state.active_background_tasks.remove(&task_id))
    }

    pub fn status(&self) -> EnboxRuntimeStatus {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        status_from_state(&state)
    }

    /// Install a local private JWK signer used to authorize HTTP sync requests.
    pub fn configure_sync_signer(&self, signer_json: String) -> Result<(), EnboxError> {
        let config: SyncSignerConfig =
            serde_json::from_str(&signer_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let signer = PrivateJwkSigner::new(config.key_id, config.algorithm, config.private_jwk);
        let mut state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        state.sync_signer = Some(signer);
        Ok(())
    }

    /// Register a tenant DID and protocol scope for subsequent sync runs.
    pub fn register_sync_identity(&self, identity_json: String) -> Result<(), EnboxError> {
        let options: SyncIdentityOptions =
            serde_json::from_str(&identity_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        let Some(node) = state.node.as_ref() else {
            return Err(EnboxError::NotInitialized);
        };
        node.register_sync_identity(options)
            .map_err(|err| EnboxError::Sync {
                detail: format!("{}: {}", err.code, err.detail),
            })
    }

    pub fn process_message(
        &self,
        tenant: String,
        message_json: String,
    ) -> Result<String, EnboxError> {
        let state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        if state.locked {
            return Err(EnboxError::Locked);
        }
        let Some(node) = state.node.as_ref() else {
            return Err(EnboxError::NotInitialized);
        };
        let message: serde_json::Value =
            serde_json::from_str(&message_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let reply = self
            .runtime
            .block_on(node.dwn().process_message(&tenant, message));
        serde_json::to_string(&reply).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Run one sync cycle against the configured remote DWN URL.
    ///
    /// `request_json` follows [`SyncOnceRequest`] (`tenant`, `remote`, `direction`, …).
    /// HTTP remotes require a signer via [`Self::configure_sync_signer`] or inline `signer`.
    pub fn sync_once(&self, request_json: String) -> Result<String, EnboxError> {
        self.run_sync_request(request_json, "ffi_sync_once", SyncBackend::SyncOnce)
    }

    /// Pull-only poll reconciliation against an HTTP remote (live-degraded fallback).
    ///
    /// `request_json` matches [`Self::sync_once`]; uses [`SqliteNativeDwn::poll_reconcile_with_http`].
    pub fn poll_reconcile(&self, request_json: String) -> Result<String, EnboxError> {
        self.run_sync_request(
            request_json,
            "ffi_poll_reconcile",
            SyncBackend::PollReconcile,
        )
    }

    /// Enumerate pending sync scopes for a tenant without running any
    /// network work. Returns a JSON array of [`FfiPendingScope`] entries
    /// matching the optional `remote` / `protocol` / `direction` filter.
    ///
    /// `query_json` is camelCase:
    /// `{ "tenant": "did:example:alice", "remote": "https://dwn.example/" }`.
    pub fn list_pending_scopes(&self, query_json: String) -> Result<String, EnboxError> {
        let query: FfiPendingScopesQuery =
            serde_json::from_str(&query_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        let Some(node) = state.node.clone() else {
            return Err(EnboxError::NotInitialized);
        };
        drop(state);

        let snapshot = node.sync_ledger().load().map_err(|err| EnboxError::Sync {
            detail: format!("{}: {}", err.code, err.detail),
        })?;
        let scopes: Vec<FfiPendingScope> = snapshot
            .checkpoints
            .values()
            .filter(|cp| matches_scope_filter(cp, &query))
            .filter(|cp| checkpoint_is_pending(cp))
            .map(FfiPendingScope::from_checkpoint)
            .collect();
        serde_json::to_string(&scopes).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Resume any pending sync work for a tenant under the supplied
    /// deadline + connectivity. Iterates the durable checkpoint ledger,
    /// filters by the optional `remote` / `protocol` / `direction`, and
    /// re-runs the sync engine on each pending scope until the work is
    /// drained or the deadline elapses. Scopes that didn't get a turn
    /// stay pending so the next call picks up where this one left off.
    ///
    /// `request_json` is camelCase and accepts the same connectivity /
    /// deadline / reason / signer fields as [`Self::sync_once`], plus an
    /// optional `direction` filter.
    pub fn resume_pending(&self, request_json: String) -> Result<String, EnboxError> {
        let request: FfiResumePendingRequest =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let deadline_ms = request.deadline_ms;
        let connectivity = request.connectivity.clone().unwrap_or_default();

        let state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        if state.locked {
            return Err(EnboxError::Locked);
        }
        if state.sync_in_progress {
            return Err(EnboxError::SyncInProgress);
        }
        let Some(node) = state.node.clone() else {
            return Err(EnboxError::NotInitialized);
        };
        let signer = if let Some(config) = request.signer.clone() {
            PrivateJwkSigner::new(config.key_id, config.algorithm, config.private_jwk)
        } else {
            state
                .sync_signer
                .clone()
                .ok_or(EnboxError::SyncSignerMissing)?
        };
        drop(state);

        let snapshot = node.sync_ledger().load().map_err(|err| EnboxError::Sync {
            detail: format!("{}: {}", err.code, err.detail),
        })?;

        let scope_query = FfiPendingScopesQuery {
            tenant: request.tenant.clone(),
            remote: request.remote.clone(),
            protocol: request.protocol.clone(),
            direction: request.direction,
        };
        let pending: Vec<SyncCheckpoint> = snapshot
            .checkpoints
            .into_values()
            .filter(|cp| matches_scope_filter(cp, &scope_query))
            .filter(checkpoint_is_pending)
            .collect();
        let attempted = pending.len();

        if pending.is_empty() {
            let response = FfiResumePendingResult {
                attempted: 0,
                results: Vec::new(),
                deadline_exceeded: false,
            };
            return serde_json::to_string(&response).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            });
        }

        {
            let mut state = self.state.lock().map_err(|err| EnboxError::Store {
                detail: format!("core state lock poisoned: {err}"),
            })?;
            state.sync_in_progress = true;
        }

        let reason = request
            .reason
            .clone()
            .unwrap_or_else(|| "ffi_resume_pending".to_string());
        let max_records = request.max_records;
        let max_bytes = request.max_bytes;
        let node_clone = node.clone();
        let signer_clone = signer.clone();
        let connectivity_clone = connectivity.clone();
        let last_remote = pending.last().map(|cp| cp.remote.clone());

        let run = async move {
            let mut results: Vec<SyncOnceResult> = Vec::with_capacity(attempted);
            for checkpoint in pending {
                let sync_request = SyncOnceRequest {
                    tenant: checkpoint.tenant.clone(),
                    remote: checkpoint.remote.clone(),
                    direction: checkpoint.direction,
                    protocol: protocol_from_scope_id(&checkpoint.scope_id),
                    max_records,
                    max_bytes,
                    connectivity: connectivity_clone.clone(),
                    reason: Some(reason.clone()),
                };
                let authorizer = JwsSyncAuthorizer::new(signer_clone.clone());
                let result = node_clone
                    .sync_once_with_http(&checkpoint.remote, authorizer, sync_request)
                    .await;
                results.push(result);
            }
            results
        };

        let (results, deadline_exceeded) = self.runtime.block_on(async move {
            match deadline_ms {
                Some(budget) => {
                    match tokio::time::timeout(std::time::Duration::from_millis(budget), run).await
                    {
                        Ok(results) => (results, false),
                        Err(_) => (Vec::new(), true),
                    }
                }
                None => (run.await, false),
            }
        });

        let mut state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        state.sync_in_progress = false;
        if let Some(last_result) = results.last().cloned() {
            state.last_sync = Some(last_result);
            state.last_sync_tenant = Some(request.tenant.clone());
            state.last_sync_remote = last_remote;
        }
        drop(state);

        let response = FfiResumePendingResult {
            attempted,
            results,
            deadline_exceeded,
        };
        serde_json::to_string(&response).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Initialize (or recover) an agent identity from a BIP-39 recovery phrase.
    ///
    /// `request_json` is JSON-encoded [`AgentIdentityInitializeRequest`]
    /// (`{ "recoveryPhrase"?: string, "dwnEndpoints": string[] }`). When the
    /// phrase is omitted a fresh 12-word English mnemonic is generated.
    ///
    /// Persists the resulting [`PortableDid`], vault content encryption key,
    /// and unlock salt to the SQLite-backed [`SqliteSecretStore`]. Returns
    /// JSON-encoded [`AgentIdentityInitialization`].
    pub fn initialize_agent_identity(&self, request_json: String) -> Result<String, EnboxError> {
        let request: AgentIdentityInitializeRequest =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let secret_store = self.require_secret_store()?;
        let service = self.build_agent_service(secret_store)?;
        let initialization = self
            .runtime
            .block_on(service.initialize_from_recovery(request))?;
        serde_json::to_string(&initialization).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Return the persisted agent [`PortableDid`] as JSON, or `None` if no
    /// identity has been initialized on this database.
    pub fn current_agent_identity(&self) -> Result<Option<String>, EnboxError> {
        let secret_store = self.require_secret_store()?;
        let service = self.build_agent_service(secret_store)?;
        let Some(portable_did) = self.runtime.block_on(service.stored_agent_did())? else {
            return Ok(None);
        };
        serde_json::to_string(&portable_did)
            .map(Some)
            .map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })
    }

    /// Derive the four-key set (vault, identity, signing, encryption) for the
    /// supplied recovery phrase **without** persisting anything. Useful for
    /// pre-flight validation on a recovery screen.
    ///
    /// Returns JSON-encoded [`AgentDerivedKeys`].
    pub fn derive_agent_keys_from_phrase(
        &self,
        recovery_phrase: String,
    ) -> Result<String, EnboxError> {
        let derived = derive_agent_keys(&recovery_phrase)?;
        serde_json::to_string(&derived).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Install a protocol definition on the local DWN for the supplied tenant.
    ///
    /// `tenant_did_json` is a JSON-encoded [`PortableDid`] (typically the
    /// value returned by [`Self::current_agent_identity`]). `definition_json`
    /// is a JSON-encoded [`Definition`]. If the protocol requires encryption,
    /// it is injected before the `ProtocolsConfigure` is signed and
    /// persisted; if the protocol is already installed, the call is a
    /// no-op (mirrors [`install_protocol_if_needed`]).
    ///
    /// Returns JSON-encoded [`ProtocolInstallResult`].
    pub fn install_protocol(
        &self,
        tenant_did_json: String,
        definition_json: String,
    ) -> Result<String, EnboxError> {
        let portable_did: PortableDid =
            serde_json::from_str(&tenant_did_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let definition: Definition =
            serde_json::from_str(&definition_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;

        let (node, key_manager) = self.require_local_endpoint_components(&portable_did)?;
        let signer = signer_from_portable_did(&portable_did)?;
        let endpoint = LocalDwnProtocolEndpoint::new(node, signer);
        let result = self.runtime.block_on(install_protocol_if_needed(
            &endpoint,
            &key_manager,
            &portable_did,
            definition,
        ))?;
        serde_json::to_string(&result).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Inject protocol-path encryption keys into a definition using the
    /// tenant's key-agreement root key.
    ///
    /// Pure function: does not touch the DWN or the vault. Useful for
    /// previewing what `install_protocol` will persist for an encrypted
    /// protocol, or for sharing a pre-augmented definition with another
    /// agent that needs to push the same protocol.
    ///
    /// Returns JSON-encoded [`Definition`] with `encryption` populated on
    /// each leaf rule set.
    pub fn inject_protocol_encryption(
        &self,
        tenant_did_json: String,
        definition_json: String,
    ) -> Result<String, EnboxError> {
        let portable_did: PortableDid =
            serde_json::from_str(&tenant_did_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let definition: Definition =
            serde_json::from_str(&definition_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let (_node, key_manager) = self.require_local_endpoint_components(&portable_did)?;
        let augmented = self.runtime.block_on(inject_protocol_encryption(
            definition,
            &key_manager,
            &portable_did,
        ))?;
        serde_json::to_string(&augmented).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Register the supplied DIDs with one or more `@enbox/dwn-server`
    /// HTTP endpoints.
    ///
    /// Input is a `TenantRegistrationRequest`:
    /// `{dwnEndpoints, agentDid, connectedDid, registrationTokens?, persistTokens?}`.
    /// When `persistTokens: true`, the agent secret store is read first
    /// (overriding any inline `registrationTokens`) and written back at
    /// the end with any refreshed tokens, matching
    /// `dwn_rs_core::setup::register_with_dwn_endpoints`.
    ///
    /// Returns the JSON-serialized `TenantRegistrationResult` (per-endpoint
    /// `records` and the final `registrationTokens` map).
    pub fn register_tenant(&self, request_json: String) -> Result<String, EnboxError> {
        let request: TenantRegistrationRequest =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let secret_store = self.require_secret_store()?;
        let client = HttpTenantRegistrationClient::new()?;
        let secret_store_ref = if request.persist_tokens {
            Some(&secret_store)
        } else {
            None
        };
        let result = self.runtime.block_on(register_with_dwn_endpoints(
            &client,
            secret_store_ref,
            request,
        ))?;
        serde_json::to_string(&result).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Push a protocol to a remote `@enbox/dwn-server` HTTP endpoint.
    ///
    /// Input is `{tenantDid, remoteUrl, definition}`. The method signs a
    /// `ProtocolsQuery` against the remote first; when the protocol is
    /// already installed it returns `{installed: false, encryptionActive: …}`
    /// without sending a configure. Encryption injection mirrors the local
    /// `install_protocol` path: protocols with `encryptionRequired: true`
    /// receive per-path key-agreement encryption derived from the tenant's
    /// `keyAgreement` verification method.
    pub fn push_protocol(&self, request_json: String) -> Result<String, EnboxError> {
        let input: setup::PushProtocolInput =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let key_manager = self.require_key_manager(&input.tenant_did)?;
        let signer = signer_from_portable_did(&input.tenant_did)?;
        let endpoint = HttpDwnProtocolEndpoint::new(input.remote_url, signer)?;
        let result = self.runtime.block_on(push_protocol_if_needed(
            &endpoint,
            &key_manager,
            &input.tenant_did,
            input.definition,
        ))?;
        serde_json::to_string(&result).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Replay protocol install + push across local and remote endpoints
    /// for a recovered agent.
    ///
    /// Input is `{agentDid, remoteUrl, protocols}`. The method:
    /// 1. Signs and installs each protocol on the local SQLite DWN.
    /// 2. Signs and pushes each protocol to the remote HTTP endpoint.
    ///
    /// Returns the JSON-serialized `RestoreFlowResult` (ordered `steps`,
    /// `localInstalls`, `remotePushes`). Identity tenant restoration is
    /// out of scope (see `dwn_rs_core::setup::run_restore_flow` docs).
    pub fn run_restore_flow(&self, request_json: String) -> Result<String, EnboxError> {
        let input: setup::RunRestoreFlowInput =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let (node, key_manager) = self.require_local_endpoint_components(&input.agent_did)?;
        let signer = signer_from_portable_did(&input.agent_did)?;
        let local = LocalDwnProtocolEndpoint::new(node, signer.clone());
        let remote = HttpDwnProtocolEndpoint::new(input.remote_url, signer)?;
        let result = self.runtime.block_on(run_restore_flow(
            &local,
            &remote,
            &key_manager,
            &input.agent_did,
            input.protocols,
        ))?;
        serde_json::to_string(&result).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Build a `PermissionRequestRecord` for a DWeb Connect request.
    ///
    /// Pure constructor: takes `{requester, scope, delegated, description?}`
    /// and returns the JSON-serialized `PermissionRequestRecord` (with a
    /// fresh ULID id). Mirrors `dwn-sdk-js`'s `PermissionRequest.create()`
    /// for the parts the agent needs to compose locally.
    pub fn create_permission_request(&self, request_json: String) -> Result<String, EnboxError> {
        let input: PermissionRequestInput =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let record = create_permission_request(
            input.requester,
            input.scope,
            input.delegated,
            input.description,
        );
        serde_json::to_string(&record).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Build a `DelegateGrant` for handing scoped access to another DID.
    ///
    /// Pure constructor: takes `{grantor, grantee, scope, dateExpires,
    /// description?}` and returns the JSON-serialized `DelegateGrant`
    /// (with a fresh ULID id and `dateGranted` set to now). The grant is
    /// always emitted with `delegated: true` to match the connect protocol
    /// contract.
    pub fn create_delegate_grant(&self, request_json: String) -> Result<String, EnboxError> {
        let input: DelegateGrantInput =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let grant = create_delegate_grant(
            input.grantor,
            input.grantee,
            input.scope,
            input.date_expires,
            input.description,
        );
        serde_json::to_string(&grant).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Build a `GrantRevocation` for an existing delegate grant.
    ///
    /// Pure constructor: takes `{grant, revocationGrantId}` and returns
    /// the JSON-serialized `GrantRevocation` (with `dateRevoked` set to
    /// now). Mobile hosts call this to revoke a delegated session before
    /// pushing the revocation through the DWN.
    pub fn create_grant_revocation(&self, request_json: String) -> Result<String, EnboxError> {
        let input: GrantRevocationInput =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let revocation = create_grant_revocation(&input.grant, input.revocation_grant_id);
        serde_json::to_string(&revocation).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Derive delegate decryption keys for a batch of connect requests.
    ///
    /// Takes `{ownerDid, requests}` where `ownerDid` is a
    /// `PortableDid` whose private keys will rehydrate a per-call
    /// `MemoryKeyManager`, and `requests` are the `ConnectPermissionRequest`
    /// objects the connecting app sent. Returns the JSON-serialized
    /// `DelegateKeyDerivationResult` (decryption keys + multi-party
    /// protocols that still need context-key delivery).
    pub fn derive_delegate_keys(&self, request_json: String) -> Result<String, EnboxError> {
        let input: DeriveDelegateKeysInput =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let key_manager = self.require_key_manager(&input.owner_did)?;
        let result = self.runtime.block_on(derive_delegate_keys(
            &key_manager,
            &input.owner_did,
            &input.requests,
        ))?;
        serde_json::to_string(&result).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Derive a context-scoped delegate key for multi-party protocol records.
    ///
    /// Takes `{ownerDid, protocol, contextId}` and returns the
    /// JSON-serialized `DelegateContextKey`. The owner's private keys
    /// rehydrate a per-call `MemoryKeyManager`; the derivation path uses
    /// the `dataFormats` derivation scheme bound to `contextId`.
    pub fn derive_context_key(&self, request_json: String) -> Result<String, EnboxError> {
        let input: DeriveContextKeyInput =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let key_manager = self.require_key_manager(&input.owner_did)?;
        let key = self.runtime.block_on(derive_context_key(
            &key_manager,
            &input.owner_did,
            input.protocol,
            input.context_id,
        ))?;
        serde_json::to_string(&key).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Persist the agent's delegate decryption keys to the secret store.
    ///
    /// Input is a JSON array of `DelegateDecryptionKey`. The keys are
    /// stored under the fixed `agent/delegate-decryption-keys` slot so
    /// subsequent `load_delegate_decryption_keys` calls return the same
    /// set. Replaces any previously stored keys.
    pub fn save_delegate_decryption_keys(&self, keys_json: String) -> Result<(), EnboxError> {
        let keys: Vec<DelegateDecryptionKey> =
            serde_json::from_str(&keys_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let secret_store = self.require_secret_store()?;
        self.runtime
            .block_on(save_delegate_decryption_keys(&secret_store, &keys))?;
        Ok(())
    }

    /// Load the agent's persisted delegate decryption keys.
    ///
    /// Returns a JSON-serialized `Vec<DelegateDecryptionKey>`; an empty
    /// vector is returned when nothing has been stored yet, matching the
    /// `dwn-rs-core::connect` helper contract.
    pub fn load_delegate_decryption_keys(&self) -> Result<String, EnboxError> {
        let secret_store = self.require_secret_store()?;
        let keys = self
            .runtime
            .block_on(load_delegate_decryption_keys(&secret_store))?;
        serde_json::to_string(&keys).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Persist the agent's delegate context keys to the secret store.
    ///
    /// Input is a JSON array of `DelegateContextKey`. Stored under the
    /// fixed `agent/delegate-context-keys` slot. Replaces any previously
    /// stored keys.
    pub fn save_delegate_context_keys(&self, keys_json: String) -> Result<(), EnboxError> {
        let keys: Vec<DelegateContextKey> =
            serde_json::from_str(&keys_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let secret_store = self.require_secret_store()?;
        self.runtime
            .block_on(save_delegate_context_keys(&secret_store, &keys))?;
        Ok(())
    }

    /// Load the agent's persisted delegate context keys.
    ///
    /// Returns a JSON-serialized `Vec<DelegateContextKey>`; an empty
    /// vector is returned when nothing has been stored yet.
    pub fn load_delegate_context_keys(&self) -> Result<String, EnboxError> {
        let secret_store = self.require_secret_store()?;
        let keys = self
            .runtime
            .block_on(load_delegate_context_keys(&secret_store))?;
        serde_json::to_string(&keys).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Return the last sync outcome for the supplied tenant (and optional remote/protocol filter).
    pub fn sync_status(&self, query_json: String) -> Result<EnboxSyncStatus, EnboxError> {
        let query: FfiSyncStatusQuery =
            serde_json::from_str(&query_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        Ok(sync_status_from_state(&state, &query))
    }
}

impl EnboxCore {
    /// Borrow the shared SQLite node and rebuild a per-call [`MemoryKeyManager`]
    /// rehydrated from the supplied [`PortableDid`]'s private keys.
    ///
    /// Setup operations (install protocol, inject encryption) need both
    /// pieces: the node for DWN dispatch and the key manager for protocol-
    /// path encryption derivation. Keeping the key manager per-call mirrors
    /// the agent-identity FFI helper and keeps the only durable state in the
    /// SQLite secret store.
    fn require_local_endpoint_components(
        &self,
        portable_did: &PortableDid,
    ) -> Result<(Arc<SqliteNativeDwn>, MemoryKeyManager), EnboxError> {
        let state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        if state.locked {
            return Err(EnboxError::Locked);
        }
        let node = state.node.clone().ok_or(EnboxError::NotInitialized)?;
        drop(state);

        let key_manager = MemoryKeyManager::default();
        self.runtime
            .block_on(import_private_keys(&key_manager, portable_did))?;
        Ok((node, key_manager))
    }

    /// Build a [`SyncOnceRequest`] from the FFI request, applying
    /// `default_reason` only when the caller didn't supply one.
    fn build_sync_once_request(
        request: &FfiSyncOnceRequest,
        default_reason: &str,
    ) -> SyncOnceRequest {
        SyncOnceRequest {
            tenant: request.tenant.clone(),
            remote: request.remote.clone(),
            direction: request.direction,
            protocol: request.protocol.clone(),
            max_records: request.max_records,
            max_bytes: request.max_bytes,
            connectivity: request.connectivity.clone().unwrap_or_default(),
            reason: Some(
                request
                    .reason
                    .clone()
                    .unwrap_or_else(|| default_reason.to_string()),
            ),
        }
    }

    /// Common scaffolding for `sync_once` and `poll_reconcile`: parses the
    /// request, gates on lock/in-progress/initialised, applies the
    /// optional `deadline_ms` budget via [`tokio::time::timeout`], and
    /// records the result in `CoreState`.
    fn run_sync_request(
        &self,
        request_json: String,
        default_reason: &str,
        backend: SyncBackend,
    ) -> Result<String, EnboxError> {
        let request: FfiSyncOnceRequest =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let sync_request = Self::build_sync_once_request(&request, default_reason);
        let deadline_ms = request.deadline_ms;

        let state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        if state.locked {
            return Err(EnboxError::Locked);
        }
        if state.sync_in_progress {
            return Err(EnboxError::SyncInProgress);
        }
        let Some(node) = state.node.clone() else {
            return Err(EnboxError::NotInitialized);
        };

        let signer = if let Some(config) = request.signer {
            PrivateJwkSigner::new(config.key_id, config.algorithm, config.private_jwk)
        } else {
            state
                .sync_signer
                .clone()
                .ok_or(EnboxError::SyncSignerMissing)?
        };
        drop(state);

        {
            let mut state = self.state.lock().map_err(|err| EnboxError::Store {
                detail: format!("core state lock poisoned: {err}"),
            })?;
            state.sync_in_progress = true;
        }

        let authorizer = JwsSyncAuthorizer::new(signer);
        let remote = request.remote.clone();
        let result = self.runtime.block_on(async move {
            let future = async {
                match backend {
                    SyncBackend::SyncOnce => {
                        node.sync_once_with_http(&remote, authorizer, sync_request)
                            .await
                    }
                    SyncBackend::PollReconcile => {
                        node.poll_reconcile_with_http(&remote, authorizer, sync_request)
                            .await
                    }
                }
            };
            match deadline_ms {
                Some(budget_ms) => {
                    match tokio::time::timeout(std::time::Duration::from_millis(budget_ms), future)
                        .await
                    {
                        Ok(result) => result,
                        Err(_) => SyncOnceResult {
                            status: SyncRunStatus::DeadlineExceeded,
                            checkpoints: Vec::new(),
                            records_pulled: 0,
                            records_pushed: 0,
                            bytes_downloaded: 0,
                            bytes_uploaded: 0,
                            next_recommended_delay_ms: Some(budget_ms),
                            error: None,
                        },
                    }
                }
                None => future.await,
            }
        });

        let mut state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        state.sync_in_progress = false;
        state.last_sync = Some(result.clone());
        state.last_sync_tenant = Some(request.tenant);
        state.last_sync_remote = Some(request.remote);

        serde_json::to_string(&result).map_err(|err| EnboxError::Json {
            detail: err.to_string(),
        })
    }

    /// Rehydrate a per-call [`MemoryKeyManager`] from the supplied
    /// [`PortableDid`]'s private keys, refusing if the core is locked.
    ///
    /// Connect operations (derive delegate keys, derive context keys)
    /// only need a key manager, not the DWN node, so we skip the
    /// `state.node.is_some()` check that `require_local_endpoint_components`
    /// imposes.
    fn require_key_manager(
        &self,
        portable_did: &PortableDid,
    ) -> Result<MemoryKeyManager, EnboxError> {
        let state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        if state.locked {
            return Err(EnboxError::Locked);
        }
        drop(state);

        let key_manager = MemoryKeyManager::default();
        self.runtime
            .block_on(import_private_keys(&key_manager, portable_did))?;
        Ok(key_manager)
    }

    fn require_secret_store(&self) -> Result<SqliteSecretStore, EnboxError> {
        let state = self.state.lock().map_err(|err| EnboxError::Store {
            detail: format!("core state lock poisoned: {err}"),
        })?;
        if state.locked {
            return Err(EnboxError::Locked);
        }
        state.secret_store.clone().ok_or(EnboxError::NotInitialized)
    }

    fn open_with_resolver(
        database_path: impl AsRef<Path>,
        resolver: StaticPublicKeyResolver,
    ) -> Result<Arc<Self>, EnboxError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| EnboxError::Store {
                detail: err.to_string(),
            })?;
        let path = database_path.as_ref().to_path_buf();
        let node = runtime
            .block_on(SqliteNativeDwn::open_at(&path, resolver))
            .map_err(|err| EnboxError::Store {
                detail: err.to_string(),
            })?;
        let database_path = if path.to_string_lossy() == ":memory:" {
            None
        } else {
            Some(path.to_string_lossy().into_owned())
        };
        let secret_store = SqliteSecretStore::new(node.store());
        Ok(Arc::new(Self {
            runtime,
            state: Arc::new(Mutex::new(CoreState {
                locked: false,
                database_path,
                node: Some(Arc::new(node)),
                secret_store: Some(secret_store),
                sync_signer: None,
                sync_in_progress: false,
                last_sync: None,
                last_sync_tenant: None,
                last_sync_remote: None,
                device_id: None,
                app_group: None,
                background_refresh_enabled: false,
                last_unlock_reason: None,
                active_background_tasks: BTreeSet::new(),
            })),
        }))
    }

    /// Build an [`AgentIdentityService`] backed by the SQLite secret store and
    /// rehydrated from any previously persisted [`PortableDid`].
    ///
    /// The key manager and DID resolver cache are rebuilt on every call. This
    /// keeps the FFI surface stateless: the only durable state is the
    /// [`SqliteSecretStore`] backed by the same SQLite file used for DWN data.
    fn build_agent_service(
        &self,
        secret_store: SqliteSecretStore,
    ) -> Result<AgentService, EnboxError> {
        let service = AgentIdentityService::new(
            DeterministicDidJwkProvider::default(),
            MemoryKeyManager::default(),
            secret_store,
            MemoryDidResolverCache::default(),
        );
        if let Some(portable_did) = self.runtime.block_on(service.stored_agent_did())? {
            self.runtime
                .block_on(import_existing_identity(&service, &portable_did))?;
        }
        Ok(service)
    }
}

pub(crate) async fn import_existing_identity(
    service: &AgentService,
    portable_did: &PortableDid,
) -> Result<(), dwn_rs_core::agent::AgentIdentityError> {
    use dwn_rs_core::agent::{DidProvider, DidResolverCache};
    service
        .did_provider()
        .import_did(portable_did.clone())
        .await?;
    service
        .resolver_cache()
        .put_did(portable_did.clone())
        .await?;
    import_private_keys(service.key_manager(), portable_did).await
}

pub(crate) async fn import_private_keys(
    key_manager: &MemoryKeyManager,
    portable_did: &PortableDid,
) -> Result<(), dwn_rs_core::agent::AgentIdentityError> {
    use dwn_rs_core::agent::AgentKeyManager;
    for jwk in &portable_did.private_keys {
        key_manager.import_private_jwk(jwk.clone()).await?;
    }
    Ok(())
}

/// Build an `EnboxRuntimeStatus` snapshot from the locked `CoreState`.
/// Centralised so `status()`, `initialize_runtime()`, and tests render
/// the same view.
fn status_from_state(state: &CoreState) -> EnboxRuntimeStatus {
    EnboxRuntimeStatus {
        initialized: state.node.is_some(),
        locked: state.locked,
        database_path: state.database_path.clone(),
        device_id: state.device_id.clone(),
        app_group: state.app_group.clone(),
        background_refresh_enabled: state.background_refresh_enabled,
        last_unlock_reason: state.last_unlock_reason.clone(),
        active_background_tasks: state.active_background_tasks.iter().cloned().collect(),
    }
}

fn sync_status_from_state(state: &CoreState, query: &FfiSyncStatusQuery) -> EnboxSyncStatus {
    let last = state.last_sync.as_ref().filter(|_| {
        state.last_sync_tenant.as_deref() == Some(query.tenant.as_str())
            && query
                .remote
                .as_ref()
                .is_none_or(|remote| state.last_sync_remote.as_deref() == Some(remote.as_str()))
    });

    let (records_pulled, records_pushed, last_status, last_error) = last
        .map(|result| {
            (
                result.records_pulled,
                result.records_pushed,
                Some(result.status.clone()),
                result.error.clone(),
            )
        })
        .unwrap_or((0, 0, None, None));

    let last_pull_cursor_json = last.and_then(|result| {
        result
            .checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.tenant == query.tenant)
            .filter(|checkpoint| {
                query
                    .remote
                    .as_ref()
                    .is_none_or(|remote| checkpoint.remote == *remote)
            })
            .filter_map(|checkpoint| checkpoint.pull_cursor.as_ref())
            .max_by_key(|cursor| cursor.position.clone())
            .and_then(|cursor| serde_json::to_string(cursor).ok())
    });

    EnboxSyncStatus {
        in_progress: state.sync_in_progress,
        last_status: last_status
            .map(sync_run_status_label)
            .unwrap_or_else(|| "idle".to_string()),
        last_error_code: last_error.as_ref().map(|error| error.code.clone()),
        last_error_detail: last_error.map(|error| error.detail),
        records_pulled,
        records_pushed,
        last_pull_cursor_json,
    }
}

fn sync_run_status_label(status: SyncRunStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessMessageSmokeRequest {
    tenant: String,
    message: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_message_roundtrips_unsigned_records_query() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let request = ProcessMessageSmokeRequest {
            tenant: "did:example:alice".to_string(),
            message: serde_json::json!({
                "descriptor": {
                    "interface": "Records",
                    "method": "Query",
                    "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                    "filter": {
                        "protocol": "https://example.com/test"
                    }
                }
            }),
        };
        let reply_json = core
            .process_message(
                request.tenant,
                serde_json::to_string(&request.message).expect("request json"),
            )
            .expect("process_message succeeds");
        let reply: serde_json::Value = serde_json::from_str(&reply_json).expect("reply json");
        assert_eq!(reply["status"]["code"], 200);
    }

    #[test]
    fn lock_blocks_process_message_with_typed_error() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        core.lock();
        let err = core
            .process_message("did:example:alice".to_string(), "{}".to_string())
            .expect_err("locked core rejects processing");
        assert!(matches!(err, EnboxError::Locked));
    }

    #[test]
    fn open_persists_at_filesystem_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("enbox.sqlite");
        let path = db_path.to_string_lossy().into_owned();

        {
            let core = EnboxCore::open(path.clone()).expect("open durable core");
            assert_eq!(core.status().database_path.as_deref(), Some(path.as_str()));
            let request = ProcessMessageSmokeRequest {
                tenant: "did:example:alice".to_string(),
                message: serde_json::json!({
                    "descriptor": {
                        "interface": "Records",
                        "method": "Query",
                        "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                        "filter": { "protocol": "https://example.com/test" }
                    }
                }),
            };
            core.process_message(
                request.tenant,
                serde_json::to_string(&request.message).expect("request json"),
            )
            .expect("process_message succeeds");
        }

        assert!(db_path.exists());
        let reopened = EnboxCore::open(path).expect("reopen durable core");
        assert!(reopened.status().initialized);
    }

    #[test]
    fn sync_once_requires_signer_and_reports_status_without_panic() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        core.register_sync_identity(
            serde_json::json!({
                "did": "did:example:alice",
                "protocols": { "type": "all" }
            })
            .to_string(),
        )
        .expect("register identity");

        let missing_signer = core.sync_once(
            serde_json::json!({
                "tenant": "did:example:alice",
                "remote": "http://127.0.0.1:9/",
                "direction": "pull"
            })
            .to_string(),
        );
        assert!(matches!(missing_signer, Err(EnboxError::SyncSignerMissing)));

        core.configure_sync_signer(
            serde_json::json!({
                "keyId": "did:example:alice#key1",
                "algorithm": "EdDSA",
                "privateJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
                    "d": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                    "kid": "did:example:alice#key1",
                    "alg": "EdDSA"
                }
            })
            .to_string(),
        )
        .expect("configure signer");

        let result_json = core
            .sync_once(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "remote": "http://127.0.0.1:9/",
                    "direction": "pull"
                })
                .to_string(),
            )
            .expect("sync_once returns json even when remote is unreachable");
        let result: SyncOnceResult = serde_json::from_str(&result_json).expect("sync result json");
        assert_eq!(result.status, SyncRunStatus::Failed);
        assert!(result.error.is_some());

        let status = core
            .sync_status(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "remote": "http://127.0.0.1:9/"
                })
                .to_string(),
            )
            .expect("sync_status");
        assert!(!status.in_progress);
        assert_eq!(status.last_status, "failed");
        assert!(status.last_error_code.is_some());

        let poll_json = core
            .poll_reconcile(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "remote": "http://127.0.0.1:9/",
                    "direction": "pull"
                })
                .to_string(),
            )
            .expect("poll_reconcile returns json even when remote is unreachable");
        let poll_result: SyncOnceResult =
            serde_json::from_str(&poll_json).expect("poll reconcile result json");
        assert_eq!(poll_result.status, SyncRunStatus::Failed);
    }

    fn configured_sync_core() -> Arc<EnboxCore> {
        let core = EnboxCore::open_in_memory().expect("core opens");
        core.register_sync_identity(
            serde_json::json!({
                "did": "did:example:alice",
                "protocols": { "type": "all" }
            })
            .to_string(),
        )
        .expect("register identity");
        core.configure_sync_signer(
            serde_json::json!({
                "keyId": "did:example:alice#key1",
                "algorithm": "EdDSA",
                "privateJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
                    "d": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                    "kid": "did:example:alice#key1",
                    "alg": "EdDSA"
                }
            })
            .to_string(),
        )
        .expect("configure signer");
        core
    }

    #[test]
    fn sync_once_respects_connectivity_offline_short_circuits_before_network() {
        let core = configured_sync_core();
        let result_json = core
            .sync_once(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "remote": "http://127.0.0.1:9/",
                    "direction": "pull",
                    "connectivity": {
                        "online": false,
                        "expensive": false,
                        "roaming": false,
                        "backgroundRestricted": false,
                        "powerSave": false,
                        "allowMetered": true,
                        "allowRoaming": false
                    }
                })
                .to_string(),
            )
            .expect("sync_once returns json when offline");
        let result: SyncOnceResult = serde_json::from_str(&result_json).expect("sync result json");
        assert_eq!(result.status, SyncRunStatus::NoConnectivity);
    }

    #[test]
    fn sync_once_respects_metered_connectivity_when_not_allowed() {
        let core = configured_sync_core();
        let result_json = core
            .sync_once(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "remote": "http://127.0.0.1:9/",
                    "direction": "pull",
                    "connectivity": {
                        "online": true,
                        "expensive": true,
                        "roaming": false,
                        "backgroundRestricted": false,
                        "powerSave": false,
                        "allowMetered": false,
                        "allowRoaming": false
                    }
                })
                .to_string(),
            )
            .expect("sync_once returns json when metered");
        let result: SyncOnceResult = serde_json::from_str(&result_json).expect("sync result json");
        assert_eq!(result.status, SyncRunStatus::NoConnectivity);
    }

    #[test]
    fn sync_once_enforces_deadline_returns_deadline_exceeded() {
        let core = configured_sync_core();
        let result_json = core
            .sync_once(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "remote": "http://10.255.255.1:9/",
                    "direction": "pull",
                    "deadlineMs": 50
                })
                .to_string(),
            )
            .expect("sync_once returns even when deadline expires");
        let result: SyncOnceResult = serde_json::from_str(&result_json).expect("sync result json");
        assert_eq!(result.status, SyncRunStatus::DeadlineExceeded);
        assert_eq!(result.next_recommended_delay_ms, Some(50));
    }

    #[test]
    fn initialize_runtime_records_host_metadata_in_status() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let baseline = core.status();
        assert!(baseline.initialized);
        assert!(baseline.device_id.is_none());
        assert!(!baseline.background_refresh_enabled);
        assert!(baseline.active_background_tasks.is_empty());

        let status = core
            .initialize_runtime(
                serde_json::json!({
                    "deviceId": "device-123",
                    "appGroup": "group.com.enbox.app",
                    "backgroundRefreshEnabled": true
                })
                .to_string(),
            )
            .expect("initialize_runtime");
        assert_eq!(status.device_id.as_deref(), Some("device-123"));
        assert_eq!(status.app_group.as_deref(), Some("group.com.enbox.app"));
        assert!(status.background_refresh_enabled);
        // database_path is set by `open_in_memory` to None; the host did
        // not override it.
        assert!(status.database_path.is_none());

        let refreshed = core.status();
        assert_eq!(refreshed, status, "status() and initialize_runtime() agree");
    }

    #[test]
    fn unlock_with_reason_records_audit_label_and_lock_clears_it() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        core.lock();
        assert!(core.status().locked);

        core.unlock_with_reason("push_notification".to_string())
            .expect("unlock_with_reason");
        let status = core.status();
        assert!(!status.locked);
        assert_eq!(
            status.last_unlock_reason.as_deref(),
            Some("push_notification")
        );

        core.lock();
        let after_lock = core.status();
        assert!(after_lock.locked);
        assert!(after_lock.last_unlock_reason.is_none());
    }

    #[test]
    fn background_task_tracking_is_idempotent_and_set_membership_based() {
        let core = EnboxCore::open_in_memory().expect("core opens");

        assert!(core.begin_background_task("task-1".to_string()).unwrap());
        assert!(core.begin_background_task("task-2".to_string()).unwrap());
        assert!(
            !core.begin_background_task("task-1".to_string()).unwrap(),
            "begin returns false when the task id is already active"
        );

        let active = core.status().active_background_tasks;
        assert_eq!(active, vec!["task-1".to_string(), "task-2".to_string()]);

        assert!(core.end_background_task("task-1".to_string()).unwrap());
        assert!(
            !core.end_background_task("task-1".to_string()).unwrap(),
            "end returns false when the task id is not active"
        );

        let remaining = core.status().active_background_tasks;
        assert_eq!(remaining, vec!["task-2".to_string()]);
    }

    #[test]
    fn list_pending_scopes_returns_empty_when_no_checkpoints_exist() {
        let core = configured_sync_core();
        let result = core
            .list_pending_scopes(serde_json::json!({ "tenant": "did:example:alice" }).to_string())
            .expect("list_pending_scopes returns json");
        let scopes: serde_json::Value = serde_json::from_str(&result).expect("json array");
        assert!(scopes.is_array());
        assert_eq!(scopes.as_array().unwrap().len(), 0);
    }

    #[test]
    fn resume_pending_returns_attempted_zero_when_no_work_is_pending() {
        let core = configured_sync_core();
        let result_json = core
            .resume_pending(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "deadlineMs": 5_000
                })
                .to_string(),
            )
            .expect("resume_pending returns json");
        let parsed: serde_json::Value =
            serde_json::from_str(&result_json).expect("response parses");
        assert_eq!(parsed["attempted"], 0);
        assert_eq!(parsed["deadlineExceeded"], false);
        assert!(parsed["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn resume_pending_rejects_missing_signer() {
        // No `configure_sync_signer` call, so the resume should fail
        // even when there's nothing to do — the lock guard runs before
        // the no-work short-circuit returns.
        let core = EnboxCore::open_in_memory().expect("core opens");
        core.register_sync_identity(
            serde_json::json!({
                "did": "did:example:alice",
                "protocols": { "type": "all" }
            })
            .to_string(),
        )
        .expect("register identity");

        let err = core.resume_pending(
            serde_json::json!({
                "tenant": "did:example:alice"
            })
            .to_string(),
        );
        assert!(matches!(err, Err(EnboxError::SyncSignerMissing)));
    }

    #[test]
    fn resume_pending_rejects_locked_core() {
        let core = configured_sync_core();
        core.lock();
        let err = core.resume_pending(
            serde_json::json!({
                "tenant": "did:example:alice"
            })
            .to_string(),
        );
        assert!(matches!(err, Err(EnboxError::Locked)));
    }

    #[test]
    fn list_pending_scopes_surfaces_seeded_checkpoint_and_resume_drains_it_against_unreachable_remote(
    ) {
        use dwn_rs_core::sync::{SyncCheckpoint, SyncDirection, SyncScope};
        use dwn_rs_core::sync_ledger::SyncLedger;

        let core = configured_sync_core();

        // Seed a pending checkpoint directly through the ledger so we
        // exercise the resume path without standing up a peer.
        {
            let state = core.state.lock().expect("state lock");
            let node = state.node.as_ref().expect("node initialised").clone();
            drop(state);
            let checkpoint = SyncCheckpoint {
                key: "did:example:alice|http://10.255.255.1:9/|global|Pull".to_string(),
                tenant: "did:example:alice".to_string(),
                remote: "http://10.255.255.1:9/".to_string(),
                scope_id: SyncScope::Full.id(),
                direction: SyncDirection::Pull,
                local_root: None,
                remote_root: None,
                pending_pull_prefixes: vec!["10".to_string()],
                pending_push_prefixes: Vec::new(),
                pull_cursor: None,
                push_cursor: None,
                records_pulled: 0,
                records_pushed: 0,
                bytes_downloaded: 0,
                bytes_uploaded: 0,
                last_error: None,
                updated_at: chrono::Utc::now(),
            };
            node.sync_ledger()
                .upsert_checkpoint(&checkpoint)
                .expect("upsert seeded checkpoint");
        }

        let scopes_json = core
            .list_pending_scopes(serde_json::json!({ "tenant": "did:example:alice" }).to_string())
            .expect("list_pending_scopes returns json");
        let scopes: serde_json::Value = serde_json::from_str(&scopes_json).expect("scopes json");
        let array = scopes.as_array().expect("scopes is array");
        assert_eq!(array.len(), 1, "the seeded checkpoint shows up as pending");
        assert_eq!(array[0]["tenant"], "did:example:alice");
        assert_eq!(array[0]["remote"], "http://10.255.255.1:9/");
        assert_eq!(array[0]["protocol"], serde_json::Value::Null);
        assert_eq!(array[0]["direction"], "pull");
        assert_eq!(array[0]["pendingPullCount"], 1);

        // Tight deadline against an unreachable IP: the resume batch
        // must finish (returning a `failed`/`deadlineExceeded` per
        // scope) without panicking and without leaving the in-progress
        // flag set.
        let resume_json = core
            .resume_pending(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "deadlineMs": 250,
                })
                .to_string(),
            )
            .expect("resume_pending returns json even when remote is unreachable");
        let resume: serde_json::Value =
            serde_json::from_str(&resume_json).expect("resume result json");
        assert_eq!(resume["attempted"], 1);
        // Either the batch finishes (`results.len == attempted`,
        // `deadlineExceeded == false` with a per-scope failure) or the
        // deadline elapses (`results.len == 0`, `deadlineExceeded ==
        // true`). Both outcomes are acceptable; what matters is that we
        // never leave sync_in_progress true.
        let deadline_exceeded = resume["deadlineExceeded"].as_bool().unwrap();
        let results_len = resume["results"].as_array().unwrap().len();
        if deadline_exceeded {
            assert_eq!(results_len, 0);
        } else {
            assert_eq!(results_len, 1);
        }

        // Verify the sync_in_progress guard was released either way.
        let status_json = core
            .sync_status(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "remote": "http://10.255.255.1:9/"
                })
                .to_string(),
            )
            .expect("sync_status");
        assert!(!status_json.in_progress);
    }

    #[test]
    fn poll_reconcile_enforces_deadline_returns_deadline_exceeded() {
        let core = configured_sync_core();
        let result_json = core
            .poll_reconcile(
                serde_json::json!({
                    "tenant": "did:example:alice",
                    "remote": "http://10.255.255.1:9/",
                    "direction": "pull",
                    "deadlineMs": 50
                })
                .to_string(),
            )
            .expect("poll_reconcile returns even when deadline expires");
        let result: SyncOnceResult = serde_json::from_str(&result_json).expect("poll result json");
        assert_eq!(result.status, SyncRunStatus::DeadlineExceeded);
    }

    const TEST_RECOVERY_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn initialize_agent_identity_is_deterministic_for_a_given_phrase() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp
            .path()
            .join("agent.sqlite")
            .to_string_lossy()
            .into_owned();

        let core = EnboxCore::open(path.clone()).expect("open core");
        let raw = core
            .initialize_agent_identity(
                serde_json::json!({
                    "recoveryPhrase": TEST_RECOVERY_PHRASE,
                    "dwnEndpoints": ["https://dwn.example/"]
                })
                .to_string(),
            )
            .expect("initialize agent");

        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("init json");
        let did_uri = parsed["portableDid"]["uri"]
            .as_str()
            .expect("did uri present")
            .to_string();
        assert!(did_uri.starts_with("did:jwk:"), "got {did_uri}");
        assert_eq!(parsed["recoveryPhrase"], TEST_RECOVERY_PHRASE);
        assert!(parsed["vaultContentEncryptionKey"].is_array());
        assert!(parsed["vaultUnlockSalt"].is_array());

        let current = core
            .current_agent_identity()
            .expect("current identity")
            .expect("identity persisted");
        let current_did: serde_json::Value =
            serde_json::from_str(&current).expect("current identity json");
        assert_eq!(
            current_did["uri"],
            serde_json::Value::String(did_uri.clone())
        );

        drop(core);
        let reopened = EnboxCore::open(path).expect("reopen core");
        let reopened_raw = reopened
            .current_agent_identity()
            .expect("current identity on reopened core")
            .expect("identity persisted across reopen");
        let reopened_did: serde_json::Value =
            serde_json::from_str(&reopened_raw).expect("reopened identity json");
        assert_eq!(reopened_did["uri"], serde_json::Value::String(did_uri));
    }

    #[test]
    fn initialize_agent_identity_without_phrase_generates_random_did() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let raw = core
            .initialize_agent_identity(serde_json::json!({ "dwnEndpoints": [] }).to_string())
            .expect("initialize agent");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("init json");
        let phrase = parsed["recoveryPhrase"].as_str().expect("generated phrase");
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn current_agent_identity_returns_none_before_initialize() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let identity = core.current_agent_identity().expect("current identity");
        assert!(identity.is_none());
    }

    #[test]
    fn derive_agent_keys_from_phrase_does_not_persist() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let derived_raw = core
            .derive_agent_keys_from_phrase(TEST_RECOVERY_PHRASE.to_string())
            .expect("derive keys");
        let derived: serde_json::Value =
            serde_json::from_str(&derived_raw).expect("derived keys json");
        assert_eq!(derived["identityPrivateJwk"]["kty"], "OKP");
        assert_eq!(derived["signingPrivateJwk"]["crv"], "Ed25519");
        assert_eq!(derived["encryptionPrivateJwk"]["crv"], "X25519");
        assert!(derived["vaultContentEncryptionKey"].is_array());

        let after = core.current_agent_identity().expect("current identity");
        assert!(
            after.is_none(),
            "deriving keys should not persist an identity"
        );
    }

    #[test]
    fn vault_touching_agent_methods_fail_when_locked() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        core.lock();
        let err = core
            .initialize_agent_identity(serde_json::json!({ "dwnEndpoints": [] }).to_string())
            .expect_err("locked initialize must fail");
        assert!(matches!(err, EnboxError::Locked));
        let err = core
            .current_agent_identity()
            .expect_err("locked current must fail");
        assert!(matches!(err, EnboxError::Locked));
    }

    #[test]
    fn derive_agent_keys_is_pure_and_works_while_locked() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        core.lock();
        let raw = core
            .derive_agent_keys_from_phrase(TEST_RECOVERY_PHRASE.to_string())
            .expect("derive runs while locked (no vault access)");
        let derived: serde_json::Value = serde_json::from_str(&raw).expect("derived keys json");
        assert_eq!(derived["signingPrivateJwk"]["crv"], "Ed25519");
    }

    fn initialized_core_with_did() -> (Arc<EnboxCore>, serde_json::Value) {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let init_raw = core
            .initialize_agent_identity(
                serde_json::json!({
                    "recoveryPhrase": TEST_RECOVERY_PHRASE,
                    "dwnEndpoints": []
                })
                .to_string(),
            )
            .expect("initialize agent");
        let init: serde_json::Value = serde_json::from_str(&init_raw).expect("initialization json");
        let portable_did = init["portableDid"].clone();
        (core, portable_did)
    }

    fn plain_protocol_definition() -> serde_json::Value {
        serde_json::json!({
            "protocol": "https://protocol.example/notes",
            "published": true,
            "types": {
                "note": {
                    "schema": "https://schema.example/note",
                    "dataFormats": ["text/plain"]
                }
            },
            "structure": {
                "note": {
                    "$actions": [{ "who": "anyone", "can": ["create", "read"] }]
                }
            }
        })
    }

    fn encrypted_protocol_definition() -> serde_json::Value {
        serde_json::json!({
            "protocol": "https://protocol.example/private-notes",
            "published": true,
            "types": {
                "note": {
                    "schema": "https://schema.example/note",
                    "dataFormats": ["text/plain"],
                    "encryptionRequired": true
                }
            },
            "structure": {
                "note": {
                    "$actions": [{ "who": "anyone", "can": ["create"] }]
                }
            }
        })
    }

    #[test]
    fn install_protocol_persists_and_is_idempotent() {
        let (core, portable_did) = initialized_core_with_did();
        let tenant = portable_did.to_string();
        let definition = plain_protocol_definition().to_string();

        let first_raw = core
            .install_protocol(tenant.clone(), definition.clone())
            .expect("install first time");
        let first: serde_json::Value =
            serde_json::from_str(&first_raw).expect("install result json");
        assert_eq!(first["installed"], true);
        assert_eq!(first["encryptionActive"], false);
        assert_eq!(first["protocol"], "https://protocol.example/notes");

        let second_raw = core
            .install_protocol(tenant, definition)
            .expect("install second time is no-op");
        let second: serde_json::Value =
            serde_json::from_str(&second_raw).expect("install result json");
        assert_eq!(second["installed"], false);
    }

    #[test]
    fn install_encrypted_protocol_injects_key_agreement() {
        let (core, portable_did) = initialized_core_with_did();
        let tenant_did_json = portable_did.to_string();
        let definition_json = encrypted_protocol_definition().to_string();

        let augmented_raw = core
            .inject_protocol_encryption(tenant_did_json.clone(), definition_json.clone())
            .expect("inject encryption");
        let augmented: serde_json::Value =
            serde_json::from_str(&augmented_raw).expect("definition json");
        assert!(
            augmented["structure"]["note"]["$encryption"].is_object(),
            "encryption block missing: {augmented:?}"
        );

        let install_raw = core
            .install_protocol(tenant_did_json, definition_json)
            .expect("install encrypted protocol");
        let install: serde_json::Value =
            serde_json::from_str(&install_raw).expect("install result");
        assert_eq!(install["installed"], true);
        assert_eq!(install["encryptionActive"], true);
    }

    #[test]
    fn install_protocol_rejects_locked_core() {
        let (core, portable_did) = initialized_core_with_did();
        core.lock();
        let err = core
            .install_protocol(
                portable_did.to_string(),
                plain_protocol_definition().to_string(),
            )
            .expect_err("install must fail while locked");
        assert!(matches!(err, EnboxError::Locked));
    }

    #[test]
    fn install_protocol_rejects_invalid_did() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let err = core
            .install_protocol(
                "not-json".to_string(),
                plain_protocol_definition().to_string(),
            )
            .expect_err("invalid did must fail");
        assert!(matches!(err, EnboxError::Json { .. }));
    }

    fn sample_permission_scope() -> serde_json::Value {
        serde_json::json!({
            "interface": "Records",
            "method": "Read",
            "protocol": "https://protocol.example/notes",
            "protocolPath": "note"
        })
    }

    #[test]
    fn create_permission_request_returns_record_with_id() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let request = serde_json::json!({
            "requester": "did:example:requester",
            "scope": sample_permission_scope(),
            "delegated": true,
            "description": "demo"
        });
        let raw = core
            .create_permission_request(request.to_string())
            .expect("create permission request");
        let record: serde_json::Value = serde_json::from_str(&raw).expect("record json");
        assert!(record["id"].as_str().is_some_and(|id| !id.is_empty()));
        assert_eq!(record["requester"], "did:example:requester");
        assert_eq!(record["delegated"], true);
        assert_eq!(record["description"], "demo");
        assert_eq!(record["scope"]["interface"], "Records");
    }

    #[test]
    fn create_delegate_grant_emits_delegated_grant_with_dates() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let request = serde_json::json!({
            "grantor": "did:example:owner",
            "grantee": "did:example:delegate",
            "scope": sample_permission_scope(),
            "dateExpires": "2030-01-01T00:00:00Z"
        });
        let raw = core
            .create_delegate_grant(request.to_string())
            .expect("create delegate grant");
        let grant: serde_json::Value = serde_json::from_str(&raw).expect("grant json");
        assert!(grant["id"].as_str().is_some_and(|id| !id.is_empty()));
        assert_eq!(grant["grantor"], "did:example:owner");
        assert_eq!(grant["grantee"], "did:example:delegate");
        assert_eq!(grant["delegated"], true);
        assert_eq!(grant["dateExpires"], "2030-01-01T00:00:00Z");
        assert!(grant["dateGranted"].as_str().is_some());
    }

    #[test]
    fn create_grant_revocation_carries_grant_and_revocation_ids() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let grant_raw = core
            .create_delegate_grant(
                serde_json::json!({
                    "grantor": "did:example:owner",
                    "grantee": "did:example:delegate",
                    "scope": sample_permission_scope(),
                    "dateExpires": "2030-01-01T00:00:00Z"
                })
                .to_string(),
            )
            .expect("create grant");
        let grant: serde_json::Value = serde_json::from_str(&grant_raw).expect("grant json");
        let grant_id = grant["id"].as_str().expect("grant id").to_string();

        let revocation_raw = core
            .create_grant_revocation(
                serde_json::json!({
                    "grant": grant,
                    "revocationGrantId": "revocation-1"
                })
                .to_string(),
            )
            .expect("create revocation");
        let revocation: serde_json::Value =
            serde_json::from_str(&revocation_raw).expect("revocation json");
        assert_eq!(revocation["grantId"], grant_id);
        assert_eq!(revocation["revocationGrantId"], "revocation-1");
        assert_eq!(revocation["grantor"], "did:example:owner");
        assert_eq!(revocation["grantee"], "did:example:delegate");
        assert!(revocation["dateRevoked"].as_str().is_some());
    }

    fn encrypted_connect_protocol_definition() -> serde_json::Value {
        serde_json::json!({
            "protocol": "https://protocol.example/private-notes",
            "published": true,
            "types": {
                "note": {
                    "dataFormats": ["text/plain"],
                    "encryptionRequired": true
                }
            },
            "structure": {
                "note": {
                    "$actions": [{ "who": "anyone", "can": ["create"] }]
                }
            }
        })
    }

    #[test]
    fn derive_delegate_keys_returns_decryption_key_for_read_scope() {
        let (core, portable_did) = initialized_core_with_did();
        let request = serde_json::json!({
            "ownerDid": portable_did,
            "requests": [{
                "protocolDefinition": encrypted_connect_protocol_definition(),
                "permissionScopes": [{
                    "interface": "Records",
                    "method": "Read",
                    "protocol": "https://protocol.example/private-notes",
                    "protocolPath": "note"
                }]
            }]
        });
        let raw = core
            .derive_delegate_keys(request.to_string())
            .expect("derive delegate keys");
        let result: serde_json::Value = serde_json::from_str(&raw).expect("derivation json");
        let keys = result["decryptionKeys"]
            .as_array()
            .expect("decryption keys array");
        assert_eq!(keys.len(), 1, "expected one decryption key: {result:?}");
        assert_eq!(
            keys[0]["protocol"],
            "https://protocol.example/private-notes"
        );
        assert_eq!(
            keys[0]["derivedPrivateKey"]["derivedPrivateKey"]["crv"],
            "X25519"
        );
        assert!(result["multiPartyProtocols"]
            .as_array()
            .is_some_and(Vec::is_empty));
    }

    #[test]
    fn derive_delegate_keys_skips_protocols_that_do_not_require_encryption() {
        let (core, portable_did) = initialized_core_with_did();
        let request = serde_json::json!({
            "ownerDid": portable_did,
            "requests": [{
                "protocolDefinition": plain_protocol_definition(),
                "permissionScopes": [{
                    "interface": "Records",
                    "method": "Read",
                    "protocol": "https://protocol.example/notes",
                    "protocolPath": "note"
                }]
            }]
        });
        let raw = core
            .derive_delegate_keys(request.to_string())
            .expect("derive delegate keys");
        let result: serde_json::Value = serde_json::from_str(&raw).expect("derivation json");
        assert!(result["decryptionKeys"]
            .as_array()
            .is_some_and(Vec::is_empty));
    }

    #[test]
    fn derive_context_key_returns_context_scoped_x25519_key() {
        let (core, portable_did) = initialized_core_with_did();
        let request = serde_json::json!({
            "ownerDid": portable_did,
            "protocol": "https://protocol.example/notes",
            "contextId": "context-abc"
        });
        let raw = core
            .derive_context_key(request.to_string())
            .expect("derive context key");
        let key: serde_json::Value = serde_json::from_str(&raw).expect("context key json");
        assert_eq!(key["protocol"], "https://protocol.example/notes");
        assert_eq!(key["contextId"], "context-abc");
        assert_eq!(
            key["derivedPrivateKey"]["derivedPrivateKey"]["crv"],
            "X25519"
        );
    }

    #[test]
    fn delegate_decryption_keys_roundtrip_through_secret_store() {
        let (core, portable_did) = initialized_core_with_did();
        let derived_raw = core
            .derive_delegate_keys(
                serde_json::json!({
                    "ownerDid": portable_did,
                    "requests": [{
                        "protocolDefinition": encrypted_connect_protocol_definition(),
                        "permissionScopes": [{
                            "interface": "Records",
                            "method": "Read",
                            "protocol": "https://protocol.example/private-notes",
                            "protocolPath": "note"
                        }]
                    }]
                })
                .to_string(),
            )
            .expect("derive delegate keys");
        let derived: serde_json::Value =
            serde_json::from_str(&derived_raw).expect("derivation json");
        let keys = derived["decryptionKeys"].clone();

        core.save_delegate_decryption_keys(keys.to_string())
            .expect("save decryption keys");
        let loaded_raw = core
            .load_delegate_decryption_keys()
            .expect("load decryption keys");
        let loaded: serde_json::Value = serde_json::from_str(&loaded_raw).expect("loaded json");
        assert_eq!(loaded, keys);
    }

    #[test]
    fn delegate_context_keys_roundtrip_through_secret_store() {
        let (core, portable_did) = initialized_core_with_did();
        let derived_raw = core
            .derive_context_key(
                serde_json::json!({
                    "ownerDid": portable_did,
                    "protocol": "https://protocol.example/notes",
                    "contextId": "context-1"
                })
                .to_string(),
            )
            .expect("derive context key");
        let key: serde_json::Value = serde_json::from_str(&derived_raw).expect("key json");

        let payload = serde_json::Value::Array(vec![key.clone()]);
        core.save_delegate_context_keys(payload.to_string())
            .expect("save context keys");
        let loaded_raw = core
            .load_delegate_context_keys()
            .expect("load context keys");
        let loaded: serde_json::Value = serde_json::from_str(&loaded_raw).expect("loaded json");
        assert_eq!(loaded, payload);
    }

    #[test]
    fn load_delegate_decryption_keys_returns_empty_array_when_unset() {
        let (core, _) = initialized_core_with_did();
        let raw = core
            .load_delegate_decryption_keys()
            .expect("load when unset");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("load json");
        assert!(parsed.as_array().is_some_and(Vec::is_empty));
    }

    #[test]
    fn load_delegate_context_keys_returns_empty_array_when_unset() {
        let (core, _) = initialized_core_with_did();
        let raw = core.load_delegate_context_keys().expect("load when unset");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("load json");
        assert!(parsed.as_array().is_some_and(Vec::is_empty));
    }

    #[test]
    fn connect_state_touching_methods_reject_locked_core() {
        let (core, portable_did) = initialized_core_with_did();
        core.lock();

        let err = core
            .derive_delegate_keys(
                serde_json::json!({ "ownerDid": portable_did, "requests": [] }).to_string(),
            )
            .expect_err("derive must fail while locked");
        assert!(matches!(err, EnboxError::Locked));

        let err = core
            .derive_context_key(
                serde_json::json!({
                    "ownerDid": portable_did,
                    "protocol": "p",
                    "contextId": "c"
                })
                .to_string(),
            )
            .expect_err("context key must fail while locked");
        assert!(matches!(err, EnboxError::Locked));

        let err = core
            .save_delegate_decryption_keys("[]".to_string())
            .expect_err("save must fail while locked");
        assert!(matches!(err, EnboxError::Locked));

        let err = core
            .load_delegate_context_keys()
            .expect_err("load must fail while locked");
        assert!(matches!(err, EnboxError::Locked));
    }

    #[test]
    fn pure_connect_constructors_work_while_locked() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        core.lock();
        let raw = core
            .create_permission_request(
                serde_json::json!({
                    "requester": "did:example:requester",
                    "scope": sample_permission_scope(),
                    "delegated": false
                })
                .to_string(),
            )
            .expect("create runs while locked - no vault access");
        let record: serde_json::Value = serde_json::from_str(&raw).expect("record json");
        assert_eq!(record["delegated"], false);
    }

    #[test]
    fn connect_methods_surface_json_errors() {
        let core = EnboxCore::open_in_memory().expect("core opens");
        let err = core
            .create_permission_request("not-json".to_string())
            .expect_err("invalid json must fail");
        assert!(matches!(err, EnboxError::Json { .. }));
        let err = core
            .save_delegate_decryption_keys("not-json".to_string())
            .expect_err("invalid json must fail");
        assert!(matches!(err, EnboxError::Json { .. }));
    }

    mod http_setup_tests {
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::thread::JoinHandle as ThreadJoinHandle;

        use axum::extract::State;
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::IntoResponse;
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use serde_json::Value as JsonValue;
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;

        use super::{
            initialized_core_with_did, plain_protocol_definition, EnboxCore, EnboxError,
            TEST_RECOVERY_PHRASE,
        };

        #[derive(Debug, Clone)]
        pub(super) struct RegistrationCall {
            pub did: String,
            pub registration_token: Option<String>,
        }

        #[derive(Default)]
        pub(super) struct MockState {
            pub info_response: JsonValue,
            pub registration_calls: Vec<RegistrationCall>,
            pub refresh_calls: Vec<String>,
            pub refresh_response: Option<JsonValue>,
            pub dwn_replies: Vec<JsonValue>,
            pub dwn_calls: Vec<JsonValue>,
        }

        /// Mock `@enbox/dwn-server`-style HTTP server that runs on a
        /// dedicated multi-threaded tokio runtime hosted on its own OS
        /// thread, so the FFI's blocking `block_on` calls can drive
        /// requests against it without the runtime being dropped between
        /// calls.
        pub(super) struct MockServer {
            pub url: String,
            pub state: Arc<Mutex<MockState>>,
            shutdown: Option<oneshot::Sender<()>>,
            thread: Option<ThreadJoinHandle<()>>,
        }

        impl MockServer {
            pub fn snapshot(&self) -> MockSnapshot {
                let guard = self.state.lock().unwrap();
                MockSnapshot {
                    registration_calls: guard.registration_calls.clone(),
                    refresh_calls: guard.refresh_calls.clone(),
                    dwn_calls: guard.dwn_calls.clone(),
                }
            }
        }

        impl Drop for MockServer {
            fn drop(&mut self) {
                if let Some(shutdown) = self.shutdown.take() {
                    let _ = shutdown.send(());
                }
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
        }

        #[derive(Debug, Clone)]
        pub(super) struct MockSnapshot {
            pub registration_calls: Vec<RegistrationCall>,
            pub refresh_calls: Vec<String>,
            pub dwn_calls: Vec<JsonValue>,
        }

        async fn info_handler(State(state): State<Arc<Mutex<MockState>>>) -> impl IntoResponse {
            let body = state.lock().unwrap().info_response.clone();
            Json(body)
        }

        async fn registration_handler(
            State(state): State<Arc<Mutex<MockState>>>,
            Json(body): Json<JsonValue>,
        ) -> impl IntoResponse {
            let did = body
                .get("did")
                .and_then(|did| did.as_str())
                .unwrap_or_default()
                .to_string();
            let registration_token = body
                .get("registrationToken")
                .and_then(|token| token.as_str())
                .map(str::to_string);
            state
                .lock()
                .unwrap()
                .registration_calls
                .push(RegistrationCall {
                    did,
                    registration_token,
                });
            StatusCode::OK
        }

        async fn refresh_handler(
            State(state): State<Arc<Mutex<MockState>>>,
            Json(body): Json<JsonValue>,
        ) -> impl IntoResponse {
            let token = body
                .get("refreshToken")
                .and_then(|token| token.as_str())
                .unwrap_or_default()
                .to_string();
            let mut guard = state.lock().unwrap();
            guard.refresh_calls.push(token);
            let response = guard.refresh_response.clone().unwrap_or_else(|| {
                serde_json::json!({
                    "registrationToken": "fresh-token",
                    "tokenUrl": "https://example.invalid/token"
                })
            });
            (StatusCode::OK, Json(response))
        }

        async fn dwn_handler(
            State(state): State<Arc<Mutex<MockState>>>,
            headers: HeaderMap,
        ) -> impl IntoResponse {
            let Some(request_header) = headers
                .get("dwn-request")
                .and_then(|value| value.to_str().ok())
            else {
                return (StatusCode::BAD_REQUEST, "missing dwn-request").into_response();
            };
            let envelope: JsonValue = match serde_json::from_str(request_header) {
                Ok(value) => value,
                Err(err) => {
                    return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
                }
            };
            let id = envelope.get("id").cloned().unwrap_or(JsonValue::Null);

            let mut guard = state.lock().unwrap();
            guard.dwn_calls.push(envelope.clone());
            let reply = if guard.dwn_replies.is_empty() {
                serde_json::json!({ "status": { "code": 202, "detail": "Accepted" } })
            } else {
                guard.dwn_replies.remove(0)
            };
            drop(guard);

            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "reply": reply }
            });
            (StatusCode::OK, Json(body)).into_response()
        }

        pub(super) fn start_mock_server() -> MockServer {
            let state = Arc::new(Mutex::new(MockState::default()));
            let state_clone = state.clone();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<String>();

            let thread = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .expect("mock server runtime");
                runtime.block_on(async move {
                    let app = Router::new()
                        .route("/info", get(info_handler))
                        .route("/registration", post(registration_handler))
                        .route("/refresh", post(refresh_handler))
                        .route("/", post(dwn_handler))
                        .with_state(state_clone);
                    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                        .await
                        .expect("listener");
                    let addr = listener.local_addr().expect("local addr");
                    ready_tx
                        .send(format!("http://{addr}"))
                        .expect("ready signal");
                    let _ = axum::serve(listener, app)
                        .with_graceful_shutdown(async {
                            let _ = shutdown_rx.await;
                        })
                        .await;
                });
            });

            let url = ready_rx.recv().expect("mock server start");
            MockServer {
                url,
                state,
                shutdown: Some(shutdown_tx),
                thread: Some(thread),
            }
        }

        fn portable_did_uri(portable_did: &JsonValue) -> String {
            portable_did["uri"].as_str().expect("did uri").to_string()
        }

        #[test]
        fn register_tenant_handles_anonymous_endpoint() {
            let server = start_mock_server();
            {
                let mut guard = server.state.lock().unwrap();
                guard.info_response = serde_json::json!({
                    "registrationRequirements": [],
                });
            }
            let (core, portable_did) = initialized_core_with_did();
            let agent_did = portable_did_uri(&portable_did);

            let raw = core
                .register_tenant(
                    serde_json::json!({
                        "dwnEndpoints": [server.url.clone()],
                        "agentDid": agent_did,
                        "connectedDid": agent_did,
                    })
                    .to_string(),
                )
                .expect("register tenant");
            let result: JsonValue = serde_json::from_str(&raw).expect("registration json");
            let records = result["records"].as_array().expect("records array");
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["endpoint"], server.url);
            assert_eq!(records[0]["did"], agent_did);
            assert_eq!(records[0]["method"], "not_required");

            let snapshot = server.snapshot();
            assert_eq!(
                snapshot.registration_calls.len(),
                0,
                "anonymous endpoints with no requirements should skip /registration"
            );
        }

        #[test]
        fn register_tenant_handles_provider_auth_endpoint() {
            let server = start_mock_server();
            {
                let mut guard = server.state.lock().unwrap();
                guard.info_response = serde_json::json!({
                    "registrationRequirements": ["provider-auth-v0"],
                    "providerAuth": {
                        "authorizeUrl": "https://example.invalid/authorize",
                        "tokenUrl": "https://example.invalid/token"
                    }
                });
            }
            let (core, portable_did) = initialized_core_with_did();
            let agent_did = portable_did_uri(&portable_did);

            let raw = core
                .register_tenant(
                    serde_json::json!({
                        "dwnEndpoints": [server.url.clone()],
                        "agentDid": agent_did,
                        "connectedDid": agent_did,
                        "registrationTokens": {
                            server.url.clone(): {
                                "registrationToken": "preset-token",
                                "tokenUrl": "https://example.invalid/token"
                            }
                        }
                    })
                    .to_string(),
                )
                .expect("register tenant with token");
            let result: JsonValue = serde_json::from_str(&raw).expect("registration json");
            let records = result["records"].as_array().expect("records array");
            assert_eq!(records[0]["method"], "provider_auth_token");

            let snapshot = server.snapshot();
            assert_eq!(snapshot.registration_calls.len(), 1);
            assert_eq!(snapshot.registration_calls[0].did, agent_did);
            assert_eq!(
                snapshot.registration_calls[0].registration_token.as_deref(),
                Some("preset-token")
            );
        }

        #[test]
        fn register_tenant_refreshes_expired_token() {
            let server = start_mock_server();
            let refresh_url = format!("{}/refresh", server.url);
            {
                let mut guard = server.state.lock().unwrap();
                guard.info_response = serde_json::json!({
                    "registrationRequirements": ["provider-auth-v0"],
                    "providerAuth": {
                        "authorizeUrl": "https://example.invalid/authorize",
                        "tokenUrl": "https://example.invalid/token",
                        "refreshUrl": refresh_url
                    }
                });
                guard.refresh_response = Some(serde_json::json!({
                    "registrationToken": "fresh-token",
                    "tokenUrl": "https://example.invalid/token"
                }));
            }
            let (core, portable_did) = initialized_core_with_did();
            let agent_did = portable_did_uri(&portable_did);

            let raw = core
                .register_tenant(
                    serde_json::json!({
                        "dwnEndpoints": [server.url.clone()],
                        "agentDid": agent_did,
                        "connectedDid": agent_did,
                        "registrationTokens": {
                            server.url.clone(): {
                                "registrationToken": "stale-token",
                                "tokenUrl": "https://example.invalid/token",
                                "refreshUrl": refresh_url,
                                "refreshToken": "stale-refresh",
                                "expiresAt": 1
                            }
                        }
                    })
                    .to_string(),
                )
                .expect("register tenant with refresh");
            let result: JsonValue = serde_json::from_str(&raw).expect("registration json");
            let tokens = result["registrationTokens"]
                .as_object()
                .expect("tokens map");
            let updated = tokens
                .get(&server.url)
                .and_then(JsonValue::as_object)
                .expect("updated entry");
            assert_eq!(
                updated.get("registrationToken").and_then(JsonValue::as_str),
                Some("fresh-token")
            );

            let snapshot = server.snapshot();
            assert_eq!(snapshot.refresh_calls, vec!["stale-refresh".to_string()]);
            assert_eq!(snapshot.registration_calls.len(), 1);
            assert_eq!(
                snapshot.registration_calls[0].registration_token.as_deref(),
                Some("fresh-token")
            );
        }

        #[test]
        fn push_protocol_returns_installed_true_when_remote_is_empty() {
            let server = start_mock_server();
            {
                let mut guard = server.state.lock().unwrap();
                guard.dwn_replies.push(serde_json::json!({
                    "status": { "code": 200, "detail": "OK" },
                    "entries": []
                }));
                guard.dwn_replies.push(serde_json::json!({
                    "status": { "code": 202, "detail": "Accepted" }
                }));
            }
            let (core, portable_did) = initialized_core_with_did();
            let raw = core
                .push_protocol(
                    serde_json::json!({
                        "tenantDid": portable_did,
                        "remoteUrl": server.url,
                        "definition": plain_protocol_definition()
                    })
                    .to_string(),
                )
                .expect("push protocol");
            let result: JsonValue = serde_json::from_str(&raw).expect("push result");
            assert_eq!(result["installed"], true);
            assert_eq!(result["encryptionActive"], false);
            assert_eq!(result["protocol"], "https://protocol.example/notes");
            let snapshot = server.snapshot();
            assert_eq!(
                snapshot.dwn_calls.len(),
                2,
                "expected query then configure roundtrips"
            );
        }

        #[test]
        fn push_protocol_is_idempotent_when_remote_already_has_definition() {
            let server = start_mock_server();
            {
                let mut guard = server.state.lock().unwrap();
                guard.dwn_replies.push(serde_json::json!({
                    "status": { "code": 200, "detail": "OK" },
                    "entries": [{
                        "descriptor": {
                            "interface": "Protocols",
                            "method": "Configure",
                            "definition": plain_protocol_definition()
                        }
                    }]
                }));
            }
            let (core, portable_did) = initialized_core_with_did();
            let raw = core
                .push_protocol(
                    serde_json::json!({
                        "tenantDid": portable_did,
                        "remoteUrl": server.url,
                        "definition": plain_protocol_definition()
                    })
                    .to_string(),
                )
                .expect("push protocol idempotent");
            let result: JsonValue = serde_json::from_str(&raw).expect("push result");
            assert_eq!(result["installed"], false);
            let snapshot = server.snapshot();
            assert_eq!(
                snapshot.dwn_calls.len(),
                1,
                "idempotent path should skip the configure roundtrip"
            );
        }

        #[test]
        fn run_restore_flow_installs_locally_and_pushes_remotely() {
            let server = start_mock_server();
            {
                let mut guard = server.state.lock().unwrap();
                guard.dwn_replies.push(serde_json::json!({
                    "status": { "code": 200, "detail": "OK" },
                    "entries": []
                }));
                guard.dwn_replies.push(serde_json::json!({
                    "status": { "code": 202, "detail": "Accepted" }
                }));
            }
            let (core, portable_did) = initialized_core_with_did();
            let raw = core
                .run_restore_flow(
                    serde_json::json!({
                        "agentDid": portable_did,
                        "remoteUrl": server.url,
                        "protocols": [plain_protocol_definition()]
                    })
                    .to_string(),
                )
                .expect("run restore flow");
            let result: JsonValue = serde_json::from_str(&raw).expect("restore json");
            let steps = result["steps"].as_array().expect("steps");
            assert_eq!(steps.len(), 3);
            assert_eq!(steps[0], "agent_did_sync");
            assert_eq!(steps[1], "protocol_install");
            assert_eq!(steps[2], "protocol_push");
            let local = result["localInstalls"].as_array().expect("local installs");
            let remote = result["remotePushes"].as_array().expect("remote pushes");
            assert_eq!(local.len(), 1);
            assert_eq!(remote.len(), 1);
            assert_eq!(local[0]["installed"], true);
            assert_eq!(remote[0]["installed"], true);
        }

        #[test]
        fn http_setup_methods_reject_locked_core() {
            let server = start_mock_server();
            let (core, portable_did) = initialized_core_with_did();
            core.lock();
            let agent_did = portable_did_uri(&portable_did);
            let err = core
                .register_tenant(
                    serde_json::json!({
                        "dwnEndpoints": [server.url.clone()],
                        "agentDid": agent_did,
                        "connectedDid": agent_did
                    })
                    .to_string(),
                )
                .expect_err("register must fail while locked");
            assert!(matches!(err, EnboxError::Locked));
            let err = core
                .push_protocol(
                    serde_json::json!({
                        "tenantDid": portable_did,
                        "remoteUrl": server.url,
                        "definition": plain_protocol_definition()
                    })
                    .to_string(),
                )
                .expect_err("push must fail while locked");
            assert!(matches!(err, EnboxError::Locked));
            let err = core
                .run_restore_flow(
                    serde_json::json!({
                        "agentDid": portable_did,
                        "remoteUrl": server.url,
                        "protocols": [plain_protocol_definition()]
                    })
                    .to_string(),
                )
                .expect_err("restore must fail while locked");
            assert!(matches!(err, EnboxError::Locked));
        }

        #[test]
        fn http_setup_methods_surface_json_errors() {
            let core = EnboxCore::open_in_memory().expect("core opens");
            core.initialize_agent_identity(
                serde_json::json!({
                    "recoveryPhrase": TEST_RECOVERY_PHRASE,
                    "dwnEndpoints": []
                })
                .to_string(),
            )
            .expect("init identity");
            let err = core
                .register_tenant("not-json".to_string())
                .expect_err("invalid json must fail");
            assert!(matches!(err, EnboxError::Json { .. }));
            let err = core
                .push_protocol("not-json".to_string())
                .expect_err("invalid json must fail");
            assert!(matches!(err, EnboxError::Json { .. }));
            let err = core
                .run_restore_flow("not-json".to_string())
                .expect_err("invalid json must fail");
            assert!(matches!(err, EnboxError::Json { .. }));
        }
    }
}
