//! UniFFI facade for mobile and other foreign-language Enbox integrations.
//!
//! This crate exposes a small, stable boundary over the native Rust DWN core.
//! Internal crates remain idiomatic Rust; DTO translation happens here.

use std::path::Path;
use std::sync::{Arc, Mutex};

use dwn_rs_core::auth::{JwsPrivateJwk, PrivateJwkSigner, StaticPublicKeyResolver};
use dwn_rs_core::sync::{
    SyncDirection, SyncIdentityOptions, SyncOnceRequest, SyncOnceResult, SyncRunStatus,
};
use dwn_rs_core::sync_endpoint::JwsSyncAuthorizer;
use dwn_rs_stores::SqliteNativeDwn;
use serde::{Deserialize, Serialize};

uniffi::setup_scaffolding!();

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnboxRuntimeStatus {
    pub initialized: bool,
    pub locked: bool,
    pub database_path: Option<String>,
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

struct CoreState {
    locked: bool,
    database_path: Option<String>,
    node: Option<Arc<SqliteNativeDwn>>,
    sync_signer: Option<PrivateJwkSigner>,
    sync_in_progress: bool,
    last_sync: Option<SyncOnceResult>,
    last_sync_tenant: Option<String>,
    last_sync_remote: Option<String>,
}

#[derive(uniffi::Object)]
pub struct EnboxCore {
    runtime: tokio::runtime::Runtime,
    state: Arc<Mutex<CoreState>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncSignerConfig {
    key_id: String,
    algorithm: String,
    private_jwk: JwsPrivateJwk,
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
        }
    }

    pub fn unlock(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.locked = false;
        }
    }

    pub fn status(&self) -> EnboxRuntimeStatus {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        EnboxRuntimeStatus {
            initialized: state.node.is_some(),
            locked: state.locked,
            database_path: state.database_path.clone(),
        }
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
        let request: FfiSyncOnceRequest =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let sync_request = SyncOnceRequest {
            tenant: request.tenant.clone(),
            remote: request.remote.clone(),
            direction: request.direction,
            protocol: request.protocol,
            max_records: request.max_records,
            max_bytes: request.max_bytes,
            connectivity: Default::default(),
            reason: Some("ffi_sync_once".to_string()),
        };

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
        let result = self.runtime.block_on(node.sync_once_with_http(
            &request.remote,
            authorizer,
            sync_request,
        ));

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

    /// Pull-only poll reconciliation against an HTTP remote (live-degraded fallback).
    ///
    /// `request_json` matches [`Self::sync_once`]; uses [`SqliteNativeDwn::poll_reconcile_with_http`].
    pub fn poll_reconcile(&self, request_json: String) -> Result<String, EnboxError> {
        let request: FfiSyncOnceRequest =
            serde_json::from_str(&request_json).map_err(|err| EnboxError::Json {
                detail: err.to_string(),
            })?;
        let sync_request = SyncOnceRequest {
            tenant: request.tenant.clone(),
            remote: request.remote.clone(),
            direction: request.direction,
            protocol: request.protocol,
            max_records: request.max_records,
            max_bytes: request.max_bytes,
            connectivity: Default::default(),
            reason: Some("ffi_poll_reconcile".to_string()),
        };

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
        let result = self.runtime.block_on(node.poll_reconcile_with_http(
            &request.remote,
            authorizer,
            sync_request,
        ));

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
        Ok(Arc::new(Self {
            runtime,
            state: Arc::new(Mutex::new(CoreState {
                locked: false,
                database_path,
                node: Some(Arc::new(node)),
                sync_signer: None,
                sync_in_progress: false,
                last_sync: None,
                last_sync_tenant: None,
                last_sync_remote: None,
            })),
        }))
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
}
