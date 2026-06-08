//! UniFFI facade for mobile and other foreign-language Enbox integrations.
//!
//! This crate exposes a small, stable boundary over the native Rust DWN core.
//! Internal crates remain idiomatic Rust; DTO translation happens here.

use std::path::Path;
use std::sync::{Arc, Mutex};

use dwn_rs_core::agent::{
    derive_agent_keys, AgentIdentityInitializeRequest, AgentIdentityService,
    DeterministicDidJwkProvider, MemoryDidResolverCache, MemoryKeyManager, PortableDid,
};
use dwn_rs_core::auth::{JwsPrivateJwk, PrivateJwkSigner, StaticPublicKeyResolver};
use dwn_rs_core::protocols::Definition;
use dwn_rs_core::setup::{inject_protocol_encryption, install_protocol_if_needed};
use dwn_rs_core::sync::{
    SyncDirection, SyncIdentityOptions, SyncOnceRequest, SyncOnceResult, SyncRunStatus,
};
use dwn_rs_core::sync_endpoint::JwsSyncAuthorizer;
use dwn_rs_stores::{SqliteNativeDwn, SqliteSecretStore};
use serde::{Deserialize, Serialize};

pub mod setup;
use setup::{signer_from_portable_did, LocalDwnProtocolEndpoint};

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
}
