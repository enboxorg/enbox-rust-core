use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::sync::{SyncOnceResult, SyncRunStatus};

pub type MobileResult<T> = Result<T, MobileError>;
pub type MobileFuture<'a, T> = Pin<Box<dyn Future<Output = MobileResult<T>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileError {
    pub code: String,
    pub detail: String,
}

impl MobileError {
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }

    fn not_initialized() -> Self {
        Self::new(
            "MobileRuntimeNotInitialized",
            "mobile runtime is not initialized",
        )
    }

    fn locked() -> Self {
        Self::new("MobileVaultLocked", "mobile vault is locked")
    }

    pub(crate) fn lock_poisoned<E: Display>(err: E) -> Self {
        Self::new(
            "MobileLockPoisoned",
            format!("mobile runtime lock poisoned: {err}"),
        )
    }
}

impl Display for MobileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for MobileError {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileInitializeRequest {
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_path: Option<String>,
    #[serde(default)]
    pub background_refresh_enabled: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileRuntimeStatus {
    pub initialized: bool,
    pub locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_path: Option<String>,
    pub background_refresh_enabled: bool,
    pub active_background_tasks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileProcessMessageRequest {
    pub tenant: String,
    pub message: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileProcessMessageResult {
    pub status_code: u16,
    pub status_detail: String,
    pub body: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileSyncRequest {
    pub tenant: String,
    pub remote: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileBackgroundSyncRequest {
    pub task_id: String,
    pub tenant: String,
    pub remote: String,
    pub max_runtime_ms: u64,
    pub network_available: bool,
}

pub trait MobileBiometricVault: Clone + Send + Sync + 'static {
    fn unlock<'a>(&'a self, reason: &'a str) -> MobileFuture<'a, ()>;
    fn lock<'a>(&'a self) -> MobileFuture<'a, ()>;
    fn is_unlocked(&self) -> bool;
}

pub trait MobileSecureStorage: Clone + Send + Sync + 'static {
    fn get<'a>(&'a self, key: &'a str) -> MobileFuture<'a, Option<Vec<u8>>>;
    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> MobileFuture<'a, ()>;
    fn delete<'a>(&'a self, key: &'a str) -> MobileFuture<'a, ()>;
}

pub trait MobileMessageProcessor: Clone + Send + Sync + 'static {
    fn process_message<'a>(
        &'a self,
        request: MobileProcessMessageRequest,
    ) -> MobileFuture<'a, MobileProcessMessageResult>;
}

pub trait MobileSyncBridge: Clone + Send + Sync + 'static {
    fn sync_once<'a>(&'a self, request: MobileSyncRequest) -> MobileFuture<'a, SyncOnceResult>;

    fn background_sync<'a>(
        &'a self,
        request: MobileBackgroundSyncRequest,
    ) -> MobileFuture<'a, SyncOnceResult>;
}

#[derive(Clone)]
pub struct MobileCore<V, T, P, S> {
    vault: V,
    secure_storage: T,
    processor: P,
    sync: S,
    state: Arc<RwLock<MobileRuntimeState>>,
}

#[derive(Debug, Default)]
struct MobileRuntimeState {
    initialized: bool,
    device_id: Option<String>,
    app_group: Option<String>,
    database_path: Option<String>,
    background_refresh_enabled: bool,
    active_background_tasks: BTreeSet<String>,
}

struct BackgroundTaskGuard {
    state: Arc<RwLock<MobileRuntimeState>>,
    task_id: String,
}

impl Drop for BackgroundTaskGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.write() {
            state.active_background_tasks.remove(&self.task_id);
        }
        // If the lock is poisoned during drop, leave the task id in the set.
        // The runtime is already in a degraded state and we'd rather not
        // panic during unwinding.
    }
}

impl<V, T, P, S> MobileCore<V, T, P, S>
where
    V: MobileBiometricVault,
    T: MobileSecureStorage,
    P: MobileMessageProcessor,
    S: MobileSyncBridge,
{
    pub fn new(vault: V, secure_storage: T, processor: P, sync: S) -> Self {
        Self {
            vault,
            secure_storage,
            processor,
            sync,
            state: Arc::new(RwLock::new(MobileRuntimeState::default())),
        }
    }

    pub fn initialize(&self, request: MobileInitializeRequest) -> MobileRuntimeStatus {
        let mut state = self
            .state
            .write()
            .expect("MobileCore state lock poisoned");
        state.initialized = true;
        state.device_id = Some(request.device_id);
        state.app_group = request.app_group;
        state.database_path = request.database_path;
        state.background_refresh_enabled = request.background_refresh_enabled;
        self.status_with_state(&state)
    }

    pub fn secure_storage(&self) -> &T {
        &self.secure_storage
    }

    pub async fn unlock(&self, reason: &str) -> MobileResult<MobileRuntimeStatus> {
        self.ensure_initialized()?;
        self.vault.unlock(reason).await?;
        Ok(self.status())
    }

    pub async fn lock(&self) -> MobileResult<MobileRuntimeStatus> {
        self.ensure_initialized()?;
        self.vault.lock().await?;
        Ok(self.status())
    }

    pub async fn process_message(
        &self,
        request: MobileProcessMessageRequest,
    ) -> MobileResult<MobileProcessMessageResult> {
        self.ensure_ready()?;
        self.processor.process_message(request).await
    }

    pub async fn sync_once(&self, request: MobileSyncRequest) -> MobileResult<SyncOnceResult> {
        self.ensure_ready()?;
        self.sync.sync_once(request).await
    }

    pub async fn background_sync(
        &self,
        request: MobileBackgroundSyncRequest,
    ) -> MobileResult<SyncOnceResult> {
        self.ensure_initialized()?;
        if !request.network_available {
            return Ok(sync_result(SyncRunStatus::NoConnectivity));
        }
        let _guard = self.track_background_task(request.task_id.clone());
        self.sync.background_sync(request).await
    }

    fn track_background_task(&self, task_id: String) -> BackgroundTaskGuard {
        self.state
            .write()
            .expect("MobileCore state lock poisoned")
            .active_background_tasks
            .insert(task_id.clone());
        BackgroundTaskGuard {
            state: Arc::clone(&self.state),
            task_id,
        }
    }

    pub fn status(&self) -> MobileRuntimeStatus {
        let state = self
            .state
            .read()
            .expect("MobileCore state lock poisoned");
        self.status_with_state(&state)
    }

    fn status_with_state(&self, state: &MobileRuntimeState) -> MobileRuntimeStatus {
        MobileRuntimeStatus {
            initialized: state.initialized,
            locked: !self.vault.is_unlocked(),
            device_id: state.device_id.clone(),
            app_group: state.app_group.clone(),
            database_path: state.database_path.clone(),
            background_refresh_enabled: state.background_refresh_enabled,
            active_background_tasks: state.active_background_tasks.iter().cloned().collect(),
        }
    }

    fn ensure_initialized(&self) -> MobileResult<()> {
        if !self
            .state
            .read()
            .map_err(MobileError::lock_poisoned)?
            .initialized
        {
            return Err(MobileError::not_initialized());
        }
        Ok(())
    }

    fn ensure_ready(&self) -> MobileResult<()> {
        self.ensure_initialized()?;
        if !self.vault.is_unlocked() {
            return Err(MobileError::locked());
        }
        Ok(())
    }
}

/// Scaffolding `MobileBiometricVault` for tests. **No actual biometric
/// prompt** — `unlock` flips a boolean. Production deployments must wire
/// a real iOS Keychain (LAContext / Secure Enclave) or Android Keystore
/// (BiometricPrompt) implementation.
#[derive(Clone, Default)]
pub struct MemoryBiometricVault {
    unlocked: Arc<RwLock<bool>>,
}

impl MobileBiometricVault for MemoryBiometricVault {
    fn unlock<'a>(&'a self, _reason: &'a str) -> MobileFuture<'a, ()> {
        Box::pin(async move {
            *self.unlocked.write().map_err(MobileError::lock_poisoned)? = true;
            Ok(())
        })
    }

    fn lock<'a>(&'a self) -> MobileFuture<'a, ()> {
        Box::pin(async move {
            *self.unlocked.write().map_err(MobileError::lock_poisoned)? = false;
            Ok(())
        })
    }

    fn is_unlocked(&self) -> bool {
        *self
            .unlocked
            .read()
            .expect("MemoryBiometricVault lock poisoned")
    }
}

/// In-memory `MobileSecureStorage` for tests. **Plaintext.** Production
/// deployments must back this with iOS Keychain (App Group) or Android
/// EncryptedSharedPreferences / Keystore-backed storage.
#[derive(Clone, Default)]
pub struct MemoryMobileSecureStorage {
    values: Arc<RwLock<BTreeMap<String, Vec<u8>>>>,
}

impl MobileSecureStorage for MemoryMobileSecureStorage {
    fn get<'a>(&'a self, key: &'a str) -> MobileFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            Ok(self
                .values
                .read()
                .map_err(MobileError::lock_poisoned)?
                .get(key)
                .cloned())
        })
    }

    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> MobileFuture<'a, ()> {
        Box::pin(async move {
            self.values
                .write()
                .map_err(MobileError::lock_poisoned)?
                .insert(key.to_string(), value);
            Ok(())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> MobileFuture<'a, ()> {
        Box::pin(async move {
            self.values
                .write()
                .map_err(MobileError::lock_poisoned)?
                .remove(key);
            Ok(())
        })
    }
}

/// Scaffolding `MobileMessageProcessor` that echoes the request payload.
/// **Does not run a DWN.** Use only for plumbing tests; real builds should
/// dispatch into `Dwn::process_message`.
#[derive(Clone, Default)]
pub struct EchoMobileMessageProcessor;

impl MobileMessageProcessor for EchoMobileMessageProcessor {
    fn process_message<'a>(
        &'a self,
        request: MobileProcessMessageRequest,
    ) -> MobileFuture<'a, MobileProcessMessageResult> {
        Box::pin(async move {
            Ok(MobileProcessMessageResult {
                status_code: 202,
                status_detail: "Accepted".to_string(),
                body: request.message,
                data: request.data,
            })
        })
    }
}

#[derive(Clone, Default)]
pub struct NoopMobileSyncBridge;

impl MobileSyncBridge for NoopMobileSyncBridge {
    fn sync_once<'a>(&'a self, _request: MobileSyncRequest) -> MobileFuture<'a, SyncOnceResult> {
        Box::pin(async move { Ok(sync_result(SyncRunStatus::Completed)) })
    }

    fn background_sync<'a>(
        &'a self,
        _request: MobileBackgroundSyncRequest,
    ) -> MobileFuture<'a, SyncOnceResult> {
        Box::pin(async move { Ok(sync_result(SyncRunStatus::Completed)) })
    }
}

fn sync_result(status: SyncRunStatus) -> SyncOnceResult {
    SyncOnceResult {
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn mobile_runtime_exposes_initialize_lock_process_and_sync() {
        let core = test_core();
        let status = core.initialize(MobileInitializeRequest {
            device_id: "ios-device".to_string(),
            app_group: Some("group.enbox".to_string()),
            database_path: Some("/tmp/enbox.sqlite".to_string()),
            background_refresh_enabled: true,
        });
        assert!(status.initialized);
        assert!(status.locked);
        assert_eq!(status.app_group.as_deref(), Some("group.enbox"));
        assert_eq!(status.database_path.as_deref(), Some("/tmp/enbox.sqlite"));
        assert!(status.background_refresh_enabled);

        core.secure_storage()
            .put("agent-key", vec![4, 5, 6])
            .await
            .unwrap();
        assert_eq!(
            core.secure_storage().get("agent-key").await.unwrap(),
            Some(vec![4, 5, 6])
        );

        assert_eq!(
            core.process_message(MobileProcessMessageRequest {
                tenant: "did:example:alice".to_string(),
                message: json!({"descriptor":{"interface":"Records","method":"Query"}}),
                data: None,
            })
            .await
            .unwrap_err()
            .code,
            "MobileVaultLocked"
        );

        core.unlock("test biometric prompt").await.unwrap();
        let reply = core
            .process_message(MobileProcessMessageRequest {
                tenant: "did:example:alice".to_string(),
                message: json!({"ok": true}),
                data: Some(vec![1, 2, 3]),
            })
            .await
            .unwrap();
        assert_eq!(reply.status_code, 202);
        assert_eq!(reply.data, Some(vec![1, 2, 3]));

        let sync = core
            .sync_once(MobileSyncRequest {
                tenant: "did:example:alice".to_string(),
                remote: "https://remote.example".to_string(),
                protocol: None,
                reason: Some("foreground".to_string()),
            })
            .await
            .unwrap();
        assert_eq!(sync.status, SyncRunStatus::Completed);

        let status = core.lock().await.unwrap();
        assert!(status.locked);
    }

    #[tokio::test]
    async fn background_sync_entrypoint_is_lifecycle_safe() {
        let core = test_core();
        core.initialize(MobileInitializeRequest {
            device_id: "android-device".to_string(),
            app_group: None,
            database_path: None,
            background_refresh_enabled: true,
        });

        let offline = core
            .background_sync(MobileBackgroundSyncRequest {
                task_id: "bg-offline".to_string(),
                tenant: "did:example:alice".to_string(),
                remote: "https://remote.example".to_string(),
                max_runtime_ms: 30_000,
                network_available: false,
            })
            .await
            .unwrap();
        assert_eq!(offline.status, SyncRunStatus::NoConnectivity);

        let online = core
            .background_sync(MobileBackgroundSyncRequest {
                task_id: "bg-online".to_string(),
                tenant: "did:example:alice".to_string(),
                remote: "https://remote.example".to_string(),
                max_runtime_ms: 30_000,
                network_available: true,
            })
            .await
            .unwrap();
        assert_eq!(online.status, SyncRunStatus::Completed);
        assert!(core.status().active_background_tasks.is_empty());
    }

    fn test_core() -> MobileCore<
        MemoryBiometricVault,
        MemoryMobileSecureStorage,
        EchoMobileMessageProcessor,
        NoopMobileSyncBridge,
    > {
        MobileCore::new(
            MemoryBiometricVault::default(),
            MemoryMobileSecureStorage::default(),
            EchoMobileMessageProcessor,
            NoopMobileSyncBridge,
        )
    }
}
