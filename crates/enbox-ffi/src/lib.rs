//! UniFFI facade for mobile and other foreign-language Enbox integrations.
//!
//! This crate exposes a small, stable boundary over the native Rust DWN core.
//! Internal crates remain idiomatic Rust; DTO translation happens here.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use dwn_rs_core::auth::StaticPublicKeyResolver;
use dwn_rs_stores::SqliteNativeDwn;
use serde::{Deserialize, Serialize};

uniffi::setup_scaffolding!();

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnboxRuntimeStatus {
    pub initialized: bool,
    pub locked: bool,
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
    #[error("Operation was cancelled")]
    Cancelled,
    #[error("Operation deadline exceeded")]
    DeadlineExceeded,
}

struct CoreState {
    locked: bool,
    node: Option<SqliteNativeDwn>,
}

#[derive(uniffi::Object)]
pub struct EnboxCore {
    runtime: tokio::runtime::Runtime,
    state: Arc<Mutex<CoreState>>,
}

#[uniffi::export]
impl EnboxCore {
    #[uniffi::constructor]
    pub fn open_in_memory() -> Result<Arc<Self>, EnboxError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| EnboxError::Store {
                detail: err.to_string(),
            })?;
        let resolver = StaticPublicKeyResolver::new(BTreeMap::new());
        let node = runtime
            .block_on(SqliteNativeDwn::open_in_memory(resolver))
            .map_err(|err| EnboxError::Store {
                detail: err.to_string(),
            })?;
        Ok(Arc::new(Self {
            runtime,
            state: Arc::new(Mutex::new(CoreState {
                locked: false,
                node: Some(node),
            })),
        }))
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
        }
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

    pub fn sync_once(&self, _request_json: String) -> Result<String, EnboxError> {
        Err(EnboxError::Sync {
            detail: "sync_once is not implemented in the enbox-ffi skeleton yet".to_string(),
        })
    }
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
}
