use super::{
    AgentIdentityError, AgentIdentityFuture, AgentIdentityResult, IdentityVault, SecretStore,
    SecretWrite,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};
use tokio::sync::Mutex;

/// Classified credential storage, separate from the vault's raw persistence backend.
pub trait CredentialStore: Send + Sync {
    fn put<'a>(
        &'a self,
        key: &'a str,
        value: Vec<u8>,
        expires_at: Option<String>,
    ) -> AgentIdentityFuture<'a, ()>;
    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>>;
    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool>;
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    jwe: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

/// Encrypts credentials with a shared vault before persisting them.
///
/// Share this instance through `Arc` to serialize reads, replacements and expiry
/// purges. Independent instances over the same backend are not coordinated.
pub struct VaultBackedSecretStore {
    vault: Arc<IdentityVault>,
    store: Arc<dyn SecretStore>,
    clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    operations: Mutex<()>,
}

impl fmt::Debug for VaultBackedSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultBackedSecretStore")
            .finish_non_exhaustive()
    }
}

impl VaultBackedSecretStore {
    pub fn new(vault: Arc<IdentityVault>, store: Arc<dyn SecretStore>) -> Self {
        Self::with_clock(vault, store, super::now_utc)
    }

    /// Supply the agent clock used for expiry comparisons.
    pub fn with_clock(
        vault: Arc<IdentityVault>,
        store: Arc<dyn SecretStore>,
        clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static,
    ) -> Self {
        Self {
            vault,
            store,
            clock: Arc::new(clock),
            operations: Mutex::new(()),
        }
    }

    async fn require_unlocked(&self) -> AgentIdentityResult<()> {
        if self.vault.is_locked().await {
            return Err(AgentIdentityError::vault_locked("vault is locked"));
        }
        Ok(())
    }
}

impl CredentialStore for VaultBackedSecretStore {
    fn put<'a>(
        &'a self,
        key: &'a str,
        value: Vec<u8>,
        expires_at: Option<String>,
    ) -> AgentIdentityFuture<'a, ()> {
        Box::pin(async move {
            let _operation = self.operations.lock().await;
            self.require_unlocked().await?;
            if let Some(expiry) = &expires_at {
                parse_expiry(expiry)?;
            }
            let envelope = Envelope {
                jwe: self.vault.encrypt_data(&value).await?,
                expires_at,
            };
            let bytes = serde_json::to_vec(&envelope).map_err(|_| invalid_envelope())?;
            self.store.apply(vec![SecretWrite::put(key, bytes)]).await
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let _operation = self.operations.lock().await;
            self.require_unlocked().await?;
            let Some(raw) = self.store.get(key).await? else {
                return Ok(None);
            };
            // Check null explicitly: an optional field must be absent or a string.
            let json: serde_json::Value =
                serde_json::from_slice(&raw).map_err(|_| invalid_envelope())?;
            if json.get("expiresAt").is_some_and(|v| !v.is_string()) {
                return Err(invalid_envelope());
            }
            let envelope: Envelope =
                serde_json::from_value(json).map_err(|_| invalid_envelope())?;
            if let Some(expiry) = &envelope.expires_at {
                if parse_expiry(expiry)? <= (self.clock)() {
                    self.store.delete(key).await?;
                    return Ok(None);
                }
            }
            self.vault.decrypt_data(&envelope.jwe).await.map(Some)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool> {
        Box::pin(async move {
            let _operation = self.operations.lock().await;
            self.store.delete(key).await
        })
    }
}

fn parse_expiry(value: &str) -> AgentIdentityResult<DateTime<Utc>> {
    if !matches!(value.as_bytes().get(10), Some(b'T' | b't')) {
        return Err(invalid_envelope());
    }
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| invalid_envelope())
}

fn invalid_envelope() -> AgentIdentityError {
    AgentIdentityError::AgentSecretInvalidEnvelope {
        detail: "invalid secret envelope".into(),
    }
}
