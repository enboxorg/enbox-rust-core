//! SQLite-backed [`SecretStore`] for the agent vault.
//!
//! Persists agent vault secrets (portable DID JSON, vault content encryption
//! key, vault unlock salt, and delegate decryption/context keys) in the same
//! SQLite database used by [`SqliteNativeDwn`](crate::SqliteNativeDwn).
//!
//! **Not encryption at rest.** The host is still responsible for binding
//! the underlying database file to a platform keychain / Secure Enclave /
//! TPM. This impl provides durability across `open()` calls so a freshly
//! restored agent can drive [`dwn_rs_core::agent::AgentIdentityService::stored_agent_did`].

use dwn_rs_core::agent::{AgentIdentityError, AgentIdentityFuture, SecretStore};
use rusqlite::{params, OptionalExtension};

use crate::sqlite::{sqlite_store_error, SqliteConnection, SqliteStore};

const VAULT_ERROR_CODE: &str = "AgentVaultError";

/// Durable [`SecretStore`] backed by the shared SQLite database.
#[derive(Clone)]
pub struct SqliteSecretStore {
    connection: SqliteConnection,
}

impl SqliteSecretStore {
    /// Build a secret store that shares the supplied database connection.
    ///
    /// The underlying `SqliteStore` must already be opened (typically by
    /// [`SqliteNativeDwn::open_at`](crate::SqliteNativeDwn::open_at)).
    pub fn new(store: &SqliteStore) -> Self {
        Self {
            connection: store.shared_connection(),
        }
    }

    /// Ensure the underlying connection is open. Idempotent.
    pub fn open(&self) -> Result<(), AgentIdentityError> {
        self.connection
            .open()
            .map_err(|err| AgentIdentityError::new(VAULT_ERROR_CODE, err.to_string()))
    }
}

impl SecretStore for SqliteSecretStore {
    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>> {
        let connection = self.connection.clone();
        let key = key.to_string();
        Box::pin(async move {
            connection
                .with_connection(|connection| {
                    connection
                        .query_row(
                            "SELECT value FROM agent_secrets WHERE key = ?1",
                            params![key],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .optional()
                        .map_err(sqlite_store_error)
                })
                .map_err(|err| AgentIdentityError::new(VAULT_ERROR_CODE, err.to_string()))
        })
    }

    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> AgentIdentityFuture<'a, ()> {
        let connection = self.connection.clone();
        let key = key.to_string();
        Box::pin(async move {
            connection
                .with_connection(|connection| {
                    connection
                        .execute(
                            "INSERT OR REPLACE INTO agent_secrets (key, value) VALUES (?1, ?2)",
                            params![key, value],
                        )
                        .map_err(sqlite_store_error)?;
                    Ok(())
                })
                .map_err(|err| AgentIdentityError::new(VAULT_ERROR_CODE, err.to_string()))
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool> {
        let connection = self.connection.clone();
        let key = key.to_string();
        Box::pin(async move {
            connection
                .with_connection(|connection| {
                    let affected = connection
                        .execute("DELETE FROM agent_secrets WHERE key = ?1", params![key])
                        .map_err(sqlite_store_error)?;
                    Ok(affected > 0)
                })
                .map_err(|err| AgentIdentityError::new(VAULT_ERROR_CODE, err.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dwn_rs_core::agent::{
        AgentIdentityInitializeRequest, AgentIdentityService, DeterministicDidJwkProvider,
        MemoryDidResolverCache, MemoryKeyManager, VAULT_PORTABLE_DID_KEY,
    };
    use dwn_rs_core::stores::MessageStore;
    use tempfile::tempdir;

    const TEST_RECOVERY_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    async fn opened_store(path: &std::path::Path) -> SqliteStore {
        let mut store = SqliteStore::new(path);
        MessageStore::open(&mut store).await.expect("open sqlite");
        store
    }

    #[tokio::test]
    async fn put_get_delete_roundtrip_persists_across_reopen() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("vault.sqlite");

        {
            let store = opened_store(&path).await;
            let vault = SqliteSecretStore::new(&store);
            vault
                .put("agent:test", b"hello".to_vec())
                .await
                .expect("put");
            assert_eq!(
                vault.get("agent:test").await.expect("get"),
                Some(b"hello".to_vec())
            );
        }

        let store = opened_store(&path).await;
        let vault = SqliteSecretStore::new(&store);
        assert_eq!(
            vault.get("agent:test").await.expect("reopened get"),
            Some(b"hello".to_vec())
        );
        assert!(vault.delete("agent:test").await.expect("delete"));
        assert_eq!(vault.get("agent:test").await.expect("post-delete"), None);
        assert!(!vault.delete("agent:test").await.expect("delete-missing"));
    }

    #[tokio::test]
    async fn agent_identity_persists_portable_did_across_reopen() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("agent.sqlite");

        let first_did_uri = {
            let store = opened_store(&path).await;
            let vault = SqliteSecretStore::new(&store);
            let service = AgentIdentityService::new(
                DeterministicDidJwkProvider::default(),
                MemoryKeyManager::default(),
                vault,
                MemoryDidResolverCache::default(),
            );
            let initialization = service
                .initialize_from_recovery(AgentIdentityInitializeRequest {
                    recovery_phrase: Some(TEST_RECOVERY_PHRASE.to_string()),
                    dwn_endpoints: vec![],
                })
                .await
                .expect("initialize");
            initialization.portable_did.uri
        };

        let store = opened_store(&path).await;
        let vault = SqliteSecretStore::new(&store);
        let raw = vault
            .get(VAULT_PORTABLE_DID_KEY)
            .await
            .expect("get vault did")
            .expect("vault did persisted");
        let restored: dwn_rs_core::agent::PortableDid =
            serde_json::from_slice(&raw).expect("vault json");
        assert_eq!(restored.uri, first_did_uri);
    }
}
