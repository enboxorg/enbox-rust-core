//! SQLite-backed [`SecretStore`] for the agent vault.
//!
//! Raw persistence for the vault's wrapped material and encrypted credential
//! envelopes in the SQLite database shared with the native node. Use
//! [`crate::agent::VaultBackedSecretStore`] for classified credential values;
//! this backend performs no encryption itself. The legacy identity initializer
//! still writes plaintext private material here, including a raw CEK that can
//! decrypt envelopes derived from the same recovery phrase. Envelopes alone
//! provide no database-reader confidentiality while that material remains.

use crate::agent::{AgentIdentityError, AgentIdentityFuture, SecretStore, SecretWrite};
use dwn_rs_core::errors::StoreError;
use dwn_rs_stores::SqliteStore;
use rusqlite::{params, OptionalExtension};

/// Durable [`SecretStore`] backed by the shared SQLite database.
#[derive(Clone)]
pub struct SqliteSecretStore {
    store: SqliteStore,
}

impl SqliteSecretStore {
    /// Build a secret store that shares the supplied database connection.
    ///
    /// The underlying `SqliteStore` must already be opened (typically by
    /// opening the native node at a database path).
    pub fn new(store: &SqliteStore) -> Self {
        Self {
            store: store.clone(),
        }
    }

    /// Ensure the underlying connection is open. Idempotent.
    pub fn open(&self) -> Result<(), AgentIdentityError> {
        // store is opened lazily
        Ok(())
    }
}

impl SecretStore for SqliteSecretStore {
    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>> {
        let key = key.to_string();
        Box::pin(async move {
            self.store
                .connection()
                .await
                .map_err(|err| AgentIdentityError::agent_vault(err.to_string()))?
                .with_reader(move |connection| {
                    connection
                        .query_row(
                            "SELECT value FROM agent_secrets WHERE key = ?1",
                            params![key],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .optional()
                        .map_err(|err| StoreError::InternalException(err.to_string()))
                })
                .await
                .map_err(|err| AgentIdentityError::agent_vault(err.to_string()))
        })
    }

    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> AgentIdentityFuture<'a, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.store
                .connection()
                .await
                .map_err(|err| AgentIdentityError::agent_vault(err.to_string()))?
                .with_writer(move |connection| {
                    connection
                        .execute(
                            "INSERT OR REPLACE INTO agent_secrets (key, value) VALUES (?1, ?2)",
                            params![key, value],
                        )
                        .map_err(|err| StoreError::InternalException(err.to_string()))?;
                    Ok(())
                })
                .await
                .map_err(|err| AgentIdentityError::agent_vault(err.to_string()))
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool> {
        let key = key.to_string();
        Box::pin(async move {
            self.store
                .connection()
                .await
                .map_err(|err| AgentIdentityError::agent_vault(err.to_string()))?
                .with_writer(move |connection| {
                    let affected = connection
                        .execute("DELETE FROM agent_secrets WHERE key = ?1", params![key])
                        .map_err(|err| StoreError::InternalException(err.to_string()))?;
                    Ok(affected > 0)
                })
                .await
                .map_err(|err| AgentIdentityError::agent_vault(err.to_string()))
        })
    }

    fn apply<'a>(&'a self, writes: Vec<SecretWrite>) -> AgentIdentityFuture<'a, ()> {
        Box::pin(async move {
            self.store
                .connection()
                .await
                .map_err(|err| AgentIdentityError::agent_vault(err.to_string()))?
                .with_writer(move |connection| {
                    let tx = connection
                        .transaction()
                        .map_err(|err| StoreError::InternalException(err.to_string()))?;
                    for write in &writes {
                        match write {
                            SecretWrite::Put { key, value } => {
                                tx.execute(
                                    "INSERT OR REPLACE INTO agent_secrets (key, value) VALUES (?1, ?2)",
                                    params![key, value],
                                )
                                .map_err(|err| StoreError::InternalException(err.to_string()))?;
                            }
                            SecretWrite::Delete { key } => {
                                tx.execute("DELETE FROM agent_secrets WHERE key = ?1", params![key])
                                    .map_err(|err| {
                                        StoreError::InternalException(err.to_string())
                                    })?;
                            }
                        }
                    }
                    // Commit is the atomicity boundary: an error or a dropped
                    // transaction leaves every write uncommitted.
                    tx.commit()
                        .map_err(|err| StoreError::InternalException(err.to_string()))?;
                    Ok(())
                })
                .await
                .map_err(|err| AgentIdentityError::agent_vault(err.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::agent::DidDhtProvider;
    use dwn_rs_core::stores::wake::WakePublishHandler;
    use dwn_rs_core::stores::MessageStore;
    use tempfile::tempdir;

    const TEST_RECOVERY_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    async fn opened_store(path: &std::path::Path) -> SqliteStore {
        let mut store = SqliteStore::new(path, WakePublishHandler::new(Arc::new(())));
        MessageStore::open(&mut store).await.expect("open sqlite");
        store
    }

    #[tokio::test]
    async fn put_get_delete_roundtrip_persists_across_reopen() {
        // Serialize file-backed tests process-wide.
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
    async fn vault_identity_reopens_without_plaintext_material() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("agent.sqlite");
        let first = {
            let store = opened_store(&path).await;
            let raw = Arc::new(SqliteSecretStore::new(&store));
            let vault = crate::agent::test_support::offline_vault(raw.clone(), Arc::new(DidDhtProvider::default()), 1);
            let initialized = vault
                .initialize("test-password", Some(TEST_RECOVERY_PHRASE), vec![])
                .await
                .unwrap();
            for key in [
                "agent:vault:portableDid",
                "agent:vault:contentEncryptionKey",
                "agent:vault:unlockSalt",
            ] {
                assert!(raw.get(key).await.unwrap().is_none());
            }
            initialized.portable_did
        };
        let store = opened_store(&path).await;
        let vault = crate::agent::test_support::offline_vault(Arc::new(SqliteSecretStore::new(&store)), Arc::new(DidDhtProvider::default()), 1);
        vault.unlock("test-password").await.unwrap();
        assert_eq!(vault.get_did().await.unwrap(), first);
    }
}
