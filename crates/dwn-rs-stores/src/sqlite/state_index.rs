//! Durable SQLite backends for [`StateIndex`], [`EventLog`], and
//! [`ResumableTaskStore`].

use std::fmt::Debug;
use std::future::Future;

use rusqlite::params;

use dwn_rs_core::errors::StoreError;
use dwn_rs_core::stores::state_index::MemoryStateIndex;
use dwn_rs_core::stores::{KeyValues, StateHash, StateIndex};
use dwn_rs_core::Value;

use crate::sqlite::{json_store_error, sqlite_store_error, SqliteStore};

/// SQLite-backed [`StateIndex`] that persists sparse-merkle-tree entries.
#[derive(Debug, Clone)]
pub struct SqliteStateIndex {
    inner: MemoryStateIndex,
    store: SqliteStore,
}

impl Default for SqliteStateIndex {
    fn default() -> Self {
        Self::new(&SqliteStore::in_memory())
    }
}

impl SqliteStateIndex {
    pub fn new(store: &SqliteStore) -> Self {
        Self {
            inner: MemoryStateIndex::default(),
            store: store.clone(),
        }
    }

    async fn load_entries(&self) -> Result<Vec<(String, String, KeyValues)>, StoreError> {
        self.store
            .connection()
            .await?
            .with_reader(|connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT tenant, message_cid, indexes_json \
                     FROM state_index_entries",
                    )
                    .map_err(sqlite_store_error)?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })
                    .map_err(sqlite_store_error)?;

                let mut entries = Vec::new();
                for row in rows {
                    let (tenant, message_cid, indexes_json) = row.map_err(sqlite_store_error)?;
                    let indexes: KeyValues =
                        serde_json::from_str(&indexes_json).map_err(json_store_error)?;
                    entries.push((tenant, message_cid, indexes));
                }
                Ok(entries)
            })
            .await
    }

    async fn persist_insert(
        &self,
        tenant: &str,
        message_cid: &str,
        indexes: &KeyValues,
    ) -> Result<(), StoreError> {
        let tenant = tenant.to_string();
        let message_cid = message_cid.to_string();

        let protocol = match indexes.get("protocol") {
            Some(Value::String(protocol)) => Some(protocol.clone()),
            _ => None,
        };
        let indexes_json = serde_json::to_string(indexes).map_err(json_store_error)?;

        self.store
            .connection()
            .await?
            .with_writer(move |connection| {
                connection
                    .execute(
                        "INSERT OR REPLACE INTO state_index_entries \
                     (tenant, message_cid, protocol, indexes_json) \
                     VALUES (?1, ?2, ?3, ?4)",
                        params![tenant, message_cid, protocol, indexes_json],
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
    }

    async fn persist_delete(
        &self,
        tenant: &str,
        message_cids: &[String],
    ) -> Result<(), StoreError> {
        let tenant = tenant.to_string();
        let message_cids = message_cids.to_vec();

        self.store
            .connection()
            .await?
            .with_writer(move |connection| {
                for message_cid in message_cids {
                    connection
                        .execute(
                            "DELETE FROM state_index_entries \
                         WHERE tenant = ?1 AND message_cid = ?2",
                            params![tenant, message_cid],
                        )
                        .map_err(sqlite_store_error)?;
                }
                Ok(())
            })
            .await
    }

    async fn persist_clear(&self) -> Result<(), StoreError> {
        self.store
            .connection()
            .await?
            .with_writer(move |connection| {
                connection
                    .execute("DELETE FROM state_index_entries", [])
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
    }
}

impl StateIndex for SqliteStateIndex {
    async fn open(&mut self) -> Result<(), StoreError> {
        self.inner.clear().await?;
        for (tenant, message_cid, indexes) in self.load_entries().await? {
            self.inner.insert(&tenant, &message_cid, indexes).await?;
        }
        Ok(())
    }

    async fn close(&mut self) {
        self.inner.clear().await.ok();
        // do not close the store pool here
    }

    async fn clear(&self) -> Result<(), StoreError> {
        self.inner.clear().await?;
        self.persist_clear().await
    }

    async fn insert(
        &self,
        tenant: &str,
        message_cid: &str,
        indexes: KeyValues,
    ) -> Result<(), StoreError> {
        let tenant = tenant.to_string();
        self.inner
            .insert(&tenant, message_cid, indexes.clone())
            .await?;
        self.persist_insert(&tenant, message_cid, &indexes).await
    }

    async fn delete(&self, tenant: &str, message_cids: &[String]) -> Result<(), StoreError> {
        let tenant = tenant.to_string();
        let message_cids = message_cids.to_vec();
        self.inner.delete(&tenant, &message_cids).await?;
        self.persist_delete(&tenant, &message_cids).await
    }

    fn get_root(&self, tenant: &str) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        self.inner.get_root(tenant)
    }

    fn get_protocol_root(
        &self,
        tenant: &str,
        protocol: &str,
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        self.inner.get_protocol_root(tenant, protocol)
    }

    fn get_subtree_hash(
        &self,
        tenant: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        self.inner.get_subtree_hash(tenant, prefix)
    }

    fn get_protocol_subtree_hash(
        &self,
        tenant: &str,
        protocol: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        self.inner
            .get_protocol_subtree_hash(tenant, protocol, prefix)
    }

    fn get_leaves(
        &self,
        tenant: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send {
        self.inner.get_leaves(tenant, prefix)
    }

    fn get_protocol_leaves(
        &self,
        tenant: &str,
        protocol: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send {
        self.inner.get_protocol_leaves(tenant, protocol, prefix)
    }
}
