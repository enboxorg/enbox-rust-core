use std::{path::Path, sync::Arc};

use dwn_rs_core::errors::StoreError;
use rusqlite::Connection;
use tokio::sync::OnceCell;

use crate::SqliteConnection;

#[derive(Debug, Clone)]
pub struct SqliteStore {
    path: Arc<Path>,
    pub(crate) conn: Arc<OnceCell<SqliteConnection>>,
}

impl Default for SqliteStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl SqliteStore {
    pub fn in_memory() -> Self {
        Self::new("file:dwn-rs?mode=memory&cache=shared")
    }

    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: Arc::from(path.as_ref()),
            conn: Arc::new(OnceCell::new()),
        }
    }

    pub(crate) async fn connection(&self) -> Result<&SqliteConnection, StoreError> {
        self.conn
            .get_or_try_init(|| SqliteConnection::open(self.path.clone(), migrate))
            .await
    }
}
pub(crate) fn sqlite_store_error(error: rusqlite::Error) -> StoreError {
    StoreError::InternalException(error.to_string())
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                tenant TEXT NOT NULL,
                message_cid TEXT NOT NULL,
                message_json TEXT NOT NULL,
                indexes_json TEXT NOT NULL,
                encoded_data TEXT NOT NULL,
                PRIMARY KEY (tenant, message_cid)
            );

            CREATE TABLE IF NOT EXISTS message_data (
                message_cid TEXT PRIMARY KEY,
                data BLOB NOT NULL,
                data_size INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS data_blocks (
                data_cid TEXT PRIMARY KEY,
                data BLOB NOT NULL,
                data_size INTEGER NOT NULL,
                ref_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS data_refs (
                tenant TEXT NOT NULL,
                record_id TEXT NOT NULL,
                data_cid TEXT NOT NULL,
                data_size INTEGER NOT NULL,
                PRIMARY KEY (tenant, record_id, data_cid),
                FOREIGN KEY (data_cid) REFERENCES data_blocks(data_cid)
            );

            CREATE TABLE IF NOT EXISTS state_index_entries (
                tenant TEXT NOT NULL,
                message_cid TEXT NOT NULL,
                protocol TEXT,
                indexes_json TEXT NOT NULL,
                PRIMARY KEY (tenant, message_cid)
            );

            CREATE TABLE IF NOT EXISTS event_log_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                epoch TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS event_log_tenant_seq (
                tenant TEXT PRIMARY KEY,
                next_seq INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS event_log_events (
                tenant TEXT NOT NULL,
                seq INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                indexes_json TEXT NOT NULL,
                message_cid TEXT NOT NULL,
                PRIMARY KEY (tenant, seq)
            );

            CREATE TABLE IF NOT EXISTS resumable_tasks (
                id TEXT PRIMARY KEY,
                task_json TEXT NOT NULL,
                timeout_ms INTEGER NOT NULL,
                retry_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_secrets (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )
        .map_err(sqlite_store_error)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use dwn_rs_core::stores::MessageStore;

    use super::*;

    #[tokio::test]
    async fn sqlite_store_migrates_schema_on_open() {
        let mut store = SqliteStore::in_memory();
        MessageStore::open(&mut store).await.unwrap();

        let tables = store
            .with_connection(|connection| {
                let mut statement = connection
                    .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
                    .map_err(sqlite_store_error)?;
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(sqlite_store_error)?;
                let mut tables = BTreeSet::new();
                for row in rows {
                    tables.insert(row.map_err(sqlite_store_error)?);
                }
                Ok(tables)
            })
            .unwrap();

        assert!(tables.contains("messages"));
        assert!(tables.contains("data_blocks"));
        assert!(tables.contains("data_refs"));
    }
}
