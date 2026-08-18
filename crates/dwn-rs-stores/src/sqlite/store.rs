use std::{path::Path, sync::Arc};

use dwn_rs_core::{errors::StoreError, stores::wake::WakePublishHandler};
use rusqlite::Connection;
use tokio::sync::OnceCell;

use crate::SqliteConnection;

#[derive(Clone)]
pub struct SqliteStore {
    pub(crate) conn: Arc<OnceCell<SqliteConnection>>,
    path: Arc<Path>,
    wake_publisher: WakePublishHandler,
}

impl Default for SqliteStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl SqliteStore {
    pub fn in_memory() -> Self {
        Self::new(unique_memory_uri(), WakePublishHandler::new(Arc::new(())))
    }

    pub fn new(path: impl AsRef<Path>, wake_publisher: WakePublishHandler) -> Self {
        Self {
            path: Arc::from(path.as_ref()),
            conn: Arc::new(OnceCell::new()),
            wake_publisher,
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

mod embedded {
    use refinery::embed_migrations;
    // Refinery discovers files named V{version}__{name}.sql at compile time.
    embed_migrations!("src/sqlite/migrations");
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    embedded::migrations::runner()
        .run(connection)
        .map_err(|e| StoreError::InternalException(e.to_string()))?;
    Ok(())
}

fn unique_memory_uri() -> String {
    format!(
        "file:dwn-mem-{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    )
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
            .connection()
            .await
            .unwrap()
            .with_reader(|connection| {
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
            .await
            .unwrap();

        assert!(tables.contains("messages"));
        assert!(tables.contains("data_blocks"));
        assert!(tables.contains("data_refs"));
    }
}
