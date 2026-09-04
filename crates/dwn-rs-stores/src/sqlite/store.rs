use std::{path::Path, sync::Arc};

use dwn_rs_core::{errors::StoreError, stores::wake::WakePublishHandler};
use rusqlite::{Connection, Transaction};
use tokio::sync::OnceCell;

use crate::{
    sqlite::data_migrations::{run_data_migrations, DATA_MIGRATIONS},
    SqliteConnection,
};

#[derive(Clone)]
pub struct SqliteStore {
    pub(crate) conn: Arc<OnceCell<SqliteConnection>>,
    path: Arc<Path>,
    pub(crate) waker_publisher: WakePublishHandler,
}

impl SqliteStore {
    pub fn in_memory(waker_publisher: Option<WakePublishHandler>) -> Self {
        // if waker_publisher is none, use the no-op publisher e.g. for tests
        let waker_publisher =
            waker_publisher.unwrap_or_else(|| WakePublishHandler::new(Arc::new(())));

        Self::new(unique_memory_uri(), waker_publisher)
    }

    pub fn new(path: impl AsRef<Path>, waker_publisher: WakePublishHandler) -> Self {
        Self {
            path: Arc::from(path.as_ref()),
            conn: Arc::new(OnceCell::new()),
            waker_publisher,
        }
    }

    pub(crate) async fn connection(&self) -> Result<&SqliteConnection, StoreError> {
        self.conn
            .get_or_try_init(|| SqliteConnection::open(self.path.clone(), migrate))
            .await
    }

    /// Handle to the connections if this store was opened, without opening it.
    ///
    /// Close paths must use this: `connection()` would lazily *create* eleven
    /// SQLite connections (and their VFS state) just to immediately close
    /// them again (issue #255).
    pub(crate) fn connection_if_open(&self) -> Option<&SqliteConnection> {
        self.conn.get()
    }

    pub(crate) fn epoch_tx(tx: &Transaction<'_>) -> Result<String, StoreError> {
        tx.query_row("SELECT epoch FROM feed_metadata WHERE id = 1", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_store_error)
    }
}
pub(crate) fn sqlite_store_error(error: rusqlite::Error) -> StoreError {
    StoreError::InternalException(error.to_string())
}

mod embedded {
    use refinery::embed_migrations;
    // Refinery discovers files named V{version}__{name}.sql at compile time.
    embed_migrations!("src/sqlite/migrations/sql");
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    embedded::migrations::runner()
        .run(connection)
        .map_err(|e| StoreError::InternalException(e.to_string()))?;

    run_data_migrations(connection, DATA_MIGRATIONS)
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
    use rusqlite::Transaction;

    use super::*;
    use crate::sqlite::data_migrations::DataMigration;

    fn epoch(connection: &Connection) -> Option<String> {
        connection
            .query_row("SELECT epoch FROM feed_metadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .ok()
    }

    #[test]
    fn fresh_database_initializes_durable_feed() {
        let mut connection = Connection::open_in_memory().unwrap();

        migrate(&mut connection).unwrap();

        assert!(epoch(&connection).is_some_and(|epoch| !epoch.is_empty()));
        assert_eq!(
            connection
                .query_row("SELECT name FROM migrations WHERE version = 1", [], |row| {
                    row.get::<_, String>(0)
                },)
                .unwrap(),
            "initialize_durable_message_feed"
        );
    }

    #[test]
    fn empty_legacy_database_migrates() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(include_str!("migrations/sql/V1__initial.sql"))
            .unwrap();

        migrate(&mut connection).unwrap();

        assert!(epoch(&connection).is_some());
    }

    #[test]
    fn populated_pre_feed_database_is_rejected_without_marking_data_migration() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(include_str!("migrations/sql/V1__initial.sql"))
            .unwrap();
        connection
            .execute(
                "INSERT INTO messages \
                 (tenant, message_cid, message_json, indexes_json) \
                 VALUES ('did:example:alice', 'cid', '{}', '{}')",
                [],
            )
            .unwrap();

        let error = migrate(&mut connection).unwrap_err();

        assert!(matches!(
            error,
            StoreError::IncompatibleDatabase { ref reason, ref action }
                if reason.contains("without trustworthy durable-feed ordering")
                    && action.contains("export")
        ));
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM migrations", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(epoch(&connection).is_none());
    }

    #[test]
    fn failed_data_migration_rolls_back_and_is_retryable() {
        fn fail_after_write(tx: &Transaction<'_>) -> Result<(), StoreError> {
            tx.execute(
                "INSERT INTO feed_metadata (id, epoch) VALUES (1, 'rolled-back')",
                [],
            )
            .map_err(sqlite_store_error)?;
            Err(StoreError::InternalException(
                "injected failure".to_string(),
            ))
        }

        let mut connection = Connection::open_in_memory().unwrap();
        embedded::migrations::runner().run(&mut connection).unwrap();
        let migration = DataMigration {
            version: 99,
            name: "rollback_test",
            migrate: fail_after_write,
        };

        assert!(run_data_migrations(&mut connection, &[migration]).is_err());
        assert!(epoch(&connection).is_none());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM migrations WHERE version = 99",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn durable_feed_schema_enforces_constraints_and_uniqueness() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection).unwrap();

        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema \
                     WHERE type = 'index' \
                       AND name = 'feed_entries_tenant_position_asc'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );

        assert!(connection
            .execute(
                "INSERT INTO feed_entries VALUES ('tenant', 0, 'zero', '{}', '[]')",
                [],
            )
            .is_err());
        assert!(connection
            .execute(
                "INSERT INTO feed_fingerprints VALUES ('tenant', '', x'00')",
                [],
            )
            .is_err());

        connection
            .execute(
                "INSERT INTO feed_entries VALUES ('tenant', 1, 'cid-1', '{}', '[]')",
                [],
            )
            .unwrap();
        assert!(connection
            .execute(
                "INSERT INTO feed_entries VALUES ('tenant', 1, 'cid-2', '{}', '[]')",
                [],
            )
            .is_err());
        assert!(connection
            .execute(
                "INSERT INTO feed_entries VALUES ('tenant', 2, 'cid-1', '{}', '[]')",
                [],
            )
            .is_err());
    }

    #[test]
    fn on_disk_reopen_preserves_epoch() {
        // Serialize file-backed tests process-wide (issue #255). Plain
        // `#[test]`: no runtime is running, so blocking acquisition is safe.
        let _disk = crate::sqlite::conn::disk_test_guard_blocking();
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("migration.sqlite3");

        let original_epoch = {
            let mut connection = Connection::open(&path).unwrap();
            migrate(&mut connection).unwrap();
            epoch(&connection).unwrap()
        };

        let mut reopened = Connection::open(&path).unwrap();
        migrate(&mut reopened).unwrap();
        assert_eq!(epoch(&reopened).as_deref(), Some(original_epoch.as_str()));
    }

    #[tokio::test]
    async fn sqlite_store_migrates_schema_on_open() {
        let mut store = SqliteStore::in_memory(None);
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
