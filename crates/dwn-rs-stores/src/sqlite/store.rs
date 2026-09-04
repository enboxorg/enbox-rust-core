use std::{path::Path, sync::Arc, sync::Mutex};

use dwn_rs_core::{errors::StoreError, stores::wake::WakePublishHandler};
use rusqlite::{Connection, Transaction};

use crate::{
    sqlite::data_migrations::{run_data_migrations, DATA_MIGRATIONS},
    SqliteConnection,
};

/// Lifecycle of the shared connection set.
///
/// The state lives behind one lock shared by every clone of the store, so a
/// `close()` observed through one handle is observed through all of them and
/// a later `open()` revives every handle at once. Operations on a `Closed`
/// store fail explicitly; only `open()` transitions out of `Closed`.
pub(crate) enum ConnState {
    Unopened,
    Open(SqliteConnection),
    Closed,
}

#[derive(Clone)]
pub struct SqliteStore {
    pub(crate) conn: Arc<Mutex<ConnState>>,
    path: Arc<Path>,
    pub(crate) waker_publisher: WakePublishHandler,
    /// Serializes first opens.
    ///
    /// Without single-flight, racing tasks each build a full eleven-handle
    /// set and the losers close theirs inline on the executor. The mutex is
    /// held across the awaited open only; every other state access takes the
    /// brief state lock without holding this one, so the order is fixed and
    /// cannot cycle.
    open_mutex: Arc<tokio::sync::Mutex<()>>,
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
            conn: Arc::new(Mutex::new(ConnState::Unopened)),
            waker_publisher,
            open_mutex: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Handle to the open connection set, opening it on first use.
    ///
    /// Operations on a closed store fail explicitly with a "closed" error —
    /// checked *before* opening, so closed handles never pay an
    /// open-then-discard cycle just to report failure. Only
    /// [`SqliteStore::open_inner`] transitions out of `Closed`.
    pub(crate) async fn connection(&self) -> Result<SqliteConnection, StoreError> {
        if let Some(conn) = self.open_conn() {
            return Ok(conn);
        }
        if matches!(
            *self.conn.lock().unwrap_or_else(|e| e.into_inner()),
            ConnState::Closed
        ) {
            return Err(closed_error());
        }
        // Single-flight the build: racing tasks would otherwise each open a
        // full handle set and discard all but one.
        let _opening = self.open_mutex.lock().await;
        if let Some(conn) = self.open_conn() {
            return Ok(conn);
        }
        if matches!(
            *self.conn.lock().unwrap_or_else(|e| e.into_inner()),
            ConnState::Closed
        ) {
            return Err(closed_error());
        }
        let fresh = SqliteConnection::open(self.path.clone(), migrate).await?;
        let mut state = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        match &*state {
            ConnState::Open(conn) if !conn.is_closed() => Ok(conn.clone()),
            // A concurrent open won, or the store was closed while we opened:
            // prefer the shared state over our redundant fresh handle, which
            // closes inline on drop.
            ConnState::Open(_) => Err(closed_error()),
            ConnState::Unopened => {
                *state = ConnState::Open(fresh.clone());
                Ok(fresh)
            }
            ConnState::Closed => Err(closed_error()),
        }
    }

    /// Open the store, reviving it if a previous `close()` drained its
    /// handles.
    ///
    /// Without the reset, `open()` after `close()` would report `Ok(())`
    /// while every later operation fails on the drained connection set. The
    /// reset goes through the shared state, so every clone of the store
    /// observes the revival at once.
    pub(crate) async fn open_inner(&mut self) -> Result<(), StoreError> {
        {
            let mut state = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(*state, ConnState::Closed) {
                *state = ConnState::Unopened;
            }
        }
        self.connection().await.map(|_| ())
    }

    /// Checkpoint, synchronously close, and mark closed.
    ///
    /// The `Closed` marker is shared, so operations through every clone fail
    /// explicitly until `open_inner` revives the store.
    pub(crate) async fn close_inner(&mut self) {
        let prev = {
            let mut state = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *state, ConnState::Closed)
        };
        if let ConnState::Open(conn) = prev {
            conn.checkpoint_and_close().await;
        }
    }

    /// Cloned open handle, if any. Never opens.
    fn open_conn(&self) -> Option<SqliteConnection> {
        match &*self.conn.lock().unwrap_or_else(|e| e.into_inner()) {
            ConnState::Open(conn) if !conn.is_closed() => Some(conn.clone()),
            _ => None,
        }
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

fn closed_error() -> StoreError {
    StoreError::InternalException(
        "sqlite: connection set closed; call open() to revive it".to_string(),
    )
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
    use std::sync::Arc;

    use dwn_rs_core::stores::wake::WakePublishHandler;
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
        // Serialize file-backed tests process-wide. Plain
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

    #[tokio::test]
    async fn ops_on_closed_store_fail_explicitly() {
        // Operations after close() must fail fast with context,
        // never hang or use a drained handle — including through clones,
        // which share the lifecycle state.
        let mut store = SqliteStore::in_memory(None);
        MessageStore::open(&mut store).await.unwrap();
        let clone = store.clone();
        MessageStore::close(&mut store).await;

        for handle in [&store, &clone] {
            let error = handle
                .connection()
                .await
                .expect_err("op on closed store must fail");
            assert!(error.to_string().contains("closed"), "{error:?}");
        }
    }

    #[tokio::test]
    async fn close_then_open_file_store_preserves_data() {
        // open() after close() yields a usable store instead of
        // Ok(()) over a dead connection set — through every clone, which
        // share one lifecycle state. File-backed, so committed rows must
        // survive the cycle (a scratch table keeps this unit test free of
        // message fixtures).
        let _disk = crate::sqlite::conn::disk_test_guard().await;
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("revive.sqlite3");

        let mut store = SqliteStore::new(&path, WakePublishHandler::new(Arc::new(())));
        MessageStore::open(&mut store).await.unwrap();
        let clone = store.clone();
        store
            .connection()
            .await
            .unwrap()
            .with_writer(|connection| {
                connection
                    .execute_batch(
                        "CREATE TABLE revive_probe (value TEXT PRIMARY KEY); \
                         INSERT INTO revive_probe VALUES ('durability-marker');",
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .unwrap();
        MessageStore::close(&mut store).await;
        MessageStore::open(&mut store).await.unwrap();

        for handle in [&store, &clone] {
            let value: String = handle
                .connection()
                .await
                .unwrap()
                .with_reader(|connection| {
                    connection
                        .query_row("SELECT value FROM revive_probe", [], |row| row.get(0))
                        .map_err(sqlite_store_error)
                })
                .await
                .unwrap();
            assert_eq!(value, "durability-marker");
        }
    }

    #[tokio::test]
    async fn close_then_open_memory_store_starts_blank() {
        // SQLite semantics: a shared-cache in-memory database is
        // destroyed when its last connection closes, so revive yields a
        // fresh, usable — but empty — database. This pins that contract
        // instead of letting a vacuous assertion pass on re-migrated schema.
        let mut store = SqliteStore::in_memory(None);
        MessageStore::open(&mut store).await.unwrap();
        store
            .connection()
            .await
            .unwrap()
            .with_writer(|connection| {
                connection
                    .execute_batch(
                        "CREATE TABLE revive_probe (value TEXT PRIMARY KEY); \
                         INSERT INTO revive_probe VALUES ('ephemeral');",
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .unwrap();
        MessageStore::close(&mut store).await;
        MessageStore::open(&mut store).await.unwrap();

        // Usable (schema migrated)…
        let epoch: String = store
            .connection()
            .await
            .unwrap()
            .with_reader(|connection| {
                connection
                    .query_row("SELECT epoch FROM feed_metadata WHERE id = 1", [], |row| {
                        row.get::<_, String>(0)
                    })
                    .map_err(sqlite_store_error)
            })
            .await
            .unwrap();
        assert!(!epoch.is_empty());
        // …but the pre-close rows are gone with the destroyed database.
        let remaining: i64 = store
            .connection()
            .await
            .unwrap()
            .with_reader(|connection| {
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE name = 'revive_probe'",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(sqlite_store_error)
            })
            .await
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn concurrent_first_opens_all_succeed() {
        // Racing first opens single-flight instead of each
        // building (and discarding) a full handle set. All racers must
        // succeed; a broken single-flight would deadlock here.
        let store = SqliteStore::in_memory(None);
        let mut joins = Vec::new();
        for _ in 0..16 {
            let handle = store.clone();
            joins.push(tokio::spawn(async move {
                handle
                    .connection()
                    .await
                    .unwrap()
                    .with_reader(|connection| {
                        connection
                            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                            .map_err(sqlite_store_error)
                    })
                    .await
                    .unwrap()
            }));
        }
        for join in joins {
            assert_eq!(join.await.unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn panicking_op_neither_poisons_nor_leaks_its_slot() {
        // A panic inside `with_*` must surface to the caller and
        // leave the slot usable; the connection is restored before
        // propagation, so nothing leaks.
        let mut store = SqliteStore::in_memory(None);
        MessageStore::open(&mut store).await.unwrap();
        let conn = store.connection().await.unwrap();

        let panicked = tokio::spawn(async move {
            conn.with_reader(|_| -> Result<(), StoreError> { panic!("injected op panic") })
                .await
        })
        .await;
        assert!(
            panicked.is_err() && panicked.unwrap_err().is_panic(),
            "panic must propagate to the caller"
        );

        let epoch: String = store
            .connection()
            .await
            .unwrap()
            .with_reader(|connection| {
                connection
                    .query_row("SELECT epoch FROM feed_metadata WHERE id = 1", [], |row| {
                        row.get::<_, String>(0)
                    })
                    .map_err(sqlite_store_error)
            })
            .await
            .unwrap();
        assert!(!epoch.is_empty());
    }
}
