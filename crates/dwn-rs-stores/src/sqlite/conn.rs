use std::fmt::Display;
use std::path::Path;

use deadpool_sqlite::{Config, Hook, HookError, Pool, Runtime};
use dwn_rs_core::errors::StoreError;
use rusqlite::Connection;

use super::store::SqliteStore;

const BUSY_TIMEOUT_MS: isize = 5000;
const READER_POOL_SIZE: usize = 10;

/// Maps any pool/interact error into a `StoreError`, tagged with context.
/// We can't `impl From<_> for StoreError` (orphan rule — both types are foreign),
/// so this is the one place pool errors get a message.
fn store_err<E: Display>(ctx: &'static str) -> impl FnOnce(E) -> StoreError {
    move |e| StoreError::InternalException(format!("sqlite: {ctx}: {e}"))
}

/// Shared SQLite connection handle used by auxiliary store backends.
#[derive(Debug, Clone)]
pub struct SqliteConnection {
    writer: Pool,
    readers: Pool,
}

impl SqliteConnection {
    pub(crate) fn from_store(store: &SqliteStore) -> Self {
        store.conn.clone()
    }

    pub async fn open(
        path: impl AsRef<Path>,
        migrate: impl FnOnce(&mut Connection) -> Result<(), StoreError> + Send + 'static,
    ) -> Result<Self, StoreError> {
        let writer = build_pool(path.as_ref(), 1, false)?;
        let readers = build_pool(path.as_ref(), READER_POOL_SIZE, true)?;

        // Run the migration once, on the writer pool, before handing out the handle.
        // Double `?`: outer peels the InteractError, inner peels the migration's StoreError.
        writer
            .get()
            .await
            .map_err(store_err("acquire writer connection"))?
            .interact(|c| migrate(c))
            .await
            .map_err(store_err("run migration"))??;

        Ok(Self { writer, readers })
    }

    pub async fn with_reader<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        run(&self.readers, "reader", f).await
    }

    pub async fn with_writer<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        run(&self.writer, "writer", f).await
    }

    pub fn close(&self) {
        self.readers.close();
        self.writer.close();
    }
}

/// Acquire a connection from `pool` and run `f` on the blocking pool.
async fn run<T, F>(pool: &Pool, which: &'static str, f: F) -> Result<T, StoreError>
where
    F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    pool.get()
        .await
        .map_err(store_err(which))?
        .interact(move |c| f(c))
        .await
        .map_err(store_err(which))?
}

fn build_pool(path: &Path, max_size: usize, read_only: bool) -> Result<Pool, StoreError> {
    Config::new(path)
        .builder(Runtime::Tokio1)
        .map_err(store_err("create pool"))?
        .max_size(max_size)
        .post_create(Hook::async_fn(move |obj, _| {
            Box::pin(async move {
                obj.interact(move |c| pragmas(c, read_only))
                    .await
                    .map_err(|e| HookError::message(e.to_string()))?
                    .map_err(|e| HookError::message(e.to_string()))?;
                Ok(())
            })
        }))
        .build()
        .map_err(store_err("build pool"))
}

fn pragmas(c: &Connection, read_only: bool) -> rusqlite::Result<()> {
    if read_only {
        c.pragma_update(None, "query_only", "ON")?;
    } else {
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "NORMAL")?;
    }

    c.pragma_update(None, "foreign_keys", "ON")?;
    c.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS)?;

    Ok(())
}
