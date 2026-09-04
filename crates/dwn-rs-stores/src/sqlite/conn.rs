use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use dwn_rs_core::errors::StoreError;
use rusqlite::Connection;
use tokio::sync::Semaphore;

const BUSY_TIMEOUT_MS: isize = 5000;
const READER_POOL_SIZE: usize = 10;

/// Bound for acquiring a connection (issue #255).
///
/// Checkout normally completes in microseconds. Without a bound, a wedged
/// pool stalls `with_reader`/`with_writer` forever: no assertion fails, the
/// test binary just hangs. A generous bound keeps production behaviour intact
/// while turning a silent stall into a contextual `StoreError`.
const POOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Process-wide serialization for file-backed SQLite tests (issue #255).
///
/// File-backed connection sets churn real files through the process-global
/// Unix VFS lock (open/shm/close); dozens of such sets racing across
/// `#[tokio::test]` threads pile up on that lock and stall forever with no
/// failing assertion. Every file-backed test holds [`disk_test_guard()`] for
/// its whole body so only one file-backed test runs per process;
/// memory-backed tests stay parallel. This is strictly a test-harness
/// constraint — production opens a handful of stores, not hundreds of racing
/// connection sets.
///
/// Hidden from docs: this is test infrastructure, not engine API. Note each
/// test *binary* (and each process generally) gets its own lock instance, so
/// this serializes within a process, not across processes.
#[doc(hidden)]
pub static DISK_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Acquire the file-backed-test serialization guard (issue #255).
///
/// Test infrastructure; see [`DISK_TEST_SERIAL`].
#[doc(hidden)]
pub async fn disk_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    DISK_TEST_SERIAL.lock().await
}

/// Blocking acquire of the file-backed-test serialization guard (issue #255).
///
/// For plain `#[test]`s only: never call this from inside an async runtime.
#[doc(hidden)]
pub fn disk_test_guard_blocking() -> tokio::sync::MutexGuard<'static, ()> {
    DISK_TEST_SERIAL.blocking_lock()
}

/// Maps any error into a `StoreError`, tagged with context.
/// We can't `impl From<_> for StoreError` (orphan rule — both types are foreign),
/// so this is the one place connection errors get a message.
fn store_err<E: Display>(ctx: &'static str) -> impl FnOnce(E) -> StoreError {
    move |e| StoreError::InternalException(format!("sqlite: {ctx}: {e}"))
}

/// One SQLite connection with an explicit lifecycle.
///
/// The handle is `take`n exactly once — by [`SqliteConnection::drain`] on a
/// blocking thread that is awaited — so `sqlite3_close` never runs as a
/// fire-and-forget background task that outlives the test body and races
/// runtime teardown (issue #255).
struct Slot {
    conn: Mutex<Option<Connection>>,
}

struct Inner {
    path: PathBuf,
    writer: Arc<Slot>,
    writer_permits: Semaphore,
    readers: Vec<Arc<Slot>>,
    reader_permits: Semaphore,
    next_reader: AtomicUsize,
    closed: AtomicBool,
}

/// Shared SQLite connection handle used by auxiliary store backends.
///
/// One writer connection plus a bounded reader set, all opened eagerly and
/// closed synchronously: every SQLite call runs on a `spawn_blocking` worker
/// that is awaited inline, and [`SqliteConnection::checkpoint_and_close`]
/// takes and closes every handle before returning. Nothing sqlite-related is
/// ever left running in the background, so `#[tokio::test]` teardown
/// (`BlockingPool::shutdown`) has no stragglers to join (issue #255).
#[derive(Clone)]
pub struct SqliteConnection {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SqliteConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteConnection")
            .field("path", &self.inner.path)
            .finish()
    }
}

impl SqliteConnection {
    pub async fn open(
        path: impl AsRef<Path>,
        migrate: impl FnOnce(&mut Connection) -> Result<(), StoreError> + Send + 'static,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();

        // Writer first: the migration runs on it before any reader opens the
        // file, and every open below is awaited before the handle escapes.
        let writer = Arc::new(Slot::open(&path, false).await?);
        interact(&writer, "writer", migrate).await?;

        let mut readers = Vec::with_capacity(READER_POOL_SIZE);
        for _ in 0..READER_POOL_SIZE {
            readers.push(Arc::new(Slot::open(&path, true).await?));
        }

        Ok(Self {
            inner: Arc::new(Inner {
                path,
                writer,
                writer_permits: Semaphore::new(1),
                readers,
                reader_permits: Semaphore::new(READER_POOL_SIZE),
                next_reader: AtomicUsize::new(0),
                closed: AtomicBool::new(false),
            }),
        })
    }

    pub async fn with_reader<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let _permit = permit(&self.inner.reader_permits, &self.inner.closed, "reader").await?;
        let idx = self.inner.next_reader.fetch_add(1, Ordering::Relaxed) % READER_POOL_SIZE;
        let slot = Arc::clone(&self.inner.readers[idx]);
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(StoreError::InternalException(
                "sqlite: reader: connection set closed".to_string(),
            ));
        }
        interact(&slot, "reader", move |c: &mut Connection| f(c)).await
    }

    pub async fn with_writer<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let _permit = permit(&self.inner.writer_permits, &self.inner.closed, "writer").await?;
        let slot = Arc::clone(&self.inner.writer);
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(StoreError::InternalException(
                "sqlite: writer: connection set closed".to_string(),
            ));
        }
        interact(&slot, "writer", f).await
    }

    /// Reject new checkouts. Synchronous and idempotent; already-open handles
    /// are closed by [`SqliteConnection::checkpoint_and_close`] (awaited) or,
    /// for handles never explicitly closed, inline when the last clone drops.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
    }

    /// Checkpoint the WAL and synchronously close every handle (issue #255).
    ///
    /// Folding `-wal`/`-shm` back into the main database before releasing the
    /// handles shrinks the window where a fresh handle on the same file
    /// contends with still-closing connections on the process-global Unix VFS
    /// lock. The checkpoint is best-effort and never fails close; the drain
    /// takes and closes every connection on blocking threads that are all
    /// awaited, so no sqlite work outlives this call.
    pub async fn checkpoint_and_close(&self) {
        if !self.inner.closed.load(Ordering::SeqCst) {
            let _ = self
                .with_writer(|c| {
                    c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                        .map_err(|e| {
                            StoreError::InternalException(format!("sqlite: checkpoint: {e}"))
                        })?;
                    Ok(())
                })
                .await;
        }
        self.close();
        self.drain().await;
    }

    /// Take every connection and close it, awaited.
    ///
    /// Strictly sequential on ONE blocking thread (issue #255): concurrent
    /// `sqlite3_close`s on handles to the same WAL database wedge the
    /// process-global Unix VFS lock permanently (no holder, 0% CPU, never
    /// recovers), hanging `#[tokio::test]` teardown forever with no failing
    /// assertion. Opens are sequential for the same reason.
    async fn drain(&self) {
        let mut slots = Vec::with_capacity(READER_POOL_SIZE + 1);
        slots.push(Arc::clone(&self.inner.writer));
        slots.extend(self.inner.readers.iter().cloned());

        let _ = tokio::task::spawn_blocking(move || {
            for slot in slots {
                let taken = slot.conn.lock().ok().and_then(|mut guard| guard.take());
                drop(taken);
            }
        })
        .await;
    }
}

/// Acquire a checkout permit, failing fast on close or after [`POOL_TIMEOUT`].
async fn permit<'a>(
    semaphore: &'a Semaphore,
    closed: &AtomicBool,
    which: &'static str,
) -> Result<tokio::sync::SemaphorePermit<'a>, StoreError> {
    if closed.load(Ordering::SeqCst) {
        return Err(StoreError::InternalException(format!(
            "sqlite: {which}: connection set closed"
        )));
    }
    tokio::time::timeout(POOL_TIMEOUT, semaphore.acquire())
        .await
        .map_err(|_| {
            StoreError::InternalException(format!(
                "sqlite: {which}: timed out waiting for a connection (see #255)"
            ))
        })?
        .map_err(|_| {
            StoreError::InternalException(format!("sqlite: {which}: connection set closed"))
        })
}

/// Run `f` against the slotted connection on a blocking thread, awaited.
async fn interact<T, F>(slot: &Arc<Slot>, which: &'static str, f: F) -> Result<T, StoreError>
where
    F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    let slot = Arc::clone(slot);
    tokio::task::spawn_blocking(move || {
        let mut guard = slot.conn.lock().map_err(|_| {
            StoreError::InternalException(format!("sqlite: {which}: connection mutex poisoned"))
        })?;
        let conn = guard.as_mut().ok_or_else(|| {
            StoreError::InternalException(format!("sqlite: {which}: connection closed"))
        })?;
        f(conn)
    })
    .await
    .map_err(store_err(which))?
}

impl Slot {
    /// Open one connection and apply its pragmas, awaited.
    async fn open(path: &Path, read_only: bool) -> Result<Self, StoreError> {
        let path = path.to_path_buf();
        let conn = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&path).map_err(|e| {
                StoreError::InternalException(format!("sqlite: open {}: {e}", path.display()))
            })?;
            pragmas(&conn, read_only)
                .map_err(|e| StoreError::InternalException(format!("sqlite: pragmas: {e}")))?;
            Ok::<_, StoreError>(conn)
        })
        .await
        .map_err(store_err("open"))??;
        Ok(Self {
            conn: Mutex::new(Some(conn)),
        })
    }
}

fn pragmas(c: &Connection, read_only: bool) -> rusqlite::Result<()> {
    // `busy_timeout` first so the `journal_mode` upgrade below waits on
    // contended locks instead of failing fast with `SQLITE_BUSY`.
    c.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS)?;
    if read_only {
        c.pragma_update(None, "query_only", "ON")?;
    } else {
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "NORMAL")?;
    }

    c.pragma_update(None, "foreign_keys", "ON")?;

    Ok(())
}
