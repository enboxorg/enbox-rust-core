use std::collections::VecDeque;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use dwn_rs_core::errors::StoreError;
use rusqlite::Connection;
use tokio::sync::Semaphore;

const BUSY_TIMEOUT_MS: isize = 5000;
const READER_POOL_SIZE: usize = 10;

/// Bound for each database operation.
///
/// Checkout and sqlite calls normally complete in microseconds/milliseconds.
/// Without a bound, a wedged state stalls `with_reader`/`with_writer`
/// forever: no assertion fails, the test binary just hangs. A generous bound
/// keeps production behaviour intact while turning a silent stall into a
/// contextual `StoreError`. Note the bound applies to the *wait*: a native
/// SQLite call already running on a worker is not preempted, the waiter is
/// just released with an error.
const POOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Process-wide serialization for file-backed SQLite tests.
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

/// Acquire the file-backed-test serialization guard.
///
/// Test infrastructure; see [`DISK_TEST_SERIAL`].
#[doc(hidden)]
pub async fn disk_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    DISK_TEST_SERIAL.lock().await
}

/// Blocking acquire of the file-backed-test serialization guard.
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
/// The connection is taken out of the slot for the duration of each call and
/// restored afterwards, so the slot mutex is never held across caller code
/// (and can never be poisoned by it). On checkout the slot is empty only if a
/// cancelled predecessor's worker still owns its connection, in which case a
/// fresh one is opened; on restore, a connection is stored only into an empty
/// slot and any stray is closed inline. Every handle is therefore closed
/// exactly once, with no leaks and no overwrites.
struct Slot {
    conn: Mutex<Option<Connection>>,
    path: PathBuf,
    read_only: bool,
    closed: Arc<AtomicBool>,
}

struct Inner {
    path: PathBuf,
    writer: Arc<Slot>,
    writer_permits: Semaphore,
    readers: Vec<Arc<Slot>>,
    /// Idle reader slots. Popping is exclusive: unlike round-robin, a permit
    /// can never admit a reader onto a slot another reader is still using
    /// (issue #255). Guarded by a plain mutex whose critical sections are
    /// allocation-free queue ops — never held across an await.
    checkout_queue: Mutex<VecDeque<Arc<Slot>>>,
    reader_permits: Semaphore,
    closed: Arc<AtomicBool>,
}

/// Shared SQLite connection handle used by auxiliary store backends.
///
/// One writer connection plus a bounded reader set, all opened eagerly and
/// closed synchronously: every SQLite call runs on a `spawn_blocking` worker
/// that is awaited inline, and [`SqliteConnection::checkpoint_and_close`]
/// takes and closes every handle before returning. Nothing sqlite-related is
/// ever left running in the background, so `#[tokio::test]` teardown
/// (`BlockingPool::shutdown`) has no stragglers to join.
///
/// Requires a Tokio runtime with the time driver enabled: `#[tokio::test]`
/// and `enable_all()` runtimes qualify (these cover every in-repo caller,
/// including the FFI runtime constructors). Without the time driver the
/// internal timeouts panic.
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
        let closed = Arc::new(AtomicBool::new(false));

        // Writer first: the migration runs on it before any reader opens the
        // file, and every open below is awaited before the handle escapes.
        let writer = Arc::new(Slot::open(&path, false, &closed).await?);
        run_cycle(&writer, "writer", migrate).await?;

        let mut readers = Vec::with_capacity(READER_POOL_SIZE);
        let mut checkout_queue = VecDeque::with_capacity(READER_POOL_SIZE);
        for _ in 0..READER_POOL_SIZE {
            let slot = Arc::new(Slot::open(&path, true, &closed).await?);
            checkout_queue.push_back(Arc::clone(&slot));
            readers.push(slot);
        }

        Ok(Self {
            inner: Arc::new(Inner {
                path,
                writer,
                writer_permits: Semaphore::new(1),
                readers,
                checkout_queue: Mutex::new(checkout_queue),
                reader_permits: Semaphore::new(READER_POOL_SIZE),
                closed,
            }),
        })
    }

    pub async fn with_reader<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let _permit = permit(&self.inner.reader_permits, &self.inner.closed, "reader").await?;
        let slot = pop_slot(&self.inner)?;
        // Pushed back by `ReturnGuard` on every exit path, including
        // cancellation and panic, so the queue never loses a slot.
        let _return = ReturnGuard::new(&self.inner.checkout_queue, Arc::clone(&slot));
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(closed_set_error("reader"));
        }
        run_cycle(&slot, "reader", move |c: &mut Connection| f(c)).await
    }

    pub async fn with_writer<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let _permit = permit(&self.inner.writer_permits, &self.inner.closed, "writer").await?;
        let slot = Arc::clone(&self.inner.writer);
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(closed_set_error("writer"));
        }
        run_cycle(&slot, "writer", f).await
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
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
    /// takes and closes every connection on one blocking thread, awaited, so
    /// no sqlite work outlives this call.
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
    ///
    /// Skipped (still checked-out) slots are safe to skip: each in-flight
    /// call owns its connection outright and restore-or-drops it on
    /// completion, so nothing is left unclosed.
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

/// Pop one idle reader slot with exclusive ownership.
///
/// Safe to unwrap in practice: one pop follows each semaphore acquire and
/// every pop is paired with exactly one push-back, so the queue can only be
/// empty if more checkouts than permits exist, which the semaphore forbids.
fn pop_slot(inner: &Inner) -> Result<Arc<Slot>, StoreError> {
    inner
        .checkout_queue
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pop_front()
        .ok_or_else(|| {
            StoreError::InternalException("sqlite: reader: no connection available".to_string())
        })
}

/// Pushes its slot back onto the checkout queue on drop.
///
/// The push is synchronous (plain-mutex queue ops, never held across an
/// await), so this also runs on cancellation and panic paths: the queue can
/// never lose a slot to a dropped future.
struct ReturnGuard<'a> {
    queue: &'a Mutex<VecDeque<Arc<Slot>>>,
    slot: Option<Arc<Slot>>,
}

impl<'a> ReturnGuard<'a> {
    fn new(queue: &'a Mutex<VecDeque<Arc<Slot>>>, slot: Arc<Slot>) -> Self {
        Self {
            queue,
            slot: Some(slot),
        }
    }
}

impl Drop for ReturnGuard<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            self.queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_back(slot);
        }
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

/// Take the slotted connection, run `f` against it on a blocking thread, and
/// restore-or-drop it — all inside one worker task, awaited.
///
/// The whole take/run/restore cycle is atomic with respect to cancellation:
/// a timed-out waiter abandons only its *wait*, never a half-moved
/// connection. A slot left empty by a cancelled predecessor is reopened
/// fresh; a restore landing on an occupied slot closes the stray instead of
/// overwriting the live connection. A panic in `f` is resumed on the caller
/// (never converted into an error, never poisoning the slot): the connection
/// is still restored first, so panics cost nothing but the panic itself.
async fn run_cycle<T, F>(slot: &Arc<Slot>, which: &'static str, f: F) -> Result<T, StoreError>
where
    F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    let slot = Arc::clone(slot);
    let outcome = tokio::time::timeout(
        POOL_TIMEOUT,
        tokio::task::spawn_blocking(
            move || -> Result<Result<T, StoreError>, Box<dyn std::any::Any + Send>> {
                let mut conn = match take_or_reopen(&slot, which) {
                    Ok(conn) => conn,
                    Err(error) => return Ok(Err(error)),
                };
                let outcome =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut conn)));
                restore(&slot, conn);
                outcome
            },
        ),
    )
    .await
    .map_err(|_| {
        StoreError::InternalException(format!(
            "sqlite: {which}: timed out waiting for the database (see #255)"
        ))
    })?
    .map_err(store_err(which))?;

    match outcome {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Take the slotted connection, reopening fresh if a cancelled predecessor's
/// worker still owns it.
///
/// Never runs caller code against a closed set: the closed flag is checked
/// before taking and again before reopening, so a call racing
/// `close()`+`drain()` fails explicitly instead of executing on a fresh
/// handle of a dead set. A close landing mid-call is benign: the call
/// linearizes before it and its connection is dropped at restore.
fn take_or_reopen(slot: &Arc<Slot>, which: &'static str) -> Result<Connection, StoreError> {
    if slot.closed.load(Ordering::SeqCst) {
        return Err(closed_set_error(which));
    }
    let taken = slot.conn.lock().unwrap_or_else(|e| e.into_inner()).take();
    match taken {
        Some(conn) => Ok(conn),
        None => {
            if slot.closed.load(Ordering::SeqCst) {
                return Err(closed_set_error(which));
            }
            let conn = open_blocking(&slot.path, slot.read_only, which)?;
            if slot.closed.load(Ordering::SeqCst) {
                drop(conn);
                return Err(closed_set_error(which));
            }
            Ok(conn)
        }
    }
}

/// Store `conn` back into an empty slot; close it inline otherwise.
///
/// A non-empty slot means a cancelled predecessor's slot was reused and
/// reopened meanwhile — closing the stray keeps handle accounting exact. A
/// set closed mid-call drops instead of restoring, so no live handle survives
/// `drain()`.
fn restore(slot: &Arc<Slot>, conn: Connection) {
    if slot.closed.load(Ordering::SeqCst) {
        drop(conn);
        return;
    }
    let mut guard = slot.conn.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(conn);
    }
    // Else: `conn` drops here, closing the stray handle on this worker.
}

fn closed_set_error(which: &'static str) -> StoreError {
    StoreError::InternalException(format!("sqlite: {which}: connection set closed"))
}

impl Slot {
    /// Open one connection and apply its pragmas, awaited.
    async fn open(
        path: &Path,
        read_only: bool,
        closed: &Arc<AtomicBool>,
    ) -> Result<Self, StoreError> {
        let path = path.to_path_buf();
        let opened_path = path.clone();
        let conn =
            tokio::task::spawn_blocking(move || open_blocking(&opened_path, read_only, "open"))
                .await
                .map_err(store_err("open"))??;
        Ok(Self::from_conn(conn, path, read_only, Arc::clone(closed)))
    }

    fn from_conn(
        conn: Connection,
        path: PathBuf,
        read_only: bool,
        closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            conn: Mutex::new(Some(conn)),
            path,
            read_only,
            closed,
        }
    }
}

/// Open one connection and apply its pragmas on the calling (blocking) thread.
fn open_blocking(
    path: &Path,
    read_only: bool,
    which: &'static str,
) -> Result<Connection, StoreError> {
    let conn = Connection::open(path).map_err(|e| {
        StoreError::InternalException(format!("sqlite: {which} {}: {e}", path.display()))
    })?;
    pragmas(&conn, read_only)
        .map_err(|e| StoreError::InternalException(format!("sqlite: {which} pragmas: {e}")))?;
    Ok(conn)
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
