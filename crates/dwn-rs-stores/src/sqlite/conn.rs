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
use tokio::sync::{OwnedMutexGuard, OwnedRwLockReadGuard, OwnedSemaphorePermit, RwLock, Semaphore};

const BUSY_TIMEOUT_MS: isize = 5000;
const READER_POOL_SIZE: usize = 10;

/// Bound for phases that own nothing: permit acquisition, slot checkout, gate
/// acquisition, open handshakes.
///
/// These normally complete in microseconds/milliseconds. Without a bound, a
/// wedged state stalls callers forever: no assertion fails, the test binary
/// just hangs. A generous bound keeps production behaviour intact while
/// turning a silent stall into a contextual `StoreError`.
///
/// Deliberately *not* bounded: a worker that already owns a connection, and
/// schema migration. Cancelling a wait abandons nothing; timing out a worker
/// would abandon its connection while the worker still acts on it — breaking
/// writer exclusivity, reporting committed writes as failures, and growing
/// live handles. So a timed-out waiter only ever abandons its *wait*. A
/// timed-out write may still be running, but no second writer can start until
/// it finishes, and no error is reported for work that already began: errors
/// imply the call never ran.
pub(crate) const POOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Cadence for stuck-wait diagnostics. Unbounded waits log instead of hanging
/// silently: a genuine wedge names itself instead of presenting as a park.
const STUCK_WARN_INTERVAL: Duration = Duration::from_secs(10);

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

/// Await `waited`, logging every [`STUCK_WARN_INTERVAL`] while it is still
/// pending, so a genuinely stuck wait names itself instead of presenting as
/// a silent park. The wait itself is never cut short.
async fn warn_while_waiting<T>(
    what: &'static str,
    waited: impl std::future::Future<Output = T>,
) -> T {
    tokio::pin!(waited);
    let mut elapsed = 0u64;
    loop {
        tokio::select! {
            biased;
            result = &mut waited => return result,
            _ = tokio::time::sleep(STUCK_WARN_INTERVAL) => {
                elapsed += 1;
                eprintln!(
                    "[dwn-rs-stores] still waiting for {what} after {}s",
                    elapsed * STUCK_WARN_INTERVAL.as_secs(),
                );
            }
        }
    }
}

/// Maps any error into a `StoreError`, tagged with context.
/// We can't `impl From<_> for StoreError` (orphan rule — both types are foreign),
/// so this is the one place connection errors get a message.
fn store_err<E: Display>(ctx: &'static str) -> impl FnOnce(E) -> StoreError {
    move |e| StoreError::InternalException(format!("sqlite: {ctx}: {e}"))
}

// Ownership model (single closer, no abandonment):
//
// A connection is owned by exactly one party at a time: its slot (idle),
// exactly one worker (during take/run/restore), or the drain (during takes).
// Checkout transfers ownership slot→worker; restore transfers it back; drain
// transfers slotted handles to itself. Timeouts bound only phases that own
// nothing (permit, checkout, gates, open handshake). Once a worker owns a
// connection it runs to completion: cancellation and timeouts abandon waits,
// never connections. The checkout queue is restored by the worker itself, so
// cancellation cannot strand a slot. Only `drain` closes connections,
// sequentially, on one awaited worker.
struct Slot {
    conn: Mutex<Option<Connection>>,
    closed: Arc<AtomicBool>,
}

struct Inner {
    path: PathBuf,
    writer: Arc<Slot>,
    readers: Vec<Arc<Slot>>,
    /// Idle reader slots. Popping is exclusive: one permit admits at most one
    /// checkout, and each checkout holds exactly one slot, so two readers can
    /// never share one. Guarded by a plain mutex whose critical sections are
    /// allocation-free queue ops — never held across an await. The queue
    /// itself travels into the worker, which pushes back on completion, so
    /// cancellation cannot strand a slot outside it.
    checkout_queue: Arc<Mutex<VecDeque<Arc<Slot>>>>,
    reader_permits: Arc<Semaphore>,
    /// Serializes writers against each other, held across the whole worker
    /// cycle (never just across the wait).
    ///
    /// Feed-position assignment assumes serialized puts, so writer
    /// exclusivity is load-bearing — not perf tuning. Readers are deliberately
    /// *not* excluded here: WAL supports concurrent readers during a write,
    /// and excluding them would throw away the concurrency an independent
    /// reader pool provides.
    writer_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes teardown against calls.
    ///
    /// Every call holds this shared across its whole worker cycle while
    /// `drain()` takes it exclusively, so an in-flight call can never close
    /// its handle concurrently with the drain's sequential closes. Writers
    /// take it shared too — their mutual exclusion comes from `writer_lock`.
    drain_gate: Arc<RwLock<()>>,
    closed: Arc<AtomicBool>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Enforced close discipline: every handle must go through `drain`
        // (explicit close paths). A live handle here means a store was
        // dropped without closing it — silent inline closes on the dropping
        // thread are exactly what wedges teardown. Debug-only: release builds
        // still close inline for production processes that exit without an
        // explicit close.
        let idle = |slot: &Arc<Slot>| {
            slot.conn
                .lock()
                .map(|guard| guard.is_none())
                .unwrap_or(true)
        };
        debug_assert!(
            idle(&self.writer) && self.readers.iter().all(idle),
            "SqliteConnection dropped with live handles; close it explicitly"
        );
    }
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
        // The gate is a throwaway: nothing can contend with it yet, since the
        // handle has no aliases and no drain can reach it. The migrate join is
        // deliberately unbounded: migration must run exactly once to
        // completion, and timing it out would let a retry overlap the
        // still-running first run on the same file.
        let gate = Arc::new(RwLock::new(()));
        let writer = Arc::new(Slot::open(&path, false, &closed).await?);
        let drain = gate.read_owned().await;
        run_cycle(
            Arc::clone(&writer),
            None,
            None,
            drain,
            None,
            "writer",
            migrate,
        )
        .await?;

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
                readers,
                checkout_queue: Arc::new(Mutex::new(checkout_queue)),
                reader_permits: Arc::new(Semaphore::new(READER_POOL_SIZE)),
                writer_lock: Arc::new(tokio::sync::Mutex::new(())),
                drain_gate: Arc::new(RwLock::new(())),
                closed,
            }),
        })
    }

    pub async fn with_reader<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        // Phase 1 (bounded, owns nothing shareable): permit, gate, slot. A
        // timeout or cancellation here abandons at most a permit wait or a
        // freshly popped slot handle — never a connection.
        let (permit, slot, drain) = tokio::time::timeout(POOL_TIMEOUT, async {
            let permit = permit(
                Arc::clone(&self.inner.reader_permits),
                &self.inner.closed,
                "reader",
            )
            .await?;
            let drain = Arc::clone(&self.inner.drain_gate).read_owned().await;
            let slot = pop_slot(&self.inner)?;
            if self.inner.closed.load(Ordering::SeqCst) {
                return Err(closed_set_error("reader"));
            }
            Ok((permit, slot, drain))
        })
        .await
        .map_err(|_| {
            StoreError::InternalException(
                "sqlite: reader: timed out waiting for the database".to_string(),
            )
        })??;
        // Phase 2 (unbounded): the worker owns permit, slot, connection and
        // gate holds until it finishes. A wedged native call stalls this
        // caller loudly (see `warn_while_waiting`) instead of corrupting
        // shared state to report an error.
        run_cycle(
            slot,
            Some(Arc::clone(&self.inner.checkout_queue)),
            Some(permit),
            drain,
            None,
            "reader",
            move |c: &mut Connection| f(c),
        )
        .await
    }

    pub async fn with_writer<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        // Phase 1 (bounded, owns nothing shareable).
        let (writer_guard, drain) = tokio::time::timeout(POOL_TIMEOUT, async {
            if self.inner.closed.load(Ordering::SeqCst) {
                return Err(closed_set_error("writer"));
            }
            // Exclusivity is acquired here but travels into the worker: a
            // timed-out waiter stops waiting, but the lock stays with the
            // running call, so no second writer can start until it finishes.
            let writer_guard = Arc::clone(&self.inner.writer_lock).lock_owned().await;
            let drain = Arc::clone(&self.inner.drain_gate).read_owned().await;
            if self.inner.closed.load(Ordering::SeqCst) {
                return Err(closed_set_error("writer"));
            }
            Ok((writer_guard, drain))
        })
        .await
        .map_err(|_| {
            StoreError::InternalException(
                "sqlite: writer: timed out waiting for the database".to_string(),
            )
        })??;
        // Phase 2 (unbounded): the worker owns the connection and holds both
        // the writer lock and the drain hold until it finishes.
        run_cycle(
            Arc::clone(&self.inner.writer),
            None,
            None,
            drain,
            Some(writer_guard),
            "writer",
            f,
        )
        .await
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

    /// Checkpoint the WAL and synchronously close every handle.
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
    /// Strictly sequential on ONE blocking thread: concurrent `sqlite3_close`s
    /// on handles to the same WAL database wedge the process-global Unix VFS
    /// lock permanently (no holder, 0% CPU, never recovers), hanging
    /// `#[tokio::test]` teardown forever with no failing assertion. Opens are
    /// sequential for the same reason.
    ///
    /// The exclusive gate is taken first — unbounded, announced by
    /// [`warn_while_waiting`] if it ever sticks — so no in-flight call can
    /// close its handle concurrently on its own worker. Bounding this wait
    /// would reintroduce exactly the concurrent closes this function exists
    /// to prevent; a wedged worker means the environment is broken, and
    /// abandoning the drain cannot fix that. Skipped (still checked-out)
    /// slots are safe to skip: each in-flight call owns its connection
    /// outright and restore-or-drops it on completion, so nothing is left
    /// unclosed.
    pub(crate) async fn drain(&self) {
        // Bound to a binding so the exclusive hold lives until the takes
        // below complete: as a bare temporary it would drop immediately and
        // the drain would race the very closes it exists to serialize.
        let _exclusive = warn_while_waiting(
            "drain: exclusive gate",
            Arc::clone(&self.inner.drain_gate).write_owned(),
        )
        .await;
        let mut slots = Vec::with_capacity(READER_POOL_SIZE + 1);
        slots.push(Arc::clone(&self.inner.writer));
        slots.extend(self.inner.readers.iter().cloned());

        let _ = warn_while_waiting(
            "drain: sequential close loop",
            tokio::task::spawn_blocking(move || {
                for slot in slots {
                    let taken = slot.conn.lock().ok().and_then(|mut guard| guard.take());
                    drop(taken);
                }
            }),
        )
        .await;
    }
}

/// Pop one idle reader slot with exclusive ownership.
///
/// Safe to unwrap in practice: one pop follows each semaphore acquire and
/// every pop is paired with exactly one worker-side push-back, so the queue
/// can only be empty if more checkouts than permits exist, which the
/// semaphore forbids.
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

/// Acquire a checkout permit, failing fast on close.
///
/// Bounded by the caller's timeout in `with_reader`; the acquire itself does
/// not time out so there is exactly one deadline per operation.
async fn permit(
    semaphore: Arc<Semaphore>,
    closed: &AtomicBool,
    which: &'static str,
) -> Result<OwnedSemaphorePermit, StoreError> {
    if closed.load(Ordering::SeqCst) {
        return Err(closed_set_error(which));
    }
    let permit = semaphore
        .acquire_owned()
        .await
        .map_err(|_| closed_set_error(which))?;
    if closed.load(Ordering::SeqCst) {
        return Err(closed_set_error(which));
    }
    Ok(permit)
}

/// Take the slotted connection, run `f` against it on a blocking thread, and
/// restore it — all inside one worker task, awaited.
///
/// Everything the call holds travels into the worker: the checkout permit,
/// the queue slot's return ticket, the drain-gate hold, and for writers the
/// exclusivity lock. Cancellation of the awaiting caller therefore abandons
/// nothing — the worker always finishes take/run/restore/push-back. The gate
/// hold means a timed-out caller stops waiting while the worker keeps both
/// its connection and its exclusivity until done.
///
/// A panic in `f` is resumed on the caller (never converted into an error,
/// never poisoning the slot): the connection is still restored first, so
/// panics cost nothing but the panic itself.
async fn run_cycle<T, F>(
    slot: Arc<Slot>,
    queue: Option<Arc<Mutex<VecDeque<Arc<Slot>>>>>,
    permit: Option<OwnedSemaphorePermit>,
    drain: OwnedRwLockReadGuard<()>,
    writer_guard: Option<OwnedMutexGuard<()>>,
    which: &'static str,
    f: F,
) -> Result<T, StoreError>
where
    F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    // No awaits before the spawn: cancellation from here abandons nothing,
    // because everything the call holds is already owned and travels into
    // the worker below.
    let outcome = warn_while_waiting(
        which,
        tokio::task::spawn_blocking(
            move || -> Result<Result<T, StoreError>, Box<dyn std::any::Any + Send>> {
                let _permit = permit;
                let _drain = drain;
                let _writer = writer_guard;
                let mut conn = match take(&slot, which) {
                    Ok(conn) => conn,
                    Err(error) => {
                        if let Some(queue) = queue.as_ref() {
                            push_back(queue, slot);
                        }
                        return Ok(Err(error));
                    }
                };
                let outcome =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut conn)));
                restore(&slot, conn);
                if let Some(queue) = queue.as_ref() {
                    push_back(queue, slot);
                }
                outcome
            },
        ),
    )
    .await
    .map_err(store_err(which))?;

    match outcome {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Take the slotted connection.
///
/// The slot is empty only if a cancelled predecessor's worker still owns its
/// connection or the drain took it; either way there is no connection to run
/// on, so report explicitly instead of reopening one — handle count never
/// grows past the pool bound, even under contention.
fn take(slot: &Arc<Slot>, which: &'static str) -> Result<Connection, StoreError> {
    if slot.closed.load(Ordering::SeqCst) {
        return Err(closed_set_error(which));
    }
    slot.conn
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or_else(|| {
            StoreError::InternalException(format!("sqlite: {which}: connection unavailable"))
        })
}

/// Store `conn` back into its slot.
///
/// Always succeeds: with exclusive checkout and the drain excluded by the
/// gate, no other party can occupy the slot meanwhile. Enforced in test
/// builds by `debug_assert!`.
fn restore(slot: &Arc<Slot>, conn: Connection) {
    let mut guard = slot.conn.lock().unwrap_or_else(|e| e.into_inner());
    debug_assert!(
        guard.is_none(),
        "sqlite: slot restored while occupied — exclusive checkout violated"
    );
    *guard = Some(conn);
}

/// Return a slot to the idle queue. Runs on the worker that just used it, so
/// cancellation of the awaiting caller can never strand it.
fn push_back(queue: &Arc<Mutex<VecDeque<Arc<Slot>>>>, slot: Arc<Slot>) {
    queue
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push_back(slot);
}

fn closed_set_error(which: &'static str) -> StoreError {
    StoreError::InternalException(format!("sqlite: {which}: connection set closed"))
}

impl Slot {
    /// Open one connection and apply its pragmas, awaited.
    ///
    /// Unbounded like every other worker join here, and announced like them:
    /// an open that sticks around past one interval is already broken enough
    /// to deserve a name in the logs.
    async fn open(
        path: &Path,
        read_only: bool,
        closed: &Arc<AtomicBool>,
    ) -> Result<Self, StoreError> {
        let path = path.to_path_buf();
        let opened_path = path.clone();
        let conn = warn_while_waiting(
            "open: connection",
            tokio::task::spawn_blocking(move || open_blocking(&opened_path, read_only, "open")),
        )
        .await
        .map_err(store_err("open"))??;
        Ok(Self::from_conn(conn, Arc::clone(closed)))
    }

    fn from_conn(conn: Connection, closed: Arc<AtomicBool>) -> Self {
        Self {
            conn: Mutex::new(Some(conn)),
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
