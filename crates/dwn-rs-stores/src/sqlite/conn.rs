use std::collections::HashMap;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, LazyLock, Mutex,
};

use dwn_rs_core::errors::StoreError;
use rusqlite::Connection;
use tokio::sync::{mpsc, OwnedMutexGuard, OwnedRwLockReadGuard, RwLock};

const BUSY_TIMEOUT_MS: isize = 5000;
const READER_POOL_SIZE: usize = 10;

/// Per-database-file lifecycle locks, shared by every connection set in the
/// process.
///
/// Opening and closing a handle both enter the process-global Unix VFS lock
/// (`findReusableFd`, `unixOpenSharedMemory`, `sqlite3_close`). Interleaving
/// those across two *independent* sets on one file wedges that lock
/// permanently — no holder, 0% CPU, never recovers, and the only symptom is a
/// hang. [`SqliteConnection::drain`] already serializes closes within a set;
/// this extends the guarantee across sets, which is what makes the hazard
/// unreachable rather than merely unlikely.
///
/// Two sets on one file are reachable in ordinary use: a host opening the same
/// database twice, or a `close()` racing a first `open()` so the loser drains
/// its freshly built set while the winner is live.
///
/// In-memory databases never contend — each store gets a unique URI. Entries
/// are keyed by the path as given and are never evicted: a process opens a
/// handful of distinct databases, so the map is bounded in practice.
static FILE_LIFECYCLE: LazyLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn file_lifecycle(path: &Path) -> Arc<tokio::sync::Mutex<()>> {
    Arc::clone(
        FILE_LIFECYCLE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(path.to_path_buf())
            .or_default(),
    )
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
// transfers slotted handles to itself. Nothing is bounded by a timeout: once a
// worker owns a connection it runs to completion, and no `await` separates a
// checkout from the `spawn_blocking` that receives it, so cancellation
// abandons waits, never connections. Only `drain` closes connections,
// sequentially, on one awaited worker.
struct Slot {
    conn: Mutex<Option<Connection>>,
}

struct Inner {
    path: PathBuf,
    writer: Arc<Slot>,
    readers: Vec<Arc<Slot>>,
    /// Idle reader slots, preloaded at open. Receiving *is* the checkout, so
    /// two callers can never share a slot.
    idle_tx: mpsc::UnboundedSender<Arc<Slot>>,
    idle_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Arc<Slot>>>>,
    /// Serializes writers against each other, held across the whole worker
    /// cycle. Feed-position assignment assumes serialized puts, so this is
    /// load-bearing, not perf tuning. Readers are deliberately not excluded:
    /// WAL supports concurrent readers during a write.
    writer_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes teardown against calls: every call holds it shared for its
    /// whole worker cycle, `drain()` takes it exclusively.
    drain_gate: Arc<RwLock<()>>,
    /// Serializes this set's opens and closes against every *other* set on the
    /// same file; see [`FILE_LIFECYCLE`].
    file_lock: Arc<tokio::sync::Mutex<()>>,
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
        let writer_lock = Arc::new(tokio::sync::Mutex::new(()));
        let drain_gate = Arc::new(RwLock::new(()));
        let file_lock = file_lifecycle(&path);

        // Held across every open below, so no other set on this file can be
        // draining while these handles are being created.
        let opening = Arc::clone(&file_lock).lock_owned().await;

        // Writer first: the migration runs on it before any reader opens the
        // file, and every open below is awaited before the handle escapes.
        // Locks are taken in `with_writer`'s order (writer lock, then gate)
        // even though nothing can contend for them yet. The migrate join is
        // deliberately unbounded: migration must run exactly once to
        // completion, and timing it out would let a retry overlap the
        // still-running first run on the same file.
        let writer = Arc::new(Slot::open(&path, false).await?);
        let writer_guard = Arc::clone(&writer_lock).lock_owned().await;
        let drain = Arc::clone(&drain_gate).read_owned().await;
        run_writer(
            Arc::clone(&writer),
            Arc::clone(&closed),
            drain,
            writer_guard,
            "writer",
            migrate,
        )
        .await?;

        let mut readers = Vec::with_capacity(READER_POOL_SIZE);
        let (idle_tx, idle_rx) = mpsc::unbounded_channel();
        for _ in 0..READER_POOL_SIZE {
            let slot = Arc::new(Slot::open(&path, true).await?);
            idle_tx
                .send(Arc::clone(&slot))
                .expect("receiver alive during open");
            readers.push(slot);
        }

        drop(opening);

        Ok(Self {
            inner: Arc::new(Inner {
                path,
                writer,
                readers,
                idle_tx,
                idle_rx: Arc::new(tokio::sync::Mutex::new(idle_rx)),
                writer_lock,
                drain_gate,
                file_lock,
                closed,
            }),
        })
    }

    pub async fn with_reader<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(closed_set_error("reader"));
        }
        // Gate before checkout: cancelling a gate wait abandons nothing.
        let drain = Arc::clone(&self.inner.drain_gate).read_owned().await;
        let slot = {
            let mut rx = self.inner.idle_rx.lock().await;
            rx.recv().await.ok_or_else(|| {
                StoreError::InternalException("sqlite: reader: no connection available".to_string())
            })?
        };
        if self.inner.closed.load(Ordering::SeqCst) {
            let _ = self.inner.idle_tx.send(slot);
            return Err(closed_set_error("reader"));
        }
        run_reader(
            slot,
            Arc::clone(&self.inner.closed),
            self.inner.idle_tx.clone(),
            drain,
            "reader",
            f,
        )
        .await
    }

    pub async fn with_writer<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(closed_set_error("writer"));
        }
        // Exclusivity travels into the worker: the lock stays with the
        // running call until it finishes.
        let writer_guard = Arc::clone(&self.inner.writer_lock).lock_owned().await;
        let drain = Arc::clone(&self.inner.drain_gate).read_owned().await;
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(closed_set_error("writer"));
        }
        run_writer(
            Arc::clone(&self.inner.writer),
            Arc::clone(&self.inner.closed),
            drain,
            writer_guard,
            "writer",
            f,
        )
        .await
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Reject new checkouts. Synchronous and idempotent; already-open handles
    /// are closed by [`SqliteConnection::drain`] (awaited) or, for handles
    /// never explicitly closed, inline when the last clone drops.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
    }

    /// Checkpoint the WAL and synchronously close every handle.
    ///
    /// Folding `-wal`/`-shm` back into the main database before releasing the
    /// handles shrinks the window where a fresh handle on the same file
    /// contends with still-closing connections on the process-global Unix VFS
    /// lock. The checkpoint is best-effort and never fails close.
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
    /// The file lock excludes every other set on this database; the exclusive
    /// gate then excludes this set's own in-flight calls. Both are
    /// deliberately unbounded: bounding either would reintroduce exactly the
    /// concurrent closes this function exists to prevent. Still-checked-out
    /// slots are safe to skip: each in-flight call owns its connection
    /// outright and restore-or-drops it on completion, so nothing is left
    /// unclosed.
    pub(crate) async fn drain(&self) {
        // Bound to bindings so both holds live until the takes below complete;
        // as bare temporaries they would drop immediately.
        let _closing = self.inner.file_lock.lock().await;
        let _exclusive = Arc::clone(&self.inner.drain_gate).write_owned().await;
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

/// Run `work` on a blocking thread and await it, resuming any panic on the
/// caller. Whatever `work` captures — slot, guards, sender — travels into the
/// worker, so cancelling this await abandons the wait, never a connection.
async fn blocking_worker<T, F>(which: &'static str, work: F) -> Result<T, StoreError>
where
    F: FnOnce() -> Result<Result<T, StoreError>, Box<dyn std::any::Any + Send>> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work)
        .await
        .map_err(store_err(which))?
    {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Take the slotted connection, run `f` against it, and return the slot to the
/// idle channel — restoring the connection before any panic propagates.
async fn run_reader<T, F>(
    slot: Arc<Slot>,
    closed: Arc<AtomicBool>,
    idle_tx: mpsc::UnboundedSender<Arc<Slot>>,
    drain: OwnedRwLockReadGuard<()>,
    which: &'static str,
    f: F,
) -> Result<T, StoreError>
where
    F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    blocking_worker(which, move || {
        let _drain = drain;
        let conn = match take(&slot, &closed, which) {
            Ok(conn) => conn,
            Err(error) => {
                let _ = idle_tx.send(slot);
                return Ok(Err(error));
            }
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&conn)));
        restore(&slot, conn);
        let _ = idle_tx.send(slot);
        outcome
    })
    .await
}

/// Writer twin of [`run_reader`] on the dedicated writer slot (which never
/// enters the idle channel), plus the exclusivity lock held across the cycle.
async fn run_writer<T, F>(
    slot: Arc<Slot>,
    closed: Arc<AtomicBool>,
    drain: OwnedRwLockReadGuard<()>,
    writer_guard: OwnedMutexGuard<()>,
    which: &'static str,
    f: F,
) -> Result<T, StoreError>
where
    F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    blocking_worker(which, move || {
        let _drain = drain;
        let _writer = writer_guard;
        let mut conn = match take(&slot, &closed, which) {
            Ok(conn) => conn,
            Err(error) => return Ok(Err(error)),
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut conn)));
        restore(&slot, conn);
        outcome
    })
    .await
}

/// Take the slotted connection.
///
/// The slot is empty only if a cancelled predecessor's worker still owns its
/// connection or the drain took it; either way there is no connection to run
/// on, so report explicitly instead of reopening one — handle count never
/// grows past the pool bound, even under contention.
fn take(
    slot: &Arc<Slot>,
    closed: &AtomicBool,
    which: &'static str,
) -> Result<Connection, StoreError> {
    if closed.load(Ordering::SeqCst) {
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

fn closed_set_error(which: &'static str) -> StoreError {
    StoreError::InternalException(format!("sqlite: {which}: connection set closed"))
}

impl Slot {
    /// Open one connection and apply its pragmas, awaited.
    async fn open(path: &Path, read_only: bool) -> Result<Self, StoreError> {
        let path = path.to_path_buf();
        let conn = tokio::task::spawn_blocking(move || open_blocking(&path, read_only, "open"))
            .await
            .map_err(store_err("open"))??;
        Ok(Self {
            conn: Mutex::new(Some(conn)),
        })
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
