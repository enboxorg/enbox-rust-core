//! Shared harness for issue #169 durable-SQLite battery.
//!
//! Provides one memory-URI helper, one RAII tempdir-backed file helper, and a
//! three-way backend factory (`memory` reference is exercised in
//! `dwn-rs-core`; here the matrix is `sqlite-mem` × `sqlite-disk`) so later
//! commits can run identical assertions on both SQLite modes without
//! copy-pasting path schemes.
//!
//! Covers: DWN-SYNC-004 (source-local cursors need per-test isolation),
//! DWN-REC-006 (reopen must use a fresh handle on a real file).

#![allow(dead_code)] // Scaffold for C1–C8; warnings would hide real ones.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dwn_rs_core::stores::wake::WakePublishHandler;
use dwn_rs_core::stores::MessageStore;

use dwn_rs_stores::SqliteStore;

/// Canonical tenant for battery tests.
pub const TENANT: &str = "did:example:alice";

/// Backend matrix shared by battery macros (C5/C6 build on this).
///
/// Memory reference types live in `dwn-rs-core`; SQLite variants are opened
/// with the helpers below.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackendKind {
    Memory,
    SqliteMem,
    SqliteDisk,
}

impl BackendKind {
    /// All backends a cross-implementation case must cover.
    pub const ALL: &'static [BackendKind] = &[
        BackendKind::Memory,
        BackendKind::SqliteMem,
        BackendKind::SqliteDisk,
    ];

    pub fn name(self) -> &'static str {
        match self {
            BackendKind::Memory => "memory",
            BackendKind::SqliteMem => "sqlite-mem",
            BackendKind::SqliteDisk => "sqlite-disk",
        }
    }
}

static DATABASE_ID: AtomicU64 = AtomicU64::new(0);

/// Unique shared-memory URI with per-test isolation (no files).
pub fn unique_memory_uri(prefix: &str) -> String {
    format!(
        "file:{prefix}-{}-{}?mode=memory&cache=shared",
        std::process::id(),
        DATABASE_ID.fetch_add(1, Ordering::Relaxed)
    )
}

/// RAII file-backed database: tempdir lives as long as the guard, so later
/// commits can `close`/drop a store and reopen the same path with a fresh
/// handle to prove real-disk durability.
pub struct TempDb {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TempDb {
    pub fn new(name: &str) -> Self {
        let dir = tempfile::tempdir().expect("battery tempdir");
        let path = dir.path().join(format!("{name}.sqlite"));
        Self { _dir: dir, path }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

fn noop_waker() -> WakePublishHandler {
    WakePublishHandler::new(Arc::new(()))
}

/// Opened in-memory SQLite store (no durability evidence on its own).
pub async fn open_sqlite_mem() -> SqliteStore {
    let mut store = SqliteStore::new(unique_memory_uri("dwn-169"), noop_waker());
    MessageStore::open(&mut store)
        .await
        .expect("sqlite mem store must open");
    store
}

/// Opened file-backed SQLite store; `db` must outlive the store.
pub async fn open_sqlite_disk(db: &TempDb) -> SqliteStore {
    let mut store = SqliteStore::new(db.path(), noop_waker());
    MessageStore::open(&mut store)
        .await
        .expect("sqlite disk store must open");
    store
}

/// Fresh (unopened) handle on the same file — the reopen half of the
/// close/drop → open cycle. Caller must `MessageStore::open` it.
pub fn reopen_sqlite_disk(db: &TempDb) -> SqliteStore {
    SqliteStore::new(db.path(), noop_waker())
}
