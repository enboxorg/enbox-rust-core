//! SQLite runners for the shared store battery (issue #169).
//!
//! Bodies live once in `dwn_rs_core::stores::store_conformance` (memory
//! runs in core); here the same suites run on sqlite-mem and sqlite-disk.

mod common;

use dwn_rs_core::stores::store_conformance::{run_data_stores, run_message_stores};
use dwn_rs_stores::SqliteStore;

#[tokio::test]
async fn sqlite_mem_conforms_to_message_store_contract() {
    run_message_stores(|| async { SqliteStore::in_memory(None) }).await;
}

#[tokio::test]
async fn sqlite_disk_conforms_to_message_store_contract() {
    // Serialize file-backed tests process-wide (issue #255).
    let _disk = common::disk_test_guard().await;
    let dir = tempfile::tempdir().expect("battery tempdir");
    let seq = std::sync::atomic::AtomicU64::new(0);
    run_message_stores(|| async {
        let n = seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SqliteStore::new(
            dir.path().join(format!("messages-{n}.sqlite")),
            common::noop_waker(),
        )
    })
    .await;
}

#[tokio::test]
async fn sqlite_mem_conforms_to_data_store_contract() {
    run_data_stores(|| async { SqliteStore::in_memory(None) }).await;
}

#[tokio::test]
async fn sqlite_disk_conforms_to_data_store_contract() {
    // Serialize file-backed tests process-wide (issue #255).
    let _disk = common::disk_test_guard().await;
    let dir = tempfile::tempdir().expect("battery tempdir");
    let seq = std::sync::atomic::AtomicU64::new(0);
    run_data_stores(|| async {
        let n = seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SqliteStore::new(
            dir.path().join(format!("data-{n}.sqlite")),
            common::noop_waker(),
        )
    })
    .await;
}
