//! Durable-SQLite battery as a single integration target.
//!
//! The suites below used to be one `tests/*.rs` file per binary (14 links on
//! every rebuild). They now live in `tests/battery/` as modules of this one
//! target: no test was added, removed, or reworded — only re-homed, so `cargo
//! test` links once instead of 14 times. Run a subset with a filter, e.g.
//! `cargo test -p dwn-rs-stores --test battery visibility_parity`.

mod atomic_feed_state;
mod common;
mod concurrent_crash;
mod control_repair_recovery;
mod durable_event_log_sqlite;
mod encryption_persistence;
mod native_dwn_integration;
mod records_context_subtree;
mod records_convergence;
mod records_record_limit;
mod sqlite_aux_persistence;
mod sqlite_disk_persistence;
mod store_conformance;
mod sync_ledger_integration;
mod visibility_parity;
