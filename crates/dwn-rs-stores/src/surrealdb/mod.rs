//! Legacy SurrealDB backend.
//!
//! This module is kept around for backward compatibility with upstream
//! `dwn-rs` consumers. It only implements the `Legacy*` trait variants
//! ([`dwn_rs_core::stores::LegacyMessageStore`] et al.) and is **not**
//! wired up to the new `MessageStore`/`DataStore`/`EventLog`/`StateIndex`/
//! `ResumableTaskStore` interfaces used by the rest of the workspace.
//!
//! New code should target the [`sqlite`](super::sqlite) backend, which
//! implements the canonical traits from `dwn-rs-core::stores`. We expect
//! to retire this backend once the legacy migration path is no longer
//! exercised; see the workspace README for the deprecation timeline.

mod auth;
pub mod core;
pub mod data_store;
pub mod errors;
pub mod event_log;
mod expr;
pub mod message_store;
mod models;
pub mod query;
pub mod resumable_task_store;

pub use core::*;
pub use errors::*;
pub use query::*;
