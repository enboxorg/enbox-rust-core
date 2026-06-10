//! Persistent backends for the `dwn-rs-core` store traits.
//!
//! [`sqlite`] is the only backend. It implements `MessageStore`, `DataStore`,
//! `StateIndex`, `EventLog`, and `ResumableTaskStore` from
//! `dwn_rs_core::stores`. See [`native_node::SqliteNativeDwn`] for the wired
//! local node entry point and [`SqliteSyncLedger`] for durable sync progress.

#[cfg(feature = "sqlite")]
pub mod native_node;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "sqlite")]
pub use crate::SqliteSecretStore;
#[cfg(feature = "sqlite")]
pub use crate::SqliteSyncLedger;
#[cfg(feature = "sqlite")]
pub use native_node::SqliteNativeDwn;
#[cfg(feature = "sqlite")]
pub use sqlite::*;
