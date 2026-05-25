//! Persistent backends for the `dwn-rs-core` store traits.
//!
//! Two backends live in this crate:
//!
//! - [`sqlite`] — the actively-developed backend. Implements the canonical
//!   `MessageStore`, `DataStore`, `EventLog`, `StateIndex`, and
//!   `ResumableTaskStore` traits from `dwn-rs-core::stores`.
//! - [`surrealdb`] — legacy backend inherited from upstream `dwn-rs`. It
//!   only implements the deprecated `Legacy*` trait counterparts and is
//!   gated behind the `surrealdb` (or `surreal-lib` / `surreal-wasm`)
//!   feature flag. New code should target [`sqlite`].

#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::*;

#[cfg(feature = "surrealdb")]
pub mod surrealdb;
#[cfg(feature = "surrealdb")]
pub use surrealdb::*;
