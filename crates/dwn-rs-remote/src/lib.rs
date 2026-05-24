//! **Legacy** remote-DWN SDK components inherited from upstream `dwn-rs`.
//!
//! This crate predates the workspace's move toward agent-native, locally-
//! running DWN deployments. It remains available so that consumers still
//! talking to remote DWN servers via JSON-RPC can keep working during the
//! migration, but it is **not** the recommended path for new code:
//!
//! - The HTTP/JSON-RPC client surface (see [`client`]) is mostly a thin
//!   wrapper around `reqwest` plus the upstream JSON-RPC envelope and has
//!   no integration with the canonical store traits in
//!   [`dwn_rs_core::stores`].
//! - The error model in [`errors`] is intentionally narrow and does not
//!   match the richer `Dwn::process_message` reply shape used by the
//!   in-process handlers.
//!
//! Prefer driving DWN messages through `dwn_rs_core::Dwn` against a local
//! [`dwn_rs_stores::sqlite`] backend; treat this crate as a compatibility
//! shim that may be retired once the migration is complete.

pub mod client;
pub mod errors;
pub mod jsonrpc;

pub use client::*;
pub use errors::*;
