//! Native Rust core for Enbox Decentralized Web Nodes (DWN).
//!
//! This crate provides the DWN message model, handlers, agent identity, sync,
//! state index, and supporting traits used by Enbox apps that need to run a
//! DWN without a JavaScript runtime. Mobile, desktop, and server consumers
//! build on the same core.
//!
//! The behavior source of truth is the TypeScript implementation in
//! [`@enbox/dwn-sdk-js`](https://github.com/enboxorg/enbox); the Rust crates
//! are kept in conformance via fixtures (see `docs/CONFORMANCE.md`).
//!
//! # Entry points
//!
//! - [`dwn::Dwn`] processes DWN messages and dispatches to method handlers.
//! - [`interfaces::Message`] is the typed DWN message model.
//! - [`stores`] defines the persistence traits a DWN engine requires.
//! - [`agent`], [`connect`], [`setup`] cover identity, connect/delegate,
//!   and tenant setup flows.
//! - [`sync`] covers the native `MessagesSync` engine and dead-letter
//!   bookkeeping.
//!
//! # Modules
//!
//! All modules under `crate::` are public. Top-level re-exports are limited
//! to the most commonly used types ([`dwn`], [`interfaces`], [`filters`],
//! [`value`], [`utils`]) to keep the prelude small. Other modules
//! (`agent`, `auth`, `connect`, `desktop`, `encryption`, `errors`, `events`,
//! `handlers`, `local`, `mobile`, `permissions`, `setup`, `state_index`,
//! `stores`, `sync`) are accessed via their qualified paths.
#![doc(issue_tracker_base_url = "https://github.com/enboxorg/enbox-rust-core/issues/")]
pub mod agent;
pub mod auth;
pub mod connect;
pub mod desktop;
pub mod dwn;
pub mod encryption;
pub mod errors;
pub mod events;
pub mod filters;
pub mod handlers;
pub mod interfaces;
pub mod local;
pub mod mobile;
pub mod permissions;
mod ser;
pub mod setup;
pub mod state_index;
pub mod stores;
pub mod sync;
pub mod value;

pub use dwn::*;
pub use events::*;
pub use filters::*;
pub use interfaces::*;
pub use value::*;

pub mod utils;
pub use utils::*;
