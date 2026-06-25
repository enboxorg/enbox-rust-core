//! Native Rust core for Enbox Decentralized Web Nodes (DWN).
//!
//! This crate provides the DWN message model, handlers, agent identity, sync,
//! state index, and supporting traits used by Enbox apps that need to run a
//! DWN without a JavaScript runtime. Mobile, desktop, and server consumers
//! build on the same core.
//!
//! Correctness is anchored in tiers. Where an external specification or test
//! vector exists, that is the source of truth: those checks form a
//! spec-conformance floor (see `fixtures/spec/` and `docs/CONFORMANCE.md`).
//! Where the DWN spec is incomplete, silent, or wrong, the behavior matches the
//! DIF reference implementation ([`@enbox/dwn-sdk-js`](https://github.com/enboxorg/enbox)),
//! and every such gap is tracked as upstream-contribution work in
//! `docs/SPEC_DIVERGENCE.md`.
//!
//! # Entry points
//!
//! - [`dwn::Dwn`] processes DWN messages and dispatches to method handlers.
//! - [`interfaces::Message`] is the typed DWN message model.
//! - [`stores`] defines the persistence traits a DWN engine requires.
//! - [`identity`] groups agent identity, connect/delegate, and tenant setup
//!   flows ([`identity::agent`], [`identity::connect`], [`identity::setup`]).
//! - [`sync`] covers the native `MessagesSync` engine and dead-letter
//!   bookkeeping.
//!
//! # Modules
//!
//! All modules under `crate::` are public. Top-level re-exports are limited
//! to the most commonly used types ([`dwn`], [`interfaces`], [`filters`],
//! [`value`], [`utils`]) to keep the prelude small. Other modules
//! (`auth`, `dwn`, `encryption`, `errors`, `events`, `handlers`, `identity`,
//! `permissions`, `runtime`, `stores`, `sync`, `tasks`) are accessed via their
//! qualified paths.
#![doc(issue_tracker_base_url = "https://github.com/enboxorg/enbox-rust-core/issues/")]
pub mod auth;
pub mod dwn;
pub mod encryption;
pub mod errors;
pub mod events;
pub mod filters;
// `Handler::handle` impls are written as `fn(..) -> impl Future<..> + Send { async move {..} }`
// rather than `async fn`, because the `+ Send` bound is required by the dyn-dispatched
// `HandlerAdapter` and bare `async fn` in a trait impl cannot express it. clippy's
// `manual_async_fn` doesn't account for that bound, so its suggestion would not compile.
#[allow(clippy::manual_async_fn)]
pub mod handlers;
pub mod identity;
pub mod interfaces;
pub mod permissions;
pub mod runtime;
mod ser;
pub mod stores;
pub mod sync;
pub mod tasks;
pub mod value;

pub use dwn::builder::{
    build_native_dwn, build_native_dwn_with_resolver, open_native_stores, NativeDwnConfig,
    NativeDwnOpenError, NativeDwnStores,
};
pub use dwn::*;
pub use errors::lock_error;
pub use events::*;
pub use filters::*;
pub use interfaces::*;
pub use value::*;

pub mod utils;
pub use utils::*;
