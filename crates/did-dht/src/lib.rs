//! `did:dht` method logic: DNS codec, BEP44 framing, sequence rules, and the
//! Pkarr-compatible gateway client.
//!
//! This crate is transport-agnostic. It owns the `DhtResolver` type and its
//! configuration, but HTTP execution is injected through [`DhtTransport`] by
//! the host crate (redirects, private-target policy, and deadlines are the
//! implementor's job). That keeps one HTTP mechanism per process while each
//! DID method ships its own complete surface.

mod bep44;
mod codec;
mod encode;
mod error;
mod gateway;
mod sequence;
mod transport;

pub use encode::validate_publishable_document;
pub use error::DhtPublishError;
pub use gateway::{DhtResolver, DhtResolverConfig, ResolvedDhtDocument};
pub use sequence::next_sequence;
pub use transport::{DhtTransport, RelayMethod, RelayRequest, RelayResponse};
