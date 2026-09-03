//! Tests for the feed-backed [`DurableEventLog`](super::DurableEventLog) adapter.

pub(crate) mod support;

mod drain;
mod initial_write;
mod lifecycle;
mod live_memory;
mod replay;
mod smoke;
