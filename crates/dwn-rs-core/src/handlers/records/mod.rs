mod common;
pub(crate) mod count;
pub(crate) mod delete;
pub(crate) mod query;
pub(crate) mod read;
pub(crate) mod subscribe;
pub(crate) mod write;

#[cfg(test)]
mod tests;

pub(crate) const RECORDS_INTERFACE: &str = "Records";
pub(crate) const WRITE_METHOD: &str = "Write";
pub(crate) const MAX_ENCODED_DATA_SIZE: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordsAuthorizationKind {
    Write,
    Read,
    Query,
    Count,
    Delete { prune: bool },
    Subscribe,
}

pub(crate) use delete::{resume_records_delete_from_task, resume_records_squash_from_task};

// Handler types live in their per-method submodules; re-export them at the `records` level so
// internal callers (builder, tests) and external store backends use a stable path.
pub(crate) use count::RecordsCountHandler;
pub(crate) use delete::RecordsDeleteHandler;
pub(crate) use query::RecordsQueryHandler;
pub(crate) use read::RecordsReadHandler;
pub(crate) use subscribe::RecordsSubscribeHandler;
pub(crate) use write::RecordsWriteHandler;

// Re-exported for external store backends (e.g. `dwn-rs-stores`) that drive a long-lived
// records subscription handler directly.
pub use subscribe::{RecordsEventLogSubscribeHandler, RecordsSubscribeReply};
