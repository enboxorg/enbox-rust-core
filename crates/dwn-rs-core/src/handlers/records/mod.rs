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

// The unit tests reference the per-method handler types by short name via `super::*`; the
// builder uses their full submodule paths, so these re-exports are only needed under `test`.
#[cfg(test)]
pub(crate) use count::RecordsCountHandler;
#[cfg(test)]
pub(crate) use delete::RecordsDeleteHandler;
#[cfg(test)]
pub(crate) use query::RecordsQueryHandler;
#[cfg(test)]
pub(crate) use read::RecordsReadHandler;
#[cfg(test)]
pub(crate) use write::RecordsWriteHandler;

// Re-exported for external store backends (e.g. `dwn-rs-stores`) that drive a long-lived
// records subscription handler directly.
pub use subscribe::{RecordsEventLogSubscribeHandler, RecordsSubscribeReply};
