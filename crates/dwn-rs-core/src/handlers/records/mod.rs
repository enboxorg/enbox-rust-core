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
