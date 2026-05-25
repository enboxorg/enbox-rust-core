use std::{collections::TryReserveError, convert::Infallible};

use thiserror::Error;
use ulid::MonotonicError;

use crate::{stores::ProgressGapInfo, FilterError, QueryError};

/// Convert a `PoisonError` (or any `RwLock`/`Mutex` lock failure) into a
/// [`StoreError::InternalException`].
///
/// Usage:
///
/// ```ignore
/// let guard = state.read().map_err(crate::lock_error)?;
/// ```
///
/// `RwLock`/`Mutex` poisoning is a programmer-visible signal that an
/// earlier critical section panicked. Inside the in-memory store
/// scaffolds that live alongside the trait definitions, the only safe
/// recovery is to bail out of the operation rather than `unwrap()` and
/// re-panic into the runtime.
pub fn lock_error<T>(err: T) -> StoreError
where
    T: std::fmt::Display,
{
    StoreError::InternalException(format!("lock poisoned: {err}"))
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("error operating store: {0}")]
    StoreError(#[from] StoreError),

    #[error("error processing message: {0}")]
    MessageError(#[from] MessageStoreError),

    #[error("error processing data: {0}")]
    DataError(#[from] DataStoreError),

    #[error("error processing event log: {0}")]
    EventLogError(#[from] EventLogError),

    #[error("error processing resumable task: {0}")]
    ResumableTaskError(#[from] ResumableTaskStoreError),

    #[error("error processing event stream: {0}")]
    EventStreamError(#[from] EventStreamError),
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("error opening database: {0}")]
    OpenError(String),

    #[error("no database initialized")]
    NoInitError,

    #[error("internal store error: {0}")]
    InternalException(String),

    #[error("unable to find record")]
    NotFound,
}

#[derive(Error, Debug)]
pub enum MessageStoreError {
    #[error("error operating the store: {0}")]
    StoreError(#[from] StoreError),

    #[error("failed to encode message: {0}")]
    MessageEncodeError(#[from] ipld_core::serde::SerdeError),

    #[error("failed to decode message: {0}")]
    MessageDecodeError(#[source] ipld_core::serde::SerdeError),

    #[error("failed to serde encode message: {0}")]
    SerdeEncodeError(#[from] serde_ipld_dagcbor::error::EncodeError<TryReserveError>),

    #[error("failed to serde decode message: {0}")]
    SerdeDecodeError(#[from] serde_ipld_dagcbor::error::DecodeError<Infallible>),

    #[error("failed to encode cid")]
    CidEncodeError(#[from] ipld_core::cid::Error),

    #[error("failed to decode cid")]
    CidDecodeError(#[source] ipld_core::cid::Error),

    #[error("unable to perform query: {0}")]
    QueryError(#[from] QueryError),

    #[error("unable to create filters: {0}")]
    FilterError(#[from] FilterError),
}

#[derive(Error, Debug)]
pub enum DataStoreError {
    #[error("error opening database: {0}")]
    OpenError(String),

    #[error("no database initialized")]
    NoInitError,

    #[error("error operating the store: {0}")]
    StoreError(#[from] StoreError),

    #[error("unable to read data from buffer")]
    ReadError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum EventLogError {
    #[error("progress token gap: {0:?}")]
    ProgressGap(Box<ProgressGapInfo>),

    #[error("error operating the store: {0}")]
    StoreError(#[from] StoreError),

    #[error("unable to create filters: {0}")]
    FilterError(#[from] FilterError),

    #[error("unable to perform query: {0}")]
    QueryError(#[from] QueryError),

    #[error("unable to generate watermark: {0}")]
    WatermarkError(#[from] MonotonicError),
}

#[derive(Error, Debug)]
pub enum ResumableTaskStoreError {
    #[error("error operating the store: {0}")]
    StoreError(#[from] StoreError),

    #[error("unable to perform query: {0}")]
    QueryError(#[from] QueryError),

    #[error("unable to generate task id: {0}")]
    IdGenerationError(#[from] MonotonicError),

    #[error("unable to create filters: {0}")]
    FilterError(#[from] FilterError),

    #[error("unable to decode task id: {0}")]
    TaskIdDecodeError(#[from] ulid::DecodeError),
}

#[derive(Error, Debug)]
pub enum EventStreamError {
    #[error("error operating the store: {0}")]
    StoreError(#[from] StoreError),

    #[error("actor error: {0}")]
    ActorError(#[from] xtra::Error),
}
