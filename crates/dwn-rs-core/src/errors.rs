use std::{collections::BTreeMap, collections::TryReserveError, convert::Infallible};

use thiserror::Error;
use ulid::MonotonicError;

use crate::{stores::ProgressGapInfo, FilterError, QueryError};

pub type DwnErrorInfo = BTreeMap<String, serde_json::Value>;

/// Stable DWN error identifiers carried across handler and replication boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwnErrorCode {
    GeneralJwsVerifierGetPublicKeyNotFound,
    ProtocolAuthorizationProtocolNotFound,
    ProtocolsConfigureComposedProtocolNotInstalled,
    ProtocolAuthorizationParentRecordNotFound,
    ProtocolAuthorizationCrossProtocolParentNotFound,
    ProtocolAuthorizationParentNotFoundConstructingRecordChain,
    RecordsWriteGetInitialWriteNotFound,
    GrantAuthorizationGrantMissing,
    ProtocolAuthorizationMatchingRoleRecordNotFound,
    ProtocolAuthorizationEncryptionRoleAudienceMissing,
    EncryptionControlValidateDeliveryAudienceMissing,
    EncryptionControlValidateDeliveryRecipientRoleRecordMissing,
    RecordsWriteMissingDataInPrevious,
    RecordsWriteMissingEncodedDataInPrevious,
    ProtocolAuthorizationImmutableRecord,
    ProtocolAuthorizationSquashBackstop,
}

impl DwnErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GeneralJwsVerifierGetPublicKeyNotFound => {
                "GeneralJwsVerifierGetPublicKeyNotFound"
            }
            Self::ProtocolAuthorizationProtocolNotFound => "ProtocolAuthorizationProtocolNotFound",
            Self::ProtocolsConfigureComposedProtocolNotInstalled => {
                "ProtocolsConfigureComposedProtocolNotInstalled"
            }
            Self::ProtocolAuthorizationParentRecordNotFound => {
                "ProtocolAuthorizationParentRecordNotFound"
            }
            Self::ProtocolAuthorizationCrossProtocolParentNotFound => {
                "ProtocolAuthorizationCrossProtocolParentNotFound"
            }
            Self::ProtocolAuthorizationParentNotFoundConstructingRecordChain => {
                "ProtocolAuthorizationParentNotFoundConstructingRecordChain"
            }
            Self::RecordsWriteGetInitialWriteNotFound => "RecordsWriteGetInitialWriteNotFound",
            Self::GrantAuthorizationGrantMissing => "GrantAuthorizationGrantMissing",
            Self::ProtocolAuthorizationMatchingRoleRecordNotFound => {
                "ProtocolAuthorizationMatchingRoleRecordNotFound"
            }
            Self::ProtocolAuthorizationEncryptionRoleAudienceMissing => {
                "ProtocolAuthorizationEncryptionRoleAudienceMissing"
            }
            Self::EncryptionControlValidateDeliveryAudienceMissing => {
                "EncryptionControlValidateDeliveryAudienceMissing"
            }
            Self::EncryptionControlValidateDeliveryRecipientRoleRecordMissing => {
                "EncryptionControlValidateDeliveryRecipientRoleRecordMissing"
            }
            Self::RecordsWriteMissingDataInPrevious => "RecordsWriteMissingDataInPrevious",
            Self::RecordsWriteMissingEncodedDataInPrevious => {
                "RecordsWriteMissingEncodedDataInPrevious"
            }
            Self::ProtocolAuthorizationImmutableRecord => "ProtocolAuthorizationImmutableRecord",
            Self::ProtocolAuthorizationSquashBackstop => "ProtocolAuthorizationSquashBackstop",
        }
    }

    pub const fn is_missing_dependency(self) -> bool {
        matches!(
            self,
            Self::ProtocolAuthorizationProtocolNotFound
                | Self::ProtocolsConfigureComposedProtocolNotInstalled
                | Self::ProtocolAuthorizationParentRecordNotFound
                | Self::ProtocolAuthorizationCrossProtocolParentNotFound
                | Self::ProtocolAuthorizationParentNotFoundConstructingRecordChain
                | Self::RecordsWriteGetInitialWriteNotFound
                | Self::GrantAuthorizationGrantMissing
                | Self::ProtocolAuthorizationMatchingRoleRecordNotFound
                | Self::ProtocolAuthorizationEncryptionRoleAudienceMissing
                | Self::EncryptionControlValidateDeliveryAudienceMissing
                | Self::EncryptionControlValidateDeliveryRecipientRoleRecordMissing
                | Self::RecordsWriteMissingDataInPrevious
                | Self::RecordsWriteMissingEncodedDataInPrevious
        )
    }
}

impl std::fmt::Display for DwnErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for DwnErrorCode {
    type Error = ();

    fn try_from(code: &str) -> Result<Self, Self::Error> {
        match code {
            "GeneralJwsVerifierGetPublicKeyNotFound" => {
                Ok(Self::GeneralJwsVerifierGetPublicKeyNotFound)
            }
            "ProtocolAuthorizationProtocolNotFound" => {
                Ok(Self::ProtocolAuthorizationProtocolNotFound)
            }
            "ProtocolsConfigureComposedProtocolNotInstalled" => {
                Ok(Self::ProtocolsConfigureComposedProtocolNotInstalled)
            }
            "ProtocolAuthorizationParentRecordNotFound" => {
                Ok(Self::ProtocolAuthorizationParentRecordNotFound)
            }
            "ProtocolAuthorizationCrossProtocolParentNotFound" => {
                Ok(Self::ProtocolAuthorizationCrossProtocolParentNotFound)
            }
            "ProtocolAuthorizationParentNotFoundConstructingRecordChain" => {
                Ok(Self::ProtocolAuthorizationParentNotFoundConstructingRecordChain)
            }
            "RecordsWriteGetInitialWriteNotFound" => Ok(Self::RecordsWriteGetInitialWriteNotFound),
            "GrantAuthorizationGrantMissing" => Ok(Self::GrantAuthorizationGrantMissing),
            "ProtocolAuthorizationMatchingRoleRecordNotFound" => {
                Ok(Self::ProtocolAuthorizationMatchingRoleRecordNotFound)
            }
            "ProtocolAuthorizationEncryptionRoleAudienceMissing" => {
                Ok(Self::ProtocolAuthorizationEncryptionRoleAudienceMissing)
            }
            "EncryptionControlValidateDeliveryAudienceMissing" => {
                Ok(Self::EncryptionControlValidateDeliveryAudienceMissing)
            }
            "EncryptionControlValidateDeliveryRecipientRoleRecordMissing" => {
                Ok(Self::EncryptionControlValidateDeliveryRecipientRoleRecordMissing)
            }
            "RecordsWriteMissingDataInPrevious" => Ok(Self::RecordsWriteMissingDataInPrevious),
            "RecordsWriteMissingEncodedDataInPrevious" => {
                Ok(Self::RecordsWriteMissingEncodedDataInPrevious)
            }
            "ProtocolAuthorizationImmutableRecord" => {
                Ok(Self::ProtocolAuthorizationImmutableRecord)
            }
            "ProtocolAuthorizationSquashBackstop" => Ok(Self::ProtocolAuthorizationSquashBackstop),
            _ => Err(()),
        }
    }
}

/// A DWN failure with a stable machine-readable code and optional structured data.
#[derive(Error, Debug, Clone, PartialEq)]
#[error("{code}: {detail}")]
pub struct DwnError {
    pub code: DwnErrorCode,
    pub detail: String,
    pub info: Option<DwnErrorInfo>,
}

impl DwnError {
    pub fn new(code: DwnErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            info: None,
        }
    }

    pub fn with_info(mut self, info: DwnErrorInfo) -> Self {
        self.info = Some(info);
        self
    }
}

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

    #[error("incompatible database: {reason}; {action}")]
    IncompatibleDatabase { reason: String, action: String },

    #[error("unable to find record")]
    NotFound,

    #[error("unable to perform duable message replication: {0}")]
    ReplicationError(#[from] MessageReplicationError),
}

#[derive(Error, Debug)]
pub enum MessageStoreError {
    #[error("error operating the store: {0}")]
    StoreError(#[from] StoreError),

    #[error("failed to encode message: {0}")]
    MessageEncodeError(#[from] serde_json::Error),

    #[error("failed to decode message: {0}")]
    MessageDecodeError(#[source] serde_json::Error),

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
pub enum MessageReplicationError {
    #[error("fingerprint scopes mismatch for existing feed entry")]
    FingerprintScopesMismatch,

    #[error("feed position overflow")]
    FeedPositionOverflow,

    #[error("encodedData must be a string or null")]
    InvalidEncodedData,

    #[error("failed to compute message cid: {0}")]
    MissingMessageCid(#[from] ipld_core::cid::Error),

    #[error("cids mismatch for existing feed entry: expected {expected}, actual {actual}")]
    CidsMismatch { expected: String, actual: String },

    #[error("feed entry exists without corresponding message: {message_cid}")]
    MissingMessage { message_cid: String },
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

    #[error("invalid progress token position: {0}")]
    InvalidProgressToken(String),

    #[error("error operating the store: {0}")]
    StoreError(#[from] StoreError),

    #[error("unable to create filters: {0}")]
    FilterError(#[from] FilterError),

    #[error("unable to perform query: {0}")]
    QueryError(#[from] QueryError),

    #[error("unable to generate watermark: {0}")]
    WatermarkError(#[from] MonotonicError),

    #[error("unsupported event log read option: {0}")]
    UnsupportedReadOption(String),

    #[error("event log is closed")]
    Closed,
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
