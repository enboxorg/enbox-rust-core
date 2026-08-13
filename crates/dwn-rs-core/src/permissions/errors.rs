use std::collections::TryReserveError;

use base64::DecodeError;
use thiserror::Error;

use crate::{
    auth::JwsError,
    descriptors::records::WriteFieldsError,
    errors::{DataStoreError, MessageStoreError, StoreError},
};

#[derive(Error, Debug)]
pub enum GrantError {
    #[error("Invalid Read descriptor type for grant")]
    InvalidRecordsDescriptorType,

    #[error("Invalid Protocol descriptor type for grant")]
    InvalidProtocolDescriptorType,

    #[error("Invalid Descriptor type for grant")]
    InvalidDescriptorType,

    #[error("unable to extract grantor")]
    UnableToExtractGrantor,

    #[error("could not find permission grant with record ID: {0}")]
    NotFound(String),

    #[error("invalid message type: must be PermissionsProtocol grant RecordsWrite")]
    InvalidMessageType(#[from] GrantMessageTypeError),

    #[error("recordId is required")]
    RecordIdRequired,

    #[error("Unexpected protocol for permission record: {0}")]
    UnexpectedProtocol(String),

    #[error("revocation parentID required")]
    RevocationParentIdRequired,

    #[error("recipient is required")]
    RecipientRequired,

    #[error("invalid grant: {0}")]
    InvalidGrant(#[from] AuthorizationValidationError),

    #[error("protocol validation error: {0}")]
    ProtocolValidationError(#[from] ProtocolValidationError),

    #[error("invalid scope for target: {0} {1}")]
    InvalidScopeForTarget(String, String),

    #[error("grant is not published")]
    UnpublishedGrant,

    #[error("grant prohibits publishing")]
    PublishProhibited,

    #[error("grant is not active")]
    NotActive,

    #[error("grant is expired")]
    Expired,

    #[error("grant is revoked")]
    Revoked,

    #[error("grant is outside of scope")]
    OutsideScope,

    #[error("grant is not authorized")]
    Unauthorized,
}

#[derive(Error, Debug)]
pub enum GrantMessageTypeError {
    #[error("invalid message type: must be PermissionsProtocol")]
    InvalidMessageType,

    #[error("invalid message type: must be PermissionsProtocol grant RecordsWrite")]
    InvalidRecordsWriteMessageType,

    #[error("invalid message type: must be PermissionsProtocol grant ProtocolsQuery")]
    InvalidProtocolsQueryMessageType,

    #[error("invalid message type: must be PermissionsProtocol grant ProtocolsConfigure")]
    InvalidProtocolsConfigureMessageType,
}

#[derive(Error, Debug)]
pub enum PermissionError {
    #[error("authorization error: {0}")]
    AuthorizationValidationError(#[from] AuthorizationValidationError),

    #[error("invalid grant: {0}")]
    InvalidGrant(#[from] GrantError),

    #[error("error operating data store: {0}")]
    DataStoreError(#[from] DataStoreError),

    #[error("error operating message store: {0}")]
    MessageStoreError(#[from] MessageStoreError),

    #[error("error operating store: {0}")]
    StoreError(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum ProtocolValidationError {
    #[error("encodedData is required")]
    MissingEncodedData,

    #[error("invalid base64 encoded data: {0}")]
    InvalidBase64(#[from] DecodeError),

    #[error(transparent)]
    WriteFields(#[from] WriteFieldsError),

    #[error("revocation parentId is required")]
    MissingRevocationParentId,

    #[error("revocation protocol mismatch")]
    RevocationProtocolMismatch,
}

#[derive(Error, Debug)]
pub enum AuthorizationValidationError {
    #[error("bad request: {0}")]
    BadRequest(#[from] AuthorizationRequestError),

    #[error("failed to parse JSON: {0}")]
    ParseFailed(#[from] serde_json::Error),

    #[error("failed to parse CID: {0}")]
    CidParseFailed(#[from] serde_ipld_dagcbor::EncodeError<TryReserveError>),

    #[error("grant is not authorized for author: given {0}, expected {1}")]
    UnexpectedGrantee(String, String),

    #[error("grant is not authorized for tenant: given {0}, expected {1}")]
    UnexpectedGrantor(String, String),

    #[error("permission grants for Records must have scope with `protocol`")]
    RecordsGrantMissingProtocol,

    #[error(
        "permission grants must have a scope with a protocol that matches the tagged protocol"
    )]
    ProtocolInvalidTags,

    #[error("unexpected permission record for: {0}")]
    UnexpectedPermissionRecord(String),

    /// Retained as the handler-facing authorization boundary. Signature
    /// verification can distinguish an unauthenticated request from a
    /// malformed authorization payload without exposing grant internals.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}

#[derive(Error, Debug)]
pub enum AuthorizationRequestError {
    #[error("only one of permissionGrantIDs or permissionGrantIds is allowed")]
    PermissionGrantIDsConflict,

    #[error("invalid request: {0}")]
    ValidationError(String),

    #[error("delegateGrantID requires authorDelegatedGrant")]
    MissingAuthorDelegateGrant,

    #[error("delegateGrantID is required")]
    DelegateGrantIDRequired,

    #[error("delegateGrantID does not match authorDelegatedGrant")]
    DelegateAuthorMismatch,

    #[error("unable to find message CID")]
    MissingCid,

    #[error("cid mismatch")]
    CidMismatch,

    #[error("descriptor is required")]
    DescriptorRequired,

    #[error("invalid message grant method: given {0}, expected Read")]
    MismatchedGrant(String),

    #[error("incoming message has method outside the scope of the grant ID: {0} {1}")]
    GrantScopeMismatch(String, String),

    #[error("`kid` is required")]
    KidRequired,

    #[error("permissionGrantIDs is required")]
    PermissionGrantIDsRequired,

    #[error("authorization signature is required")]
    SignatureRequired,

    #[error("authorization signature is mismatched")]
    SignatureMismatch,

    #[error("invalid signature: {0}")]
    SignatureDecodeError(#[from] serde_json::Error),

    #[error("invalid signature: {0}")]
    InvalidSignature(#[from] JwsError),

    #[error("invalid signature payload: {0}")]
    InvalidBase64(#[from] DecodeError),

    #[error("expected exactly one signature")]
    ExpectedOneSignature,

    #[error("no signer found")]
    NoSignerFound,
}
