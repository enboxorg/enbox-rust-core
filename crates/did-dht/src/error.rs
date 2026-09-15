//! Method-level errors for `did:dht` codec, BEP44, and gateway operations.
//!
//! One operation error enum covers the whole method surface. The resolve path
//! never constructs the publish-only variants (`ValueTooLarge`, `Signer`,
//! `GatewayRejected`); the host maps this enum into its own resolver errors.

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum DhtPublishError {
    #[error("invalid DID document: {0}")]
    InvalidDocument(String),

    #[error("DID method '{0}' is not supported")]
    MethodNotSupported(String),

    #[error("DID document not found")]
    NotFound,

    #[error("invalid document length: expected {min}..={max}, found {found}")]
    InvalidDocumentLength {
        min: usize,
        max: usize,
        found: usize,
    },

    #[error("invalid gateway uri: {0}")]
    InvalidGatewayUri(String),

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid public key length: expected {expected}, found {found}")]
    InvalidPublicKeyLength { found: usize, expected: usize },

    #[error("invalid public key type: found {found}")]
    InvalidPublicKeyType { found: String },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("gateway rejected publication: status {status}, sequence {sequence}")]
    GatewayRejected { status: u16, sequence: u64 },

    #[error("signer failed: {0}")]
    Signer(String),

    #[error("document too large: {found} bytes")]
    ValueTooLarge { found: usize },

    #[error("time is before the unix epoch")]
    TimeBeforeEpoch,

    #[error("sequence number overflowed")]
    SequenceOverflow,

    #[error("transport failed: {0}")]
    Transport(String),
}
