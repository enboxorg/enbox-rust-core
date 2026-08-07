#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolverError {
    #[error("invalid DID")]
    InvalidDid,

    #[error("invalid DID document: {0}")]
    InvalidDocument(String),

    #[error("DID method '{0}' is not supported")]
    MethodNotSupported(String),

    #[error("DID document not found")]
    NotFound,

    #[error("internal error: {0}")]
    Internal(String),

    #[error("invalid document length: expected {expected}, found {found}")]
    InvalidDocumentLength { expected: usize, found: usize },

    #[error("invalid gateway uri: {0}")]
    InvalidGatewayUri(String),

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid public key length: found {found}")]
    InvalidPublicKeyLength { found: usize, expected: usize },

    #[error("invalid public key type: found {found}")]
    InvalidPublicKeyType { found: String },

    #[error("invalid signature")]
    InvalidSignature,
}

impl ResolverError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidDid => "invalidDid",
            Self::InvalidDocument(_) => "invalidData",
            Self::MethodNotSupported(_) => "methodNotSupported",
            Self::NotFound => "notFound",

            Self::Internal(_) => "internalError",
            Self::InvalidDocumentLength { .. } => "invalidDidDocumentLength",
            Self::InvalidGatewayUri(_) => "invalidGatewayUri",
            Self::InvalidPublicKey => "invalidPublicKey",
            Self::InvalidPublicKeyLength { .. } => "invalidPublicKeyLength",
            Self::InvalidPublicKeyType { .. } => "invalidPublicKeyType",
            Self::InvalidSignature => "invalidSignature",
        }
    }
}
