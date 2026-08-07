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
}

impl ResolverError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidDid => "invalidDid",
            Self::InvalidDocument(_) => "invalidData",
            Self::MethodNotSupported(_) => "methodNotSupported",
            Self::NotFound => "notFound",
        }
    }
}
