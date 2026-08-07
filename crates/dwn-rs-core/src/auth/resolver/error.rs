pub use ssi_dids_core::resolution::Error;

pub enum ResolverError {
    InvalidDid,
    MethodNotSupported(String),
    NotFound,
    Network(String),
    InvalidData(Vec<u8>),
    ResolutionError(Error),
}
impl ResolverError {
    pub fn code(&self) -> &'static str {
        match self {
            ResolverError::InvalidDid => "invalidDid",
            ResolverError::MethodNotSupported(_) => "methodNotSupported",
            ResolverError::NotFound => "notFound",
            ResolverError::Network(_) => "networkError",
            ResolverError::InvalidData(_) => "invalidData",
            ResolverError::ResolutionError(err) => match err {
                Error::MethodNotSupported(_) => "methodNotSupported",
                Error::NotFound => "notFound",
                Error::InvalidData(_) => "invalidData",
                _ => "resolutionError",
            },
        }
    }
}
