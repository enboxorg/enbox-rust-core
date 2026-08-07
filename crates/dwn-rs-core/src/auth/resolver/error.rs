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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dht_errors_expose_enbox_codes() {
        let errors = [
            (ResolverError::Internal("failure".into()), "internalError"),
            (
                ResolverError::InvalidDocumentLength {
                    min: 72,
                    max: 1072,
                    found: 71,
                },
                "invalidDidDocumentLength",
            ),
            (
                ResolverError::InvalidGatewayUri("http://localhost".into()),
                "invalidGatewayUri",
            ),
            (ResolverError::InvalidPublicKey, "invalidPublicKey"),
            (
                ResolverError::InvalidPublicKeyLength {
                    expected: 32,
                    found: 31,
                },
                "invalidPublicKeyLength",
            ),
            (
                ResolverError::InvalidPublicKeyType {
                    found: "unsupported".into(),
                },
                "invalidPublicKeyType",
            ),
            (ResolverError::InvalidSignature, "invalidSignature"),
        ];

        for (error, expected) in errors {
            assert_eq!(error.code(), expected);
        }
    }

    #[test]
    fn length_errors_report_their_complete_constraints() {
        assert_eq!(
            ResolverError::InvalidDocumentLength {
                min: 72,
                max: 1072,
                found: 71,
            }
            .to_string(),
            "invalid document length: expected 72..=1072, found 71"
        );
        assert_eq!(
            ResolverError::InvalidPublicKeyLength {
                expected: 32,
                found: 31,
            }
            .to_string(),
            "invalid public key length: expected 32, found 31"
        );
    }
}
