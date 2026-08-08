use thiserror::Error;

/// Errors from DWN record encryption (A256CTR + X25519-HKDF-SHA256+A256KW).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptionError {
    #[error("unsupported content encryption algorithm '{0}'")]
    UnsupportedContentEncryptionAlgorithm(String),

    #[error("unsupported key agreement algorithm '{0}'")]
    UnsupportedKeyAgreementAlgorithm(String),

    #[error("content encryption key must be 32 bytes, got {found}")]
    InvalidContentEncryptionKeyLength { found: usize },

    #[error("initialization vector must be 16 bytes, got {found}")]
    InvalidInitializationVectorLength { found: usize },

    #[error("key encryption inputs must not be empty")]
    EmptyKeyEncryptionInputs,

    #[error("key agreement requires an OKP JWK, got kty '{kty}'")]
    NotAnX25519Jwk { kty: String },

    #[error("key agreement requires crv X25519, got '{curve}'")]
    UnsupportedCurve { curve: String },

    #[error("X25519 public key must be 32 bytes, got {found}")]
    InvalidPublicKeyLength { found: usize },

    #[error("X25519 private key must be 32 bytes, got {found}")]
    InvalidPrivateKeyLength { found: usize },

    #[error("X25519 private JWK missing 'd' parameter")]
    MissingPrivateKeyMaterial,

    #[error("roleAudience key encryption requires a protocol")]
    MissingRoleAudienceProtocol,

    #[error("roleAudience key encryption requires a rolePath")]
    MissingRoleAudienceRolePath,

    #[error("invalid empty key derivation path segment")]
    EmptyDerivationPathSegment,

    #[error("invalid base64url {label}: {error}")]
    InvalidBase64Url { label: String, error: String },

    #[error("missing key encryption entry at index {index}")]
    MissingKeyEncryptionEntry { index: usize },

    #[error("AES key wrap: {0}")]
    AesKeyWrap(String),
}
