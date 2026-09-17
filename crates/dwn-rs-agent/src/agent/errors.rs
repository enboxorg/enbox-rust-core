use super::*;

pub type AgentIdentityResult<T> = Result<T, AgentIdentityError>;
pub type AgentIdentityFuture<'a, T> =
    Pin<Box<dyn Future<Output = AgentIdentityResult<T>> + Send + 'a>>;

pub const VAULT_PORTABLE_DID_KEY: &str = "agent:vault:portableDid";
/// Secret-store key for the vault content-encryption key bytes.
pub const VAULT_CONTENT_ENCRYPTION_KEY: &str = "agent:vault:contentEncryptionKey";
/// Secret-store key for the vault unlock salt bytes.
pub const VAULT_UNLOCK_SALT_KEY: &str = "agent:vault:unlockSalt";

/// Agent error with a stable machine-readable code and human detail.
///
/// Each variant preserves the code string previously carried in the
/// `code` field, exposed through [`AgentIdentityError::code`]. Codes pass
/// through the FFI surface verbatim. Backend implementors outside this
/// crate report their own failures through [`AgentIdentityError::new`],
/// which carries any code and detail unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AgentIdentityError {
    #[error("AgentIdentityInvalidMnemonic: {detail}")]
    InvalidMnemonic { detail: String },
    #[error("AgentIdentityInvalidKeyMaterial: {detail}")]
    InvalidKeyMaterial { detail: String },
    #[error("AgentIdentityDidError: {detail}")]
    Did { detail: String },
    #[error("AgentIdentityKeyManagerError: {detail}")]
    KeyManager { detail: String },
    #[error("AgentIdentityVaultError: {detail}")]
    Vault { detail: String },
    #[error("AgentIdentityLockPoisoned: {detail}")]
    LockPoisoned { detail: String },
    #[error("AgentVaultError: {detail}")]
    AgentVault { detail: String },
    #[error("RegistrationTokenStoreInvalid: {detail}")]
    RegistrationTokenStore { detail: String },
    #[error("DelegateSecretInvalid: {detail}")]
    DelegateSecret { detail: String },
    #[error("DelegateKeyMissingKeyAgreement: {detail}")]
    DelegateKeyAgreement { detail: String },
    #[error("DelegateKeyMissingX25519: {detail}")]
    DelegateKeyX25519 { detail: String },
    #[error("ProtocolInstallInvalidPath: {detail}")]
    ProtocolPath { detail: String },
    #[error("ProtocolInstallMissingKeyAgreement: {detail}")]
    ProtocolAgreement { detail: String },
    #[error("ProtocolInstallMissingX25519: {detail}")]
    ProtocolX25519 { detail: String },
    #[error("{code}: {detail}")]
    Backend { code: String, detail: String },
}

impl AgentIdentityError {
    /// Build a failure for the given code and detail.
    ///
    /// Codes the crate defines map to their typed variant, so a failure
    /// built here compares equal to one raised internally with the same
    /// code and detail. Anything else becomes an implementor-defined
    /// [`AgentIdentityError::Backend`] failure, which reaches the caller
    /// and the FFI mapping unchanged.
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        let code = code.into();
        let detail: String = detail.into();
        match code.as_str() {
            "AgentIdentityInvalidMnemonic" => Self::InvalidMnemonic { detail },
            "AgentIdentityInvalidKeyMaterial" => Self::InvalidKeyMaterial { detail },
            "AgentIdentityDidError" => Self::Did { detail },
            "AgentIdentityKeyManagerError" => Self::KeyManager { detail },
            "AgentIdentityVaultError" => Self::Vault { detail },
            "AgentIdentityLockPoisoned" => Self::LockPoisoned { detail },
            "AgentVaultError" => Self::AgentVault { detail },
            "RegistrationTokenStoreInvalid" => Self::RegistrationTokenStore { detail },
            "DelegateSecretInvalid" => Self::DelegateSecret { detail },
            "DelegateKeyMissingKeyAgreement" => Self::DelegateKeyAgreement { detail },
            "DelegateKeyMissingX25519" => Self::DelegateKeyX25519 { detail },
            "ProtocolInstallInvalidPath" => Self::ProtocolPath { detail },
            "ProtocolInstallMissingKeyAgreement" => Self::ProtocolAgreement { detail },
            "ProtocolInstallMissingX25519" => Self::ProtocolX25519 { detail },
            _ => Self::Backend { code, detail },
        }
    }

    /// Stable machine-readable code for this failure.
    pub fn code(&self) -> &str {
        match self {
            Self::InvalidMnemonic { .. } => "AgentIdentityInvalidMnemonic",
            Self::InvalidKeyMaterial { .. } => "AgentIdentityInvalidKeyMaterial",
            Self::Did { .. } => "AgentIdentityDidError",
            Self::KeyManager { .. } => "AgentIdentityKeyManagerError",
            Self::Vault { .. } => "AgentIdentityVaultError",
            Self::LockPoisoned { .. } => "AgentIdentityLockPoisoned",
            Self::AgentVault { .. } => "AgentVaultError",
            Self::RegistrationTokenStore { .. } => "RegistrationTokenStoreInvalid",
            Self::DelegateSecret { .. } => "DelegateSecretInvalid",
            Self::DelegateKeyAgreement { .. } => "DelegateKeyMissingKeyAgreement",
            Self::DelegateKeyX25519 { .. } => "DelegateKeyMissingX25519",
            Self::ProtocolPath { .. } => "ProtocolInstallInvalidPath",
            Self::ProtocolAgreement { .. } => "ProtocolInstallMissingKeyAgreement",
            Self::ProtocolX25519 { .. } => "ProtocolInstallMissingX25519",
            Self::Backend { code, .. } => code,
        }
    }

    /// Human-readable detail. Never contains key material, salts, or tokens.
    pub fn detail(&self) -> &str {
        match self {
            Self::InvalidMnemonic { detail }
            | Self::InvalidKeyMaterial { detail }
            | Self::Did { detail }
            | Self::KeyManager { detail }
            | Self::Vault { detail }
            | Self::LockPoisoned { detail }
            | Self::AgentVault { detail }
            | Self::RegistrationTokenStore { detail }
            | Self::DelegateSecret { detail }
            | Self::DelegateKeyAgreement { detail }
            | Self::DelegateKeyX25519 { detail }
            | Self::ProtocolPath { detail }
            | Self::ProtocolAgreement { detail }
            | Self::ProtocolX25519 { detail }
            | Self::Backend { detail, .. } => detail,
        }
    }

    pub(crate) fn invalid_mnemonic(detail: impl Into<String>) -> Self {
        Self::InvalidMnemonic {
            detail: detail.into(),
        }
    }

    pub(crate) fn invalid_key_material(detail: impl Into<String>) -> Self {
        Self::InvalidKeyMaterial {
            detail: detail.into(),
        }
    }

    pub(crate) fn did(detail: impl Into<String>) -> Self {
        Self::Did {
            detail: detail.into(),
        }
    }

    pub(crate) fn key_manager(detail: impl Into<String>) -> Self {
        Self::KeyManager {
            detail: detail.into(),
        }
    }

    pub(crate) fn vault(detail: impl Into<String>) -> Self {
        Self::Vault {
            detail: detail.into(),
        }
    }

    pub(crate) fn lock_poisoned<E: Display>(err: E) -> Self {
        Self::LockPoisoned {
            detail: format!("agent identity store lock poisoned: {err}"),
        }
    }

    pub(crate) fn agent_vault(detail: impl Into<String>) -> Self {
        Self::AgentVault {
            detail: detail.into(),
        }
    }

    pub(crate) fn registration_token_store(detail: impl Into<String>) -> Self {
        Self::RegistrationTokenStore {
            detail: detail.into(),
        }
    }

    pub(crate) fn delegate_secret(detail: impl Into<String>) -> Self {
        Self::DelegateSecret {
            detail: detail.into(),
        }
    }

    pub(crate) fn delegate_key_agreement(detail: impl Into<String>) -> Self {
        Self::DelegateKeyAgreement {
            detail: detail.into(),
        }
    }

    pub(crate) fn delegate_key_x25519(detail: impl Into<String>) -> Self {
        Self::DelegateKeyX25519 {
            detail: detail.into(),
        }
    }

    pub(crate) fn protocol_path(detail: impl Into<String>) -> Self {
        Self::ProtocolPath {
            detail: detail.into(),
        }
    }

    pub(crate) fn protocol_agreement(detail: impl Into<String>) -> Self {
        Self::ProtocolAgreement {
            detail: detail.into(),
        }
    }

    pub(crate) fn protocol_x25519(detail: impl Into<String>) -> Self {
        Self::ProtocolX25519 {
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        type ErrorCase = (fn(String) -> AgentIdentityError, &'static str);
        let cases: [ErrorCase; 14] = [
            (
                AgentIdentityError::invalid_mnemonic,
                "AgentIdentityInvalidMnemonic",
            ),
            (
                AgentIdentityError::invalid_key_material,
                "AgentIdentityInvalidKeyMaterial",
            ),
            (AgentIdentityError::did, "AgentIdentityDidError"),
            (
                AgentIdentityError::key_manager,
                "AgentIdentityKeyManagerError",
            ),
            (AgentIdentityError::vault, "AgentIdentityVaultError"),
            (
                AgentIdentityError::lock_poisoned,
                "AgentIdentityLockPoisoned",
            ),
            (AgentIdentityError::agent_vault, "AgentVaultError"),
            (
                AgentIdentityError::registration_token_store,
                "RegistrationTokenStoreInvalid",
            ),
            (AgentIdentityError::delegate_secret, "DelegateSecretInvalid"),
            (
                AgentIdentityError::delegate_key_agreement,
                "DelegateKeyMissingKeyAgreement",
            ),
            (
                AgentIdentityError::delegate_key_x25519,
                "DelegateKeyMissingX25519",
            ),
            (
                AgentIdentityError::protocol_path,
                "ProtocolInstallInvalidPath",
            ),
            (
                AgentIdentityError::protocol_agreement,
                "ProtocolInstallMissingKeyAgreement",
            ),
            (
                AgentIdentityError::protocol_x25519,
                "ProtocolInstallMissingX25519",
            ),
        ];
        for (build, code) in cases {
            let error = build("detail".to_string());
            assert_eq!(error.code(), code);
            assert_eq!(error.to_string(), format!("{code}: {}", error.detail()));
            assert!(!error.detail().is_empty());
            if code == "AgentIdentityLockPoisoned" {
                // lock_poisoned prefixes its detail, so it cannot round-trip
                // through new(); the code mapping still holds.
                assert!(error.detail().contains("lock poisoned"));
            } else {
                assert_eq!(AgentIdentityError::new(code, "detail"), error);
            }
        }
        for code in ["HttpRegistrationTransportFailed", "CustomHostCode"] {
            let error = AgentIdentityError::new(code, "host detail");
            assert_eq!(error.code(), code);
            assert_eq!(error.detail(), "host detail");
            assert_eq!(error.to_string(), format!("{code}: host detail"));
        }
    }
}
