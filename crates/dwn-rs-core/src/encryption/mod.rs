//! DWN record encryption.
//!
//! Models the current `@enbox/dwn-sdk-js` encryption envelope used by
//! RecordsWrite: A256CTR content encryption (AES-256 in counter mode, 16-byte
//! counter, no AEAD tag) with X25519-HKDF-SHA256+A256KW key agreement. This
//! replaces the legacy JWE General serialization (`protected/iv/tag/recipients`)
//! removed upstream.
//!
//! Primitive implementations live in [`ctr`], [`aes_kw`], [`kdf`], and
//! [`x25519`]; this module owns the wire types and the `Encryption` facade.
//! The agent encryption-control seal key wrap is modeled separately ([`SealKeyWrap`])
//! because upstream keeps it distinct from `DwnEncryption.keyEncryption`.

pub mod aes_kw;
pub mod ctr;
pub mod error;
pub mod kdf;
pub mod legacy_jwe;
pub mod x25519;

pub use error::EncryptionError;
pub use kdf::derive_private_key_bytes;

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD as base64url};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

pub const KEY_AGREEMENT_ALGORITHM: &str = "X25519-HKDF-SHA256+A256KW";
pub const ROLE_AUDIENCE_DERIVATION_SCHEME: &str = "roleAudience";
pub const SEAL_DERIVATION_SCHEME: &str = "seal";

/// RecordsWrite `keyEncryption` derivation schemes. Upstream only admits
/// `protocolPath` and `roleAudience` here; seal wrapping is a separate type.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum DerivationScheme {
    #[serde(rename = "protocolPath")]
    ProtocolPath,
    #[serde(rename = "roleAudience")]
    RoleAudience,
}

impl DerivationScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            DerivationScheme::ProtocolPath => "protocolPath",
            DerivationScheme::RoleAudience => "roleAudience",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum ContentEncryptionAlgorithm {
    #[serde(rename = "A256CTR")]
    A256Ctr,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum KeyAgreementAlgorithm {
    #[serde(rename = "X25519-HKDF-SHA256+A256KW")]
    X25519HkdfSha256A256Kw,
}

impl KeyAgreementAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyAgreementAlgorithm::X25519HkdfSha256A256Kw => "X25519-HKDF-SHA256+A256KW",
        }
    }
}

/// A single `DwnEncryption.keyEncryption` entry, discriminated by
/// `derivationScheme`. `protocolPath` carries no extra fields; `roleAudience`
/// requires both `protocol` and `rolePath` (enforced structurally).
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "derivationScheme")]
pub enum KeyEncryption {
    #[serde(rename = "protocolPath")]
    ProtocolPath {
        algorithm: KeyAgreementAlgorithm,
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "ephemeralPublicKey")]
        ephemeral_public_key: JWK,
        #[serde(rename = "encryptedKey")]
        encrypted_key: String,
    },
    #[serde(rename = "roleAudience")]
    RoleAudience {
        algorithm: KeyAgreementAlgorithm,
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "ephemeralPublicKey")]
        ephemeral_public_key: JWK,
        #[serde(rename = "encryptedKey")]
        encrypted_key: String,
        protocol: String,
        #[serde(rename = "rolePath")]
        role_path: String,
    },
}

impl KeyEncryption {
    pub fn key_id(&self) -> &str {
        match self {
            KeyEncryption::ProtocolPath { key_id, .. } => key_id,
            KeyEncryption::RoleAudience { key_id, .. } => key_id,
        }
    }

    pub fn ephemeral_public_key(&self) -> &JWK {
        match self {
            KeyEncryption::ProtocolPath {
                ephemeral_public_key,
                ..
            } => ephemeral_public_key,
            KeyEncryption::RoleAudience {
                ephemeral_public_key,
                ..
            } => ephemeral_public_key,
        }
    }

    pub fn encrypted_key(&self) -> &str {
        match self {
            KeyEncryption::ProtocolPath { encrypted_key, .. } => encrypted_key,
            KeyEncryption::RoleAudience { encrypted_key, .. } => encrypted_key,
        }
    }

    pub fn derivation_scheme(&self) -> DerivationScheme {
        match self {
            KeyEncryption::ProtocolPath { .. } => DerivationScheme::ProtocolPath,
            KeyEncryption::RoleAudience { .. } => DerivationScheme::RoleAudience,
        }
    }

    pub fn protocol(&self) -> Option<&str> {
        match self {
            KeyEncryption::ProtocolPath { .. } => None,
            KeyEncryption::RoleAudience { protocol, .. } => Some(protocol),
        }
    }

    pub fn role_path(&self) -> Option<&str> {
        match self {
            KeyEncryption::ProtocolPath { .. } => None,
            KeyEncryption::RoleAudience { role_path, .. } => Some(role_path),
        }
    }

    pub fn algorithm(&self) -> KeyAgreementAlgorithm {
        match self {
            KeyEncryption::ProtocolPath { algorithm, .. } => *algorithm,
            KeyEncryption::RoleAudience { algorithm, .. } => *algorithm,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Encryption {
    Envelope(EncryptionEnvelope),
    LegacyJwe(legacy_jwe::LegacyJweEncryption),
}

impl Encryption {
    pub fn decrypt(
        &self,
        private_jwk: &JWK,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        match self {
            Encryption::Envelope(envelope) => envelope.decrypt(private_jwk, ciphertext),
            Encryption::LegacyJwe(jwe) => jwe.decrypt(private_jwk, ciphertext),
        }
    }

    pub fn is_legacy_jwe(&self) -> bool {
        matches!(self, Encryption::LegacyJwe(_))
    }
}

/// Encryption envelope for a RecordsWrite, including the CEK, IV, and
/// `keyEncryption` entries.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EncryptionEnvelope {
    pub algorithm: ContentEncryptionAlgorithm,
    #[serde(rename = "initializationVector")]
    pub initialization_vector: String,
    #[serde(rename = "keyEncryption")]
    pub key_encryption: Vec<KeyEncryption>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EncryptionInput {
    pub algorithm: Option<ContentEncryptionAlgorithm>,
    pub key: Vec<u8>,
    #[serde(rename = "initializationVector")]
    pub initialization_vector: Vec<u8>,
    #[serde(rename = "keyEncryptionInputs")]
    pub key_encryption_inputs: Vec<KeyEncryptionInput>,
}

/// Builder input for a single `keyEncryption` entry, discriminated by
/// `derivationScheme`. `roleAudience` requires `protocol`/`rolePath`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "derivationScheme")]
pub enum KeyEncryptionInput {
    #[serde(rename = "protocolPath")]
    ProtocolPath {
        algorithm: KeyAgreementAlgorithm,
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "publicKey")]
        public_key: JWK,
    },
    #[serde(rename = "roleAudience")]
    RoleAudience {
        algorithm: KeyAgreementAlgorithm,
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "publicKey")]
        public_key: JWK,
        protocol: String,
        #[serde(rename = "rolePath")]
        role_path: String,
    },
}

impl KeyEncryptionInput {
    pub fn key_id(&self) -> &str {
        match self {
            KeyEncryptionInput::ProtocolPath { key_id, .. } => key_id,
            KeyEncryptionInput::RoleAudience { key_id, .. } => key_id,
        }
    }

    pub fn public_key(&self) -> &JWK {
        match self {
            KeyEncryptionInput::ProtocolPath { public_key, .. } => public_key,
            KeyEncryptionInput::RoleAudience { public_key, .. } => public_key,
        }
    }

    pub fn derivation_scheme(&self) -> DerivationScheme {
        match self {
            KeyEncryptionInput::ProtocolPath { .. } => DerivationScheme::ProtocolPath,
            KeyEncryptionInput::RoleAudience { .. } => DerivationScheme::RoleAudience,
        }
    }

    pub fn protocol(&self) -> Option<&str> {
        match self {
            KeyEncryptionInput::ProtocolPath { .. } => None,
            KeyEncryptionInput::RoleAudience { protocol, .. } => Some(protocol),
        }
    }

    pub fn role_path(&self) -> Option<&str> {
        match self {
            KeyEncryptionInput::ProtocolPath { .. } => None,
            KeyEncryptionInput::RoleAudience { role_path, .. } => Some(role_path),
        }
    }

    pub fn algorithm(&self) -> KeyAgreementAlgorithm {
        match self {
            KeyEncryptionInput::ProtocolPath { algorithm, .. } => *algorithm,
            KeyEncryptionInput::RoleAudience { algorithm, .. } => *algorithm,
        }
    }
}

/// Agent encryption-control seal key wrap. This is a separate type from
/// `DwnEncryption.keyEncryption`; its KEK derivation binds protocol,
/// rolePath, contextId, and audienceKeyId, not a `keyId`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "derivationScheme")]
pub enum SealKeyWrap {
    #[serde(rename = "seal")]
    Seal {
        algorithm: KeyAgreementAlgorithm,
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "ephemeralPublicKey")]
        ephemeral_public_key: JWK,
        #[serde(rename = "encryptedKey")]
        encrypted_key: String,
    },
}

impl SealKeyWrap {
    pub fn algorithm(&self) -> KeyAgreementAlgorithm {
        match self {
            SealKeyWrap::Seal { algorithm, .. } => *algorithm,
        }
    }

    pub fn key_id(&self) -> &str {
        match self {
            SealKeyWrap::Seal { key_id, .. } => key_id,
        }
    }

    pub fn ephemeral_public_key(&self) -> &JWK {
        match self {
            SealKeyWrap::Seal {
                ephemeral_public_key,
                ..
            } => ephemeral_public_key,
        }
    }

    pub fn encrypted_key(&self) -> &str {
        match self {
            SealKeyWrap::Seal { encrypted_key, .. } => encrypted_key,
        }
    }
}

/// Inputs required to build a seal wrap (`SealKeyWrapInput` upstream).
pub struct SealKeyWrapInput<'a> {
    pub algorithm: KeyAgreementAlgorithm,
    pub key_id: String,
    pub public_key: JWK,
    pub protocol: &'a str,
    pub role_path: &'a str,
    pub context_id: &'a str,
    pub audience_key_id: &'a str,
}

impl EncryptionEnvelope {
    /// Builds an encryption envelope, mirroring
    /// `Encryption.buildEncryptionProperty` including its parameter
    /// validation (CEK length, IV length, non-empty key-encryption inputs).
    pub fn build_encryption(input: &EncryptionInput) -> Result<Self, EncryptionError> {
        let algorithm = input
            .algorithm
            .unwrap_or(ContentEncryptionAlgorithm::A256Ctr);
        validate_content_encryption_algorithm(algorithm)?;
        if input.key.len() != 32 {
            return Err(EncryptionError::InvalidContentEncryptionKeyLength {
                found: input.key.len(),
            });
        }
        if input.initialization_vector.len() != 16 {
            return Err(EncryptionError::InvalidInitializationVectorLength {
                found: input.initialization_vector.len(),
            });
        }
        if input.key_encryption_inputs.is_empty() {
            return Err(EncryptionError::EmptyKeyEncryptionInputs);
        }

        let mut key_encryption = Vec::with_capacity(input.key_encryption_inputs.len());
        for key_input in &input.key_encryption_inputs {
            let algorithm = key_input.algorithm();
            validate_key_agreement_algorithm(algorithm)?;

            let ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
            let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
            let wrapped_key = x25519_hkdf_a256kw_wrap(
                &ephemeral_secret.to_bytes(),
                &x25519::public_key_bytes(key_input.public_key())?,
                key_input.key_id(),
                key_input.derivation_scheme(),
                key_input.protocol(),
                key_input.role_path(),
                &input.key,
            )?;

            key_encryption.push(match key_input {
                KeyEncryptionInput::ProtocolPath { .. } => KeyEncryption::ProtocolPath {
                    algorithm,
                    key_id: key_input.key_id().to_string(),
                    ephemeral_public_key: x25519::public_jwk(ephemeral_public.as_bytes()),
                    encrypted_key: base64url.encode(wrapped_key),
                },
                KeyEncryptionInput::RoleAudience {
                    protocol,
                    role_path,
                    ..
                } => KeyEncryption::RoleAudience {
                    algorithm,
                    key_id: key_input.key_id().to_string(),
                    ephemeral_public_key: x25519::public_jwk(ephemeral_public.as_bytes()),
                    encrypted_key: base64url.encode(wrapped_key),
                    protocol: protocol.clone(),
                    role_path: role_path.clone(),
                },
            });
        }

        Ok(Self {
            algorithm,
            initialization_vector: base64url.encode(&input.initialization_vector),
            key_encryption,
        })
    }

    /// Validates the decrypted semantics of an inbound encryption envelope.
    ///
    /// JSON Schema only constrains `initializationVector` to be base64url; this
    /// check decodes it and requires exactly 16 bytes (A256CTR counter block),
    /// then validates every `keyEncryption` entry's key-agreement algorithm and
    /// ephemeral public key.
    pub fn validate(&self) -> Result<(), EncryptionError> {
        let initialization_vector =
            decode_base64url(&self.initialization_vector, "initializationVector")?;
        if initialization_vector.len() != 16 {
            return Err(EncryptionError::InvalidInitializationVectorLength {
                found: initialization_vector.len(),
            });
        }

        for entry in &self.key_encryption {
            validate_key_agreement_algorithm(entry.algorithm())?;
            x25519::validate_public_key(entry.ephemeral_public_key())?;
        }
        Ok(())
    }

    pub fn decrypt(
        &self,
        recipient_private_jwk: &JWK,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_with_key_encryption(0, recipient_private_jwk, ciphertext)
    }

    pub fn decrypt_with_key_encryption(
        &self,
        key_encryption_index: usize,
        recipient_private_jwk: &JWK,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let cek =
            self.unwrap_cek_with_key_encryption(key_encryption_index, recipient_private_jwk)?;
        ctr::decrypt(
            &cek,
            &decode_base64url(&self.initialization_vector, "initializationVector")?,
            ciphertext,
        )
    }

    pub fn unwrap_cek(&self, recipient_private_jwk: &JWK) -> Result<Vec<u8>, EncryptionError> {
        self.unwrap_cek_with_key_encryption(0, recipient_private_jwk)
    }

    pub fn unwrap_cek_with_key_encryption(
        &self,
        key_encryption_index: usize,
        recipient_private_jwk: &JWK,
    ) -> Result<Vec<u8>, EncryptionError> {
        let key_encryption = self.key_encryption.get(key_encryption_index).ok_or(
            EncryptionError::MissingKeyEncryptionEntry {
                index: key_encryption_index,
            },
        )?;
        let encrypted_key = decode_base64url(key_encryption.encrypted_key(), "encryptedKey")?;
        x25519_hkdf_a256kw_unwrap(
            &x25519::private_key_bytes(recipient_private_jwk)?,
            &x25519::public_key_bytes(key_encryption.ephemeral_public_key())?,
            key_encryption.key_id(),
            key_encryption.derivation_scheme(),
            key_encryption.protocol(),
            key_encryption.role_path(),
            &encrypted_key,
        )
    }

    pub fn ctr_encrypt(
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        ctr::encrypt(key, iv, plaintext)
    }

    pub fn ctr_decrypt(
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        ctr::decrypt(key, iv, ciphertext)
    }
}

/// Wraps a CEK for a RecordsWrite `keyEncryption` entry using the
/// X25519-HKDF-SHA256+A256KW key agreement.
pub fn x25519_hkdf_a256kw_wrap(
    ephemeral_private_key: &[u8; 32],
    recipient_public_key: &[u8; 32],
    key_id: &str,
    derivation_scheme: DerivationScheme,
    protocol: Option<&str>,
    role_path: Option<&str>,
    cek: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    if cek.len() != 32 {
        return Err(EncryptionError::InvalidContentEncryptionKeyLength { found: cek.len() });
    }
    let shared_secret = x25519::shared_secret(ephemeral_private_key, recipient_public_key);
    let kek = kdf::a256kw_kek(
        &shared_secret,
        key_id,
        derivation_scheme,
        protocol,
        role_path,
    )?;
    aes_kw::wrap(&kek, cek)
}

/// Unwraps a CEK from a RecordsWrite `keyEncryption` entry.
pub fn x25519_hkdf_a256kw_unwrap(
    recipient_private_key: &[u8; 32],
    ephemeral_public_key: &[u8; 32],
    key_id: &str,
    derivation_scheme: DerivationScheme,
    protocol: Option<&str>,
    role_path: Option<&str>,
    wrapped_key: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let shared_secret = x25519::shared_secret(recipient_private_key, ephemeral_public_key);
    let kek = kdf::a256kw_kek(
        &shared_secret,
        key_id,
        derivation_scheme,
        protocol,
        role_path,
    )?;
    aes_kw::unwrap(&kek, wrapped_key)
}

/// Seals a private key (seal key wrap). The KEK derivation binds protocol,
/// rolePath, contextId, and audienceKeyId.
pub fn seal_wrap(
    input: &SealKeyWrapInput<'_>,
    private_key_bytes: &[u8],
) -> Result<SealKeyWrap, EncryptionError> {
    let ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
    let shared_secret = x25519::shared_secret(
        &ephemeral_secret.to_bytes(),
        &x25519::public_key_bytes(&input.public_key)?,
    );
    let kek = kdf::seal_kek(
        &shared_secret,
        input.protocol,
        input.role_path,
        input.context_id,
        input.audience_key_id,
    )?;
    let wrapped = aes_kw::wrap(&kek, private_key_bytes)?;

    Ok(SealKeyWrap::Seal {
        algorithm: input.algorithm,
        key_id: input.key_id.clone(),
        ephemeral_public_key: x25519::public_jwk(ephemeral_public.as_bytes()),
        encrypted_key: base64url.encode(wrapped),
    })
}

/// Opens a seal key wrap given the audience private key and the seal context.
pub fn seal_unwrap(
    recipient_private_key: &[u8; 32],
    seal: &SealKeyWrap,
    protocol: &str,
    role_path: &str,
    context_id: &str,
    audience_key_id: &str,
) -> Result<Vec<u8>, EncryptionError> {
    let shared_secret = x25519::shared_secret(
        recipient_private_key,
        &x25519::public_key_bytes(seal.ephemeral_public_key())?,
    );
    let kek = kdf::seal_kek(
        &shared_secret,
        protocol,
        role_path,
        context_id,
        audience_key_id,
    )?;
    let encrypted_key = decode_base64url(seal.encrypted_key(), "encryptedKey")?;
    aes_kw::unwrap(&kek, &encrypted_key)
}

fn decode_base64url(value: &str, label: &str) -> Result<Vec<u8>, EncryptionError> {
    base64url
        .decode(value)
        .map_err(|err| EncryptionError::InvalidBase64Url {
            label: label.to_string(),
            error: err.to_string(),
        })
}

fn validate_content_encryption_algorithm(
    algorithm: ContentEncryptionAlgorithm,
) -> Result<(), EncryptionError> {
    match algorithm {
        ContentEncryptionAlgorithm::A256Ctr => Ok(()),
    }
}

fn validate_key_agreement_algorithm(
    algorithm: KeyAgreementAlgorithm,
) -> Result<(), EncryptionError> {
    match algorithm {
        KeyAgreementAlgorithm::X25519HkdfSha256A256Kw => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_private_key_bytes_matches_upstream_hd_key_contract() {
        // Deterministic 32-byte X25519 private key.
        let key = (0u8..32).collect::<Vec<_>>();

        // Empty path returns the input unchanged.
        assert_eq!(
            derive_private_key_bytes(&key, &[]).unwrap(),
            key,
            "empty path must be identity"
        );

        // Each segment folds as HKDF-SHA256(empty salt, segment-as-info).
        let one = derive_private_key_bytes(&key, &["a"]).unwrap();
        let chained = derive_private_key_bytes(&key, &["a", "b"]).unwrap();
        let from_a = derive_private_key_bytes(&one, &["b"]).unwrap();
        assert_eq!(chained, from_a, "segments must fold left-to-right");

        // Empty segments are rejected (upstream HdKey rejects empty path segments).
        assert!(derive_private_key_bytes(&key, &[""]).is_err());
        assert!(derive_private_key_bytes(&key, &["a", ""]).is_err());

        // Output is always 32 bytes (X25519 private-key length).
        for path in [vec!["a"], vec!["a", "b", "c"]] {
            assert_eq!(derive_private_key_bytes(&key, &path).unwrap().len(), 32);
        }
    }

    #[test]
    fn key_encryption_tagged_serialization() {
        let protocol_path = serde_json::json!({
            "derivationScheme": "protocolPath",
            "algorithm": "X25519-HKDF-SHA256+A256KW",
            "keyId": "kid",
            "ephemeralPublicKey": {
                "kty": "OKP",
                "crv": "X25519",
                "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
            },
            "encryptedKey": "a2V5"
        });
        let parsed: KeyEncryption = serde_json::from_value(protocol_path.clone()).unwrap();
        assert_eq!(parsed.derivation_scheme(), DerivationScheme::ProtocolPath);
        assert_eq!(parsed.protocol(), None);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), protocol_path);

        let role_audience = serde_json::json!({
            "derivationScheme": "roleAudience",
            "algorithm": "X25519-HKDF-SHA256+A256KW",
            "keyId": "kid",
            "ephemeralPublicKey": {
                "kty": "OKP",
                "crv": "X25519",
                "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
            },
            "encryptedKey": "a2V5",
            "protocol": "https://example.com/protocol",
            "rolePath": "member"
        });
        let parsed: KeyEncryption = serde_json::from_value(role_audience.clone()).unwrap();
        assert_eq!(parsed.derivation_scheme(), DerivationScheme::RoleAudience);
        assert_eq!(parsed.protocol(), Some("https://example.com/protocol"));
        assert_eq!(parsed.role_path(), Some("member"));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), role_audience);

        // `roleAudience` entries require protocol/rolePath.
        assert!(serde_json::from_value::<KeyEncryption>(serde_json::json!({
            "derivationScheme": "roleAudience",
            "algorithm": "X25519-HKDF-SHA256+A256KW",
            "keyId": "kid",
            "ephemeralPublicKey": {
                "kty": "OKP",
                "crv": "X25519",
                "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
            },
            "encryptedKey": "a2V5"
        }))
        .is_err());

        // A `roleAudience` entry missing only `rolePath` is invalid.
        assert!(serde_json::from_value::<KeyEncryption>(serde_json::json!({
            "derivationScheme": "roleAudience",
            "algorithm": "X25519-HKDF-SHA256+A256KW",
            "keyId": "kid",
            "ephemeralPublicKey": {
                "kty": "OKP",
                "crv": "X25519",
                "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
            },
            "encryptedKey": "a2V5",
            "protocol": "https://example.com/protocol"
        }))
        .is_err());
    }

    #[test]
    fn builder_validates_encryption_input() {
        let valid_input = EncryptionInput {
            algorithm: None,
            key: (0u8..32).collect(),
            initialization_vector: (0xa0u8..0xb0).collect(),
            key_encryption_inputs: vec![KeyEncryptionInput::ProtocolPath {
                algorithm: KeyAgreementAlgorithm::X25519HkdfSha256A256Kw,
                key_id: "kid".to_string(),
                public_key: serde_json::from_value(serde_json::json!({
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
                }))
                .unwrap(),
            }],
        };
        assert!(EncryptionEnvelope::build_encryption(&valid_input).is_ok());

        // Short CEK must fail.
        let short_key = EncryptionInput {
            key: (0u8..31).collect(),
            ..valid_input.clone()
        };
        assert!(EncryptionEnvelope::build_encryption(&short_key).is_err());

        // Short IV must fail.
        let short_iv = EncryptionInput {
            initialization_vector: (0xa0u8..0xaf).collect(),
            ..valid_input.clone()
        };
        assert!(EncryptionEnvelope::build_encryption(&short_iv).is_err());

        // Empty keyEncryptionInputs must fail.
        let empty_inputs = EncryptionInput {
            key_encryption_inputs: vec![],
            ..valid_input.clone()
        };
        assert!(EncryptionEnvelope::build_encryption(&empty_inputs).is_err());
    }

    #[test]
    fn validate_accepts_16_byte_iv_and_rejects_other_lengths() {
        let key_encryption = KeyEncryption::ProtocolPath {
            algorithm: KeyAgreementAlgorithm::X25519HkdfSha256A256Kw,
            key_id: "kid".to_string(),
            ephemeral_public_key: serde_json::from_value(serde_json::json!({
                "kty": "OKP",
                "crv": "X25519",
                "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
            }))
            .unwrap(),
            encrypted_key: "a2V5".to_string(),
        };

        // A 16-byte IV decodes to the required A256CTR counter block length.
        let valid = EncryptionEnvelope {
            algorithm: ContentEncryptionAlgorithm::A256Ctr,
            initialization_vector: "oKGio6SlpqeoqaqrrK2urw".to_string(),
            key_encryption: vec![key_encryption.clone()],
        };
        valid.validate().expect("16-byte IV must validate");

        // A 15-byte IV must be rejected.
        let short_iv = EncryptionEnvelope {
            initialization_vector: "AAECAwQFBgcICQoLDA0O".to_string(),
            ..valid.clone()
        };
        let error = short_iv.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "initialization vector must be 16 bytes, got 15"
        );

        // A 17-byte IV must be rejected.
        let long_iv = EncryptionEnvelope {
            initialization_vector: format!("{}{}", valid.initialization_vector, "AA"),
            ..valid.clone()
        };
        assert!(long_iv.validate().is_err());

        // An invalid-base64url IV must be rejected.
        let bad_b64 = EncryptionEnvelope {
            initialization_vector: "!!not-base64!!".to_string(),
            ..valid.clone()
        };
        assert!(matches!(
            bad_b64.validate(),
            Err(EncryptionError::InvalidBase64Url { .. })
        ));
    }

    #[test]
    fn validate_rejects_non_okp_ephemeral_key() {
        let key_encryption = KeyEncryption::ProtocolPath {
            algorithm: KeyAgreementAlgorithm::X25519HkdfSha256A256Kw,
            key_id: "kid".to_string(),
            ephemeral_public_key: serde_json::from_value(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
            }))
            .unwrap(),
            encrypted_key: "a2V5".to_string(),
        };
        let encryption = EncryptionEnvelope {
            algorithm: ContentEncryptionAlgorithm::A256Ctr,
            initialization_vector: "oKGio6SlpqeoqaqrrK2urw".to_string(),
            key_encryption: vec![key_encryption],
        };
        assert!(matches!(
            encryption.validate(),
            Err(EncryptionError::UnsupportedCurve { .. })
        ));
    }

    #[test]
    fn x25519_helpers_reject_non_okp_and_non_x25519_jwks() {
        let x25519_public = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
        });
        let x25519_private = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "d": "ZDpyZWNpcGllbnQtcHJvdG9jb2wtcGF0aFhYWFhYWFg",
            "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
        });

        // Valid X25519 keys pass.
        let public: JWK = serde_json::from_value(x25519_public.clone()).unwrap();
        let private: JWK = serde_json::from_value(x25519_private.clone()).unwrap();
        assert!(x25519::public_key_bytes(&public).is_ok());
        assert!(x25519::private_key_bytes(&private).is_ok());

        // Ed25519 OKP key with a 32-byte x must NOT be accepted as X25519.
        let ed25519_public = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
        });
        let ed25519_private = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "d": "ZDpyZWNpcGllbnQtcHJvdG9jb2wtcGF0aFhYWFhYWFg",
            "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
        });
        let ed_public: JWK = serde_json::from_value(ed25519_public).unwrap();
        let ed_private: JWK = serde_json::from_value(ed25519_private).unwrap();
        assert!(x25519::public_key_bytes(&ed_public).is_err());
        assert!(x25519::private_key_bytes(&ed_private).is_err());

        // EC (secp256k1) JWK must be rejected.
        let ec = serde_json::json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "hL91YiYrvWlACFdI875q-lKuMXFVGB7OMbZjUcz_pLA",
            "y": "jMQ9Y7KFnUaf7hXzHJ7bUyQmbm_QQH6HOC1g_EURrNg"
        });
        let ec: JWK = serde_json::from_value(ec).unwrap();
        assert!(x25519::public_key_bytes(&ec).is_err());

        // Symmetric (oct) JWK must be rejected.
        let oct = serde_json::json!({
            "kty": "oct",
            "k": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
        });
        let oct: JWK = serde_json::from_value(oct).unwrap();
        assert!(x25519::public_key_bytes(&oct).is_err());

        // X25519 private JWK missing `d` must be rejected.
        let missing_d = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
        });
        let missing_d: JWK = serde_json::from_value(missing_d).unwrap();
        assert!(x25519::private_key_bytes(&missing_d).is_err());

        // Wrong-length X25519 public key must be rejected.
        let short_x = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvG"
        });
        let short_x: JWK = serde_json::from_value(short_x).unwrap();
        assert!(x25519::public_key_bytes(&short_x).is_err());

        // Wrong-length X25519 private key must be rejected.
        let short_d = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "d": "ZDpyZWNpcGllbnQtcHJvdG9jb2wtcGF0aFhYWFhYWFg",
            "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvG"
        });
        let short_d: JWK = serde_json::from_value(short_d).unwrap();
        assert!(x25519::private_key_bytes(&short_d).is_err());
    }
}
