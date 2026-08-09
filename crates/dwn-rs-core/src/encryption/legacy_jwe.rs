//! Read-only support for RecordsWrite encryption envelopes emitted by the
//! previous Rust implementation.
//!
//! New records must use the current DWN encryption envelope. This module only
//! preserves the legacy JWE-General-shaped metadata long enough to decrypt
//! historical stored records.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce as AesGcmNonce, Tag as AesGcmTag,
};
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD as base64url};
use chacha20poly1305::{Tag as XChaCha20Poly1305Tag, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssi_jwk::JWK;

use super::{aes_kw, x25519, EncryptionError};

/// The legacy JWE protected-header key-agreement algorithm.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum LegacyKeyAgreementAlgorithm {
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,
}

/// Content ciphers emitted by the previous Rust implementation.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum LegacyContentEncryptionAlgorithm {
    #[serde(rename = "A256GCM")]
    A256Gcm,
    #[serde(rename = "XC20P")]
    Xc20p,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct LegacyJweProtectedHeader {
    pub alg: LegacyKeyAgreementAlgorithm,
    pub enc: LegacyContentEncryptionAlgorithm,
}

/// Legacy derivation metadata was informational to the former key wrapping
/// implementation. Keep it losslessly so signed stored messages round-trip.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum LegacyDerivationScheme {
    #[serde(rename = "dataFormats")]
    DataFormats,
    #[serde(rename = "protocolContext")]
    ProtocolContext,
    #[serde(rename = "protocolPath")]
    ProtocolPath,
    #[serde(rename = "schemas")]
    Schemas,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct LegacyJweRecipientHeader {
    pub kid: String,
    pub epk: JWK,
    #[serde(rename = "derivationScheme")]
    pub derivation_scheme: LegacyDerivationScheme,
    #[serde(rename = "derivedPublicKey", skip_serializing_if = "Option::is_none")]
    pub derived_public_key: Option<JWK>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct LegacyJweRecipient {
    pub header: LegacyJweRecipientHeader,
    pub encrypted_key: String,
}

/// The former JWE-General-shaped top-level `encryption` property.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct LegacyJweEncryption {
    pub protected: String,
    pub iv: String,
    pub tag: String,
    pub recipients: Vec<LegacyJweRecipient>,
}

impl LegacyJweEncryption {
    pub fn protected_header(&self) -> Result<LegacyJweProtectedHeader, EncryptionError> {
        let protected = decode_base64url(&self.protected, "protected")?;
        serde_json::from_slice(&protected).map_err(|error| legacy_error(error))
    }

    pub fn decrypt(
        &self,
        recipient_private_jwk: &JWK,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_with_recipient(0, recipient_private_jwk, ciphertext)
    }

    pub fn decrypt_with_recipient(
        &self,
        recipient_index: usize,
        recipient_private_jwk: &JWK,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let protected = self.protected_header()?;
        let cek = self.unwrap_cek_with_recipient(recipient_index, recipient_private_jwk)?;
        decrypt_aead(
            protected.enc,
            &cek,
            &decode_base64url(&self.iv, "iv")?,
            ciphertext,
            &decode_base64url(&self.tag, "tag")?,
        )
    }

    pub fn unwrap_cek_with_recipient(
        &self,
        recipient_index: usize,
        recipient_private_jwk: &JWK,
    ) -> Result<Vec<u8>, EncryptionError> {
        let recipient = self.recipients.get(recipient_index).ok_or(
            EncryptionError::MissingKeyEncryptionEntry {
                index: recipient_index,
            },
        )?;
        let shared_secret = x25519::shared_secret(
            &x25519::private_key_bytes(recipient_private_jwk)?,
            &x25519::public_key_bytes(&recipient.header.epk)?,
        )?;
        aes_kw::unwrap(
            &legacy_a256kw_kek(&shared_secret),
            &decode_base64url(&recipient.encrypted_key, "encrypted_key")?,
        )
    }
}

fn decrypt_aead(
    algorithm: LegacyContentEncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    validate_len(key, 32, "content encryption key")?;
    validate_len(tag, 16, "authentication tag")?;
    let mut plaintext = ciphertext.to_vec();
    match algorithm {
        LegacyContentEncryptionAlgorithm::A256Gcm => {
            validate_len(iv, 12, "A256GCM IV")?;
            Aes256Gcm::new_from_slice(key)
                .map_err(legacy_error)?
                .decrypt_in_place_detached(
                    AesGcmNonce::from_slice(iv),
                    b"",
                    &mut plaintext,
                    AesGcmTag::from_slice(tag),
                )
                .map_err(legacy_error)?;
        }
        LegacyContentEncryptionAlgorithm::Xc20p => {
            validate_len(iv, 24, "XC20P IV")?;
            XChaCha20Poly1305::new_from_slice(key)
                .map_err(legacy_error)?
                .decrypt_in_place_detached(
                    XNonce::from_slice(iv),
                    b"",
                    &mut plaintext,
                    XChaCha20Poly1305Tag::from_slice(tag),
                )
                .map_err(legacy_error)?;
        }
    }
    Ok(plaintext)
}

fn legacy_a256kw_kek(shared_secret: &[u8]) -> Vec<u8> {
    let mut fixed_info = Vec::new();
    append_length_prefixed(&mut fixed_info, b"A256KW");
    append_length_prefixed(&mut fixed_info, b"");
    append_length_prefixed(&mut fixed_info, b"");
    fixed_info.extend_from_slice(&256u32.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(1u32.to_be_bytes());
    hasher.update(shared_secret);
    hasher.update(fixed_info);
    hasher.finalize()[..32].to_vec()
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn decode_base64url(value: &str, label: &str) -> Result<Vec<u8>, EncryptionError> {
    base64url
        .decode(value)
        .map_err(|error| EncryptionError::InvalidBase64Url {
            label: label.to_string(),
            error: error.to_string(),
        })
}

fn validate_len(value: &[u8], expected: usize, label: &str) -> Result<(), EncryptionError> {
    if value.len() != expected {
        return Err(EncryptionError::LegacyJwe(format!(
            "{label} must be {expected} bytes, got {}",
            value.len()
        )));
    }
    Ok(())
}

fn legacy_error(error: impl std::fmt::Display) -> EncryptionError {
    EncryptionError::LegacyJwe(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt_legacy(
        algorithm: LegacyContentEncryptionAlgorithm,
        private_jwk: &JWK,
        plaintext: &[u8],
    ) -> (LegacyJweEncryption, Vec<u8>) {
        let recipient_private = x25519::private_key_bytes(private_jwk).unwrap();
        let recipient_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(recipient_private));
        let ephemeral_private = [42; 32];
        let ephemeral_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(ephemeral_private));
        let cek = [7; 32];
        let iv = match algorithm {
            LegacyContentEncryptionAlgorithm::A256Gcm => vec![9; 12],
            LegacyContentEncryptionAlgorithm::Xc20p => vec![9; 24],
        };
        let mut ciphertext = plaintext.to_vec();
        let tag = match algorithm {
            LegacyContentEncryptionAlgorithm::A256Gcm => Aes256Gcm::new_from_slice(&cek)
                .unwrap()
                .encrypt_in_place_detached(AesGcmNonce::from_slice(&iv), b"", &mut ciphertext)
                .unwrap()
                .to_vec(),
            LegacyContentEncryptionAlgorithm::Xc20p => XChaCha20Poly1305::new_from_slice(&cek)
                .unwrap()
                .encrypt_in_place_detached(XNonce::from_slice(&iv), b"", &mut ciphertext)
                .unwrap()
                .to_vec(),
        };
        let shared_secret =
            x25519::shared_secret(&ephemeral_private, recipient_public.as_bytes()).unwrap();
        let wrapped_cek = aes_kw::wrap(&legacy_a256kw_kek(&shared_secret), &cek).unwrap();
        let protected = base64url.encode(
            serde_json::to_vec(&LegacyJweProtectedHeader {
                alg: LegacyKeyAgreementAlgorithm::EcdhEsA256Kw,
                enc: algorithm,
            })
            .unwrap(),
        );
        (
            LegacyJweEncryption {
                protected,
                iv: base64url.encode(iv),
                tag: base64url.encode(tag),
                recipients: vec![LegacyJweRecipient {
                    header: LegacyJweRecipientHeader {
                        kid: "legacy-key".to_string(),
                        epk: x25519::public_jwk(ephemeral_public.as_bytes()),
                        derivation_scheme: LegacyDerivationScheme::ProtocolPath,
                        derived_public_key: None,
                    },
                    encrypted_key: base64url.encode(wrapped_cek),
                }],
            },
            ciphertext,
        )
    }

    fn private_jwk() -> JWK {
        let private = [3; 32];
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
        let mut jwk = x25519::public_jwk(public.as_bytes());
        if let ssi_jwk::Params::OKP(params) = &mut jwk.params {
            params.private_key = Some(ssi_jwk::Base64urlUInt(private.to_vec()));
        }
        jwk
    }

    #[test]
    fn decrypts_legacy_a256gcm_record() {
        let private_jwk = private_jwk();
        let (encryption, ciphertext) = encrypt_legacy(
            LegacyContentEncryptionAlgorithm::A256Gcm,
            &private_jwk,
            b"legacy plaintext",
        );
        assert_eq!(
            encryption.decrypt(&private_jwk, &ciphertext).unwrap(),
            b"legacy plaintext"
        );
    }

    #[test]
    fn decrypts_legacy_xc20p_record() {
        let private_jwk = private_jwk();
        let (encryption, ciphertext) = encrypt_legacy(
            LegacyContentEncryptionAlgorithm::Xc20p,
            &private_jwk,
            b"legacy plaintext",
        );
        assert_eq!(
            encryption.decrypt(&private_jwk, &ciphertext).unwrap(),
            b"legacy plaintext"
        );
    }

    #[test]
    fn legacy_envelope_roundtrips_its_wire_shape() {
        let private_jwk = private_jwk();
        let (encryption, _) = encrypt_legacy(
            LegacyContentEncryptionAlgorithm::A256Gcm,
            &private_jwk,
            b"legacy plaintext",
        );
        let json = serde_json::to_value(&encryption).unwrap();
        assert!(json.get("protected").is_some());
        assert!(json.get("iv").is_some());
        assert!(json.get("tag").is_some());
        assert!(json.get("recipients").is_some());
        assert!(json.get("algorithm").is_none());
        assert_eq!(
            serde_json::from_value::<LegacyJweEncryption>(json.clone()).unwrap(),
            encryption
        );
    }

    #[test]
    fn rejects_malformed_legacy_protected_header() {
        let private_jwk = private_jwk();
        let (mut encryption, _) = encrypt_legacy(
            LegacyContentEncryptionAlgorithm::A256Gcm,
            &private_jwk,
            b"legacy plaintext",
        );
        encryption.protected = "not-base64url!".to_string();

        assert!(matches!(
            encryption.protected_header(),
            Err(EncryptionError::InvalidBase64Url { label, .. }) if label == "protected"
        ));
    }

    #[test]
    fn rejects_legacy_aead_with_invalid_iv_or_tag() {
        let private_jwk = private_jwk();
        let (mut encryption, ciphertext) = encrypt_legacy(
            LegacyContentEncryptionAlgorithm::A256Gcm,
            &private_jwk,
            b"legacy plaintext",
        );
        encryption.iv = base64url.encode([0; 11]);
        assert!(matches!(
            encryption.decrypt(&private_jwk, &ciphertext),
            Err(EncryptionError::LegacyJwe(message)) if message.contains("A256GCM IV must be 12 bytes")
        ));

        let (mut encryption, ciphertext) = encrypt_legacy(
            LegacyContentEncryptionAlgorithm::A256Gcm,
            &private_jwk,
            b"legacy plaintext",
        );
        encryption.tag = base64url.encode([0; 15]);
        assert!(matches!(
            encryption.decrypt(&private_jwk, &ciphertext),
            Err(EncryptionError::LegacyJwe(message)) if message.contains("authentication tag must be 16 bytes")
        ));
    }

    #[test]
    fn rejects_legacy_recipient_with_non_x25519_ephemeral_key() {
        let private_jwk = private_jwk();
        let (encryption, ciphertext) = encrypt_legacy(
            LegacyContentEncryptionAlgorithm::A256Gcm,
            &private_jwk,
            b"legacy plaintext",
        );
        let mut value = serde_json::to_value(encryption).unwrap();
        value["recipients"][0]["header"]["epk"]["crv"] = serde_json::json!("Ed25519");
        let encryption: LegacyJweEncryption = serde_json::from_value(value).unwrap();

        assert!(matches!(
            encryption.decrypt(&private_jwk, &ciphertext),
            Err(EncryptionError::UnsupportedCurve { curve }) if curve == "Ed25519"
        ));
    }
}
