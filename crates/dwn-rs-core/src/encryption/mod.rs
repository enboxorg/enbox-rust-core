pub mod asymmetric;
pub mod errors;
pub mod hd_keys;
pub mod symmetric;

pub use asymmetric::secretkey::SecretKey;
pub use errors::Error;
pub use hd_keys::{DerivedPrivateJWK, HashAlgorithm};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes_gcm::{aead::AeadInPlace, Aes256Gcm, Nonce as AesGcmNonce, Tag as AesGcmTag};
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD as base64url};
use chacha20poly1305::{Tag as XChaCha20Poly1305Tag, XChaCha20Poly1305, XNonce};
use k256::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use ssi_jwk::{Base64urlUInt, OctetParams, Params, JWK};

// DerivationScheme represents the derivation scheme used for deriving keys for encryption.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DerivationScheme {
    #[serde(rename = "dataFormats")]
    DataFormats,
    #[serde(rename = "protocolContext")]
    ProtocolContext,
    #[serde(rename = "protocolPath")]
    ProtocolPath,
    #[serde(rename = "schemas")]
    Schemas,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum ContentEncryptionAlgorithm {
    #[serde(rename = "A256GCM")]
    A256GCM,
    #[serde(rename = "XC20P")]
    XC20P,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum KeyAgreementAlgorithm {
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256kw,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct JweProtectedHeader {
    pub alg: KeyAgreementAlgorithm,
    pub enc: ContentEncryptionAlgorithm,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct JweRecipientHeader {
    pub kid: String,
    pub epk: JWK,
    #[serde(rename = "derivationScheme")]
    pub derivation_scheme: DerivationScheme,
    #[serde(rename = "derivedPublicKey", skip_serializing_if = "Option::is_none")]
    pub derived_public_key: Option<JWK>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct JweRecipient {
    pub header: JweRecipientHeader,
    pub encrypted_key: String,
}

/// JWE General JSON-like encryption metadata used by TypeScript RecordsWrite.
///
/// The encrypted record data is stored separately, so this shape intentionally
/// omits the JWE `ciphertext` member and keeps only protected metadata, IV, tag,
/// and recipient key wrapping entries.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Encryption {
    pub protected: String,
    pub iv: String,
    pub tag: String,
    pub recipients: Vec<JweRecipient>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EncryptionInput {
    pub algorithm: Option<ContentEncryptionAlgorithm>,
    pub key: Vec<u8>,
    #[serde(rename = "initializationVector")]
    pub initialization_vector: Vec<u8>,
    #[serde(rename = "authenticationTag")]
    pub authentication_tag: Vec<u8>,
    #[serde(rename = "keyEncryptionInputs")]
    pub key_encryption_inputs: Vec<KeyEncryptionInput>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct KeyEncryptionInput {
    #[serde(rename = "derivationScheme")]
    pub derivation_scheme: DerivationScheme,
    #[serde(rename = "publicKeyId")]
    pub public_key_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: JWK,
    pub algorithm: Option<KeyAgreementAlgorithm>,
}

impl Encryption {
    pub fn build_jwe(input: &EncryptionInput) -> Result<Self, Error> {
        let enc = input
            .algorithm
            .unwrap_or(ContentEncryptionAlgorithm::A256GCM);
        let protected_header = JweProtectedHeader {
            alg: KeyAgreementAlgorithm::EcdhEsA256kw,
            enc,
        };
        let protected = base64url.encode(serde_json::to_vec(&protected_header).map_err(jwe_error)?);

        let mut recipients = Vec::with_capacity(input.key_encryption_inputs.len());
        for key_input in &input.key_encryption_inputs {
            let ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
            let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
            let wrapped_key = ecdh_es_wrap_key(
                &ephemeral_secret.to_bytes(),
                &x25519_public_key_bytes(&key_input.public_key)?,
                &input.key,
            )?;

            recipients.push(JweRecipient {
                header: JweRecipientHeader {
                    kid: key_input.public_key_id.clone(),
                    epk: x25519_public_jwk(ephemeral_public.as_bytes()),
                    derivation_scheme: key_input.derivation_scheme.clone(),
                    derived_public_key: match key_input.derivation_scheme {
                        DerivationScheme::ProtocolContext => Some(key_input.public_key.clone()),
                        _ => None,
                    },
                },
                encrypted_key: base64url.encode(wrapped_key),
            });
        }

        Ok(Self {
            protected,
            iv: base64url.encode(&input.initialization_vector),
            tag: base64url.encode(&input.authentication_tag),
            recipients,
        })
    }

    pub fn protected_header(&self) -> Result<JweProtectedHeader, Error> {
        let protected = decode_base64url(&self.protected, "protected")?;
        serde_json::from_slice(&protected).map_err(jwe_error)
    }

    pub fn decrypt(
        &self,
        recipient_private_jwk: &JWK,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.decrypt_with_recipient(0, recipient_private_jwk, ciphertext)
    }

    pub fn decrypt_with_recipient(
        &self,
        recipient_index: usize,
        recipient_private_jwk: &JWK,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let protected = self.protected_header()?;
        let cek = self.unwrap_cek_with_recipient(recipient_index, recipient_private_jwk)?;
        aead_decrypt(
            protected.enc,
            &cek,
            &decode_base64url(&self.iv, "iv")?,
            ciphertext,
            &decode_base64url(&self.tag, "tag")?,
        )
    }

    pub fn unwrap_cek(&self, recipient_private_jwk: &JWK) -> Result<Vec<u8>, Error> {
        self.unwrap_cek_with_recipient(0, recipient_private_jwk)
    }

    pub fn unwrap_cek_with_recipient(
        &self,
        recipient_index: usize,
        recipient_private_jwk: &JWK,
    ) -> Result<Vec<u8>, Error> {
        let recipient = self.recipients.get(recipient_index).ok_or_else(|| {
            jwe_error(format!("missing JWE recipient at index {recipient_index}"))
        })?;
        let encrypted_key = decode_base64url(&recipient.encrypted_key, "encrypted_key")?;
        ecdh_es_unwrap_key(
            &x25519_private_key_bytes(recipient_private_jwk)?,
            &x25519_public_key_bytes(&recipient.header.epk)?,
            &encrypted_key,
        )
    }

    pub fn aead_encrypt(
        algorithm: ContentEncryptionAlgorithm,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        aead_encrypt(algorithm, key, iv, plaintext)
    }

    pub fn aead_decrypt(
        algorithm: ContentEncryptionAlgorithm,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        aead_decrypt(algorithm, key, iv, ciphertext, tag)
    }
}

fn aead_encrypt(
    algorithm: ContentEncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match algorithm {
        ContentEncryptionAlgorithm::A256GCM => {
            validate_len(key, 32, "A256GCM key")?;
            validate_len(iv, 12, "A256GCM IV")?;
            let cipher = Aes256Gcm::new_from_slice(key).map_err(jwe_error)?;
            let mut ciphertext = plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(AesGcmNonce::from_slice(iv), b"", &mut ciphertext)
                .map_err(jwe_error)?;
            Ok((ciphertext, tag.to_vec()))
        }
        ContentEncryptionAlgorithm::XC20P => {
            validate_len(key, 32, "XC20P key")?;
            validate_len(iv, 24, "XC20P IV")?;
            let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(jwe_error)?;
            let mut ciphertext = plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(XNonce::from_slice(iv), b"", &mut ciphertext)
                .map_err(jwe_error)?;
            Ok((ciphertext, tag.to_vec()))
        }
    }
}

fn aead_decrypt(
    algorithm: ContentEncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, Error> {
    match algorithm {
        ContentEncryptionAlgorithm::A256GCM => {
            validate_len(key, 32, "A256GCM key")?;
            validate_len(iv, 12, "A256GCM IV")?;
            validate_len(tag, 16, "A256GCM tag")?;
            let cipher = Aes256Gcm::new_from_slice(key).map_err(jwe_error)?;
            let mut plaintext = ciphertext.to_vec();
            cipher
                .decrypt_in_place_detached(
                    AesGcmNonce::from_slice(iv),
                    b"",
                    &mut plaintext,
                    AesGcmTag::from_slice(tag),
                )
                .map_err(jwe_error)?;
            Ok(plaintext)
        }
        ContentEncryptionAlgorithm::XC20P => {
            validate_len(key, 32, "XC20P key")?;
            validate_len(iv, 24, "XC20P IV")?;
            validate_len(tag, 16, "XC20P tag")?;
            let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(jwe_error)?;
            let mut plaintext = ciphertext.to_vec();
            cipher
                .decrypt_in_place_detached(
                    XNonce::from_slice(iv),
                    b"",
                    &mut plaintext,
                    XChaCha20Poly1305Tag::from_slice(tag),
                )
                .map_err(jwe_error)?;
            Ok(plaintext)
        }
    }
}

fn ecdh_es_wrap_key(
    ephemeral_private_key: &[u8; 32],
    recipient_public_key: &[u8; 32],
    cek: &[u8],
) -> Result<Vec<u8>, Error> {
    let shared_secret = x25519_shared_secret(ephemeral_private_key, recipient_public_key);
    let kek = concat_kdf_a256kw(&shared_secret);
    aes_key_wrap(&kek, cek)
}

fn ecdh_es_unwrap_key(
    recipient_private_key: &[u8; 32],
    ephemeral_public_key: &[u8; 32],
    wrapped_key: &[u8],
) -> Result<Vec<u8>, Error> {
    let shared_secret = x25519_shared_secret(recipient_private_key, ephemeral_public_key);
    let kek = concat_kdf_a256kw(&shared_secret);
    aes_key_unwrap(&kek, wrapped_key)
}

fn x25519_shared_secret(private_key: &[u8; 32], public_key: &[u8; 32]) -> Vec<u8> {
    let secret = x25519_dalek::StaticSecret::from(*private_key);
    let public = x25519_dalek::PublicKey::from(*public_key);
    secret.diffie_hellman(&public).as_bytes().to_vec()
}

fn concat_kdf_a256kw(shared_secret: &[u8]) -> Vec<u8> {
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

fn aes_key_wrap(kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext.len() < 16 || !plaintext.len().is_multiple_of(8) {
        return Err(jwe_error(
            "AES-KW plaintext must be at least 16 bytes and 64-bit aligned",
        ));
    }

    let cipher = aes::Aes256::new_from_slice(kek).map_err(jwe_error)?;
    let n = plaintext.len() / 8;
    let mut a = [0xa6; 8];
    let mut r = plaintext
        .chunks_exact(8)
        .map(|chunk| {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            block
        })
        .collect::<Vec<_>>();

    for j in 0..6 {
        for (i, block) in r.iter_mut().enumerate() {
            let mut input = [0u8; 16];
            input[..8].copy_from_slice(&a);
            input[8..].copy_from_slice(block);

            let mut encrypted = GenericArray::clone_from_slice(&input);
            cipher.encrypt_block(&mut encrypted);

            a.copy_from_slice(&encrypted[..8]);
            xor_aes_kw_counter(&mut a, (n * j + i + 1) as u64);
            block.copy_from_slice(&encrypted[8..]);
        }
    }

    let mut wrapped = Vec::with_capacity(8 + plaintext.len());
    wrapped.extend_from_slice(&a);
    for block in r {
        wrapped.extend_from_slice(&block);
    }
    Ok(wrapped)
}

fn aes_key_unwrap(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, Error> {
    if wrapped_key.len() < 24 || !wrapped_key.len().is_multiple_of(8) {
        return Err(jwe_error(
            "AES-KW ciphertext must be at least 24 bytes and 64-bit aligned",
        ));
    }

    let cipher = aes::Aes256::new_from_slice(kek).map_err(jwe_error)?;
    let n = wrapped_key.len() / 8 - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped_key[..8]);
    let mut r = wrapped_key[8..]
        .chunks_exact(8)
        .map(|chunk| {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            block
        })
        .collect::<Vec<_>>();

    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let mut block_a = a;
            xor_aes_kw_counter(&mut block_a, (n * j + i + 1) as u64);

            let mut input = [0u8; 16];
            input[..8].copy_from_slice(&block_a);
            input[8..].copy_from_slice(&r[i]);

            let mut decrypted = GenericArray::clone_from_slice(&input);
            cipher.decrypt_block(&mut decrypted);

            a.copy_from_slice(&decrypted[..8]);
            r[i].copy_from_slice(&decrypted[8..]);
        }
    }

    if a != [0xa6; 8] {
        return Err(jwe_error("AES-KW integrity check failed"));
    }

    let mut plaintext = Vec::with_capacity(wrapped_key.len() - 8);
    for block in r {
        plaintext.extend_from_slice(&block);
    }
    Ok(plaintext)
}

fn xor_aes_kw_counter(a: &mut [u8; 8], counter: u64) {
    for (left, right) in a.iter_mut().zip(counter.to_be_bytes()) {
        *left ^= right;
    }
}

fn x25519_public_jwk(public_key: &[u8; 32]) -> JWK {
    JWK::from(Params::OKP(OctetParams {
        curve: "X25519".to_string(),
        public_key: Base64urlUInt(public_key.to_vec()),
        private_key: None,
    }))
}

fn x25519_public_key_bytes(jwk: &JWK) -> Result<[u8; 32], Error> {
    decode_base64url_array(&jwk_string_param(jwk, "x")?, "x")
}

fn x25519_private_key_bytes(jwk: &JWK) -> Result<[u8; 32], Error> {
    decode_base64url_array(&jwk_string_param(jwk, "d")?, "d")
}

fn jwk_string_param(jwk: &JWK, name: &str) -> Result<String, Error> {
    let value = serde_json::to_value(jwk).map_err(jwe_error)?;
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| jwe_error(format!("X25519 JWK missing '{name}' parameter")))
}

fn decode_base64url_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], Error> {
    let bytes = decode_base64url(value, label)?;
    bytes
        .try_into()
        .map_err(|_| jwe_error(format!("{label} must be {N} bytes")))
}

fn decode_base64url(value: &str, label: &str) -> Result<Vec<u8>, Error> {
    base64url
        .decode(value)
        .map_err(|err| jwe_error(format!("invalid base64url {label}: {err}")))
}

fn validate_len(value: &[u8], expected: usize, label: &str) -> Result<(), Error> {
    if value.len() != expected {
        return Err(jwe_error(format!(
            "{label} must be {expected} bytes, got {}",
            value.len()
        )));
    }
    Ok(())
}

fn jwe_error(error: impl std::fmt::Display) -> Error {
    Error::JweError(error.to_string())
}
