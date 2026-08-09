use super::error::EncryptionError;

use ctr::cipher::{KeyIvInit, StreamCipher};

/// AES-256 in counter mode (A256CTR), the only upstream content-encryption
/// algorithm. The counter is the full 16-byte IV block; there is no AEAD tag.
pub(crate) fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if key.len() != 32 {
        return Err(EncryptionError::InvalidContentEncryptionKeyLength { found: key.len() });
    }
    if iv.len() != 16 {
        return Err(EncryptionError::InvalidInitializationVectorLength { found: iv.len() });
    }
    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|err| EncryptionError::AesKeyWrap(err.to_string()))?;
    let mut ciphertext = plaintext.to_vec();
    cipher.apply_keystream(&mut ciphertext);
    Ok(ciphertext)
}

/// AES-256-CTR is symmetric; decryption applies the same keystream.
pub(crate) fn decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    encrypt(key, iv, ciphertext)
}
