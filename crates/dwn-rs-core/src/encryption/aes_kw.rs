use super::error::EncryptionError;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

/// AES-256 key wrap (RFC 3394).
pub(crate) fn wrap(kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if plaintext.len() < 16 || !plaintext.len().is_multiple_of(8) {
        return Err(EncryptionError::AesKeyWrap(
            "plaintext must be at least 16 bytes and 64-bit aligned".to_string(),
        ));
    }

    let cipher = aes::Aes256::new_from_slice(kek)
        .map_err(|err| EncryptionError::AesKeyWrap(format!("invalid KEK: {err}")))?;
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
            xor_counter(&mut a, (n * j + i + 1) as u64);
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

/// AES-256 key unwrap (RFC 3394).
pub(crate) fn unwrap(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if wrapped_key.len() < 24 || !wrapped_key.len().is_multiple_of(8) {
        return Err(EncryptionError::AesKeyWrap(
            "ciphertext must be at least 24 bytes and 64-bit aligned".to_string(),
        ));
    }

    let cipher = aes::Aes256::new_from_slice(kek)
        .map_err(|err| EncryptionError::AesKeyWrap(format!("invalid KEK: {err}")))?;
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
            xor_counter(&mut block_a, (n * j + i + 1) as u64);

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
        return Err(EncryptionError::AesKeyWrap(
            "integrity check failed".to_string(),
        ));
    }

    let mut plaintext = Vec::with_capacity(wrapped_key.len() - 8);
    for block in r {
        plaintext.extend_from_slice(&block);
    }
    Ok(plaintext)
}

fn xor_counter(a: &mut [u8; 8], counter: u64) {
    for (left, right) in a.iter_mut().zip(counter.to_be_bytes()) {
        *left ^= right;
    }
}
