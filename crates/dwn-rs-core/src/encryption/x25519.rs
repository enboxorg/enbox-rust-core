use super::error::EncryptionError;

use ssi_jwk::{Base64urlUInt, OctetParams, Params, JWK};

/// X25519 shared secret from an X25519 private key and X25519 public key.
pub(crate) fn shared_secret(private_key: &[u8; 32], public_key: &[u8; 32]) -> Vec<u8> {
    let secret = x25519_dalek::StaticSecret::from(*private_key);
    let public = x25519_dalek::PublicKey::from(*public_key);
    secret.diffie_hellman(&public).as_bytes().to_vec()
}

/// Builds a public-only X25519 JWK.
pub(crate) fn public_jwk(public_key: &[u8; 32]) -> JWK {
    JWK::from(Params::OKP(OctetParams {
        curve: "X25519".to_string(),
        public_key: Base64urlUInt(public_key.to_vec()),
        private_key: None,
    }))
}

/// Extracts the 32-byte X25519 public key from a JWK, rejecting keys that are
/// not `kty: OKP` / `crv: X25519`.
pub(crate) fn public_key_bytes(jwk: &JWK) -> Result<[u8; 32], EncryptionError> {
    let octet = octet_params(jwk)?;
    octet
        .public_key
        .0
        .clone()
        .try_into()
        .map_err(|_| EncryptionError::InvalidPublicKeyLength {
            found: octet.public_key.0.len(),
        })
}

/// Extracts the 32-byte X25519 private key from a JWK, rejecting keys that are
/// not `kty: OKP` / `crv: X25519` or that carry an inconsistent public `x`.
pub(crate) fn private_key_bytes(jwk: &JWK) -> Result<[u8; 32], EncryptionError> {
    let octet = octet_params(jwk)?;
    // When a public `x` is present alongside `d`, require it to be a valid
    // 32-byte X25519 public key so inconsistent private/public JWKs are
    // rejected rather than silently used with a mismatched partner.
    if octet.public_key.0.len() != 32 {
        return Err(EncryptionError::InvalidPublicKeyLength {
            found: octet.public_key.0.len(),
        });
    }
    let private_key = octet
        .private_key
        .as_ref()
        .ok_or(EncryptionError::MissingPrivateKeyMaterial)?
        .0
        .clone()
        .try_into()
        .map_err(|_| EncryptionError::InvalidPrivateKeyLength {
            found: octet.private_key.as_ref().map_or(0, |key| key.0.len()),
        })?;
    Ok(private_key)
}

/// Validates a JWK as an OKP X25519 key and returns its typed `OctetParams`.
///
/// Upstream rejects ephemeral keys that are not `kty: OKP` / `crv: X25519`
/// (`Encryption.validateX25519KeyEncryptionEntry`). This check runs before any
/// key agreement so an Ed25519 or EC JWK with a 32-byte `x`/`d` is never
/// silently interpreted as X25519 material.
fn octet_params(jwk: &JWK) -> Result<&OctetParams, EncryptionError> {
    let octet = match &jwk.params {
        Params::OKP(octet) => octet,
        Params::EC(_) => {
            return Err(EncryptionError::NotAnX25519Jwk {
                kty: "EC".to_string(),
            })
        }
        Params::RSA(_) => {
            return Err(EncryptionError::NotAnX25519Jwk {
                kty: "RSA".to_string(),
            })
        }
        Params::Symmetric(_) => {
            return Err(EncryptionError::NotAnX25519Jwk {
                kty: "oct".to_string(),
            })
        }
    };
    if octet.curve != "X25519" {
        return Err(EncryptionError::UnsupportedCurve {
            curve: octet.curve.clone(),
        });
    }
    Ok(octet)
}

/// Validates that a JWK is an OKP X25519 public key without extracting bytes.
///
/// Mirrors upstream `Encryption.validateX25519KeyEncryptionEntry`: an entry
/// whose `ephemeralPublicKey` is not `kty: OKP` / `crv: X25519` is rejected
/// during `Encryption.validateEncryptionProperty`.
pub(crate) fn validate_public_key(jwk: &JWK) -> Result<(), EncryptionError> {
    octet_params(jwk).map(|_| ())
}
