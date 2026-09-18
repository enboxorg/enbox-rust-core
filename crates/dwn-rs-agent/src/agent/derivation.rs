use super::{
    ed25519_private_jwk, ed25519_public_key_bytes, jwk_curve, relationship_contains,
    verification_method_jwk, x25519_private_jwk, AgentIdentityError, AgentIdentityResult,
    PortableDid,
};
use std::borrow::Cow;
use std::fmt::Debug;

use bip39::{Language, Mnemonic};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};
use ssi_jwk::JWK;

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDerivedKeys {
    pub identity_private_jwk: JWK,
    pub signing_private_jwk: JWK,
    pub encryption_private_jwk: JWK,
    pub vault_content_encryption_key: Vec<u8>,
    pub vault_unlock_salt: Vec<u8>,
}

impl Debug for AgentDerivedKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentDerivedKeys")
            .finish_non_exhaustive()
    }
}

impl AgentDerivedKeys {
    pub fn private_jwks(&self) -> Vec<JWK> {
        vec![
            self.identity_private_jwk.clone(),
            self.signing_private_jwk.clone(),
            self.encryption_private_jwk.clone(),
        ]
    }
}

/// Derive the deterministic key set (vault, identity, signing, encryption) from a BIP-39 phrase.
///
/// Pure: derives the same keys for the same phrase and persists nothing.
pub fn derive_agent_keys(recovery_phrase: &str) -> AgentIdentityResult<AgentDerivedKeys> {
    let mnemonic = parse_recovery_phrase(recovery_phrase)?;
    let seed = mnemonic.to_seed("");
    let vault = derive_slip10_ed25519(&seed, "m/44'/0'/0'/0'/0'")?;
    let identity = derive_slip10_ed25519(&seed, "m/44'/0'/1708523827'/0'/0'")?;
    let signing = derive_slip10_ed25519(&seed, "m/44'/0'/1708523827'/0'/1'")?;
    let encryption = derive_slip10_ed25519(&seed, "m/44'/0'/1708523827'/0'/2'")?;
    let mut vault_public = [0; 33];
    vault_public[1..].copy_from_slice(&ed25519_public_key_bytes(vault.private_key));

    Ok(AgentDerivedKeys {
        identity_private_jwk: ed25519_private_jwk(identity.private_key, None),
        signing_private_jwk: ed25519_private_jwk(signing.private_key, Some("EdDSA")),
        encryption_private_jwk: x25519_private_jwk(encryption.private_key),
        vault_content_encryption_key: hkdf_sha512(&vault.private_key, b"vault_cek", 32)?,
        vault_unlock_salt: hkdf_sha512(&vault_public, b"vault_unlock_salt", 32)?,
    })
}

/// Check that a portable DID carries usable signing and encryption key material.
pub fn validate_agent_did_key_requirements(portable_did: &PortableDid) -> AgentIdentityResult<()> {
    let has_signing_method = portable_did
        .document
        .verification_method
        .iter()
        .any(|method| {
            verification_method_jwk(method)
                .as_ref()
                .is_some_and(|jwk| jwk_curve(jwk) == Some("Ed25519"))
                && (relationship_contains(
                    &portable_did.document,
                    &portable_did
                        .document
                        .verification_relationships
                        .authentication,
                    method,
                ) || relationship_contains(
                    &portable_did.document,
                    &portable_did
                        .document
                        .verification_relationships
                        .assertion_method,
                    method,
                ))
        });
    let has_key_agreement_method = portable_did
        .document
        .verification_method
        .iter()
        .any(|method| {
            verification_method_jwk(method)
                .as_ref()
                .is_some_and(|jwk| jwk_curve(jwk) == Some("X25519"))
                && relationship_contains(
                    &portable_did.document,
                    &portable_did
                        .document
                        .verification_relationships
                        .key_agreement,
                    method,
                )
        });
    let has_ed25519_private = portable_did
        .private_keys
        .iter()
        .any(|jwk| jwk_curve(jwk) == Some("Ed25519") && !jwk.is_public());
    let has_x25519_private = portable_did
        .private_keys
        .iter()
        .any(|jwk| jwk_curve(jwk) == Some("X25519") && !jwk.is_public());

    if !has_signing_method || !has_ed25519_private {
        return Err(AgentIdentityError::invalid_key_material(
            "agent DID requires Ed25519 signing key material",
        ));
    }
    if !has_key_agreement_method || !has_x25519_private {
        return Err(AgentIdentityError::invalid_key_material(
            "agent DID requires X25519 key agreement material",
        ));
    }
    Ok(())
}

pub(crate) fn validate_recovery_phrase(recovery_phrase: &str) -> AgentIdentityResult<()> {
    parse_recovery_phrase(recovery_phrase).map(|_| ())
}

fn parse_recovery_phrase(recovery_phrase: &str) -> AgentIdentityResult<Mnemonic> {
    let mut normalized = Cow::Borrowed(recovery_phrase);
    Mnemonic::normalize_utf8_cow(&mut normalized);
    if normalized.split_whitespace().collect::<Vec<_>>().join(" ") != normalized {
        return Err(AgentIdentityError::invalid_mnemonic(
            "invalid recovery phrase separators",
        ));
    }
    Mnemonic::parse_in_normalized(Language::English, &normalized)
        .map_err(|err| AgentIdentityError::invalid_mnemonic(err.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slip10Node {
    private_key: [u8; 32],
    chain_code: [u8; 32],
}

fn derive_slip10_ed25519(seed: &[u8], path: &str) -> AgentIdentityResult<Slip10Node> {
    let master = hmac_sha512(b"ed25519 seed", seed)?;
    let mut node = Slip10Node {
        private_key: fixed_32(&master[..32])?,
        chain_code: fixed_32(&master[32..])?,
    };
    if path == "m" {
        return Ok(node);
    }
    let Some(segments) = path.strip_prefix("m/") else {
        return Err(AgentIdentityError::invalid_key_material(format!(
            "invalid derivation path {path}"
        )));
    };
    for segment in segments.split('/') {
        let Some(index) = segment.strip_suffix('\'') else {
            return Err(AgentIdentityError::invalid_key_material(
                "SLIP-0010 Ed25519 derivation requires hardened path segments",
            ));
        };
        let index = index.parse::<u32>().map_err(|_| {
            AgentIdentityError::invalid_key_material(format!(
                "invalid derivation path index {index}"
            ))
        })?;
        if index >= 0x8000_0000 {
            return Err(AgentIdentityError::invalid_key_material(
                "derivation path index is out of range",
            ));
        }
        let mut data = Vec::with_capacity(37);
        data.push(0);
        data.extend_from_slice(&node.private_key);
        data.extend_from_slice(&(index | 0x8000_0000).to_be_bytes());
        let child = hmac_sha512(&node.chain_code, &data)?;
        node = Slip10Node {
            private_key: fixed_32(&child[..32])?,
            chain_code: fixed_32(&child[32..])?,
        };
    }
    Ok(node)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> AgentIdentityResult<[u8; 64]> {
    let mut mac = HmacSha512::new_from_slice(key)
        .map_err(|err| AgentIdentityError::invalid_key_material(err.to_string()))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&result);
    Ok(bytes)
}

fn hkdf_sha512(base_key: &[u8], info: &[u8], length: usize) -> AgentIdentityResult<Vec<u8>> {
    let hkdf = hkdf::Hkdf::<Sha512>::new(Some(&[]), base_key);
    let mut out = vec![0u8; length];
    hkdf.expand(info, &mut out)
        .map_err(|err| AgentIdentityError::invalid_key_material(err.to_string()))?;
    Ok(out)
}

pub(crate) fn hkdf_sha256(
    base_key: &[u8],
    info: &[u8],
    length: usize,
) -> AgentIdentityResult<Vec<u8>> {
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&[]), base_key);
    let mut out = vec![0u8; length];
    hkdf.expand(info, &mut out)
        .map_err(|err| AgentIdentityError::invalid_key_material(err.to_string()))?;
    Ok(out)
}

pub(crate) fn fixed_32(bytes: &[u8]) -> AgentIdentityResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(AgentIdentityError::invalid_key_material(
            "expected 32 bytes of key material",
        ));
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(bytes);
    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use bip39::{Language, Mnemonic};

    #[test]
    fn recovery_phrase_derives_stable_agent_key_material() {
        let first = derive_agent_keys(RECOVERY_PHRASE).unwrap();
        let second = derive_agent_keys(RECOVERY_PHRASE).unwrap();

        assert_eq!(first, second);
        assert_eq!(jwk_curve(&first.signing_private_jwk), Some("Ed25519"));
        assert_eq!(jwk_curve(&first.encryption_private_jwk), Some("X25519"));
        assert_eq!(first.vault_content_encryption_key.len(), 32);
        assert_eq!(first.vault_unlock_salt.len(), 32);
    }

    #[test]
    fn recovery_phrase_acceptance_matches_english_bip39() {
        for entropy_bytes in [16, 20, 24, 28, 32] {
            let phrase = Mnemonic::from_entropy_in(Language::English, &vec![0; entropy_bytes])
                .unwrap()
                .to_string();
            assert!(derive_agent_keys(&phrase).is_ok(), "{entropy_bytes} bytes");
        }

        let expected = derive_agent_keys(RECOVERY_PHRASE).unwrap();
        for separator in ['\u{a0}', '\u{3000}'] {
            let phrase = RECOVERY_PHRASE.replacen(' ', &separator.to_string(), 1);
            assert_eq!(derive_agent_keys(&phrase).unwrap(), expected);
        }

        for phrase in [
            RECOVERY_PHRASE.to_uppercase(),
            RECOVERY_PHRASE.replacen(' ', "  ", 1),
            format!(" {RECOVERY_PHRASE}"),
            format!("{RECOVERY_PHRASE} "),
            RECOVERY_PHRASE.replacen(' ', "\t", 1),
            RECOVERY_PHRASE.replacen(' ', "\n", 1),
            format!("{RECOVERY_PHRASE} about"),
            RECOVERY_PHRASE.replace("about", "abandon"),
            RECOVERY_PHRASE.replace("about", "notaword"),
            String::new(),
            "  ".to_string(),
        ] {
            assert_eq!(
                derive_agent_keys(&phrase).unwrap_err().code(),
                "AgentIdentityInvalidMnemonic",
                "{phrase:?}"
            );
        }
    }

    #[tokio::test]
    async fn did_import_rejects_agent_did_without_x25519_key_agreement() {
        let provider = DeterministicDidJwkProvider::default();
        let derived = derive_agent_keys(RECOVERY_PHRASE).unwrap();
        let mut portable_did = provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived.identity_private_jwk,
                signing_private_jwk: derived.signing_private_jwk,
                encryption_private_jwk: derived.encryption_private_jwk,
                dwn_endpoints: Vec::new(),
            })
            .await
            .unwrap();
        portable_did
            .document
            .verification_relationships
            .key_agreement
            .clear();
        portable_did
            .private_keys
            .retain(|jwk| jwk_curve(jwk) != Some("X25519"));

        let error = provider.import_did(portable_did).await.unwrap_err();

        assert_eq!(error.code(), "AgentIdentityInvalidKeyMaterial");
        assert!(error.detail().contains("X25519"));
    }
}
