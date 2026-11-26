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

/// HD derivation scheme used for vault and agent keys.
///
/// `V1` is the legacy BIP-44 tree; `V2` is the BIP-43 tree used for fresh
/// vaults. Both share the same HKDF inputs; only the derivation paths differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultDerivationVersion {
    V1 = 1,
    V2 = 2,
}

impl VaultDerivationVersion {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            _ => None,
        }
    }

    fn paths(self) -> &'static VaultDerivationPaths {
        match self {
            Self::V1 => &V1_PATHS,
            Self::V2 => &V2_PATHS,
        }
    }
}

impl From<VaultDerivationVersion> for u8 {
    fn from(version: VaultDerivationVersion) -> Self {
        version as u8
    }
}

impl Serialize for VaultDerivationVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for VaultDerivationVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        Self::from_u8(value)
            .ok_or_else(|| serde::de::Error::custom("derivation version must be 1 or 2"))
    }
}

struct VaultDerivationPaths {
    vault: &'static str,
    identity: &'static str,
    signing: &'static str,
    encryption: &'static str,
}

const V1_PATHS: VaultDerivationPaths = VaultDerivationPaths {
    vault: "m/44'/0'/0'/0'/0'",
    identity: "m/44'/0'/1708523827'/0'/0'",
    signing: "m/44'/0'/1708523827'/0'/1'",
    encryption: "m/44'/0'/1708523827'/0'/2'",
};

const V2_PATHS: VaultDerivationPaths = VaultDerivationPaths {
    vault: "m/43'/1708523827'/0'/0'",
    identity: "m/43'/1708523827'/1'/0'/0'",
    signing: "m/43'/1708523827'/1'/0'/1'",
    encryption: "m/43'/1708523827'/1'/0'/2'",
};

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

/// Derive the legacy `V1` key set from a BIP-39 phrase.
///
/// Pure: derives the same keys for the same phrase and persists nothing.
/// Fresh vaults use [`VaultDerivationVersion::V2`] through
/// [`derive_agent_keys_with_version`].
pub fn derive_agent_keys(recovery_phrase: &str) -> AgentIdentityResult<AgentDerivedKeys> {
    derive_agent_keys_with_version(recovery_phrase, VaultDerivationVersion::V1)
}

/// Derive the deterministic key set (vault, identity, signing, encryption) for
/// an explicit derivation version.
///
/// Pure: derives the same keys for the same phrase and version, and persists
/// nothing.
pub fn derive_agent_keys_with_version(
    recovery_phrase: &str,
    version: VaultDerivationVersion,
) -> AgentIdentityResult<AgentDerivedKeys> {
    let mnemonic = parse_recovery_phrase(recovery_phrase)?;
    let seed = mnemonic.to_seed("");
    let paths = version.paths();
    let vault = derive_slip10_ed25519(&seed, paths.vault)?;
    let identity = derive_slip10_ed25519(&seed, paths.identity)?;
    let signing = derive_slip10_ed25519(&seed, paths.signing)?;
    let encryption = derive_slip10_ed25519(&seed, paths.encryption)?;
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // Covers: ENBOX-AGENT-001
    #[test]
    fn derivation_versions_match_golden_vectors() {
        let v1 =
            derive_agent_keys_with_version(RECOVERY_PHRASE, VaultDerivationVersion::V1).unwrap();
        assert_eq!(
            hex(&v1.vault_content_encryption_key),
            "b99ff78488da4c83cbe590b5374bfca38551eb47e65514667018cc33c91f4913"
        );
        assert_eq!(
            hex(&v1.vault_unlock_salt),
            "cf6389ce23de14b02e05413e1bcc3715f6fed4c2b0eda9412701279288f37d20"
        );

        let v2 =
            derive_agent_keys_with_version(RECOVERY_PHRASE, VaultDerivationVersion::V2).unwrap();
        assert_eq!(
            hex(&v2.vault_content_encryption_key),
            "a19daef652efd7e05e22a9184a244d63983fd5ef2714b113b8d60dc53028fd67"
        );
        assert_eq!(
            hex(&v2.vault_unlock_salt),
            "faa7f7433146bb721fd77c7b6a1cc6dc4725886130d6f05582eabca26bde85c0"
        );

        assert_eq!(derive_agent_keys(RECOVERY_PHRASE).unwrap(), v1);
        assert_ne!(v1, v2);
    }

    // Covers: ENBOX-AGENT-001
    #[test]
    fn derivation_version_is_an_integer_one_or_two() {
        assert_eq!(
            serde_json::to_string(&VaultDerivationVersion::V1).unwrap(),
            "1"
        );
        assert_eq!(
            serde_json::to_string(&VaultDerivationVersion::V2).unwrap(),
            "2"
        );
        assert_eq!(
            serde_json::from_str::<VaultDerivationVersion>("1").unwrap(),
            VaultDerivationVersion::V1
        );
        assert_eq!(
            serde_json::from_str::<VaultDerivationVersion>("2").unwrap(),
            VaultDerivationVersion::V2
        );
        for raw in ["0", "3", "\"2\"", "null", "1.5", "true", "{}"] {
            assert!(
                serde_json::from_str::<VaultDerivationVersion>(raw).is_err(),
                "{raw}"
            );
        }
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
