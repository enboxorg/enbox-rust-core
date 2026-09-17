use super::*;

type HmacSha512 = Hmac<Sha512>;

/// Derive the deterministic key set (vault, identity, signing, encryption) from a BIP-39 phrase.
///
/// Pure: derives the same keys for the same phrase and persists nothing.
pub fn derive_agent_keys(recovery_phrase: &str) -> AgentIdentityResult<AgentDerivedKeys> {
    let mnemonic = Mnemonic::parse_in(Language::English, recovery_phrase)
        .map_err(|err| AgentIdentityError::invalid_mnemonic(err.to_string()))?;
    let seed = mnemonic.to_seed("");
    let vault = derive_slip10_ed25519(&seed, "m/44'/0'/0'/0'/0'")?;
    let identity = derive_slip10_ed25519(&seed, "m/44'/0'/1708523827'/0'/0'")?;
    let signing = derive_slip10_ed25519(&seed, "m/44'/0'/1708523827'/0'/1'")?;
    let encryption = derive_slip10_ed25519(&seed, "m/44'/0'/1708523827'/0'/2'")?;
    let vault_public = ed25519_public_key_bytes(vault.private_key);

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
    Mnemonic::parse_in(Language::English, recovery_phrase)
        .map(|_| ())
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

pub(crate) fn hkdf_sha256(base_key: &[u8], info: &[u8], length: usize) -> AgentIdentityResult<Vec<u8>> {
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
    use super::*;

    const RECOVERY_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
