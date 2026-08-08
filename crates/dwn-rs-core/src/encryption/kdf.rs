use super::error::EncryptionError;
use super::DerivationScheme;

use hkdf::Hkdf;
use k256::sha2::Sha256;

use super::KEY_AGREEMENT_ALGORITHM;

/// HKDF-SHA256 with an empty salt and the given `info`, producing 32 bytes.
pub(crate) fn hkdf_sha256_32(
    input_key_material: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let hkdf = Hkdf::<Sha256>::new(None, input_key_material);
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm)
        .map_err(|err| EncryptionError::AesKeyWrap(err.to_string()))?;
    Ok(okm.to_vec())
}

/// Derives the A256KW KEK from the X25519 shared secret for a RecordsWrite
/// `keyEncryption` entry. The `info` tuple matches `Encryption.getKekInfo`.
pub(crate) fn a256kw_kek(
    shared_secret: &[u8],
    key_id: &str,
    derivation_scheme: DerivationScheme,
    protocol: Option<&str>,
    role_path: Option<&str>,
) -> Result<Vec<u8>, EncryptionError> {
    let info = match derivation_scheme {
        DerivationScheme::ProtocolPath => {
            serde_json::to_string(&[KEY_AGREEMENT_ALGORITHM, "protocolPath", key_id])
                .expect("protocolPath KEK info must serialize")
        }
        DerivationScheme::RoleAudience => {
            let protocol = protocol.ok_or(EncryptionError::MissingRoleAudienceProtocol)?;
            let role_path = role_path.ok_or(EncryptionError::MissingRoleAudienceRolePath)?;
            serde_json::to_string(&[
                KEY_AGREEMENT_ALGORITHM,
                "roleAudience",
                protocol,
                role_path,
                key_id,
            ])
            .expect("roleAudience KEK info must serialize")
        }
    };
    hkdf_sha256_32(shared_secret, info.as_bytes())
}

/// Derives the seal KEK. Binds protocol, rolePath, contextId, and
/// audienceKeyId (no `keyId`).
pub(crate) fn seal_kek(
    shared_secret: &[u8],
    protocol: &str,
    role_path: &str,
    context_id: &str,
    audience_key_id: &str,
) -> Result<Vec<u8>, EncryptionError> {
    let info = serde_json::to_string(&[
        KEY_AGREEMENT_ALGORITHM,
        "seal",
        protocol,
        role_path,
        context_id,
        audience_key_id,
    ])
    .expect("seal KEK info must serialize");
    hkdf_sha256_32(shared_secret, info.as_bytes())
}

/// Derives a hardened hierarchical deterministic private key along a relative
/// derivation path, matching `@enbox/dwn-sdk-js` `HdKey.derivePrivateKeyBytes`
/// (`Records.derivePrivateKey`) used by the `protocolPath` decrypt path.
///
/// Each path segment is applied as one HKDF-SHA256 step with an empty salt and
/// the segment bytes as the `info` value, producing a 32-byte key that becomes
/// the input for the next segment.
pub fn derive_private_key_bytes(
    private_key: &[u8],
    relative_path: &[&str],
) -> Result<Vec<u8>, EncryptionError> {
    let mut current = private_key.to_vec();
    for segment in relative_path {
        if segment.is_empty() {
            return Err(EncryptionError::EmptyDerivationPathSegment);
        }
        current = hkdf_sha256_32(&current, segment.as_bytes())?;
    }
    Ok(current)
}
