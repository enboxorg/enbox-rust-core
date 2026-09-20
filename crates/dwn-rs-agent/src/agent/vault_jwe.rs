//! At-rest vault JWE codec for the three logical vault values.
//!
//! Pure compact-JWE encode/decode for the three logical vault values. The
//! codec owns neither derivation nor storage: the B1 salt and work factor
//! arrive as parameters, and callers persist the resulting strings.

use super::{
    validate_agent_did_key_requirements, AgentIdentityError, AgentIdentityResult, PortableDid,
};
use aes::cipher::{array::Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes_gcm::{
    aead::{Aead, KeyInit as GcmKeyInit},
    Aes256Gcm, Nonce,
};
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD as base64url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Secret-store key for the password-wrapped CEK compact JWE.
pub const VAULT_CEK_JWE_KEY: &str = "agent:vault:cekJwe";
/// Secret-store key for the `dir`/A256GCM encrypted DID compact JWE.
pub const VAULT_DID_JWE_KEY: &str = "agent:vault:didJwe";
/// Secret-store key for the vault status JSON.
pub const VAULT_STATUS_KEY: &str = "agent:vault:status";

/// Default PBES2 work factor for fresh wraps.
pub const DEFAULT_PBES2_ITERATIONS: u32 = 210_000;

const PBES2_ALG: &str = "PBES2-HS512+A256KW";
const DIRECT_ALG: &str = "dir";
const A256GCM: &str = "A256GCM";
const GCM_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// Vault status JSON stored alongside the wrapped CEK and DID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub initialized: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_restore: Option<String>,
}

impl VaultStatus {
    pub fn uninitialized() -> Self {
        Self {
            initialized: false,
            last_backup: None,
            last_restore: None,
        }
    }

    /// Parse stored status bytes; missing maps to uninitialized.
    pub fn parse(bytes: Option<&[u8]>) -> AgentIdentityResult<Self> {
        let Some(bytes) = bytes else {
            return Ok(Self::uninitialized());
        };
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|err| AgentIdentityError::vault(format!("invalid vault status: {err}")))?;
        let initialized = value
            .get("initialized")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| AgentIdentityError::vault("invalid vault status".to_string()))?;
        let opt_string = |key: &str| -> AgentIdentityResult<Option<String>> {
            match value.get(key) {
                // Absent keys are rejected: only a wholly absent status entry
                // defaults; a present entry must carry both timestamp keys.
                None => Err(AgentIdentityError::vault(
                    "invalid vault status".to_string(),
                )),
                Some(serde_json::Value::Null) => Ok(None),
                Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(AgentIdentityError::vault(
                    "invalid vault status".to_string(),
                )),
            }
        };
        Ok(Self {
            initialized,
            last_backup: opt_string("lastBackup")?,
            last_restore: opt_string("lastRestore")?,
        })
    }

    pub fn encode(&self) -> AgentIdentityResult<Vec<u8>> {
        let mut value = serde_json::json!({ "initialized": self.initialized });
        value["lastBackup"] = self.last_backup.clone().into();
        value["lastRestore"] = self.last_restore.clone().into();
        serde_json::to_vec(&value)
            .map_err(|err| AgentIdentityError::vault(format!("invalid vault status: {err}")))
    }
}

/// Parsed CEK header parameters needed by password-change callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CekHeader {
    pub p2c: u32,
    pub p2s: Vec<u8>,
    pub cty: Option<String>,
}

#[derive(Serialize)]
struct CekProtectedHeader<'a> {
    alg: &'a str,
    enc: &'a str,
    cty: &'a str,
    p2c: u32,
    p2s: &'a str,
}

#[derive(Serialize)]
struct DirectProtectedHeader<'a> {
    alg: &'a str,
    enc: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<&'a str>,
}

/// Wrap a 32-byte vault CEK as a PBES2 compact JWE under the raw password bytes.
///
/// The salt is opaque bytes: fresh wraps pass the 32-byte derivation salt,
/// while password changes echo the stored salt of any length back verbatim.
pub fn wrap_cek(
    password: &[u8],
    cek: &[u8; 32],
    salt: &[u8],
    p2c: u32,
) -> AgentIdentityResult<String> {
    if p2c < 1 {
        return Err(AgentIdentityError::vault(
            "invalid vault work factor".to_string(),
        ));
    }
    wrap_raw_plaintext(password, salt, p2c, &oct_jwk_bytes(cek)?)
}

/// Re-wrap the CEK inside an existing CEK JWE under a new password.
///
/// Verifies the old password by unwrapping, then wraps the same CEK while
/// echoing the stored salt, work factor, and content type verbatim. Pure:
/// touches no storage; the caller owns the atomic swap.
pub fn rewrap_cek(
    old_password: &[u8],
    new_password: &[u8],
    cek_jwe: &str,
) -> AgentIdentityResult<String> {
    let (cek, header) = unwrap_cek(cek_jwe, old_password)?;
    wrap_raw_plaintext(new_password, &header.p2s, header.p2c, &oct_jwk_bytes(&cek)?)
}

fn oct_jwk_bytes(cek: &[u8; 32]) -> AgentIdentityResult<Vec<u8>> {
    let cek_jwk = oct_jwk(cek)?;
    serde_json::to_vec(&cek_jwk)
        .map_err(|err| AgentIdentityError::vault(format!("invalid vault key: {err}")))
}

fn wrap_raw_plaintext(
    password: &[u8],
    salt: &[u8],
    p2c: u32,
    plaintext: &[u8],
) -> AgentIdentityResult<String> {
    let p2s = base64url.encode(salt);
    let header = CekProtectedHeader {
        alg: PBES2_ALG,
        enc: A256GCM,
        cty: "text/plain",
        p2c,
        p2s: &p2s,
    };
    let encoded =
        base64url
            .encode(serde_json::to_vec(&header).map_err(|err| {
                AgentIdentityError::vault(format!("invalid vault header: {err}"))
            })?);

    let wrapping_key = derive_pbes2_kek(password, &p2s, p2c)?;
    let mut content_key = [0u8; 32];
    getrandom::fill(&mut content_key)
        .map_err(|err| AgentIdentityError::vault(format!("vault randomness failed: {err}")))?;
    let encrypted_key = aes_kw_wrap(&wrapping_key, &content_key)?;
    let (iv, ciphertext, tag) = aes_gcm_encrypt(&content_key, &encoded, plaintext)?;

    Ok(format!(
        "{encoded}.{}.{}.{}.{}",
        base64url.encode(encrypted_key),
        base64url.encode(iv),
        base64url.encode(ciphertext),
        base64url.encode(tag)
    ))
}

/// Unwrap a CEK JWE; returns the raw CEK and the stored header parameters.
pub fn unwrap_cek(jwe: &str, password: &[u8]) -> AgentIdentityResult<([u8; 32], CekHeader)> {
    let parts = split_compact(jwe)?;
    let header_value = decode_header(&parts.protected)?;
    require_alg_enc(&header_value, PBES2_ALG, A256GCM)?;
    let p2c = header_value
        .get("p2c")
        .and_then(serde_json::Value::as_u64)
        .filter(|v| *v >= 1 && *v <= u32::MAX as u64)
        .map(|v| v as u32)
        .ok_or_else(|| AgentIdentityError::vault("invalid vault iteration count".to_string()))?;
    let p2s = header_value
        .get("p2s")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AgentIdentityError::vault("invalid vault salt".to_string()))?;
    let salt = base64url
        .decode(p2s)
        .map_err(|_| AgentIdentityError::vault("invalid vault salt".to_string()))?;
    let encrypted_key = parts.encrypted_key.ok_or_else(|| {
        AgentIdentityError::vault("invalid vault JWE: missing encrypted key".to_string())
    })?;

    let wrapping_key = derive_pbes2_kek(password, p2s, p2c)?;
    let content_key = aes_kw_unwrap(&wrapping_key, &encrypted_key)
        .map_err(|_| AgentIdentityError::vault("vault authentication failed".to_string()))?;
    let cek_bytes: [u8; 32] = content_key
        .as_slice()
        .try_into()
        .map_err(|_| AgentIdentityError::vault("vault authentication failed".to_string()))?;
    let plaintext = aes_gcm_decrypt(
        &cek_bytes,
        &parts.protected,
        &parts.iv,
        &parts.ciphertext,
        &parts.tag,
    )
    .map_err(|_| AgentIdentityError::vault("vault authentication failed".to_string()))?;
    let cek = parse_oct_jwk(&plaintext)?;
    Ok((
        cek,
        CekHeader {
            p2c,
            p2s: salt,
            cty: header_value
                .get("cty")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        },
    ))
}

/// Encrypt `PortableDid` JSON bytes under the vault CEK with JWE direct
/// encryption (alg "dir") and A256GCM, `cty json`.
pub fn encrypt_did(portable_did_json: &[u8], cek: &[u8; 32]) -> AgentIdentityResult<String> {
    // Reject payloads that are not JSON objects early so cross-runtime
    // `getDid` failures stay typed at the codec boundary.
    let value: serde_json::Value = serde_json::from_slice(portable_did_json)
        .map_err(|_| AgentIdentityError::vault("invalid portable DID".to_string()))?;
    if !value.is_object() {
        return Err(AgentIdentityError::vault(
            "invalid portable DID".to_string(),
        ));
    }
    encrypt_direct(
        portable_did_json,
        cek,
        DirectProtectedHeader {
            alg: DIRECT_ALG,
            enc: A256GCM,
            cty: Some("json"),
        },
    )
}

/// Decrypt a DID JWE; accepts only JWE direct encryption (alg "dir") with A256GCM
/// and rejects payloads that are not usable agent DIDs.
pub fn decrypt_did(jwe: &str, cek: &[u8; 32]) -> AgentIdentityResult<Vec<u8>> {
    let bytes = decrypt_direct(jwe, cek)?;
    let did: PortableDid = serde_json::from_slice(&bytes)
        .map_err(|_| AgentIdentityError::vault("invalid portable DID".to_string()))?;
    validate_agent_did_key_requirements(&did)
        .map_err(|_| AgentIdentityError::vault("invalid portable DID".to_string()))?;
    Ok(bytes)
}

/// Encrypt arbitrary bytes under the vault CEK with JWE direct encryption
/// (alg "dir") and A256GCM, no `cty`.
pub fn encrypt_data(plaintext: &[u8], cek: &[u8; 32]) -> AgentIdentityResult<String> {
    encrypt_direct(
        plaintext,
        cek,
        DirectProtectedHeader {
            alg: DIRECT_ALG,
            enc: A256GCM,
            cty: None,
        },
    )
}

/// Decrypt an arbitrary-data JWE; accepts only JWE direct encryption
/// (alg "dir") with A256GCM.
pub fn decrypt_data(jwe: &str, cek: &[u8; 32]) -> AgentIdentityResult<Vec<u8>> {
    decrypt_direct(jwe, cek)
}

fn encrypt_direct(
    plaintext: &[u8],
    cek: &[u8; 32],
    header: DirectProtectedHeader<'_>,
) -> AgentIdentityResult<String> {
    let encoded =
        base64url
            .encode(serde_json::to_vec(&header).map_err(|err| {
                AgentIdentityError::vault(format!("invalid vault header: {err}"))
            })?);
    let (iv, ciphertext, tag) = aes_gcm_encrypt(cek, &encoded, plaintext)?;
    Ok(format!(
        "{encoded}..{}.{}.{}",
        base64url.encode(iv),
        base64url.encode(ciphertext),
        base64url.encode(tag)
    ))
}

fn decrypt_direct(jwe: &str, cek: &[u8; 32]) -> AgentIdentityResult<Vec<u8>> {
    let parts = split_compact(jwe)?;
    if parts.encrypted_key.is_some() {
        return Err(AgentIdentityError::vault(
            "invalid vault JWE: encrypted key must be empty".to_string(),
        ));
    }
    let header_value = decode_header(&parts.protected)?;
    require_alg_enc(&header_value, DIRECT_ALG, A256GCM)?;
    aes_gcm_decrypt(
        cek,
        &parts.protected,
        &parts.iv,
        &parts.ciphertext,
        &parts.tag,
    )
    .map_err(|_| AgentIdentityError::vault("vault authentication failed".to_string()))
}

struct CompactParts {
    protected: String,
    encrypted_key: Option<Vec<u8>>,
    iv: [u8; 12],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}

fn split_compact(jwe: &str) -> AgentIdentityResult<CompactParts> {
    let mut segments = jwe.split('.');
    let (protected, enc_key, iv, ciphertext, tag) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    );
    if segments.next().is_some() {
        return Err(AgentIdentityError::vault("invalid vault JWE".to_string()));
    }
    let (Some(protected), Some(enc_key), Some(iv), Some(ciphertext), Some(tag)) =
        (protected, enc_key, iv, ciphertext, tag)
    else {
        return Err(AgentIdentityError::vault("invalid vault JWE".to_string()));
    };
    if protected.is_empty() || iv.is_empty() || tag.is_empty() {
        return Err(AgentIdentityError::vault("invalid vault JWE".to_string()));
    }
    // The ciphertext segment may be empty (empty plaintext); it still
    // authenticates through the tag.
    let encrypted_key = if enc_key.is_empty() {
        None
    } else {
        Some(
            base64url
                .decode(enc_key)
                .map_err(|_| AgentIdentityError::vault("invalid vault JWE".to_string()))?,
        )
    };
    let iv_bytes = base64url
        .decode(iv)
        .map_err(|_| AgentIdentityError::vault("invalid vault JWE".to_string()))?;
    let tag_bytes = base64url
        .decode(tag)
        .map_err(|_| AgentIdentityError::vault("invalid vault JWE".to_string()))?;
    if iv_bytes.len() != GCM_IV_LEN || tag_bytes.len() != GCM_TAG_LEN {
        return Err(AgentIdentityError::vault("invalid vault JWE".to_string()));
    }
    Ok(CompactParts {
        protected: protected.to_string(),
        encrypted_key,
        iv: iv_bytes.as_slice().try_into().expect("length checked"),
        ciphertext: base64url
            .decode(ciphertext)
            .map_err(|_| AgentIdentityError::vault("invalid vault JWE".to_string()))?,
        tag: tag_bytes.as_slice().try_into().expect("length checked"),
    })
}

fn decode_header(encoded: &str) -> AgentIdentityResult<serde_json::Value> {
    let bytes = base64url
        .decode(encoded)
        .map_err(|_| AgentIdentityError::vault("invalid vault header".to_string()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| AgentIdentityError::vault("invalid vault header".to_string()))?;
    if !value.is_object() {
        return Err(AgentIdentityError::vault(
            "invalid vault header".to_string(),
        ));
    }
    Ok(value)
}

fn require_alg_enc(header: &serde_json::Value, alg: &str, enc: &str) -> AgentIdentityResult<()> {
    let ok = header.get("alg").and_then(serde_json::Value::as_str) == Some(alg)
        && header.get("enc").and_then(serde_json::Value::as_str) == Some(enc);
    if ok {
        Ok(())
    } else {
        Err(AgentIdentityError::vault(
            "unsupported vault algorithm".to_string(),
        ))
    }
}

fn derive_pbes2_kek(password: &[u8], p2s: &str, p2c: u32) -> AgentIdentityResult<[u8; 32]> {
    let salt_input = base64url
        .decode(p2s)
        .map_err(|_| AgentIdentityError::vault("invalid vault salt".to_string()))?;
    let mut salt = Vec::with_capacity(PBES2_ALG.len() + 1 + salt_input.len());
    salt.extend_from_slice(PBES2_ALG.as_bytes());
    salt.push(0x00);
    salt.extend_from_slice(&salt_input);
    let mut kek = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha512>(password, &salt, p2c, &mut kek);
    Ok(kek)
}

#[derive(Serialize, Deserialize)]
struct OctJwk {
    k: String,
    kty: String,
    kid: String,
}

fn oct_jwk(cek: &[u8; 32]) -> AgentIdentityResult<OctJwk> {
    let k = base64url.encode(cek);
    Ok(OctJwk {
        kid: oct_thumbprint(&k),
        k,
        kty: "oct".to_string(),
    })
}

fn parse_oct_jwk(plaintext: &[u8]) -> AgentIdentityResult<[u8; 32]> {
    let jwk: OctJwk = serde_json::from_slice(plaintext)
        .map_err(|_| AgentIdentityError::vault("invalid vault key".to_string()))?;
    if jwk.kty != "oct" {
        return Err(AgentIdentityError::vault("invalid vault key".to_string()));
    }
    let raw = base64url
        .decode(&jwk.k)
        .map_err(|_| AgentIdentityError::vault("invalid vault key".to_string()))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AgentIdentityError::vault("invalid vault key".to_string()))?;
    if jwk.kid != oct_thumbprint(&jwk.k) {
        return Err(AgentIdentityError::vault("invalid vault key".to_string()));
    }
    Ok(bytes)
}

fn oct_thumbprint(k: &str) -> String {
    let canonical = format!(r#"{{"k":"{k}","kty":"oct"}}"#);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    base64url.encode(hasher.finalize())
}

fn aes_gcm_encrypt(
    key: &[u8; 32],
    encoded_header: &str,
    plaintext: &[u8],
) -> AgentIdentityResult<([u8; 12], Vec<u8>, [u8; 16])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AgentIdentityError::vault("invalid vault key".to_string()))?;
    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv)
        .map_err(|err| AgentIdentityError::vault(format!("vault randomness failed: {err}")))?;
    let mut combined = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: encoded_header.as_bytes(),
            },
        )
        .map_err(|_| AgentIdentityError::vault("vault encryption failed".to_string()))?;
    if combined.len() < GCM_TAG_LEN {
        return Err(AgentIdentityError::vault(
            "vault encryption failed".to_string(),
        ));
    }
    let tag_start = combined.len() - GCM_TAG_LEN;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&combined[tag_start..]);
    combined.truncate(tag_start);
    Ok((iv, combined, tag))
}

fn aes_gcm_decrypt(
    key: &[u8; 32],
    encoded_header: &str,
    iv: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    cipher.decrypt(
        Nonce::from_slice(iv),
        aes_gcm::aead::Payload {
            msg: &combined,
            aad: encoded_header.as_bytes(),
        },
    )
}

fn aes_kw_wrap(kek: &[u8; 32], plaintext: &[u8; 32]) -> AgentIdentityResult<Vec<u8>> {
    let cipher = aes::Aes256::new_from_slice(kek)
        .map_err(|_| AgentIdentityError::vault("invalid vault key".to_string()))?;
    let mut a = [0xa6u8; 8];
    let mut blocks = [[0u8; 8]; 4];
    for (i, chunk) in plaintext.chunks(8).enumerate() {
        blocks[i].copy_from_slice(chunk);
    }
    for j in 0..6 {
        for (i, block) in blocks.iter_mut().enumerate() {
            let mut input = [0u8; 16];
            input[..8].copy_from_slice(&a);
            input[8..].copy_from_slice(block);
            let mut encrypted = Array::<u8, _>::try_from(&input[..]).expect("16 bytes");
            cipher.encrypt_block(&mut encrypted);
            a.copy_from_slice(&encrypted[..8]);
            xor_counter(&mut a, (4 * j + i + 1) as u64);
            block.copy_from_slice(&encrypted[8..]);
        }
    }
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&a);
    for block in blocks {
        out.extend_from_slice(&block);
    }
    Ok(out)
}

fn aes_kw_unwrap(kek: &[u8; 32], wrapped: &[u8]) -> AgentIdentityResult<[u8; 32]> {
    if wrapped.len() != 40 {
        return Err(AgentIdentityError::vault("invalid vault key".to_string()));
    }
    let cipher = aes::Aes256::new_from_slice(kek)
        .map_err(|_| AgentIdentityError::vault("invalid vault key".to_string()))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    let mut blocks = [[0u8; 8]; 4];
    for (i, chunk) in wrapped[8..].chunks(8).enumerate() {
        blocks[i].copy_from_slice(chunk);
    }
    for j in (0..6).rev() {
        for i in (0..4).rev() {
            let mut masked = a;
            xor_counter(&mut masked, (4 * j + i + 1) as u64);
            let mut input = [0u8; 16];
            input[..8].copy_from_slice(&masked);
            input[8..].copy_from_slice(&blocks[i]);
            let mut decrypted = Array::<u8, _>::try_from(&input[..]).expect("16 bytes");
            cipher.decrypt_block(&mut decrypted);
            a.copy_from_slice(&decrypted[..8]);
            blocks[i].copy_from_slice(&decrypted[8..]);
        }
    }
    if a != [0xa6u8; 8] {
        return Err(AgentIdentityError::vault("invalid vault key".to_string()));
    }
    let mut out = [0u8; 32];
    for (i, block) in blocks.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(block);
    }
    Ok(out)
}

fn xor_counter(a: &mut [u8; 8], counter: u64) {
    for (left, right) in a.iter_mut().zip(counter.to_be_bytes()) {
        *left ^= right;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"vault-interop-password";
    const CEK: [u8; 32] = [0x42; 32];
    const SALT: [u8; 32] = [0x11; 32];

    fn header_of(jwe: &str) -> serde_json::Value {
        let protected = jwe.split('.').next().unwrap();
        serde_json::from_slice(&base64url.decode(protected).unwrap()).unwrap()
    }

    #[test]
    fn cek_round_trip_returns_stored_header_parameters() {
        let jwe = wrap_cek(PASSWORD, &CEK, &SALT, 1).unwrap();
        let (cek, header) = unwrap_cek(&jwe, PASSWORD).unwrap();
        assert_eq!(cek, CEK);
        assert_eq!(header.p2c, 1);
        assert_eq!(header.p2s, SALT);
        assert_eq!(header.cty.as_deref(), Some("text/plain"));
    }

    #[test]
    fn cek_writer_shape_matches_contract() {
        let jwe = wrap_cek(PASSWORD, &CEK, &SALT, 10_000).unwrap();
        let header = header_of(&jwe);
        assert_eq!(header["alg"], PBES2_ALG);
        assert_eq!(header["enc"], A256GCM);
        assert_eq!(header["cty"], "text/plain");
        assert_eq!(header["p2c"], 10_000);
        assert_eq!(header["p2s"], base64url.encode(SALT));

        let segments: Vec<&str> = jwe.split('.').collect();
        assert_eq!(segments.len(), 5);
        assert_eq!(base64url.decode(segments[2]).unwrap().len(), GCM_IV_LEN);

        let (cek, _) = unwrap_cek(&jwe, PASSWORD).unwrap();
        assert_eq!(cek, CEK);
        // Unwrap already proves the embedded oct JWK carries matching
        // `k`/`kty`/`kid`; the thumbprint itself is 43 base64url chars.
        assert_eq!(oct_thumbprint(&base64url.encode(CEK)).len(), 43);
    }

    #[test]
    fn pbes2_work_factor_variants_open_with_stored_count() {
        for p2c in [1, 10_000, DEFAULT_PBES2_ITERATIONS] {
            let jwe = wrap_cek(PASSWORD, &CEK, &SALT, p2c).unwrap();
            assert_eq!(header_of(&jwe)["p2c"], p2c);
            let (cek, header) = unwrap_cek(&jwe, PASSWORD).unwrap();
            assert_eq!(cek, CEK);
            assert_eq!(header.p2c, p2c);
        }
    }

    #[test]
    fn non_default_salt_opens() {
        let salt = [0x77; 32];
        let jwe = wrap_cek(PASSWORD, &CEK, &salt, 1).unwrap();
        let (cek, header) = unwrap_cek(&jwe, PASSWORD).unwrap();
        assert_eq!(cek, CEK);
        assert_eq!(header.p2s, salt);
    }

    #[test]
    fn rewrap_preserves_stored_salt_and_count() {
        // Short non-default salt: the stored bytes echo back verbatim even
        // though fresh wraps always use the 32-byte derivation salt.
        let salt = [0x77; 5];
        let jwe = wrap_cek(PASSWORD, &CEK, &salt, 10_000).unwrap();
        let rewrapped = rewrap_cek(PASSWORD, b"new-password", &jwe).unwrap();
        let (cek, header) = unwrap_cek(&rewrapped, b"new-password").unwrap();
        assert_eq!(cek, CEK);
        assert_eq!(header.p2s, salt);
        assert_eq!(header.p2c, 10_000);
        assert!(unwrap_cek(&rewrapped, PASSWORD).is_err());
        assert!(rewrap_cek(b"wrong", b"new-password", &jwe).is_err());
    }

    #[test]
    fn writer_rejects_non_positive_work_factor() {
        assert!(wrap_cek(PASSWORD, &CEK, &SALT, 0).is_err());
    }

    #[test]
    fn wrong_password_fails_closed() {
        let jwe = wrap_cek(PASSWORD, &CEK, &SALT, 1).unwrap();
        assert!(unwrap_cek(&jwe, b"wrong-password").is_err());
    }

    #[test]
    fn invalid_key_plaintexts_are_unusable() {
        let k = base64url.encode([0x42; 32]);
        let kid = oct_thumbprint(&k);
        for plaintext in [
            serde_json::json!({"k": k, "kty": "EC", "kid": kid}).to_string(),
            serde_json::json!({"k": base64url.encode([0x42; 16]), "kty": "oct", "kid": kid})
                .to_string(),
            serde_json::json!({"k": k, "kty": "oct", "kid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
                .to_string(),
            "not json".to_string(),
        ] {
            let jwe =
                wrap_raw_plaintext(PASSWORD, &SALT, 1, plaintext.as_bytes()).unwrap();
            assert!(unwrap_cek(&jwe, PASSWORD).is_err(), "{plaintext}");
        }
    }

    #[test]
    fn data_round_trips_arbitrary_bytes() {
        for plaintext in [b"hello".as_slice(), b"", &[0, 1, 2, 250, 255, 16, 32]] {
            let jwe = encrypt_data(plaintext, &CEK).unwrap();
            assert_eq!(decrypt_data(&jwe, &CEK).unwrap(), plaintext);
        }
    }

    #[test]
    fn passwords_are_raw_bytes_without_normalization() {
        // NFC "é" (2 bytes) vs NFD "e" + combining accent (3 bytes).
        let nfc = "passé".as_bytes().to_vec();
        let mut nfd = "passe".as_bytes().to_vec();
        nfd.extend_from_slice(&[0xcc, 0x81]);
        assert_ne!(nfc, nfd);
        let jwe = wrap_cek(&nfc, &CEK, &SALT, 1).unwrap();
        assert!(unwrap_cek(&jwe, &nfd).is_err());
        assert_eq!(unwrap_cek(&jwe, &nfc).unwrap().0, CEK);
    }

    #[test]
    fn status_missing_maps_to_uninitialized() {
        assert_eq!(
            VaultStatus::parse(None).unwrap(),
            VaultStatus::uninitialized()
        );
    }

    #[test]
    fn status_round_trip_keeps_explicit_nulls() {
        let status = VaultStatus {
            initialized: true,
            last_backup: None,
            last_restore: Some("2026-09-20T00:00:00Z".to_string()),
        };
        let bytes = status.encode().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["initialized"], true);
        assert_eq!(value["lastBackup"], serde_json::Value::Null);
        assert_eq!(value["lastRestore"], "2026-09-20T00:00:00Z");
        assert_eq!(VaultStatus::parse(Some(&bytes)).unwrap(), status);
    }

    #[test]
    fn status_rejects_malformed_values() {
        for raw in [
            "not json",
            "{}",
            r#"{"initialized": "yes", "lastBackup": null, "lastRestore": null}"#,
            r#"{"initialized": true, "lastBackup": 7, "lastRestore": null}"#,
            r#"{"initialized": true, "lastRestore": null}"#,
            r#"{"initialized": true, "lastBackup": null}"#,
            r#"{"initialized": false, "lastBackup": null}"#,
        ] {
            assert!(VaultStatus::parse(Some(raw.as_bytes())).is_err(), "{raw}");
        }
    }

    #[tokio::test]
    async fn did_round_trip_through_provider_did() {
        use super::super::{
            derive_agent_keys, AgentDidCreateRequest, DidDhtProvider, DidProvider, RECOVERY_PHRASE,
        };

        let derived = derive_agent_keys(RECOVERY_PHRASE).unwrap();
        let portable_did = DidDhtProvider::default()
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived.identity_private_jwk,
                signing_private_jwk: derived.signing_private_jwk,
                encryption_private_jwk: derived.encryption_private_jwk,
                dwn_endpoints: vec!["https://dwn.example".to_string()],
            })
            .await
            .unwrap();
        let cek: [u8; 32] = derived
            .vault_content_encryption_key
            .as_slice()
            .try_into()
            .unwrap();
        let json = serde_json::to_vec(&portable_did).unwrap();
        let jwe = encrypt_did(&json, &cek).unwrap();
        let header = header_of(&jwe);
        assert_eq!(header["alg"], DIRECT_ALG);
        assert_eq!(header["enc"], A256GCM);
        assert_eq!(header["cty"], "json");
        assert_eq!(decrypt_did(&jwe, &cek).unwrap(), json);

        // Payloads that are not usable agent DIDs fail at the codec boundary.
        let not_did = encrypt_data(br#"{"uri": "did:example:1"}"#, &cek).unwrap();
        assert!(decrypt_did(&not_did, &cek).is_err());
        let not_object = encrypt_data(b"[1, 2]", &cek).unwrap();
        assert!(decrypt_did(&not_object, &cek).is_err());
        assert!(encrypt_did(b"[1, 2]", &cek).is_err());
    }
}
