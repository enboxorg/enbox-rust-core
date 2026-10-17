//! Password vault lifecycle over the at-rest JWE codec.
//!
//! The vault holds the CEK in memory only while unlocked and persists the
//! three logical values through [`SecretStore::apply`], so every mutation is
//! one atomic commit. It owns no network or host-keychain access: the DID is
//! built by the injected [`DidProvider`].

use super::{
    decrypt_did, derive_agent_keys, encrypt_did, unwrap_cek_typed,
    validate_agent_did_key_requirements, validate_recovery_phrase, wrap_cek, AgentDidCreateRequest,
    AgentIdentityError, AgentIdentityResult, CekDecodeError, CekHeader, DidProvider, PortableDid,
    SecretStore, SecretWrite, VaultStatus, DEFAULT_PBES2_ITERATIONS, VAULT_CEK_JWE_KEY,
    VAULT_DID_JWE_KEY, VAULT_STATUS_KEY,
};
use std::fmt::Debug;
use std::sync::Arc;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD as base64url};
use bip39::{Language, Mnemonic};
use chrono::SecondsFormat;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

/// Lifecycle payload returned by [`IdentityVault::initialize`].
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInitialization {
    pub recovery_phrase: String,
    pub portable_did: PortableDid,
}

impl Debug for VaultInitialization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultInitialization")
            .field("portable_did", &self.portable_did)
            .finish_non_exhaustive()
    }
}

/// Exported vault blob: the at-rest values plus the status at export time.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityVaultBackup {
    pub date_created: String,
    pub size: serde_json::Number,
    pub data: String,
}

impl Debug for IdentityVaultBackup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityVaultBackup")
            .field("date_created", &self.date_created)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct VaultState {
    cek: Option<Zeroizing<[u8; 32]>>,
}

/// Backend-agnostic password vault with the `HdIdentityVault` lifecycle.
///
/// Lock state is per instance and in memory only. Operations are serialized
/// through one async mutex, so mutations never interleave their
/// read-check-write sequences.
///
/// Password-stretching is offloaded to a blocking thread, so key derivation does
/// not stall the async executor. An operation still holds the vault's lock for
/// its whole duration, as required for linearizable state.
pub struct IdentityVault {
    store: Arc<dyn SecretStore>,
    did_provider: Arc<dyn DidProvider>,
    work_factor: u32,
    state: Mutex<VaultState>,
}

impl Debug for IdentityVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityVault")
            .field("work_factor", &self.work_factor)
            .finish_non_exhaustive()
    }
}

impl IdentityVault {
    /// Build a vault over the given store and DID provider using the default
    /// work factor.
    pub fn new(store: Arc<dyn SecretStore>, did_provider: Arc<dyn DidProvider>) -> Self {
        Self::with_work_factor(store, did_provider, DEFAULT_PBES2_ITERATIONS)
    }

    /// Build a vault with an explicit PBES2 work factor.
    pub fn with_work_factor(
        store: Arc<dyn SecretStore>,
        did_provider: Arc<dyn DidProvider>,
        work_factor: u32,
    ) -> Self {
        Self {
            store,
            did_provider,
            work_factor,
            state: Mutex::new(VaultState::default()),
        }
    }

    /// Whether the vault currently holds no in-memory CEK.
    pub async fn is_locked(&self) -> bool {
        self.state.lock().await.cek.is_none()
    }

    /// The stored status; absent entry reads as uninitialized.
    pub async fn status(&self) -> AgentIdentityResult<VaultStatus> {
        let _guard = self.state.lock().await;
        Ok(self.read_status().await?.0)
    }

    /// Create a fresh identity, persisting all three values atomically.
    pub async fn initialize(
        &self,
        password: &str,
        recovery_phrase: Option<&str>,
        dwn_endpoints: Vec<String>,
    ) -> AgentIdentityResult<VaultInitialization> {
        let mut state = self.state.lock().await;
        let (status, _) = self.read_status_locking_on_error(&mut state).await?;
        if status.initialized {
            return Err(already_initialized());
        }
        if password.trim().is_empty() {
            return Err(blank_password());
        }
        let recovery_phrase = match recovery_phrase {
            Some(phrase) => {
                validate_recovery_phrase(phrase)?;
                phrase.to_string()
            }
            None => Mnemonic::generate_in(Language::English, 12)
                .map_err(|err| AgentIdentityError::invalid_mnemonic(err.to_string()))?
                .to_string(),
        };

        let derived = derive_agent_keys(&recovery_phrase)?;
        let cek = fixed_cek(&derived.vault_content_encryption_key)?;
        let salt = derived.vault_unlock_salt;
        let portable_did = self
            .did_provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived.identity_private_jwk,
                signing_private_jwk: derived.signing_private_jwk,
                encryption_private_jwk: derived.encryption_private_jwk,
                dwn_endpoints,
            })
            .await?;
        validate_agent_did_key_requirements(&portable_did)?;

        let cek_entry =
            wrap_cek_blocking(password.as_bytes().to_vec(), cek, salt, self.work_factor).await?;
        let did_json = serde_json::to_vec(&portable_did)
            .map_err(|err| AgentIdentityError::vault(format!("invalid portable DID: {err}")))?;
        let did_entry = encrypt_did(&did_json, &cek)?;
        let stored_status = VaultStatus {
            initialized: true,
            last_backup: None,
            last_restore: None,
        };

        self.store
            .apply(vec![
                SecretWrite::put(VAULT_CEK_JWE_KEY, cek_entry.into_bytes()),
                SecretWrite::put(VAULT_DID_JWE_KEY, did_entry.into_bytes()),
                SecretWrite::put(VAULT_STATUS_KEY, stored_status.encode()?),
            ])
            .await?;

        state.cek = Some(Zeroizing::new(cek));
        Ok(VaultInitialization {
            recovery_phrase,
            portable_did,
        })
    }

    /// Unlock with the password, replacing any in-memory CEK. Never writes.
    pub async fn unlock(&self, password: &str) -> AgentIdentityResult<()> {
        let mut state = self.state.lock().await;
        let (status, _) = self.read_status_locking_on_error(&mut state).await?;
        if !status.initialized {
            return Err(uninitialized());
        }
        state.cek = None;
        let cek_entry = self.read_secret_string(VAULT_CEK_JWE_KEY).await?;
        let (cek, _) = match unwrap_cek_blocking(cek_entry, password.as_bytes().to_vec()).await? {
            Ok(opened) => opened,
            Err(CekDecodeError::Authentication) => return Err(invalid_password()),
            Err(CekDecodeError::Corrupt) => return Err(corrupt("stored vault key is invalid")),
        };
        state.cek = Some(Zeroizing::new(cek));
        Ok(())
    }

    /// Lock an initialized vault, clearing the in-memory CEK. Idempotent.
    pub async fn lock(&self) -> AgentIdentityResult<()> {
        let mut state = self.state.lock().await;
        let (status, _) = self.read_status_locking_on_error(&mut state).await?;
        if !status.initialized {
            return Err(uninitialized());
        }
        state.cek = None;
        Ok(())
    }

    /// The stored agent DID, decrypted under the in-memory CEK.
    pub async fn get_did(&self) -> AgentIdentityResult<PortableDid> {
        let state = self.state.lock().await;
        let cek = state.cek.as_ref().ok_or_else(locked)?;
        let did_entry = self.read_secret_string(VAULT_DID_JWE_KEY).await?;
        let did_bytes =
            decrypt_did(&did_entry, cek).map_err(|_| corrupt("stored vault DID is invalid"))?;
        serde_json::from_slice(&did_bytes).map_err(|_| corrupt("stored vault DID is invalid"))
    }

    /// Re-wrap the CEK under `new`, preserving the stored salt and work factor.
    pub async fn change_password(&self, old: &str, new: &str) -> AgentIdentityResult<()> {
        let mut state = self.state.lock().await;
        let (status, _) = self.read_status_locking_on_error(&mut state).await?;
        if !status.initialized {
            return Err(uninitialized());
        }
        if new.trim().is_empty() {
            return Err(blank_password());
        }
        state.cek = None;

        let cek_entry = self.read_secret_string(VAULT_CEK_JWE_KEY).await?;
        let (cek, header) = match unwrap_cek_blocking(cek_entry, old.as_bytes().to_vec()).await? {
            Ok(opened) => opened,
            Err(CekDecodeError::Authentication) => return Err(invalid_password()),
            Err(CekDecodeError::Corrupt) => return Err(corrupt("stored vault key is invalid")),
        };
        let new_cek_entry =
            wrap_cek_blocking(new.as_bytes().to_vec(), cek, header.p2s, header.p2c).await?;

        self.store
            .apply(vec![SecretWrite::put(
                VAULT_CEK_JWE_KEY,
                new_cek_entry.into_bytes(),
            )])
            .await?;
        state.cek = Some(Zeroizing::new(cek));
        Ok(())
    }

    /// Reset the password from the recovery phrase, requiring the stored DID
    /// to match the phrase.
    pub async fn reset_password_with_recovery_phrase(
        &self,
        recovery_phrase: &str,
        password: &str,
    ) -> AgentIdentityResult<()> {
        let mut state = self.state.lock().await;
        let (status, _) = self.read_status_locking_on_error(&mut state).await?;
        if !status.initialized {
            return Err(uninitialized());
        }
        state.cek = None;
        if password.trim().is_empty() {
            return Err(blank_password());
        }
        validate_recovery_phrase(recovery_phrase)?;

        let derived = derive_agent_keys(recovery_phrase)?;
        let derived_cek = fixed_cek(&derived.vault_content_encryption_key)?;
        let salt = derived.vault_unlock_salt;

        let stored_did = self
            .store
            .get(VAULT_DID_JWE_KEY)
            .await?
            .ok_or_else(recovery_phrase_mismatch)?;
        let did_entry = String::from_utf8(stored_did).map_err(|_| recovery_phrase_mismatch())?;
        let did_bytes =
            decrypt_did(&did_entry, &derived_cek).map_err(|_| recovery_phrase_mismatch())?;
        let stored_did: PortableDid =
            serde_json::from_slice(&did_bytes).map_err(|_| recovery_phrase_mismatch())?;
        let derived_did = self
            .did_provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived.identity_private_jwk,
                signing_private_jwk: derived.signing_private_jwk,
                encryption_private_jwk: derived.encryption_private_jwk,
                dwn_endpoints: Vec::new(),
            })
            .await
            .map_err(|_| recovery_phrase_mismatch())?;
        if stored_did.uri != derived_did.uri {
            return Err(recovery_phrase_mismatch());
        }

        let cek_entry = wrap_cek_blocking(
            password.as_bytes().to_vec(),
            derived_cek,
            salt,
            self.work_factor,
        )
        .await?;
        self.store
            .apply(vec![SecretWrite::put(
                VAULT_CEK_JWE_KEY,
                cek_entry.into_bytes(),
            )])
            .await?;
        state.cek = Some(Zeroizing::new(derived_cek));
        Ok(())
    }

    /// Export the currently stored values as a portable backup blob.
    pub async fn backup(&self) -> AgentIdentityResult<IdentityVaultBackup> {
        let mut state = self.state.lock().await;
        let (status, status_bytes) = self.read_status_locking_on_error(&mut state).await?;
        if !status.initialized {
            return Err(uninitialized());
        }
        if state.cek.is_none() {
            return Err(locked());
        }

        let did_entry = self.read_secret_string(VAULT_DID_JWE_KEY).await?;
        let cek_entry = self.read_secret_string(VAULT_CEK_JWE_KEY).await?;
        let status_value: serde_json::Value = serde_json::from_slice(
            status_bytes
                .as_deref()
                .ok_or_else(|| corrupt("stored vault status is missing"))?,
        )
        .map_err(|_| corrupt("stored vault status is invalid"))?;
        let data_json = serde_json::json!({
            "did": did_entry,
            "contentEncryptionKey": cek_entry,
            "status": status_value,
        });
        let data_bytes = serde_json::to_vec(&data_json)
            .map_err(|err| AgentIdentityError::vault(format!("invalid vault backup: {err}")))?;
        let data = base64url.encode(&data_bytes);
        let size = data.chars().count();

        let date_created = now_iso_millis();
        let updated = VaultStatus {
            initialized: true,
            last_backup: Some(date_created.clone()),
            last_restore: status.last_restore,
        };
        self.store
            .apply(vec![SecretWrite::put(VAULT_STATUS_KEY, updated.encode()?)])
            .await?;

        Ok(IdentityVaultBackup {
            date_created,
            size: serde_json::Number::from(size as u64),
            data,
        })
    }

    /// Restore a parsed backup blob, replacing the CEK and DID entries.
    pub async fn restore(
        &self,
        backup: &IdentityVaultBackup,
        password: &str,
    ) -> AgentIdentityResult<()> {
        let bytes = serde_json::to_vec(backup)
            .map_err(|_| AgentIdentityError::vault_invalid_backup("invalid vault backup"))?;
        self.restore_json(&bytes, password).await
    }

    /// Restore a backup from its raw JSON form.
    pub async fn restore_json(
        &self,
        backup_json: &[u8],
        password: &str,
    ) -> AgentIdentityResult<()> {
        let mut state = self.state.lock().await;
        // Every failed restore, including a malformed blob, ends locked.
        state.cek = None;

        let backup: IdentityVaultBackup =
            serde_json::from_slice(backup_json).map_err(|_| invalid_backup())?;
        let raw = decode_base64url_lenient(&backup.data).ok_or_else(invalid_backup)?;
        let value: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|_| invalid_backup())?;
        let did_entry = value
            .get("did")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid_backup)?
            .to_string();
        let cek_entry = value
            .get("contentEncryptionKey")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid_backup)?
            .to_string();
        let backup_status = value
            .get("status")
            .filter(|value| value.is_object())
            .ok_or_else(invalid_backup)?;
        if backup_status.get("initialized") != Some(&serde_json::Value::Bool(true)) {
            return Err(invalid_backup());
        }
        let backup_last_backup = backup_status
            .get("lastBackup")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let (current, _) = self.read_status().await?;
        let recovered_cek =
            match unwrap_cek_blocking(cek_entry.clone(), password.as_bytes().to_vec()).await? {
                Ok((cek, _)) => cek,
                Err(CekDecodeError::Authentication) => return Err(invalid_password()),
                Err(CekDecodeError::Corrupt) => return Err(invalid_backup()),
            };
        decrypt_did(&did_entry, &recovered_cek).map_err(|_| invalid_backup())?;

        let status = VaultStatus {
            initialized: true,
            last_backup: backup_last_backup.or(current.last_backup),
            last_restore: Some(now_iso_millis()),
        };
        self.store
            .apply(vec![
                SecretWrite::put(VAULT_CEK_JWE_KEY, cek_entry.into_bytes()),
                SecretWrite::put(VAULT_DID_JWE_KEY, did_entry.into_bytes()),
                SecretWrite::put(VAULT_STATUS_KEY, status.encode()?),
            ])
            .await?;
        state.cek = Some(Zeroizing::new(recovered_cek));
        Ok(())
    }

    /// Encrypt arbitrary data under the in-memory CEK.
    pub async fn encrypt_data(&self, plaintext: &[u8]) -> AgentIdentityResult<String> {
        let state = self.state.lock().await;
        let cek = state.cek.as_ref().ok_or_else(locked)?;
        super::encrypt_data(plaintext, cek)
    }

    /// Decrypt a data JWE under the in-memory CEK.
    pub async fn decrypt_data(&self, jwe: &str) -> AgentIdentityResult<Vec<u8>> {
        let state = self.state.lock().await;
        let cek = state.cek.as_ref().ok_or_else(locked)?;
        super::decrypt_data(jwe, cek)
    }

    async fn read_status(&self) -> AgentIdentityResult<(VaultStatus, Option<Vec<u8>>)> {
        let bytes = self.store.get(VAULT_STATUS_KEY).await?;
        let status = VaultStatus::parse(bytes.as_deref())
            .map_err(|_| corrupt("stored vault status is invalid"))?;
        Ok((status, bytes))
    }

    /// Read status, dropping the in-memory CEK if the read fails.
    ///
    /// Key hygiene outranks the error's exact origin: a vault whose status
    /// cannot be trusted must not stay unlocked.
    async fn read_status_locking_on_error(
        &self,
        state: &mut VaultState,
    ) -> AgentIdentityResult<(VaultStatus, Option<Vec<u8>>)> {
        match self.read_status().await {
            Ok(value) => Ok(value),
            Err(error) => {
                state.cek = None;
                Err(error)
            }
        }
    }

    async fn read_secret_string(&self, key: &str) -> AgentIdentityResult<String> {
        let bytes = self
            .store
            .get(key)
            .await?
            .ok_or_else(|| corrupt("stored vault value is missing"))?;
        String::from_utf8(bytes).map_err(|_| corrupt("stored vault value is not valid UTF-8"))
    }
}

/// Wrap the CEK off the async executor: PBKDF2 is CPU-bound.
async fn wrap_cek_blocking(
    password: Vec<u8>,
    cek: [u8; 32],
    salt: Vec<u8>,
    p2c: u32,
) -> AgentIdentityResult<String> {
    tokio::task::spawn_blocking(move || wrap_cek(&password, &cek, &salt, p2c))
        .await
        .map_err(join_error)?
}

/// Unwrap the CEK off the async executor, preserving the codec's failure class.
async fn unwrap_cek_blocking(
    jwe: String,
    password: Vec<u8>,
) -> AgentIdentityResult<Result<([u8; 32], CekHeader), CekDecodeError>> {
    tokio::task::spawn_blocking(move || unwrap_cek_typed(&jwe, &password))
        .await
        .map_err(join_error)
}

fn join_error(error: tokio::task::JoinError) -> AgentIdentityError {
    AgentIdentityError::vault(format!("vault key derivation task failed: {error}"))
}

fn fixed_cek(bytes: &[u8]) -> AgentIdentityResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| AgentIdentityError::invalid_key_material("vault key must be 32 bytes"))
}

fn decode_base64url_lenient(value: &str) -> Option<Vec<u8>> {
    base64url.decode(value).ok().or_else(|| {
        let unpadded = value.trim_end_matches('=');
        base64url.decode(unpadded).ok()
    })
}

fn now_iso_millis() -> String {
    super::now_utc().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn uninitialized() -> AgentIdentityError {
    AgentIdentityError::vault_uninitialized("vault is not initialized")
}

fn already_initialized() -> AgentIdentityError {
    AgentIdentityError::vault_already_initialized("vault is already initialized")
}

fn locked() -> AgentIdentityError {
    AgentIdentityError::vault_locked("vault is locked")
}

fn invalid_password() -> AgentIdentityError {
    AgentIdentityError::vault_invalid_password("invalid vault password")
}

fn blank_password() -> AgentIdentityError {
    AgentIdentityError::vault_blank_password("vault password must not be blank")
}

fn invalid_backup() -> AgentIdentityError {
    AgentIdentityError::vault_invalid_backup("invalid vault backup")
}

fn corrupt(detail: impl Into<String>) -> AgentIdentityError {
    AgentIdentityError::vault_corrupt(detail)
}

fn recovery_phrase_mismatch() -> AgentIdentityError {
    AgentIdentityError::recovery_phrase_mismatch("recovery phrase does not match the stored vault")
}
