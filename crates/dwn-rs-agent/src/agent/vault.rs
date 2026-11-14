//! Password vault lifecycle over the at-rest JWE codec.
//!
//! The vault holds the CEK in memory only while unlocked and persists the
//! three logical values through [`SecretStore::apply`], so every mutation is
//! one atomic commit. It owns no network or host-keychain access: the DID is
//! built by the injected [`DidProvider`].

use super::{
    clock_system_time, copy_resolved_dwn_service, decrypt_did, derive_agent_keys,
    dwn_endpoint_status, encrypt_did, normalize_dwn_endpoints, replace_dwn_service_endpoint_urls,
    system_clock, unwrap_cek_typed, validate_agent_did_key_requirements, validate_recovery_phrase,
    wrap_cek, AgentClock, AgentDerivedKeys, AgentDidCreateRequest, AgentDidNetwork, AgentDidSigner,
    AgentIdentityError, AgentIdentityResult, CekDecodeError, CekHeader, DerivedIdentitySigner,
    DidDhtNetwork, DidProvider, DidResolution, DwnEndpointStatus, PortableDid, SecretStore,
    SecretWrite, VaultStatus, DEFAULT_PBES2_ITERATIONS, VAULT_CEK_JWE_KEY, VAULT_DID_JWE_KEY,
    VAULT_STATUS_KEY,
};
use std::fmt::Debug;
use std::sync::Arc;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD as base64url};
use bip39::{Language, Mnemonic};
use chrono::{DateTime, SecondsFormat, Utc};
use did_dht::next_sequence;
use serde::{Deserialize, Serialize};
use ssi_dids_core::Document;
use ssi_jwk::JWK;
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
    did_network: Arc<dyn AgentDidNetwork>,
    signer: Option<Arc<dyn AgentDidSigner>>,
    clock: AgentClock,
    work_factor: u32,
    state: Mutex<VaultState>,
}

impl Debug for IdentityVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityVault")
            .field("work_factor", &self.work_factor)
            .field("has_signer", &self.signer.is_some())
            .finish_non_exhaustive()
    }
}

impl IdentityVault {
    /// Build a vault over the given store and DID provider using the default
    /// work factor and the native `did:dht` gateway.
    pub fn new(store: Arc<dyn SecretStore>, did_provider: Arc<dyn DidProvider>) -> Self {
        Self::with_work_factor(store, did_provider, DEFAULT_PBES2_ITERATIONS)
    }

    /// Build a vault with an explicit PBES2 work factor.
    pub fn with_work_factor(
        store: Arc<dyn SecretStore>,
        did_provider: Arc<dyn DidProvider>,
        work_factor: u32,
    ) -> Self {
        Self::with_did_network(
            store,
            did_provider,
            work_factor,
            Arc::new(DidDhtNetwork::native()),
        )
    }

    /// Build a vault over explicit DID resolution and publication seams.
    pub fn with_did_network(
        store: Arc<dyn SecretStore>,
        did_provider: Arc<dyn DidProvider>,
        work_factor: u32,
        did_network: Arc<dyn AgentDidNetwork>,
    ) -> Self {
        Self {
            store,
            did_provider,
            did_network,
            signer: None,
            clock: system_clock(),
            work_factor,
            state: Mutex::new(VaultState::default()),
        }
    }

    /// Sign publications through a host-supplied identity-key signer.
    pub fn with_signer(mut self, signer: Arc<dyn AgentDidSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Read time through a host-supplied clock.
    pub fn with_clock(mut self, clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
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
        let is_recovery = recovery_phrase.is_some();
        let dwn_endpoints = if dwn_endpoints.is_empty() {
            Vec::new()
        } else {
            normalize_dwn_endpoints(&dwn_endpoints).ok_or_else(|| {
                AgentIdentityError::did(
                    "DWN endpoint URL must use HTTP(S) without a query or fragment.",
                )
            })?
        };
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
        let AgentDerivedKeys {
            identity_private_jwk,
            signing_private_jwk,
            encryption_private_jwk,
            vault_content_encryption_key,
            vault_unlock_salt,
        } = derived;
        let identity_private_jwk = identity_private_jwk.clone();
        let vault_content_encryption_key = Zeroizing::new(vault_content_encryption_key);
        let cek = Zeroizing::new(fixed_cek(&vault_content_encryption_key)?);
        let salt = vault_unlock_salt;
        let created = self
            .did_provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: identity_private_jwk.clone(),
                signing_private_jwk,
                encryption_private_jwk,
                dwn_endpoints: dwn_endpoints.clone(),
            })
            .await?;
        validate_agent_did_key_requirements(&created)?;

        // Publication and reconciliation complete before the first write, so a
        // failure leaves a fresh vault uninitialized.
        let portable_did = if is_recovery {
            self.reconcile_recovered_did(
                &created,
                replacement_endpoints(&dwn_endpoints),
                true,
                false,
                &identity_private_jwk,
            )
            .await?
        } else {
            self.publish_document(
                &created,
                created.document.clone(),
                created.document.clone(),
                None,
                &[],
                &identity_private_jwk,
            )
            .await?
        };

        let cek_entry = wrap_cek_blocking(
            Zeroizing::new(password.as_bytes().to_vec()),
            *cek,
            salt,
            self.work_factor,
        )
        .await?;
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

        state.cek = Some(cek);
        Ok(VaultInitialization {
            recovery_phrase,
            portable_did,
        })
    }

    /// Unlock with the password, replacing any in-memory CEK. Never writes.
    pub async fn unlock(&self, password: &str) -> AgentIdentityResult<()> {
        let mut state = self.state.lock().await;
        state.cek = None;
        let (status, _) = self.read_status_locking_on_error(&mut state).await?;
        if !status.initialized {
            return Err(uninitialized());
        }
        let cek_entry = self.read_secret_string(VAULT_CEK_JWE_KEY).await?;
        let (cek, _) =
            match unwrap_cek_blocking(cek_entry, Zeroizing::new(password.as_bytes().to_vec()))
                .await?
            {
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
        state.cek = None;
        let (status, _) = self.read_status_locking_on_error(&mut state).await?;
        if !status.initialized {
            return Err(uninitialized());
        }
        Ok(())
    }

    /// The stored agent DID, decrypted under the in-memory CEK.
    pub async fn get_did(&self) -> AgentIdentityResult<PortableDid> {
        let state = self.state.lock().await;
        let cek = state.cek.as_ref().ok_or_else(locked)?;
        let did_entry = self.read_secret_string(VAULT_DID_JWE_KEY).await?;
        let did_bytes =
            decrypt_did(&did_entry, cek).map_err(|_| corrupt("stored vault DID is invalid"))?;
        let did_bytes = Zeroizing::new(did_bytes);
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
        let (cek, header) =
            match unwrap_cek_blocking(cek_entry, Zeroizing::new(old.as_bytes().to_vec())).await? {
                Ok(opened) => opened,
                Err(CekDecodeError::Authentication) => return Err(invalid_password()),
                Err(CekDecodeError::Corrupt) => return Err(corrupt("stored vault key is invalid")),
            };
        let cek = Zeroizing::new(cek);
        let new_cek_entry = wrap_cek_blocking(
            Zeroizing::new(new.as_bytes().to_vec()),
            *cek,
            header.p2s,
            header.p2c,
        )
        .await?;

        self.store
            .apply(vec![SecretWrite::put(
                VAULT_CEK_JWE_KEY,
                new_cek_entry.into_bytes(),
            )])
            .await?;
        state.cek = Some(cek);
        Ok(())
    }

    /// Reset the password from the recovery phrase, requiring the stored DID
    /// to match the phrase.
    ///
    /// Supplying `dwn_endpoints` opts into reconciliation against the
    /// authoritative document. Without them, and without the internal defer
    /// flag, only the password-wrapped key is replaced and no network access
    /// happens.
    pub async fn reset_password_with_recovery_phrase(
        &self,
        recovery_phrase: &str,
        password: &str,
        dwn_endpoints: Option<Vec<String>>,
    ) -> AgentIdentityResult<()> {
        self.reset_password_inner(recovery_phrase, password, dwn_endpoints, false)
            .await
    }

    /// Reset with DWN endpoint replacement deferred to the caller.
    ///
    /// The flag stays crate-internal; orchestration decides when to defer.
    #[allow(dead_code)]
    pub(crate) async fn reset_password_with_recovery_phrase_deferred(
        &self,
        recovery_phrase: &str,
        password: &str,
        dwn_endpoints: Option<Vec<String>>,
    ) -> AgentIdentityResult<()> {
        self.reset_password_inner(recovery_phrase, password, dwn_endpoints, true)
            .await
    }

    async fn reset_password_inner(
        &self,
        recovery_phrase: &str,
        password: &str,
        dwn_endpoints: Option<Vec<String>>,
        defer_replacement: bool,
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
        let AgentDerivedKeys {
            identity_private_jwk,
            signing_private_jwk,
            encryption_private_jwk,
            vault_content_encryption_key,
            vault_unlock_salt,
        } = derived;
        let identity_private_jwk = identity_private_jwk.clone();
        let vault_content_encryption_key = Zeroizing::new(vault_content_encryption_key);
        let derived_cek = Zeroizing::new(fixed_cek(&vault_content_encryption_key)?);
        let salt = vault_unlock_salt;

        let stored_did = self
            .store
            .get(VAULT_DID_JWE_KEY)
            .await?
            .ok_or_else(recovery_phrase_mismatch)?;
        let did_entry = String::from_utf8(stored_did).map_err(|_| recovery_phrase_mismatch())?;
        let did_bytes =
            decrypt_did(&did_entry, &derived_cek).map_err(|_| recovery_phrase_mismatch())?;
        let did_bytes = Zeroizing::new(did_bytes);
        let stored_did: PortableDid =
            serde_json::from_slice(&did_bytes).map_err(|_| recovery_phrase_mismatch())?;
        let derived_did = self
            .did_provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: identity_private_jwk.clone(),
                signing_private_jwk,
                encryption_private_jwk,
                dwn_endpoints: Vec::new(),
            })
            .await
            .map_err(|_| recovery_phrase_mismatch())?;
        if stored_did.uri != derived_did.uri {
            return Err(recovery_phrase_mismatch());
        }

        let reconcile = dwn_endpoints.is_some() || defer_replacement;
        let stored_did = if reconcile {
            self.reconcile_recovered_did(
                &stored_did,
                dwn_endpoints,
                defer_replacement,
                true,
                &identity_private_jwk,
            )
            .await?
        } else {
            stored_did
        };

        let cek_entry = wrap_cek_blocking(
            Zeroizing::new(password.as_bytes().to_vec()),
            *derived_cek,
            salt,
            self.work_factor,
        )
        .await?;
        let mut writes = vec![SecretWrite::put(VAULT_CEK_JWE_KEY, cek_entry.into_bytes())];
        if reconcile {
            let did_json = serde_json::to_vec(&stored_did)
                .map_err(|err| AgentIdentityError::vault(format!("invalid portable DID: {err}")))?;
            let did_entry = encrypt_did(&did_json, &derived_cek)?;
            writes.push(SecretWrite::put(VAULT_DID_JWE_KEY, did_entry.into_bytes()));
        }
        self.store.apply(writes).await?;
        state.cek = Some(derived_cek);
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

        let date_created = self.now_iso_millis();
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
        let recovered_cek = match unwrap_cek_blocking(
            cek_entry.clone(),
            Zeroizing::new(password.as_bytes().to_vec()),
        )
        .await?
        {
            Ok((cek, _)) => cek,
            Err(CekDecodeError::Authentication) => return Err(invalid_password()),
            Err(CekDecodeError::Corrupt) => return Err(invalid_backup()),
        };
        let recovered_cek = Zeroizing::new(recovered_cek);
        decrypt_did(&did_entry, &recovered_cek).map_err(|_| invalid_backup())?;

        let status = VaultStatus {
            initialized: true,
            last_backup: backup_last_backup.or(current.last_backup),
            last_restore: Some(self.now_iso_millis()),
        };
        self.store
            .apply(vec![
                SecretWrite::put(VAULT_CEK_JWE_KEY, cek_entry.into_bytes()),
                SecretWrite::put(VAULT_DID_JWE_KEY, did_entry.into_bytes()),
                SecretWrite::put(VAULT_STATUS_KEY, status.encode()?),
            ])
            .await?;
        state.cek = Some(recovered_cek);
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

    async fn reconcile_recovered_did(
        &self,
        portable_did: &PortableDid,
        replacement_endpoints: Option<Vec<String>>,
        defer_replacement: bool,
        use_stored_on_not_found: bool,
        identity_private_jwk: &JWK,
    ) -> AgentIdentityResult<PortableDid> {
        let resolved = match self.did_network.resolve(&portable_did.uri).await? {
            DidResolution::Found(resolved) => *resolved,
            DidResolution::NotFound => {
                return self
                    .reconcile_not_found(
                        portable_did,
                        replacement_endpoints,
                        defer_replacement,
                        use_stored_on_not_found,
                        identity_private_jwk,
                    )
                    .await
            }
        };

        match dwn_endpoint_status(&resolved.document, &portable_did.uri) {
            DwnEndpointStatus::Ready(_) => {
                let local_document =
                    copy_resolved_dwn_service(&portable_did.document, &resolved.document);
                let Some(replacement) = replacement_endpoints else {
                    return Ok(PortableDid {
                        document: local_document,
                        metadata: resolved.metadata(),
                        ..portable_did.clone()
                    });
                };
                if defer_replacement {
                    return Ok(PortableDid {
                        document: local_document,
                        metadata: resolved.metadata(),
                        ..portable_did.clone()
                    });
                }
                let public_document =
                    replace_dwn_service_endpoint_urls(&resolved.document, &replacement)?;
                let local_document =
                    replace_dwn_service_endpoint_urls(&local_document, &replacement)?;
                self.publish_document(
                    portable_did,
                    public_document,
                    local_document,
                    Some(resolved.sequence),
                    resolved.types.as_deref().unwrap_or(&[]),
                    identity_private_jwk,
                )
                .await
            }
            status => {
                let Some(replacement) = replacement_endpoints else {
                    return Err(AgentIdentityError::did(status.message().to_string()));
                };
                let public_document =
                    replace_dwn_service_endpoint_urls(&resolved.document, &replacement)?;
                let local_document =
                    replace_dwn_service_endpoint_urls(&portable_did.document, &replacement)?;
                self.publish_document(
                    portable_did,
                    public_document,
                    local_document,
                    Some(resolved.sequence),
                    resolved.types.as_deref().unwrap_or(&[]),
                    identity_private_jwk,
                )
                .await
            }
        }
    }

    async fn reconcile_not_found(
        &self,
        portable_did: &PortableDid,
        replacement_endpoints: Option<Vec<String>>,
        defer_replacement: bool,
        use_stored_on_not_found: bool,
        identity_private_jwk: &JWK,
    ) -> AgentIdentityResult<PortableDid> {
        if use_stored_on_not_found && (replacement_endpoints.is_none() || defer_replacement) {
            let status = dwn_endpoint_status(&portable_did.document, &portable_did.uri);
            if matches!(status, DwnEndpointStatus::Ready(_)) {
                return self
                    .publish_document(
                        portable_did,
                        portable_did.document.clone(),
                        portable_did.document.clone(),
                        None,
                        &[],
                        identity_private_jwk,
                    )
                    .await;
            }
            if replacement_endpoints.is_none() {
                return Err(AgentIdentityError::did(status.message().to_string()));
            }
        }

        let Some(replacement) = replacement_endpoints else {
            return Err(AgentIdentityError::did(format!(
                "Recovered DID '{}' was not found. Provide DWN endpoints explicitly to bootstrap recovery.",
                portable_did.uri
            )));
        };
        let document = replace_dwn_service_endpoint_urls(&portable_did.document, &replacement)?;
        self.publish_document(
            portable_did,
            document.clone(),
            document,
            None,
            &[],
            identity_private_jwk,
        )
        .await
    }

    async fn publish_document(
        &self,
        portable_did: &PortableDid,
        public_document: Document,
        local_document: Document,
        previous: Option<u64>,
        types: &[u64],
        identity_private_jwk: &JWK,
    ) -> AgentIdentityResult<PortableDid> {
        let sequence = next_sequence(clock_system_time(&self.clock), previous)
            .map_err(|error| AgentIdentityError::did(error.to_string()))?;
        let signer = self.identity_signer(identity_private_jwk)?;
        let published = self
            .did_network
            .publish(&public_document, types, sequence, signer.as_ref())
            .await?;
        Ok(PortableDid {
            document: local_document,
            metadata: published_metadata(published),
            ..portable_did.clone()
        })
    }

    fn identity_signer(
        &self,
        identity_private_jwk: &JWK,
    ) -> AgentIdentityResult<Arc<dyn AgentDidSigner>> {
        match &self.signer {
            Some(signer) => Ok(signer.clone()),
            None => Ok(Arc::new(DerivedIdentitySigner::from_jwk(
                identity_private_jwk,
            )?)),
        }
    }

    fn now_iso_millis(&self) -> String {
        (self.clock)().to_rfc3339_opts(SecondsFormat::Millis, true)
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
    password: Zeroizing<Vec<u8>>,
    cek: [u8; 32],
    salt: Vec<u8>,
    p2c: u32,
) -> AgentIdentityResult<String> {
    tokio::task::spawn_blocking(move || {
        let cek = Zeroizing::new(cek);
        wrap_cek(&password, &cek, &salt, p2c)
    })
    .await
    .map_err(join_error)?
}

/// Unwrap the CEK off the async executor, preserving the codec's failure class.
async fn unwrap_cek_blocking(
    jwe: String,
    password: Zeroizing<Vec<u8>>,
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

fn replacement_endpoints(dwn_endpoints: &[String]) -> Option<Vec<String>> {
    if dwn_endpoints.is_empty() {
        None
    } else {
        Some(dwn_endpoints.to_vec())
    }
}

fn published_metadata(sequence: u64) -> super::DidMetadata {
    super::DidMetadata {
        published: Some(true),
        extra: std::collections::BTreeMap::from([(
            "versionId".to_string(),
            serde_json::json!(sequence.to_string()),
        )]),
    }
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

#[cfg(test)]
mod deferred_reconcile_tests {
    use super::*;
    use crate::agent::test_support::ready_document;
    use crate::agent::{
        derive_agent_keys, encrypt_did, AgentIdentityFuture, DidDhtProvider, DidResolution,
        MemorySecretStore, ResolvedAgentDid,
    };
    use ssi_dids_core::Document;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use chrono::{TimeZone, Utc};

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const PASSWORD: &str = "vault-password";
    const PASSWORD_2: &str = "vault-password-2";

    struct RecordingNetwork {
        resolution: Mutex<DidResolution>,
        publishes: AtomicUsize,
    }

    impl RecordingNetwork {
        fn not_found() -> Self {
            Self {
                resolution: Mutex::new(DidResolution::NotFound),
                publishes: AtomicUsize::new(0),
            }
        }

        fn set(&self, resolution: DidResolution) {
            *self.resolution.lock().unwrap() = resolution;
        }

        fn publishes(&self) -> usize {
            self.publishes.load(Ordering::SeqCst)
        }
    }

    impl AgentDidNetwork for RecordingNetwork {
        fn resolve<'a>(&'a self, _did_uri: &'a str) -> AgentIdentityFuture<'a, DidResolution> {
            let resolution = self.resolution.lock().unwrap().clone();
            Box::pin(async move { Ok(resolution) })
        }

        fn publish<'a>(
            &'a self,
            _document: &'a Document,
            _types: &'a [u64],
            sequence: u64,
            _signer: &'a dyn AgentDidSigner,
        ) -> AgentIdentityFuture<'a, u64> {
            self.publishes.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(sequence) })
        }
    }

    fn vault(network: Arc<RecordingNetwork>) -> IdentityVault {
        IdentityVault::with_did_network(
            Arc::new(MemorySecretStore::default()),
            Arc::new(DidDhtProvider::default()),
            1,
            network,
        )
        .with_clock(|| {
            Utc.timestamp_opt(1_700_000_000, 0)
                .single()
                .expect("valid timestamp")
        })
    }

    async fn seeded(network: Arc<RecordingNetwork>) -> IdentityVault {
        let vault = vault(network);
        vault
            .initialize(
                PASSWORD,
                Some(PHRASE),
                vec!["https://stored.example".to_string()],
            )
            .await
            .unwrap();
        vault
    }

    // Covers: DID-DHT-006
    #[tokio::test]
    async fn deferred_ready_reset_stores_the_resolved_service_without_publishing() {
        let network = Arc::new(RecordingNetwork::not_found());
        let vault = seeded(network.clone()).await;
        network.set(DidResolution::Found(Box::new(ResolvedAgentDid {
            document: ready_document(
                "did:dht:qftx7z968xcpfy1a1diu75pg5meap3gdtg6ezagaw849wdh6oubo",
            ),
            sequence: 9,
            types: None,
        })));

        vault
            .reset_password_with_recovery_phrase_deferred(
                PHRASE,
                PASSWORD_2,
                Some(vec!["https://caller.example".to_string()]),
            )
            .await
            .unwrap();

        assert_eq!(network.publishes(), 1);
        let stored = vault.get_did().await.unwrap();
        assert_eq!(
            serde_json::to_value(&stored.document).unwrap()["service"][0]["serviceEndpoint"],
            serde_json::json!(["https://dwn.example"])
        );
    }

    // Covers: DID-DHT-006
    #[tokio::test]
    async fn deferred_not_found_reset_republishes_the_stored_shape() {
        let network = Arc::new(RecordingNetwork::not_found());
        let vault = seeded(network.clone()).await;

        vault
            .reset_password_with_recovery_phrase_deferred(PHRASE, PASSWORD_2, None)
            .await
            .unwrap();

        assert_eq!(network.publishes(), 2);
        let stored = vault.get_did().await.unwrap();
        assert_eq!(
            serde_json::to_value(&stored.document).unwrap()["service"][0]["serviceEndpoint"],
            serde_json::json!(["https://stored.example"])
        );
    }

    // Covers: DID-DHT-006
    #[tokio::test]
    async fn deferred_not_found_reset_with_unusable_stored_publishes_the_replacement() {
        let network = Arc::new(RecordingNetwork::not_found());
        let vault = seeded(network.clone()).await;

        let derived = derive_agent_keys(PHRASE).unwrap();
        let cek: [u8; 32] = derived
            .vault_content_encryption_key
            .as_slice()
            .try_into()
            .unwrap();
        let mut stored = vault.get_did().await.unwrap();
        stored.document.service.clear();
        let entry = encrypt_did(&serde_json::to_vec(&stored).unwrap(), &cek).unwrap();
        vault
            .store
            .put(VAULT_DID_JWE_KEY, entry.into_bytes())
            .await
            .unwrap();

        vault
            .reset_password_with_recovery_phrase_deferred(
                PHRASE,
                PASSWORD_2,
                Some(vec!["https://replacement.example".to_string()]),
            )
            .await
            .unwrap();

        assert_eq!(network.publishes(), 2);
        let stored = vault.get_did().await.unwrap();
        assert_eq!(
            serde_json::to_value(&stored.document).unwrap()["service"][0]["serviceEndpoint"],
            serde_json::json!(["https://replacement.example"])
        );
    }
}
