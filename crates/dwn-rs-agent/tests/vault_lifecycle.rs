//! Vault lifecycle semantics: state machine, atomic persistence, backup
//! interop, and key hygiene.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD as base64url};
use dwn_rs_agent::agent::{
    derive_agent_keys, encrypt_data, encrypt_did, AgentDidCreateRequest, AgentIdentityError,
    AgentIdentityFuture, AgentIdentityResult, DidDhtProvider, DidProvider, IdentityVault,
    IdentityVaultBackup, MemorySecretStore, PortableDid, SecretStore, SecretWrite, VaultStatus,
    DEFAULT_PBES2_ITERATIONS, VAULT_CEK_JWE_KEY, VAULT_DID_JWE_KEY, VAULT_STATUS_KEY,
};
use serde_json::Value;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PHRASE_B: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PASSWORD: &str = "vault-password";
const PASSWORD_2: &str = "vault-password-2";
const DID_URI: &str = "did:dht:qftx7z968xcpfy1a1diu75pg5meap3gdtg6ezagaw849wdh6oubo";

const LEGACY_PORTABLE_DID_KEY: &str = "agent:vault:portableDid";
const LEGACY_CEK_KEY: &str = "agent:vault:contentEncryptionKey";
const LEGACY_SALT_KEY: &str = "agent:vault:unlockSalt";

fn memory_store() -> Arc<MemorySecretStore> {
    Arc::new(MemorySecretStore::default())
}

fn vault(store: Arc<dyn SecretStore>) -> Arc<IdentityVault> {
    Arc::new(IdentityVault::new(
        store,
        Arc::new(DidDhtProvider::default()),
    ))
}

fn memory_vault() -> (Arc<IdentityVault>, Arc<MemorySecretStore>) {
    let store = memory_store();
    let vault = vault(store.clone());
    (vault, store)
}

fn code<T: std::fmt::Debug>(result: AgentIdentityResult<T>) -> String {
    result.unwrap_err().code().to_string()
}

fn header(jwe: &str) -> Value {
    let protected = jwe.split('.').next().unwrap();
    serde_json::from_slice(&base64url.decode(protected).unwrap()).unwrap()
}

async fn snapshot<S: SecretStore + ?Sized>(store: &S) -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    for key in [
        VAULT_CEK_JWE_KEY,
        VAULT_DID_JWE_KEY,
        VAULT_STATUS_KEY,
        LEGACY_PORTABLE_DID_KEY,
        LEGACY_CEK_KEY,
        LEGACY_SALT_KEY,
    ] {
        if let Some(value) = store.get(key).await.unwrap() {
            map.insert(key.to_string(), value);
        }
    }
    map
}

async fn read_string<S: SecretStore + ?Sized>(store: &S, key: &str) -> String {
    String::from_utf8(store.get(key).await.unwrap().unwrap()).unwrap()
}

async fn stored_status<S: SecretStore + ?Sized>(store: &S) -> VaultStatus {
    let bytes = store.get(VAULT_STATUS_KEY).await.unwrap();
    VaultStatus::parse(bytes.as_deref()).unwrap()
}

fn assert_iso_millis(value: &str) {
    let bytes = value.as_bytes();
    assert_eq!(bytes.len(), 24, "{value}");
    for (index, byte) in bytes.iter().enumerate() {
        match index {
            4 | 7 => assert_eq!(*byte, b'-', "{value}"),
            10 => assert_eq!(*byte, b'T', "{value}"),
            13 | 16 => assert_eq!(*byte, b':', "{value}"),
            19 => assert_eq!(*byte, b'.', "{value}"),
            23 => assert_eq!(*byte, b'Z', "{value}"),
            _ => assert!(byte.is_ascii_digit(), "{value}"),
        }
    }
}

fn with_p2c(jwe: &str, p2c: u64) -> String {
    let mut parts: Vec<String> = jwe.split('.').map(str::to_string).collect();
    let mut header: Value = serde_json::from_slice(&base64url.decode(&parts[0]).unwrap()).unwrap();
    header["p2c"] = Value::Number(p2c.into());
    parts[0] = base64url.encode(serde_json::to_vec(&header).unwrap());
    parts.join(".")
}

/// A present status entry missing `lastBackup`; only a wholly absent entry is
/// a valid uninitialized vault.
const CORRUPT_STATUS: &[u8] = br#"{"initialized":true,"lastRestore":null}"#;

async fn initialized_vault_with_corrupt_status() -> (Arc<IdentityVault>, Arc<MemorySecretStore>) {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    assert!(!vault.is_locked().await);
    store
        .put(VAULT_STATUS_KEY, CORRUPT_STATUS.to_vec())
        .await
        .unwrap();
    (vault, store)
}

#[derive(Clone, Default)]
struct FaultyStore {
    inner: MemorySecretStore,
    fail_apply: Arc<AtomicBool>,
}

impl SecretStore for FaultyStore {
    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>> {
        self.inner.get(key)
    }
    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> AgentIdentityFuture<'a, ()> {
        self.inner.put(key, value)
    }
    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool> {
        self.inner.delete(key)
    }
    fn apply<'a>(&'a self, writes: Vec<SecretWrite>) -> AgentIdentityFuture<'a, ()> {
        if self.fail_apply.load(Ordering::SeqCst) {
            return Box::pin(async move {
                Err(AgentIdentityError::new(
                    "AgentVaultError",
                    "injected commit failure",
                ))
            });
        }
        self.inner.apply(writes)
    }
}

#[derive(Clone, Default)]
struct FailingDidProvider;

impl DidProvider for FailingDidProvider {
    fn create_did<'a>(
        &'a self,
        _request: AgentDidCreateRequest,
    ) -> AgentIdentityFuture<'a, PortableDid> {
        Box::pin(async move {
            Err(AgentIdentityError::new(
                "AgentIdentityDidError",
                "injected DID failure",
            ))
        })
    }
    fn import_did<'a>(
        &'a self,
        _portable_did: PortableDid,
    ) -> AgentIdentityFuture<'a, PortableDid> {
        Box::pin(async move {
            Err(AgentIdentityError::new(
                "AgentIdentityDidError",
                "injected DID failure",
            ))
        })
    }
    fn export_did<'a>(&'a self, _did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>> {
        Box::pin(async move { Ok(None) })
    }
}

#[tokio::test]
async fn fresh_state_is_locked_uninitialized_and_writes_nothing() {
    let (vault, store) = memory_vault();
    assert_eq!(
        vault.status().await.unwrap(),
        VaultStatus {
            initialized: false,
            last_backup: None,
            last_restore: None
        }
    );
    assert!(vault.is_locked().await);
    assert!(snapshot(&*store).await.is_empty());
}

#[tokio::test]
async fn uninitialized_operations_keep_their_codes() {
    let (vault, _) = memory_vault();
    assert_eq!(
        code(vault.unlock(PASSWORD).await),
        "AgentVaultUninitialized"
    );
    assert_eq!(code(vault.lock().await), "AgentVaultUninitialized");
    assert_eq!(
        code(vault.change_password(PASSWORD, PASSWORD_2).await),
        "AgentVaultUninitialized"
    );
    assert_eq!(
        code(
            vault
                .reset_password_with_recovery_phrase(PHRASE, PASSWORD)
                .await
        ),
        "AgentVaultUninitialized"
    );
    assert_eq!(code(vault.backup().await), "AgentVaultUninitialized");
    assert_eq!(code(vault.get_did().await), "AgentVaultLocked");
    assert_eq!(code(vault.encrypt_data(b"x").await), "AgentVaultLocked");
    assert_eq!(
        code(vault.decrypt_data("a.b.c.d.e").await),
        "AgentVaultLocked"
    );
}

#[tokio::test]
async fn initialize_persists_wrapped_values_and_unlocks() {
    let (vault, store) = memory_vault();
    let init = vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://dwn.example".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(init.recovery_phrase, PHRASE);
    assert_eq!(init.portable_did.uri, DID_URI);
    assert!(!vault.is_locked().await);
    assert_eq!(vault.get_did().await.unwrap().uri, DID_URI);

    let salt = derive_agent_keys(PHRASE).unwrap().vault_unlock_salt;
    let cek_header = header(&read_string(&*store, VAULT_CEK_JWE_KEY).await);
    assert_eq!(cek_header["alg"], "PBES2-HS512+A256KW");
    assert_eq!(cek_header["enc"], "A256GCM");
    assert_eq!(cek_header["cty"], "text/plain");
    assert_eq!(cek_header["p2c"], DEFAULT_PBES2_ITERATIONS);
    assert_eq!(cek_header["p2s"], base64url.encode(&salt));

    let did_header = header(&read_string(&*store, VAULT_DID_JWE_KEY).await);
    assert_eq!(did_header["alg"], "dir");
    assert_eq!(did_header["enc"], "A256GCM");
    assert_eq!(did_header["cty"], "json");

    assert_eq!(
        stored_status(&*store).await,
        VaultStatus {
            initialized: true,
            last_backup: None,
            last_restore: None
        }
    );
}

#[tokio::test]
async fn initialize_generates_twelve_word_phrase() {
    let (vault, _) = memory_vault();
    let init = vault.initialize(PASSWORD, None, vec![]).await.unwrap();
    assert_eq!(init.recovery_phrase.split(' ').count(), 12);
    assert!(derive_agent_keys(&init.recovery_phrase).is_ok());

    let derived = derive_agent_keys(&init.recovery_phrase).unwrap();
    let rederived = DidDhtProvider::default()
        .create_did(AgentDidCreateRequest {
            identity_private_jwk: derived.identity_private_jwk,
            signing_private_jwk: derived.signing_private_jwk,
            encryption_private_jwk: derived.encryption_private_jwk,
            dwn_endpoints: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(rederived.uri, init.portable_did.uri);
}

#[tokio::test]
async fn initialize_error_precedence_is_already_initialized_first() {
    let (vault, _) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let error = vault
        .initialize("   ", Some("not a phrase"), vec![])
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentVaultAlreadyInitialized");
}

#[tokio::test]
async fn blank_password_is_rejected_without_writes() {
    let (vault, store) = memory_vault();
    for password in ["", "   ", "\t\n "] {
        let error = vault
            .initialize(password, Some(PHRASE), vec![])
            .await
            .unwrap_err();
        assert_eq!(error.code(), "AgentVaultBlankPassword");
        assert!(snapshot(&*store).await.is_empty());
    }
}

#[tokio::test]
async fn invalid_phrase_is_rejected_without_writes() {
    let (vault, store) = memory_vault();
    let error = vault
        .initialize(PASSWORD, Some("not a phrase"), vec![])
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentIdentityInvalidMnemonic");
    assert!(snapshot(&*store).await.is_empty());
}

#[tokio::test]
async fn initialize_twice_keeps_store_byte_identical() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before = snapshot(&*store).await;
    let error = vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentVaultAlreadyInitialized");
    assert_eq!(snapshot(&*store).await, before);
}

#[tokio::test]
async fn initialize_did_failure_leaves_store_empty_and_locked() {
    let store = memory_store();
    let vault = Arc::new(IdentityVault::new(
        store.clone(),
        Arc::new(FailingDidProvider),
    ));
    let error = vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentIdentityDidError");
    assert!(vault.is_locked().await);
    assert!(snapshot(&*store).await.is_empty());
}

#[tokio::test]
async fn unlock_wrong_password_locks_and_keeps_store() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before = snapshot(&*store).await;
    assert_eq!(
        vault.unlock("wrong").await.unwrap_err().code(),
        "AgentVaultInvalidPassword"
    );
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&*store).await, before);

    vault.unlock(PASSWORD).await.unwrap();
    assert!(!vault.is_locked().await);
    assert_eq!(
        vault.unlock("wrong").await.unwrap_err().code(),
        "AgentVaultInvalidPassword"
    );
    assert!(vault.is_locked().await);
}

#[tokio::test]
async fn unlock_structurally_invalid_cek_is_corrupt() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    vault.lock().await.unwrap();

    store.delete(VAULT_CEK_JWE_KEY).await.unwrap();
    assert_eq!(
        vault.unlock(PASSWORD).await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
    assert!(vault.is_locked().await);

    store
        .put(VAULT_CEK_JWE_KEY, b"not-a-jwe".to_vec())
        .await
        .unwrap();
    assert_eq!(
        vault.unlock(PASSWORD).await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
    assert!(vault.is_locked().await);

    let cek: [u8; 32] = derive_agent_keys(PHRASE)
        .unwrap()
        .vault_content_encryption_key
        .as_slice()
        .try_into()
        .unwrap();
    let dir_jwe = encrypt_data(b"x", &cek).unwrap();
    store
        .put(VAULT_CEK_JWE_KEY, dir_jwe.into_bytes())
        .await
        .unwrap();
    assert_eq!(
        vault.unlock(PASSWORD).await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
}

#[tokio::test]
async fn corrupt_status_blocks_status_reading_operations() {
    let (vault, store) = memory_vault();
    // A present entry missing `lastBackup` is invalid: only a wholly absent
    // status entry defaults to uninitialized.
    store
        .put(
            VAULT_STATUS_KEY,
            br#"{"initialized":true,"lastRestore":null}"#.to_vec(),
        )
        .await
        .unwrap();

    assert_eq!(
        vault.status().await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
    assert_eq!(
        vault
            .initialize(PASSWORD, Some(PHRASE), vec![])
            .await
            .unwrap_err()
            .code(),
        "AgentVaultCorrupt"
    );
    assert_eq!(
        vault.unlock(PASSWORD).await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
    assert_eq!(vault.lock().await.unwrap_err().code(), "AgentVaultCorrupt");
    assert_eq!(
        vault
            .change_password(PASSWORD, PASSWORD_2)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultCorrupt"
    );
    assert_eq!(
        vault.backup().await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
}

#[tokio::test]
async fn lock_gates_key_operations_and_is_idempotent() {
    let (vault, _) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    vault.lock().await.unwrap();
    assert_eq!(
        vault.get_did().await.unwrap_err().code(),
        "AgentVaultLocked"
    );
    assert_eq!(
        vault.encrypt_data(b"x").await.unwrap_err().code(),
        "AgentVaultLocked"
    );
    assert_eq!(
        vault.decrypt_data("a.b.c.d.e").await.unwrap_err().code(),
        "AgentVaultLocked"
    );
    assert_eq!(vault.backup().await.unwrap_err().code(), "AgentVaultLocked");
    vault.lock().await.unwrap();
    assert!(vault.is_locked().await);
}

#[tokio::test]
async fn get_did_returns_isolated_copy() {
    let (vault, _) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let first = vault.get_did().await.unwrap();
    let mut mutated = first.clone();
    mutated.uri = "did:example:mutated".to_string();
    assert_eq!(vault.get_did().await.unwrap(), first);
}

#[tokio::test]
async fn get_did_corrupt_did_stays_unlocked() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    store
        .put(VAULT_DID_JWE_KEY, b"garbage".to_vec())
        .await
        .unwrap();
    assert_eq!(
        vault.get_did().await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
    assert!(!vault.is_locked().await);
    let jwe = vault.encrypt_data(b"hello").await.unwrap();
    assert_eq!(vault.decrypt_data(&jwe).await.unwrap(), b"hello");
}

#[tokio::test]
async fn change_password_preserves_salt_factor_and_other_entries() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before_header = header(&read_string(&*store, VAULT_CEK_JWE_KEY).await);
    let before_did = read_string(&*store, VAULT_DID_JWE_KEY).await;
    let before_status = read_string(&*store, VAULT_STATUS_KEY).await;

    vault.change_password(PASSWORD, PASSWORD_2).await.unwrap();
    assert!(!vault.is_locked().await);

    let after_header = header(&read_string(&*store, VAULT_CEK_JWE_KEY).await);
    assert_eq!(after_header["p2s"], before_header["p2s"]);
    assert_eq!(after_header["p2c"], before_header["p2c"]);
    assert_eq!(after_header["cty"], before_header["cty"]);
    assert_eq!(read_string(&*store, VAULT_DID_JWE_KEY).await, before_did);
    assert_eq!(read_string(&*store, VAULT_STATUS_KEY).await, before_status);

    vault.lock().await.unwrap();
    vault.unlock(PASSWORD_2).await.unwrap();
    assert_eq!(
        vault.unlock(PASSWORD).await.unwrap_err().code(),
        "AgentVaultInvalidPassword"
    );
}

#[tokio::test]
async fn change_password_wrong_old_locks_and_keeps_store() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before = snapshot(&*store).await;
    assert_eq!(
        vault
            .change_password("wrong", PASSWORD_2)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultInvalidPassword"
    );
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&*store).await, before);
}

#[tokio::test]
async fn change_password_blank_new_stays_unlocked_and_keeps_store() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before = snapshot(&*store).await;
    for blank in ["", " ", "\t"] {
        assert_eq!(
            vault
                .change_password(PASSWORD, blank)
                .await
                .unwrap_err()
                .code(),
            "AgentVaultBlankPassword"
        );
        assert!(!vault.is_locked().await);
        assert_eq!(snapshot(&*store).await, before);
    }
}

#[tokio::test]
async fn reset_with_matching_phrase_rewraps_cek_and_keeps_entries() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before_did = read_string(&*store, VAULT_DID_JWE_KEY).await;
    let before_status = read_string(&*store, VAULT_STATUS_KEY).await;
    vault.lock().await.unwrap();

    vault
        .reset_password_with_recovery_phrase(PHRASE, PASSWORD_2)
        .await
        .unwrap();
    assert!(!vault.is_locked().await);

    let salt = derive_agent_keys(PHRASE).unwrap().vault_unlock_salt;
    let header = header(&read_string(&*store, VAULT_CEK_JWE_KEY).await);
    assert_eq!(header["p2s"], base64url.encode(&salt));
    assert_eq!(header["p2c"], DEFAULT_PBES2_ITERATIONS);
    assert_eq!(read_string(&*store, VAULT_DID_JWE_KEY).await, before_did);
    assert_eq!(read_string(&*store, VAULT_STATUS_KEY).await, before_status);

    vault.lock().await.unwrap();
    vault.unlock(PASSWORD_2).await.unwrap();
    assert_eq!(
        vault.unlock(PASSWORD).await.unwrap_err().code(),
        "AgentVaultInvalidPassword"
    );
}

#[tokio::test]
async fn reset_with_other_phrase_is_mismatch_and_locks() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before = snapshot(&*store).await;
    let error = vault
        .reset_password_with_recovery_phrase(PHRASE_B, PASSWORD_2)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "HD_IDENTITY_VAULT_RECOVERY_PHRASE_MISMATCH");
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&*store).await, before);
}

#[tokio::test]
async fn backup_encodes_stored_entries_and_updates_status() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let did_entry = read_string(&*store, VAULT_DID_JWE_KEY).await;
    let cek_entry = read_string(&*store, VAULT_CEK_JWE_KEY).await;

    let backup = vault.backup().await.unwrap();
    assert_iso_millis(&backup.date_created);
    assert_eq!(
        backup.size,
        serde_json::Number::from(backup.data.chars().count() as u64)
    );

    let value: Value = serde_json::from_slice(&base64url.decode(&backup.data).unwrap()).unwrap();
    assert_eq!(value["did"], did_entry);
    assert_eq!(value["contentEncryptionKey"], cek_entry);
    assert_eq!(value["status"]["initialized"], true);
    assert_eq!(value["status"]["lastBackup"], Value::Null);

    let status = stored_status(&*store).await;
    assert_eq!(
        status.last_backup.as_deref(),
        Some(backup.date_created.as_str())
    );
}

#[tokio::test]
async fn backup_commit_failure_leaves_status_unchanged() {
    let store = Arc::new(FaultyStore::default());
    let vault = Arc::new(IdentityVault::new(
        store.clone(),
        Arc::new(DidDhtProvider::default()),
    ));
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before = snapshot(&*store).await;

    store.fail_apply.store(true, Ordering::SeqCst);
    assert_eq!(vault.backup().await.unwrap_err().code(), "AgentVaultError");
    assert_eq!(snapshot(&*store).await, before);
}

#[tokio::test]
async fn restore_round_trip_after_password_change() {
    let (vault, _) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let backup = vault.backup().await.unwrap();
    vault.change_password(PASSWORD, PASSWORD_2).await.unwrap();

    vault.restore(&backup, PASSWORD).await.unwrap();
    assert!(!vault.is_locked().await);

    vault.lock().await.unwrap();
    vault.unlock(PASSWORD).await.unwrap();
    assert_eq!(
        vault.unlock(PASSWORD_2).await.unwrap_err().code(),
        "AgentVaultInvalidPassword"
    );

    let status = vault.status().await.unwrap();
    assert!(status.last_restore.is_some());
    assert_eq!(
        status.last_backup.as_deref(),
        Some(backup.date_created.as_str())
    );
}

#[tokio::test]
async fn restore_onto_fresh_vault_succeeds() {
    let (source, _) = memory_vault();
    let init = source
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let backup = source.backup().await.unwrap();

    let (fresh, _) = memory_vault();
    assert!(!fresh.status().await.unwrap().initialized);
    fresh.restore(&backup, PASSWORD).await.unwrap();
    assert!(!fresh.is_locked().await);
    assert!(fresh.status().await.unwrap().initialized);
    assert_eq!(fresh.get_did().await.unwrap().uri, init.portable_did.uri);
}

#[tokio::test]
async fn restore_failure_matrix_on_initialized_and_fresh() {
    let (source, source_store) = memory_vault();
    source
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let backup = source.backup().await.unwrap();
    let valid_data = backup.data.clone();
    let cek_entry = read_string(&*source_store, VAULT_CEK_JWE_KEY).await;
    let cek: [u8; 32] = derive_agent_keys(PHRASE)
        .unwrap()
        .vault_content_encryption_key
        .as_slice()
        .try_into()
        .unwrap();

    // A DID entry that decrypts under the recovered CEK but fails agent-DID
    // validation (no X25519 key agreement or private material).
    let mut invalid_did = source.get_did().await.unwrap();
    invalid_did.private_keys.clear();
    invalid_did
        .document
        .verification_relationships
        .key_agreement
        .clear();
    let invalid_did_entry = encrypt_did(&serde_json::to_vec(&invalid_did).unwrap(), &cek).unwrap();

    let data_with = |did: &str, status: Option<Value>| {
        let mut value = serde_json::json!({
            "did": did,
            "contentEncryptionKey": cek_entry.clone(),
        });
        if let Some(status) = status {
            value["status"] = status;
        }
        base64url.encode(serde_json::to_vec(&value).unwrap())
    };

    let cases: Vec<(Vec<u8>, &str)> = vec![
        // missing `size`
        (
            br#"{"dateCreated":"x","data":"y"}"#.to_vec(),
            "AgentVaultInvalidBackup",
        ),
        // `size` mistyped as a string
        (
            serde_json::to_vec(&serde_json::json!({
                "dateCreated": "x", "size": "5", "data": valid_data,
            }))
            .unwrap(),
            "AgentVaultInvalidBackup",
        ),
        // `data` is not base64url
        (
            serde_json::to_vec(&serde_json::json!({
                "dateCreated": "x", "size": 1, "data": "!!!",
            }))
            .unwrap(),
            "AgentVaultInvalidBackup",
        ),
        // status without `initialized:true`
        (
            serde_json::to_vec(&serde_json::json!({
                "dateCreated": "x",
                "size": 1,
                "data": data_with("x", Some(serde_json::json!({"initialized": false}))),
            }))
            .unwrap(),
            "AgentVaultInvalidBackup",
        ),
        // status member missing entirely
        (
            serde_json::to_vec(&serde_json::json!({
                "dateCreated": "x", "size": 1, "data": data_with("x", None),
            }))
            .unwrap(),
            "AgentVaultInvalidBackup",
        ),
        // DID entry that is not a JWE at all
        (
            serde_json::to_vec(&serde_json::json!({
                "dateCreated": "x",
                "size": 1,
                "data": data_with("garbage", Some(serde_json::json!({"initialized": true}))),
            }))
            .unwrap(),
            "AgentVaultInvalidBackup",
        ),
        // DID entry decrypts but fails agent-DID validation
        (
            serde_json::to_vec(&serde_json::json!({
                "dateCreated": "x",
                "size": 1,
                "data": data_with(&invalid_did_entry, Some(serde_json::json!({"initialized": true}))),
            }))
            .unwrap(),
            "AgentVaultInvalidBackup",
        ),
    ];

    for (backup_json, expected) in &cases {
        let (vault, store) = memory_vault();
        vault
            .initialize(PASSWORD, Some(PHRASE), vec![])
            .await
            .unwrap();
        let before = snapshot(&*store).await;
        assert_eq!(
            vault
                .restore_json(backup_json, PASSWORD)
                .await
                .unwrap_err()
                .code(),
            *expected
        );
        assert!(vault.is_locked().await);
        assert_eq!(snapshot(&*store).await, before);

        let (fresh, store) = memory_vault();
        assert_eq!(
            fresh
                .restore_json(backup_json, PASSWORD)
                .await
                .unwrap_err()
                .code(),
            *expected
        );
        assert!(fresh.is_locked().await);
        assert!(!fresh.status().await.unwrap().initialized);
        assert!(snapshot(&*store).await.is_empty());
    }

    // Wrong password on both an initialized and a fresh store.
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before = snapshot(&*store).await;
    assert_eq!(
        vault.restore(&backup, "wrong").await.unwrap_err().code(),
        "AgentVaultInvalidPassword"
    );
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&*store).await, before);

    let (fresh, store) = memory_vault();
    assert_eq!(
        fresh.restore(&backup, "wrong").await.unwrap_err().code(),
        "AgentVaultInvalidPassword"
    );
    assert!(fresh.is_locked().await);
    assert!(!fresh.status().await.unwrap().initialized);
    assert!(snapshot(&*store).await.is_empty());
}

#[tokio::test]
async fn ts_vault_values_restore_through_the_vault() {
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/interop/vault-jwe.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let cek_entry = fixture["vector"]["contentEncryptionKey"].as_str().unwrap();
    let did_entry = fixture["vector"]["did"].as_str().unwrap();
    let status: Value =
        serde_json::from_str(fixture["vector"]["vaultStatus"].as_str().unwrap()).unwrap();
    let password = fixture["inputs"]["password"].as_str().unwrap();
    let uri = fixture["vector"]["portableDidUri"].as_str().unwrap();

    let data = base64url.encode(
        serde_json::to_vec(&serde_json::json!({
            "did": did_entry,
            "contentEncryptionKey": cek_entry,
            "status": status,
        }))
        .unwrap(),
    );
    let backup = IdentityVaultBackup {
        date_created: "2026-01-01T00:00:00.000Z".to_string(),
        size: serde_json::Number::from(data.chars().count() as u64),
        data,
    };

    let (fresh, _) = memory_vault();
    fresh.restore(&backup, password).await.unwrap();
    assert_eq!(fresh.get_did().await.unwrap().uri, uri);

    // The same TS-produced values overwrite an already-initialized vault.
    let (initialized, _) = memory_vault();
    initialized
        .initialize(PASSWORD_2, None, vec![])
        .await
        .unwrap();
    initialized.restore(&backup, password).await.unwrap();
    assert_eq!(initialized.get_did().await.unwrap().uri, uri);
}

#[tokio::test]
async fn rust_backup_carries_the_ts_backup_shape() {
    let (vault, _) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let backup = vault.backup().await.unwrap();
    let value: Value = serde_json::from_slice(&base64url.decode(&backup.data).unwrap()).unwrap();
    assert!(value.get("did").unwrap().is_string());
    assert!(value.get("contentEncryptionKey").unwrap().is_string());
    assert!(value.get("status").unwrap().is_object());
}

#[tokio::test]
async fn interrupted_initialize_leaves_store_untouched_and_retry_succeeds() {
    let store = Arc::new(FaultyStore::default());
    let vault = Arc::new(IdentityVault::new(
        store.clone(),
        Arc::new(DidDhtProvider::default()),
    ));
    store.fail_apply.store(true, Ordering::SeqCst);
    assert_eq!(
        vault
            .initialize(PASSWORD, Some(PHRASE), vec![])
            .await
            .unwrap_err()
            .code(),
        "AgentVaultError"
    );
    assert!(vault.is_locked().await);
    assert!(snapshot(&*store).await.is_empty());
    assert!(!vault.status().await.unwrap().initialized);

    store.fail_apply.store(false, Ordering::SeqCst);
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    assert!(vault.status().await.unwrap().initialized);
    assert!(!vault.is_locked().await);
}

#[tokio::test]
async fn failures_leave_no_reachable_key_material() {
    let (vault, _) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();

    assert_eq!(
        vault.unlock("bad").await.unwrap_err().code(),
        "AgentVaultInvalidPassword"
    );
    assert_eq!(
        vault.encrypt_data(b"x").await.unwrap_err().code(),
        "AgentVaultLocked"
    );
    assert_eq!(
        vault.get_did().await.unwrap_err().code(),
        "AgentVaultLocked"
    );

    vault.unlock(PASSWORD).await.unwrap();
    let backup = vault.backup().await.unwrap();
    let mut bad = backup.clone();
    bad.data = "!!!".to_string();
    assert_eq!(
        vault.restore(&bad, PASSWORD).await.unwrap_err().code(),
        "AgentVaultInvalidBackup"
    );
    assert!(vault.is_locked().await);

    vault.unlock(PASSWORD).await.unwrap();
    assert_eq!(
        vault
            .reset_password_with_recovery_phrase(PHRASE_B, PASSWORD_2)
            .await
            .unwrap_err()
            .code(),
        "HD_IDENTITY_VAULT_RECOVERY_PHRASE_MISMATCH"
    );
    assert!(vault.is_locked().await);
}

#[tokio::test]
async fn debug_and_errors_do_not_leak_secrets() {
    let (vault, _) = memory_vault();
    let init = vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let derived = derive_agent_keys(PHRASE).unwrap();
    let cek_b64 = base64url.encode(&derived.vault_content_encryption_key);
    let private_jwk = serde_json::to_string(&derived.signing_private_jwk).unwrap();
    let backup = vault.backup().await.unwrap();
    let errors = [
        vault.unlock("wrong").await.unwrap_err(),
        vault.get_did().await.unwrap_err(),
        vault.encrypt_data(b"x").await.unwrap_err(),
    ];

    let mut rendered = vec![
        format!("{vault:?}"),
        format!("{init:?}"),
        format!("{backup:?}"),
    ];
    for error in &errors {
        rendered.push(error.to_string());
        rendered.push(format!("{error:?}"));
    }
    for text in rendered {
        assert!(!text.contains(PHRASE), "{text}");
        assert!(!text.contains(PASSWORD), "{text}");
        assert!(!text.contains(&cek_b64), "{text}");
        assert!(!text.contains(&private_jwk), "{text}");
    }
}

#[tokio::test]
async fn concurrent_operations_stay_consistent() {
    let (vault, _) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();

    let mut handles = Vec::new();
    for index in 0..8 {
        let vault = vault.clone();
        handles.push(tokio::spawn(async move {
            match index % 4 {
                0 => {
                    let _ = vault.unlock(PASSWORD).await;
                }
                1 => {
                    let _ = vault.unlock("wrong").await;
                }
                2 => {
                    let _ = vault.lock().await;
                }
                _ => {
                    let _ = vault.change_password(PASSWORD, PASSWORD_2).await;
                }
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    assert!(vault.status().await.unwrap().initialized);
    if vault.unlock(PASSWORD).await.is_err() {
        vault.unlock(PASSWORD_2).await.unwrap();
    }
}

#[tokio::test]
async fn legacy_plaintext_keys_are_never_read_or_removed() {
    let store = memory_store();
    for (key, value) in [
        (LEGACY_PORTABLE_DID_KEY, b"legacy-did".to_vec()),
        (LEGACY_CEK_KEY, b"legacy-cek".to_vec()),
        (LEGACY_SALT_KEY, b"legacy-salt".to_vec()),
    ] {
        store.put(key, value).await.unwrap();
    }
    let before = snapshot(&*store).await;

    let vault = vault(store.clone());
    assert!(!vault.status().await.unwrap().initialized);
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();

    let after = snapshot(&*store).await;
    for key in [LEGACY_PORTABLE_DID_KEY, LEGACY_CEK_KEY, LEGACY_SALT_KEY] {
        assert_eq!(after.get(key), before.get(key));
    }
}

#[tokio::test]
async fn corrupt_status_locks_key_material() {
    let (vault, _) = initialized_vault_with_corrupt_status().await;
    assert_eq!(
        vault.unlock(PASSWORD).await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
    assert!(vault.is_locked().await);

    let (vault, _) = initialized_vault_with_corrupt_status().await;
    assert_eq!(vault.lock().await.unwrap_err().code(), "AgentVaultCorrupt");
    assert!(vault.is_locked().await);

    let (vault, _) = initialized_vault_with_corrupt_status().await;
    assert_eq!(
        vault
            .change_password(PASSWORD, PASSWORD_2)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultCorrupt"
    );
    assert!(vault.is_locked().await);

    let (vault, _) = initialized_vault_with_corrupt_status().await;
    assert_eq!(
        vault
            .reset_password_with_recovery_phrase(PHRASE, PASSWORD_2)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultCorrupt"
    );
    assert!(vault.is_locked().await);

    let (vault, _) = initialized_vault_with_corrupt_status().await;
    assert_eq!(
        vault.backup().await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
    assert!(vault.is_locked().await);
}

#[tokio::test]
async fn change_password_commit_failure_keeps_store_and_locks() {
    let store = Arc::new(FaultyStore::default());
    let vault = Arc::new(IdentityVault::new(
        store.clone(),
        Arc::new(DidDhtProvider::default()),
    ));
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before = snapshot(&*store).await;

    store.fail_apply.store(true, Ordering::SeqCst);
    assert_eq!(
        vault
            .change_password(PASSWORD, PASSWORD_2)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultError"
    );
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&*store).await, before);

    store.fail_apply.store(false, Ordering::SeqCst);
    vault.change_password(PASSWORD, PASSWORD_2).await.unwrap();
    vault.lock().await.unwrap();
    vault.unlock(PASSWORD_2).await.unwrap();
}

#[tokio::test]
async fn reset_commit_failure_keeps_store_and_locks() {
    let store = Arc::new(FaultyStore::default());
    let vault = Arc::new(IdentityVault::new(
        store.clone(),
        Arc::new(DidDhtProvider::default()),
    ));
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    vault.lock().await.unwrap();
    let before = snapshot(&*store).await;

    store.fail_apply.store(true, Ordering::SeqCst);
    assert_eq!(
        vault
            .reset_password_with_recovery_phrase(PHRASE, PASSWORD_2)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultError"
    );
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&*store).await, before);

    store.fail_apply.store(false, Ordering::SeqCst);
    vault
        .reset_password_with_recovery_phrase(PHRASE, PASSWORD_2)
        .await
        .unwrap();
    vault.lock().await.unwrap();
    vault.unlock(PASSWORD_2).await.unwrap();
}

#[tokio::test]
async fn restore_commit_failure_keeps_store_and_locks() {
    let (source, _) = memory_vault();
    source
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let backup = source.backup().await.unwrap();

    let store = Arc::new(FaultyStore::default());
    let vault = Arc::new(IdentityVault::new(
        store.clone(),
        Arc::new(DidDhtProvider::default()),
    ));
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    vault.change_password(PASSWORD, PASSWORD_2).await.unwrap();
    let before = snapshot(&*store).await;

    store.fail_apply.store(true, Ordering::SeqCst);
    assert_eq!(
        vault.restore(&backup, PASSWORD).await.unwrap_err().code(),
        "AgentVaultError"
    );
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&*store).await, before);

    store.fail_apply.store(false, Ordering::SeqCst);
    vault.restore(&backup, PASSWORD).await.unwrap();
    assert!(!vault.is_locked().await);
}

#[tokio::test]
async fn configured_work_factor_is_written_and_opens() {
    let store = memory_store();
    let vault = Arc::new(IdentityVault::with_work_factor(
        store.clone(),
        Arc::new(DidDhtProvider::default()),
        10_000,
    ));
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    assert_eq!(
        header(&read_string(&*store, VAULT_CEK_JWE_KEY).await)["p2c"],
        10_000
    );

    vault.lock().await.unwrap();
    vault.unlock(PASSWORD).await.unwrap();
}

#[tokio::test]
async fn non_positive_work_factor_is_corrupt() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    vault.lock().await.unwrap();

    let tampered = with_p2c(&read_string(&*store, VAULT_CEK_JWE_KEY).await, 0);
    store
        .put(VAULT_CEK_JWE_KEY, tampered.into_bytes())
        .await
        .unwrap();
    assert_eq!(
        vault.unlock(PASSWORD).await.unwrap_err().code(),
        "AgentVaultCorrupt"
    );
    assert!(vault.is_locked().await);
}

#[tokio::test]
async fn reset_validation_and_precedence() {
    let (vault, store) = memory_vault();
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let before = snapshot(&*store).await;

    assert_eq!(
        vault
            .reset_password_with_recovery_phrase(PHRASE, "\t")
            .await
            .unwrap_err()
            .code(),
        "AgentVaultBlankPassword"
    );
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&*store).await, before);

    // A blank password is reported before the invalid phrase.
    vault.unlock(PASSWORD).await.unwrap();
    assert_eq!(
        vault
            .reset_password_with_recovery_phrase("not a phrase", " ")
            .await
            .unwrap_err()
            .code(),
        "AgentVaultBlankPassword"
    );
    assert!(vault.is_locked().await);

    vault.unlock(PASSWORD).await.unwrap();
    assert_eq!(
        vault
            .reset_password_with_recovery_phrase("not a phrase", PASSWORD_2)
            .await
            .unwrap_err()
            .code(),
        "AgentIdentityInvalidMnemonic"
    );
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&*store).await, before);
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use dwn_rs_agent::SqliteSecretStore;
    use dwn_rs_core::errors::StoreError;
    use dwn_rs_core::stores::wake::WakePublishHandler;
    use dwn_rs_core::stores::MessageStore;
    use dwn_rs_stores::SqliteStore;
    use tempfile::tempdir;

    async fn open(path: &std::path::Path) -> SqliteStore {
        let mut store = SqliteStore::new(path, WakePublishHandler::new(Arc::new(())));
        MessageStore::open(&mut store).await.unwrap();
        store
    }

    async fn sqlite_vault(sqlite: &SqliteStore) -> Arc<IdentityVault> {
        let store = Arc::new(SqliteSecretStore::new(sqlite));
        Arc::new(IdentityVault::new(
            store,
            Arc::new(DidDhtProvider::default()),
        ))
    }

    #[tokio::test]
    async fn apply_commits_one_batch() {
        let temp = tempdir().unwrap();
        let sqlite = open(&temp.path().join("vault.sqlite")).await;
        let store = SqliteSecretStore::new(&sqlite);
        store
            .apply(vec![
                SecretWrite::put("k1", b"a".to_vec()),
                SecretWrite::put("k2", b"b".to_vec()),
                SecretWrite::delete("k1"),
            ])
            .await
            .unwrap();
        assert_eq!(store.get("k1").await.unwrap(), None);
        assert_eq!(store.get("k2").await.unwrap(), Some(b"b".to_vec()));
    }

    #[tokio::test]
    async fn transaction_rolls_back_when_dropped_without_commit() {
        let temp = tempdir().unwrap();
        let sqlite = open(&temp.path().join("rollback.sqlite")).await;
        let store = SqliteSecretStore::new(&sqlite);
        store.put("existing", b"keep".to_vec()).await.unwrap();

        sqlite
            .connection()
            .await
            .unwrap()
            .with_writer(|connection| -> Result<(), StoreError> {
                let tx = connection
                    .transaction()
                    .map_err(|err| StoreError::InternalException(err.to_string()))?;
                tx.execute(
                    "INSERT OR REPLACE INTO agent_secrets (key, value) VALUES (?1, ?2)",
                    rusqlite::params!["existing", b"changed".to_vec()],
                )
                .map_err(|err| StoreError::InternalException(err.to_string()))?;
                tx.execute(
                    "INSERT OR REPLACE INTO agent_secrets (key, value) VALUES (?1, ?2)",
                    rusqlite::params!["partial", b"partial".to_vec()],
                )
                .map_err(|err| StoreError::InternalException(err.to_string()))?;
                Err(StoreError::InternalException("abort".to_string()))
            })
            .await
            .unwrap_err();

        assert_eq!(store.get("existing").await.unwrap(), Some(b"keep".to_vec()));
        assert_eq!(store.get("partial").await.unwrap(), None);
    }

    #[tokio::test]
    async fn apply_rolls_back_the_whole_batch_when_one_statement_fails() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("batch.sqlite");
        let sqlite = open(&path).await;
        let store = SqliteSecretStore::new(&sqlite);
        store.put("existing", b"keep".to_vec()).await.unwrap();

        // A trigger that aborts a later statement in the batch, so `apply`
        // exercises a mid-batch failure on the real backend rather than raw
        // rusqlite.
        sqlite
            .connection()
            .await
            .unwrap()
            .with_writer(|connection| -> Result<(), StoreError> {
                connection
                    .execute(
                        "CREATE TRIGGER reject_boom AFTER INSERT ON agent_secrets \
                         WHEN NEW.key = 'boom' BEGIN SELECT RAISE(ABORT, 'injected'); END",
                        [],
                    )
                    .map_err(|err| StoreError::InternalException(err.to_string()))?;
                Ok(())
            })
            .await
            .unwrap();

        let error = store
            .apply(vec![
                SecretWrite::put("existing", b"changed".to_vec()),
                SecretWrite::put("boom", b"nope".to_vec()),
                SecretWrite::put("added", b"new".to_vec()),
            ])
            .await
            .unwrap_err();
        assert_eq!(error.code(), "AgentVaultError");

        // Reopen the file: a commit-per-statement implementation would have
        // left `existing` changed and `added` present.
        drop(store);
        drop(sqlite);
        let sqlite = open(&path).await;
        let store = SqliteSecretStore::new(&sqlite);
        assert_eq!(store.get("existing").await.unwrap(), Some(b"keep".to_vec()));
        assert_eq!(store.get("boom").await.unwrap(), None);
        assert_eq!(store.get("added").await.unwrap(), None);
    }

    #[tokio::test]
    async fn initialize_and_change_password_survive_reopen() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.sqlite");
        let did_uri = {
            let sqlite = open(&path).await;
            let vault = sqlite_vault(&sqlite).await;
            let init = vault
                .initialize(PASSWORD, Some(PHRASE), vec![])
                .await
                .unwrap();
            vault.change_password(PASSWORD, PASSWORD_2).await.unwrap();
            init.portable_did.uri
        };

        let sqlite = open(&path).await;
        let vault = sqlite_vault(&sqlite).await;
        assert!(vault.status().await.unwrap().initialized);
        vault.unlock(PASSWORD_2).await.unwrap();
        assert_eq!(vault.get_did().await.unwrap().uri, did_uri);
        assert_eq!(
            vault.unlock(PASSWORD).await.unwrap_err().code(),
            "AgentVaultInvalidPassword"
        );
    }

    #[tokio::test]
    async fn reset_and_restore_survive_reopen() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.sqlite");
        let (backup, fresh_path) = {
            let sqlite = open(&path).await;
            let vault = sqlite_vault(&sqlite).await;
            vault
                .initialize(PASSWORD, Some(PHRASE), vec![])
                .await
                .unwrap();
            let backup = vault.backup().await.unwrap();
            vault
                .reset_password_with_recovery_phrase(PHRASE, PASSWORD_2)
                .await
                .unwrap();
            (backup, temp.path().join("fresh.sqlite"))
        };

        let sqlite = open(&path).await;
        let vault = sqlite_vault(&sqlite).await;
        vault.unlock(PASSWORD_2).await.unwrap();

        let sqlite = open(&fresh_path).await;
        let fresh = sqlite_vault(&sqlite).await;
        assert!(!fresh.status().await.unwrap().initialized);
        fresh.restore(&backup, PASSWORD).await.unwrap();
        assert!(fresh.get_did().await.unwrap().uri.starts_with("did:dht:"));
    }
}
