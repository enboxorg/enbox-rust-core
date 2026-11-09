use chrono::{TimeZone, Utc};
use dwn_rs_agent::agent::*;
use serde_json::{json, Value};
use std::future::Future;
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const KEY: &str = "enbox:auth:registrationTokens";

async fn setup() -> (
    Arc<MemorySecretStore>,
    Arc<IdentityVault>,
    Arc<VaultBackedSecretStore>,
    Arc<AtomicI64>,
) {
    let raw = Arc::new(MemorySecretStore::default());
    let vault = Arc::new(IdentityVault::with_work_factor(
        raw.clone(),
        Arc::new(DidDhtProvider::default()),
        1,
    ));
    vault
        .initialize("password", Some(PHRASE), vec![])
        .await
        .unwrap();
    let clock = Arc::new(AtomicI64::new(1000));
    let time = clock.clone();
    let secrets = Arc::new(VaultBackedSecretStore::with_clock(
        vault.clone(),
        raw.clone(),
        move || {
            Utc.timestamp_millis_opt(time.load(Ordering::SeqCst))
                .unwrap()
        },
    ));
    (raw, vault, secrets, clock)
}

#[tokio::test]
async fn binary_replacement_and_locked_operations() {
    let (raw, vault, secrets, _) = setup().await;
    for bytes in [vec![], vec![0, 1, 127, 128, 255], b"secret-token".to_vec()] {
        secrets.put(KEY, bytes.clone(), None).await.unwrap();
        let envelope: Value =
            serde_json::from_slice(&raw.get(KEY).await.unwrap().unwrap()).unwrap();
        assert!(envelope["jwe"].is_string());
        assert!(envelope.get("expiresAt").is_none());
        assert_eq!(secrets.get(KEY).await.unwrap(), Some(bytes));
    }
    assert_eq!(secrets.get("absent").await.unwrap(), None);
    vault.lock().await.unwrap();
    for key in [KEY, "absent"] {
        assert_eq!(
            secrets.get(key).await.unwrap_err().code(),
            "AgentVaultLocked"
        );
        assert_eq!(
            secrets
                .put(key, vec![0], Some("bad".into()))
                .await
                .unwrap_err()
                .code(),
            "AgentVaultLocked"
        );
    }
    assert!(secrets.delete(KEY).await.unwrap());
    assert!(!secrets.delete(KEY).await.unwrap());
    assert!(!secrets.delete("absent").await.unwrap());
    assert!(!format!("{secrets:?}").contains("secret-token"));
}

#[tokio::test]
async fn expiry_boundaries_and_no_ttl() {
    let (raw, _, secrets, clock) = setup().await;
    for timestamp in ["1970-01-01T00:00:02.000Z", "1970-01-01T01:00:02+01:00"] {
        secrets
            .put(KEY, vec![5], Some(timestamp.into()))
            .await
            .unwrap();
        clock.store(1999, Ordering::SeqCst);
        assert_eq!(secrets.get(KEY).await.unwrap(), Some(vec![5]));
        clock.store(2000, Ordering::SeqCst);
        assert_eq!(secrets.get(KEY).await.unwrap(), None);
        assert_eq!(raw.get(KEY).await.unwrap(), None);
        secrets
            .put(KEY, vec![5], Some(timestamp.into()))
            .await
            .unwrap();
        clock.store(2001, Ordering::SeqCst);
        assert_eq!(secrets.get(KEY).await.unwrap(), None);
    }
    secrets.put(KEY, vec![9], None).await.unwrap();
    clock.store(999999, Ordering::SeqCst);
    assert_eq!(secrets.get(KEY).await.unwrap(), Some(vec![9]));
}

#[tokio::test]
async fn malformed_envelopes_are_typed_preserved_and_redacted() {
    let (raw, vault, secrets, _) = setup().await;
    for bytes in [
        vec![255],
        b"secret-token".to_vec(),
        b"null".to_vec(),
        b"[]".to_vec(),
        br#"{"token":"secret-token"}"#.to_vec(),
        br#"{"jwe":12}"#.to_vec(),
        br#"{"jwe":"secret-token","expiresAt":null}"#.to_vec(),
        br#"{"jwe":"secret-token","expiresAt":"invalid-secret-date"}"#.to_vec(),
    ] {
        raw.put(KEY, bytes.clone()).await.unwrap();
        let error = secrets.get(KEY).await.unwrap_err();
        assert_eq!(error.code(), "AgentSecretInvalidEnvelope");
        assert_eq!(AgentIdentityError::new(error.code(), error.detail()), error);
        assert!(!format!("{error:?} {error}").contains("secret-token"));
        assert_eq!(raw.get(KEY).await.unwrap(), Some(bytes));
    }
    let before = raw.get(KEY).await.unwrap();
    for expiry in ["bad", "2026-11-07", "2026-11-07T12:00:00"] {
        assert_eq!(
            secrets
                .put(KEY, vec![3], Some(expiry.into()))
                .await
                .unwrap_err()
                .code(),
            "AgentSecretInvalidEnvelope"
        );
        assert_eq!(raw.get(KEY).await.unwrap(), before);
    }
    vault.lock().await.unwrap();
    assert_eq!(
        secrets.get(KEY).await.unwrap_err().code(),
        "AgentVaultLocked"
    );
    assert_eq!(raw.get(KEY).await.unwrap(), before);
    assert!(secrets.delete(KEY).await.unwrap());
}

#[tokio::test]
async fn expired_jwe_is_not_authenticated_but_live_jwe_is() {
    let (raw, vault, secrets, _) = setup().await;
    raw.put(
        KEY,
        serde_json::to_vec(&json!({"jwe":"broken", "expiresAt":"1970-01-01T00:00:00Z"})).unwrap(),
    )
    .await
    .unwrap();
    vault.lock().await.unwrap();
    assert_eq!(
        secrets.get(KEY).await.unwrap_err().code(),
        "AgentVaultLocked"
    );
    assert!(raw.get(KEY).await.unwrap().is_some());
    vault.unlock("password").await.unwrap();
    assert_eq!(secrets.get(KEY).await.unwrap(), None);
    let bytes = serde_json::to_vec(&json!({"jwe":"broken", "extra":"ignored"})).unwrap();
    raw.put(KEY, bytes.clone()).await.unwrap();
    assert!(secrets.get(KEY).await.is_err());
    assert_eq!(raw.get(KEY).await.unwrap(), Some(bytes));
    secrets.put(KEY, vec![8], None).await.unwrap();
    let mut envelope: Value =
        serde_json::from_slice(&raw.get(KEY).await.unwrap().unwrap()).unwrap();
    envelope["unknown"] = json!({"anything": true});
    raw.put(KEY, serde_json::to_vec(&envelope).unwrap())
        .await
        .unwrap();
    assert_eq!(secrets.get(KEY).await.unwrap(), Some(vec![8]));
}

#[tokio::test]
async fn typescript_envelope_decrypts_and_exports_rust_envelope() {
    let (raw, _, secrets, _) = setup().await;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/interop/vault-secret-envelope.json"
    ))
    .unwrap();
    raw.put(
        KEY,
        fixture["envelope"].as_str().unwrap().as_bytes().to_vec(),
    )
    .await
    .unwrap();
    let expected = vec![0, 1, 127, 128, 255];
    assert_eq!(secrets.get(KEY).await.unwrap(), Some(expected.clone()));
    secrets
        .put(KEY, expected, Some("2099-01-01T00:00:00.000Z".into()))
        .await
        .unwrap();
    if let Some(path) = std::env::var_os("VAULT_SECRET_EXPORT") {
        std::fs::write(path, raw.get(KEY).await.unwrap().unwrap()).unwrap();
    }
}

struct ControlledStore {
    inner: Arc<MemorySecretStore>,
    fail: std::sync::atomic::AtomicU8,
    pause_read: std::sync::atomic::AtomicBool,
    pause_write: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
impl ControlledStore {
    fn new(inner: Arc<MemorySecretStore>) -> Self {
        Self {
            inner,
            fail: 0.into(),
            pause_read: false.into(),
            pause_write: false.into(),
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        }
    }
    fn check(&self, operation: u8) -> AgentIdentityResult<()> {
        if self.fail.load(Ordering::SeqCst) == operation {
            Err(AgentIdentityError::new(
                "AgentVaultError",
                "backend unavailable",
            ))
        } else {
            Ok(())
        }
    }
}
impl SecretStore for ControlledStore {
    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            self.check(1)?;
            let result = self.inner.get(key).await?;
            if self.pause_read.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.resume.notified().await;
            }
            Ok(result)
        })
    }
    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> AgentIdentityFuture<'a, ()> {
        self.inner.put(key, value)
    }
    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool> {
        Box::pin(async move {
            self.check(2)?;
            self.inner.delete(key).await
        })
    }
    fn apply<'a>(&'a self, writes: Vec<SecretWrite>) -> AgentIdentityFuture<'a, ()> {
        Box::pin(async move {
            self.check(3)?;
            if self.pause_write.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.resume.notified().await;
            }
            self.inner.apply(writes).await
        })
    }
}

#[tokio::test]
async fn backend_failures_preserve_state_and_error_identity() {
    let (raw, vault, _, _) = setup().await;
    let controlled = Arc::new(ControlledStore::new(raw.clone()));
    let secrets = VaultBackedSecretStore::with_clock(vault, controlled.clone(), || {
        Utc.timestamp_millis_opt(1000).unwrap()
    });
    secrets.put(KEY, b"keep".to_vec(), None).await.unwrap();
    let before = raw.get(KEY).await.unwrap();
    controlled.fail.store(3, Ordering::SeqCst);
    assert_eq!(
        secrets
            .put(KEY, b"replacement".to_vec(), None)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultError"
    );
    assert_eq!(raw.get(KEY).await.unwrap(), before);
    controlled.fail.store(1, Ordering::SeqCst);
    assert_eq!(
        secrets.get(KEY).await.unwrap_err().code(),
        "AgentVaultError"
    );
    controlled.fail.store(2, Ordering::SeqCst);
    assert_eq!(
        secrets.delete(KEY).await.unwrap_err().code(),
        "AgentVaultError"
    );
    assert_eq!(raw.get(KEY).await.unwrap(), before);
    raw.put(
        KEY,
        br#"{"jwe":"broken","expiresAt":"1970-01-01T00:00:00Z"}"#.to_vec(),
    )
    .await
    .unwrap();
    let before = raw.get(KEY).await.unwrap();
    assert_eq!(
        secrets.get(KEY).await.unwrap_err().code(),
        "AgentVaultError"
    );
    assert_eq!(raw.get(KEY).await.unwrap(), before);
}

#[tokio::test]
async fn expiry_purge_cannot_delete_a_concurrent_replacement() {
    let (raw, vault, _, _) = setup().await;
    let controlled = Arc::new(ControlledStore::new(raw.clone()));
    let secrets = Arc::new(VaultBackedSecretStore::with_clock(
        vault,
        controlled.clone(),
        || Utc.timestamp_millis_opt(1000).unwrap(),
    ));
    secrets
        .put(KEY, vec![1], Some("1970-01-01T00:00:00Z".into()))
        .await
        .unwrap();
    controlled.pause_read.store(true, Ordering::SeqCst);
    let read = {
        let secrets = secrets.clone();
        tokio::spawn(async move { secrets.get(KEY).await })
    };
    controlled.entered.notified().await;
    let mut write = Box::pin(secrets.put(KEY, vec![2], None));
    // Poll the replacement while the expired read holds the operation boundary.
    std::future::poll_fn(|cx| {
        assert!(write.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    controlled.resume.notify_one();
    assert_eq!(read.await.unwrap().unwrap(), None);
    write.await.unwrap();
    assert_eq!(secrets.get(KEY).await.unwrap(), Some(vec![2]));
}

#[tokio::test]
async fn lock_during_read_prevents_decryption() {
    let (raw, vault, _, _) = setup().await;
    let controlled = Arc::new(ControlledStore::new(raw));
    let secrets = Arc::new(VaultBackedSecretStore::new(
        vault.clone(),
        controlled.clone(),
    ));
    secrets.put(KEY, vec![1], None).await.unwrap();
    controlled.pause_read.store(true, Ordering::SeqCst);
    let read = {
        let secrets = secrets.clone();
        tokio::spawn(async move { secrets.get(KEY).await })
    };
    controlled.entered.notified().await;
    vault.lock().await.unwrap();
    controlled.resume.notify_one();
    assert_eq!(read.await.unwrap().unwrap_err().code(), "AgentVaultLocked");
}

#[tokio::test]
async fn fresh_vault_is_gated_and_different_cek_cannot_read() {
    let (raw, _, secrets, _) = setup().await;
    secrets.put(KEY, vec![1], None).await.unwrap();
    let other_raw = Arc::new(MemorySecretStore::default());
    let other = Arc::new(IdentityVault::with_work_factor(
        other_raw,
        Arc::new(DidDhtProvider::default()),
        1,
    ));
    let other_secrets = VaultBackedSecretStore::new(other.clone(), raw.clone());
    assert_eq!(
        other_secrets.get("absent").await.unwrap_err().code(),
        "AgentVaultLocked"
    );
    other
        .initialize(
            "other",
            Some("legal winner thank year wave sausage worth useful legal winner thank yellow"),
            vec![],
        )
        .await
        .unwrap();
    let before = raw.get(KEY).await.unwrap();
    assert!(other_secrets.get(KEY).await.is_err());
    assert_eq!(raw.get(KEY).await.unwrap(), before);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_credentials_survive_reopen_and_password_change() {
    use dwn_rs_agent::SqliteSecretStore;
    use dwn_rs_core::stores::{wake::WakePublishHandler, MessageStore};
    use dwn_rs_stores::SqliteStore;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.sqlite");
    {
        let mut database = SqliteStore::new(&path, WakePublishHandler::new(Arc::new(())));
        MessageStore::open(&mut database).await.unwrap();
        let raw = Arc::new(SqliteSecretStore::new(&database));
        let vault = Arc::new(IdentityVault::with_work_factor(
            raw.clone(),
            Arc::new(DidDhtProvider::default()),
            1,
        ));
        vault.initialize("old", Some(PHRASE), vec![]).await.unwrap();
        let secrets = VaultBackedSecretStore::new(vault.clone(), raw.clone());
        secrets
            .put(KEY, b"private-token".to_vec(), None)
            .await
            .unwrap();
        let bytes = raw.get(KEY).await.unwrap().unwrap();
        assert!(!String::from_utf8(bytes.clone())
            .unwrap()
            .contains("private-token"));
        assert!(serde_json::from_slice::<Value>(&bytes).unwrap()["jwe"].is_string());
        vault.change_password("old", "new").await.unwrap();
    }
    let mut database = SqliteStore::new(&path, WakePublishHandler::new(Arc::new(())));
    MessageStore::open(&mut database).await.unwrap();
    let raw = Arc::new(SqliteSecretStore::new(&database));
    let vault = Arc::new(IdentityVault::with_work_factor(
        raw.clone(),
        Arc::new(DidDhtProvider::default()),
        1,
    ));
    let secrets = VaultBackedSecretStore::new(vault.clone(), raw);
    assert_eq!(
        secrets.get(KEY).await.unwrap_err().code(),
        "AgentVaultLocked"
    );
    vault.unlock("new").await.unwrap();
    assert_eq!(
        secrets.get(KEY).await.unwrap(),
        Some(b"private-token".to_vec())
    );
}

#[tokio::test]
async fn encrypted_write_can_finish_after_lock_and_delete_is_ordered() {
    let (raw, vault, _, _) = setup().await;
    let controlled = Arc::new(ControlledStore::new(raw.clone()));
    let secrets = Arc::new(VaultBackedSecretStore::new(
        vault.clone(),
        controlled.clone(),
    ));
    controlled.pause_write.store(true, Ordering::SeqCst);
    let write = {
        let secrets = secrets.clone();
        tokio::spawn(async move { secrets.put(KEY, b"private-token".to_vec(), None).await })
    };
    controlled.entered.notified().await;
    vault.lock().await.unwrap();
    let mut delete = secrets.delete(KEY);
    std::future::poll_fn(|cx| {
        assert!(delete.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    controlled.resume.notify_one();
    write.await.unwrap().unwrap();
    let bytes = raw.get(KEY).await.unwrap().unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains("private-token"));
    assert!(delete.await.unwrap());
    assert_eq!(raw.get(KEY).await.unwrap(), None);
}

#[tokio::test]
async fn auth_helpers_use_envelopes_and_propagate_lock_and_legacy_errors() {
    use dwn_rs_agent::auth::{connect::*, setup::*};
    let (raw, vault, secrets, _) = setup().await;
    let private_key = vault
        .get_did()
        .await
        .unwrap()
        .private_keys
        .last()
        .unwrap()
        .clone();
    let derived = DerivedPrivateJwk {
        root_key_id: "test-key".into(),
        derivation_scheme: "protocolPath".into(),
        derivation_path: vec![],
        derived_private_key: private_key,
    };
    let decryption = vec![DelegateDecryptionKey {
        protocol: "https://example.com/protocol".into(),
        scope: DelegateDecryptionScope::Protocol,
        derived_private_key: derived.clone(),
    }];
    let context = vec![DelegateContextKey {
        protocol: "https://example.com/protocol".into(),
        context_id: "context".into(),
        derived_private_key: derived,
    }];
    let tokens = std::collections::BTreeMap::from([(
        "https://example.com".into(),
        RegistrationTokenData {
            registration_token: "bearer-secret".into(),
            refresh_token: Some("refresh-secret".into()),
            expires_at: None,
            token_url: "https://example.com/token".into(),
            refresh_url: None,
        },
    )]);
    save_registration_tokens(&secrets, &tokens).await.unwrap();
    save_delegate_decryption_keys(&secrets, &decryption)
        .await
        .unwrap();
    save_delegate_context_keys(&secrets, &context)
        .await
        .unwrap();
    assert_eq!(load_registration_tokens(&secrets).await.unwrap(), tokens);
    assert_eq!(
        load_delegate_decryption_keys(&secrets).await.unwrap(),
        decryption
    );
    assert_eq!(load_delegate_context_keys(&secrets).await.unwrap(), context);
    for (key, expected) in [
        (
            REGISTRATION_TOKENS_KEY,
            serde_json::to_value(&tokens).unwrap(),
        ),
        (
            DELEGATE_DECRYPTION_KEYS_KEY,
            serde_json::to_value(&decryption).unwrap(),
        ),
        (
            DELEGATE_CONTEXT_KEYS_KEY,
            serde_json::to_value(&context).unwrap(),
        ),
    ] {
        let bytes = raw.get(key).await.unwrap().unwrap();
        let envelope: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(envelope.as_object().unwrap().len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(
                &vault
                    .decrypt_data(envelope["jwe"].as_str().unwrap())
                    .await
                    .unwrap()
            )
            .unwrap(),
            expected
        );
        assert_ne!(bytes, serde_json::to_vec(&expected).unwrap());
    }
    vault.lock().await.unwrap();
    assert_eq!(
        load_registration_tokens(&secrets).await.unwrap_err().code(),
        "AgentVaultLocked"
    );
    assert_eq!(
        load_delegate_decryption_keys(&secrets)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultLocked"
    );
    assert_eq!(
        load_delegate_context_keys(&secrets)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultLocked"
    );
    assert_eq!(
        save_registration_tokens(&secrets, &tokens)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultLocked"
    );
    assert_eq!(
        save_delegate_decryption_keys(&secrets, &decryption)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultLocked"
    );
    assert_eq!(
        save_delegate_context_keys(&secrets, &context)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultLocked"
    );
    vault.unlock("password").await.unwrap();
    for key in [
        REGISTRATION_TOKENS_KEY,
        DELEGATE_DECRYPTION_KEYS_KEY,
        DELEGATE_CONTEXT_KEYS_KEY,
    ] {
        raw.put(key, b"[]".to_vec()).await.unwrap();
    }
    assert_eq!(
        load_registration_tokens(&secrets).await.unwrap_err().code(),
        "AgentSecretInvalidEnvelope"
    );
    assert_eq!(
        load_delegate_decryption_keys(&secrets)
            .await
            .unwrap_err()
            .code(),
        "AgentSecretInvalidEnvelope"
    );
    assert_eq!(
        load_delegate_context_keys(&secrets)
            .await
            .unwrap_err()
            .code(),
        "AgentSecretInvalidEnvelope"
    );
    // Domain JSON defaults remain distinct from invalid outer envelopes.
    for key in [
        REGISTRATION_TOKENS_KEY,
        DELEGATE_DECRYPTION_KEYS_KEY,
        DELEGATE_CONTEXT_KEYS_KEY,
    ] {
        secrets
            .put(key, b"malformed domain JSON".to_vec(), None)
            .await
            .unwrap();
    }
    assert!(load_registration_tokens(&secrets).await.unwrap().is_empty());
    assert!(load_delegate_decryption_keys(&secrets)
        .await
        .unwrap()
        .is_empty());
    assert!(load_delegate_context_keys(&secrets)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn auth_helpers_preserve_backend_error_identity() {
    use dwn_rs_agent::auth::{connect::*, setup::*};
    let (raw, vault, _, _) = setup().await;
    let controlled = Arc::new(ControlledStore::new(raw));
    let secrets = VaultBackedSecretStore::new(vault, controlled.clone());
    controlled.fail.store(1, Ordering::SeqCst);
    assert_eq!(
        load_registration_tokens(&secrets).await.unwrap_err().code(),
        "AgentVaultError"
    );
    assert_eq!(
        load_delegate_decryption_keys(&secrets)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultError"
    );
    assert_eq!(
        load_delegate_context_keys(&secrets)
            .await
            .unwrap_err()
            .code(),
        "AgentVaultError"
    );
    controlled.fail.store(3, Ordering::SeqCst);
    assert_eq!(
        save_registration_tokens(&secrets, &Default::default())
            .await
            .unwrap_err()
            .code(),
        "AgentVaultError"
    );
    assert_eq!(
        save_delegate_decryption_keys(&secrets, &[])
            .await
            .unwrap_err()
            .code(),
        "AgentVaultError"
    );
    assert_eq!(
        save_delegate_context_keys(&secrets, &[])
            .await
            .unwrap_err()
            .code(),
        "AgentVaultError"
    );
}

#[tokio::test]
async fn credential_keys_cannot_modify_vault_entries() {
    let (raw, vault, secrets, _) = setup().await;
    for key in [
        VAULT_CEK_JWE_KEY,
        VAULT_DID_JWE_KEY,
        VAULT_STATUS_KEY,
        "agent:vault:unknown",
    ] {
        let before = raw.get(key).await.unwrap();
        assert_eq!(
            secrets.get(key).await.unwrap_err().code(),
            "AgentSecretInvalidEnvelope"
        );
        assert_eq!(
            secrets.put(key, vec![1], None).await.unwrap_err().code(),
            "AgentSecretInvalidEnvelope"
        );
        assert_eq!(
            secrets.delete(key).await.unwrap_err().code(),
            "AgentSecretInvalidEnvelope"
        );
        vault.lock().await.unwrap();
        assert_eq!(
            secrets.get(key).await.unwrap_err().code(),
            "AgentVaultLocked"
        );
        assert_eq!(
            secrets.put(key, vec![1], None).await.unwrap_err().code(),
            "AgentVaultLocked"
        );
        assert_eq!(
            secrets.delete(key).await.unwrap_err().code(),
            "AgentSecretInvalidEnvelope"
        );
        assert_eq!(raw.get(key).await.unwrap(), before);
        vault.unlock("password").await.unwrap();
    }
}

#[tokio::test]
async fn auth_key_families_and_locked_expiry_use_the_same_envelope_contract() {
    use dwn_rs_agent::auth::connect::{
        DELEGATE_MULTI_PARTY_PROTOCOLS_KEY, SESSION_REVOCATIONS_KEY,
    };
    let (raw, vault, secrets, _) = setup().await;
    for key in [DELEGATE_MULTI_PARTY_PROTOCOLS_KEY, SESSION_REVOCATIONS_KEY] {
        secrets.put(key, b"secret".to_vec(), None).await.unwrap();
        assert!(
            serde_json::from_slice::<Value>(&raw.get(key).await.unwrap().unwrap()).unwrap()["jwe"]
                .is_string()
        );
        assert_eq!(secrets.get(key).await.unwrap(), Some(b"secret".to_vec()));
    }
    for bytes in [
        br#"{"jwe":"broken","expiresAt":"1970-01-01T00:00:00Z"}"#.to_vec(),
        b"malformed".to_vec(),
    ] {
        raw.put(KEY, bytes.clone()).await.unwrap();
        vault.lock().await.unwrap();
        assert_eq!(
            secrets.put(KEY, vec![9], None).await.unwrap_err().code(),
            "AgentVaultLocked"
        );
        assert_eq!(
            secrets.get(KEY).await.unwrap_err().code(),
            "AgentVaultLocked"
        );
        assert_eq!(raw.get(KEY).await.unwrap(), Some(bytes));
        assert!(secrets.delete(KEY).await.unwrap());
        vault.unlock("password").await.unwrap();
    }
}

#[tokio::test]
async fn tampered_envelopes_preserve_codec_errors_and_stored_bytes() {
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD as base64url, Engine as _};
    let (raw, vault, secrets, _) = setup().await;
    let jwe = vault.encrypt_data(b"secret").await.unwrap();
    let parts: Vec<_> = jwe.split('.').collect();
    let mut bad_tag = parts[4].as_bytes().to_vec();
    bad_tag[0] = if bad_tag[0] == b'A' { b'B' } else { b'A' };
    let mut bad_parts = parts.clone();
    let tag = String::from_utf8(bad_tag).unwrap();
    bad_parts[4] = &tag;
    let mut variants = vec![bad_parts.join("."), "invalid.segment".into()];
    for header in [
        json!({"alg":"wrong","enc":"A256GCM"}),
        json!({"alg":"dir","enc":"wrong"}),
    ] {
        let header = base64url.encode(serde_json::to_vec(&header).unwrap());
        let mut bad_parts = parts.clone();
        bad_parts[0] = &header;
        variants.push(bad_parts.join("."));
    }
    for jwe in variants {
        let bytes = serde_json::to_vec(&json!({"jwe":jwe})).unwrap();
        raw.put(KEY, bytes.clone()).await.unwrap();
        assert_eq!(
            secrets.get(KEY).await.unwrap_err().code(),
            "AgentIdentityVaultError"
        );
        assert_eq!(raw.get(KEY).await.unwrap(), Some(bytes));
    }
}
