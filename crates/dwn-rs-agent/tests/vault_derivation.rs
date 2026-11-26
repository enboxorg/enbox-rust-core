//! Vault derivation versions: golden vectors, recovery fallback, status
//! metadata, and backup/restore preservation.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD as base64url};
use chrono::{TimeZone, Utc};
use dwn_rs_agent::agent::{
    derive_agent_keys_with_version, AgentDidCreateRequest, AgentDidNetwork, AgentDidSigner,
    AgentIdentityError, AgentIdentityFuture, DidDhtProvider, DidProvider, DidResolution,
    IdentityVault, IdentityVaultBackup, MemorySecretStore, ResolvedAgentDid, SecretStore,
    VaultDerivationVersion, VaultStatus, VAULT_STATUS_KEY,
};
use serde_json::Value;
use ssi_dids_core::Document;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER_PHRASE: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PASSWORD: &str = "vault-password";
const PASSWORD_2: &str = "vault-password-2";
const V1_DID: &str = "did:dht:qftx7z968xcpfy1a1diu75pg5meap3gdtg6ezagaw849wdh6oubo";
const V2_DID: &str = "did:dht:3pcjxsbcm5py5xaffs4uppp8ywubyy9bw4erbicw7qrkue1t81uo";

#[derive(Clone, Copy)]
enum Outcome {
    Found,
    NotFound,
    Error,
}

struct RecordingNetwork {
    v2: Outcome,
    v1: Outcome,
    calls: Mutex<Vec<String>>,
    publishes: AtomicUsize,
}

impl RecordingNetwork {
    fn new(v2: Outcome, v1: Outcome) -> Self {
        Self {
            v2,
            v1,
            calls: Mutex::new(Vec::new()),
            publishes: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn publishes(&self) -> usize {
        self.publishes.load(Ordering::SeqCst)
    }
}

impl AgentDidNetwork for RecordingNetwork {
    fn resolve<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, DidResolution> {
        self.calls.lock().unwrap().push(did_uri.to_string());
        let outcome = if did_uri == V2_DID {
            self.v2
        } else if did_uri == V1_DID {
            self.v1
        } else {
            Outcome::NotFound
        };
        let did_uri = did_uri.to_string();
        Box::pin(async move {
            match outcome {
                Outcome::Found => Ok(DidResolution::Found(Box::new(ResolvedAgentDid {
                    document: ready_document(&did_uri),
                    sequence: 1,
                    types: None,
                }))),
                Outcome::NotFound => Ok(DidResolution::NotFound),
                Outcome::Error => Err(AgentIdentityError::new(
                    "AgentIdentityDidError",
                    "gateway failure",
                )),
            }
        })
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

fn ready_document(did_uri: &str) -> Document {
    serde_json::from_value(serde_json::json!({
        "id": did_uri,
        "service": [{
            "id": format!("{did_uri}#dwn"),
            "type": "DecentralizedWebNode",
            "serviceEndpoint": ["https://dwn.example"],
        }],
    }))
    .unwrap()
}

fn new_vault(network: Arc<RecordingNetwork>) -> (Arc<IdentityVault>, Arc<MemorySecretStore>) {
    let store = Arc::new(MemorySecretStore::default());
    let vault = IdentityVault::with_did_network(
        store.clone(),
        Arc::new(DidDhtProvider::default()),
        1,
        network,
    )
    .with_clock(|| {
        Utc.timestamp_opt(1_700_000_000, 0)
            .single()
            .expect("valid timestamp")
    });
    (Arc::new(vault), store)
}

async fn stored_status(store: &MemorySecretStore) -> VaultStatus {
    let bytes = store.get(VAULT_STATUS_KEY).await.unwrap();
    VaultStatus::parse(bytes.as_deref()).unwrap()
}

async fn snapshot(
    store: &MemorySecretStore,
) -> (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) {
    (
        store.get(VAULT_STATUS_KEY).await.unwrap(),
        store
            .get(dwn_rs_agent::agent::VAULT_CEK_JWE_KEY)
            .await
            .unwrap(),
        store
            .get(dwn_rs_agent::agent::VAULT_DID_JWE_KEY)
            .await
            .unwrap(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Covers: ENBOX-AGENT-001
#[test]
fn golden_cek_and_salt_match_typescript_vectors() {
    for (version, cek, salt) in [
        (
            VaultDerivationVersion::V1,
            "b99ff78488da4c83cbe590b5374bfca38551eb47e65514667018cc33c91f4913",
            "cf6389ce23de14b02e05413e1bcc3715f6fed4c2b0eda9412701279288f37d20",
        ),
        (
            VaultDerivationVersion::V2,
            "a19daef652efd7e05e22a9184a244d63983fd5ef2714b113b8d60dc53028fd67",
            "faa7f7433146bb721fd77c7b6a1cc6dc4725886130d6f05582eabca26bde85c0",
        ),
    ] {
        let derived = derive_agent_keys_with_version(PHRASE, version).unwrap();
        assert_eq!(
            hex(&derived.vault_content_encryption_key),
            cek,
            "{version:?}"
        );
        assert_eq!(hex(&derived.vault_unlock_salt), salt, "{version:?}");
    }
}

#[tokio::test]
// Covers: ENBOX-AGENT-001, ENBOX-AGENT-009
async fn golden_agent_dids_match_typescript_vectors() {
    for (version, expected) in [
        (VaultDerivationVersion::V1, V1_DID),
        (VaultDerivationVersion::V2, V2_DID),
    ] {
        let derived = derive_agent_keys_with_version(PHRASE, version).unwrap();
        let did = DidDhtProvider::default()
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived.identity_private_jwk,
                signing_private_jwk: derived.signing_private_jwk,
                encryption_private_jwk: derived.encryption_private_jwk,
                dwn_endpoints: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(did.uri, expected, "{version:?}");
    }
}

// Covers: ENBOX-AGENT-001, ENBOX-AGENT-005
#[tokio::test]
async fn fresh_initialize_defaults_to_v2_and_explicit_v1_is_kept() {
    let network = Arc::new(RecordingNetwork::new(Outcome::NotFound, Outcome::NotFound));
    let (vault, store) = new_vault(network.clone());
    let init = vault.initialize(PASSWORD, None, vec![]).await.unwrap();
    assert_eq!(
        derive_did_uri(&init.recovery_phrase, VaultDerivationVersion::V2).await,
        init.portable_did.uri
    );
    assert_eq!(
        stored_status(&store).await.derivation_version,
        Some(VaultDerivationVersion::V2)
    );
    assert!(network.calls().is_empty());
    assert_eq!(network.publishes(), 1);

    let (v1_vault, v1_store) = new_vault(Arc::new(RecordingNetwork::new(
        Outcome::Error,
        Outcome::Error,
    )));
    let init = v1_vault
        .initialize_with_version(PASSWORD, None, vec![], Some(VaultDerivationVersion::V1))
        .await
        .unwrap();
    assert_eq!(
        derive_did_uri(&init.recovery_phrase, VaultDerivationVersion::V1).await,
        init.portable_did.uri
    );
    assert_eq!(
        stored_status(&v1_store).await.derivation_version,
        Some(VaultDerivationVersion::V1)
    );
}

async fn derive_did_uri(phrase: &str, version: VaultDerivationVersion) -> String {
    let derived = derive_agent_keys_with_version(phrase, version).unwrap();
    DidDhtProvider::default()
        .create_did(AgentDidCreateRequest {
            identity_private_jwk: derived.identity_private_jwk,
            signing_private_jwk: derived.signing_private_jwk,
            encryption_private_jwk: derived.encryption_private_jwk,
            dwn_endpoints: Vec::new(),
        })
        .await
        .unwrap()
        .uri
}

// Covers: ENBOX-AGENT-001, ENBOX-AGENT-009
#[tokio::test]
async fn recovery_v2_found_uses_v2_with_one_lookup() {
    let network = Arc::new(RecordingNetwork::new(Outcome::Found, Outcome::Error));
    let (vault, store) = new_vault(network.clone());
    let init = vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    assert_eq!(init.portable_did.uri, V2_DID);
    assert_eq!(
        stored_status(&store).await.derivation_version,
        Some(VaultDerivationVersion::V2)
    );
    assert_eq!(network.calls(), vec![V2_DID.to_string()]);
    assert_eq!(network.publishes(), 0);
}

// Covers: ENBOX-AGENT-001, ENBOX-AGENT-009
#[tokio::test]
async fn recovery_v2_not_found_falls_back_to_v1() {
    let network = Arc::new(RecordingNetwork::new(Outcome::NotFound, Outcome::Found));
    let (vault, store) = new_vault(network.clone());
    let init = vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    assert_eq!(init.portable_did.uri, V1_DID);
    assert_eq!(
        stored_status(&store).await.derivation_version,
        Some(VaultDerivationVersion::V1)
    );
    assert_eq!(
        network.calls(),
        vec![V2_DID.to_string(), V1_DID.to_string()]
    );
    assert_eq!(network.publishes(), 0);
}

// Covers: ENBOX-AGENT-009
#[tokio::test]
async fn recovery_v2_transport_error_does_not_fall_back() {
    let network = Arc::new(RecordingNetwork::new(Outcome::Error, Outcome::Found));
    let (vault, store) = new_vault(network.clone());
    let error = vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentIdentityDidError");
    assert_eq!(network.calls(), vec![V2_DID.to_string()]);
    assert_eq!(network.publishes(), 0);
    assert!(vault.is_locked().await);
    assert!(!stored_status(&store).await.initialized);
}

// Covers: ENBOX-AGENT-009
#[tokio::test]
async fn recovery_v1_transport_error_does_not_fall_through_to_v2_publish() {
    let network = Arc::new(RecordingNetwork::new(Outcome::NotFound, Outcome::Error));
    let (vault, store) = new_vault(network.clone());
    let error = vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentIdentityDidError");
    assert_eq!(
        network.calls(),
        vec![V2_DID.to_string(), V1_DID.to_string()]
    );
    assert_eq!(network.publishes(), 0);
    assert!(vault.is_locked().await);
    assert!(!stored_status(&store).await.initialized);
}

// Covers: ENBOX-AGENT-001, ENBOX-AGENT-009
#[tokio::test]
async fn recovery_neither_version_found_publishes_v2() {
    let network = Arc::new(RecordingNetwork::new(Outcome::NotFound, Outcome::NotFound));
    let (vault, store) = new_vault(network.clone());
    let init = vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://dwn.example".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(init.portable_did.uri, V2_DID);
    assert_eq!(
        stored_status(&store).await.derivation_version,
        Some(VaultDerivationVersion::V2)
    );
    assert_eq!(
        network.calls(),
        vec![V2_DID.to_string(), V1_DID.to_string()]
    );
    assert_eq!(network.publishes(), 1);
}

// Covers: ENBOX-AGENT-001, ENBOX-AGENT-009
#[tokio::test]
async fn recovery_explicit_v1_resolves_v1_without_a_v2_lookup() {
    let network = Arc::new(RecordingNetwork::new(Outcome::Error, Outcome::Found));
    let (vault, store) = new_vault(network.clone());
    let init = vault
        .initialize_with_version(
            PASSWORD,
            Some(PHRASE),
            vec![],
            Some(VaultDerivationVersion::V1),
        )
        .await
        .unwrap();
    assert_eq!(init.portable_did.uri, V1_DID);
    assert_eq!(
        stored_status(&store).await.derivation_version,
        Some(VaultDerivationVersion::V1)
    );
    assert_eq!(network.calls(), vec![V1_DID.to_string()]);
    assert_eq!(network.publishes(), 0);
}

// Covers: ENBOX-AGENT-004
#[tokio::test]
async fn invalid_stored_derivation_version_is_corrupt() {
    let network = Arc::new(RecordingNetwork::new(Outcome::Found, Outcome::NotFound));
    let (vault, store) = new_vault(network);
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    vault.lock().await.unwrap();

    for raw in [
        r#"{"initialized":true,"lastBackup":null,"lastRestore":null,"derivationVersion":0}"#,
        r#"{"initialized":true,"lastBackup":null,"lastRestore":null,"derivationVersion":3}"#,
        r#"{"initialized":true,"lastBackup":null,"lastRestore":null,"derivationVersion":"2"}"#,
        r#"{"initialized":true,"lastBackup":null,"lastRestore":null,"derivationVersion":null}"#,
    ] {
        store
            .put(VAULT_STATUS_KEY, raw.as_bytes().to_vec())
            .await
            .unwrap();
        assert_eq!(
            vault.status().await.unwrap_err().code(),
            "AgentVaultCorrupt",
            "{raw}"
        );
    }
}

async fn v1_legacy_backup() -> IdentityVaultBackup {
    let (vault, _) = new_vault(Arc::new(RecordingNetwork::new(
        Outcome::Error,
        Outcome::Found,
    )));
    vault
        .initialize_with_version(
            PASSWORD,
            Some(PHRASE),
            vec![],
            Some(VaultDerivationVersion::V1),
        )
        .await
        .unwrap();
    let backup = vault.backup().await.unwrap();

    let mut data: Value = serde_json::from_slice(&base64url.decode(&backup.data).unwrap()).unwrap();
    data["status"]
        .as_object_mut()
        .unwrap()
        .remove("derivationVersion");
    let encoded = base64url.encode(serde_json::to_vec(&data).unwrap());
    IdentityVaultBackup {
        date_created: backup.date_created,
        size: serde_json::Number::from(encoded.chars().count() as u64),
        data: encoded,
    }
}

// Covers: ENBOX-AGENT-006
#[tokio::test]
async fn backup_preserves_v2_and_restore_legacy_v1_does_not_leak_v2() {
    let network = Arc::new(RecordingNetwork::new(Outcome::Found, Outcome::NotFound));
    let (v2, v2_store) = new_vault(network.clone());
    v2.initialize(PASSWORD, Some(PHRASE), vec![]).await.unwrap();
    let backup = v2.backup().await.unwrap();
    let decoded: Value = serde_json::from_slice(&base64url.decode(&backup.data).unwrap()).unwrap();
    assert_eq!(decoded["status"]["derivationVersion"], 2);
    assert_eq!(
        stored_status(&v2_store).await.derivation_version,
        Some(VaultDerivationVersion::V2)
    );

    let (restored, restored_store) = new_vault(Arc::new(RecordingNetwork::new(
        Outcome::Found,
        Outcome::NotFound,
    )));
    restored.restore(&backup, PASSWORD).await.unwrap();
    assert_eq!(
        stored_status(&restored_store).await.derivation_version,
        Some(VaultDerivationVersion::V2)
    );
    assert_eq!(restored.get_did().await.unwrap().uri, V2_DID);

    let legacy = v1_legacy_backup().await;
    v2.restore(&legacy, PASSWORD).await.unwrap();
    assert_eq!(stored_status(&v2_store).await.derivation_version, None);
    assert_eq!(v2.get_did().await.unwrap().uri, V1_DID);
}

// Covers: ENBOX-AGENT-006, ENBOX-AGENT-007
#[tokio::test]
async fn wrong_password_legacy_restore_keeps_v2_vault_locked_and_unchanged() {
    let network = Arc::new(RecordingNetwork::new(Outcome::Found, Outcome::NotFound));
    let (v2, v2_store) = new_vault(network);
    v2.initialize(PASSWORD, Some(PHRASE), vec![]).await.unwrap();
    let legacy = v1_legacy_backup().await;
    let before = snapshot(&v2_store).await;

    let error = v2.restore(&legacy, "wrong-password").await.unwrap_err();
    assert_eq!(error.code(), "AgentVaultInvalidPassword");
    assert!(v2.is_locked().await);
    assert_eq!(snapshot(&v2_store).await, before);
    assert_eq!(
        stored_status(&v2_store).await.derivation_version,
        Some(VaultDerivationVersion::V2)
    );
}

// Covers: ENBOX-AGENT-006, ENBOX-AGENT-007
#[tokio::test]
async fn restore_rejects_invalid_backup_derivation_version() {
    let (vault, store) = new_vault(Arc::new(RecordingNetwork::new(
        Outcome::Found,
        Outcome::NotFound,
    )));
    vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();
    let backup = vault.backup().await.unwrap();
    let before = snapshot(&store).await;
    let data: Value = serde_json::from_slice(&base64url.decode(&backup.data).unwrap()).unwrap();

    for invalid in [
        serde_json::json!(0),
        serde_json::json!(3),
        serde_json::json!("2"),
        Value::Null,
    ] {
        let mut payload = data.clone();
        payload["status"]["derivationVersion"] = invalid;
        let encoded = base64url.encode(serde_json::to_vec(&payload).unwrap());
        let candidate = IdentityVaultBackup {
            date_created: backup.date_created.clone(),
            size: serde_json::Number::from(encoded.chars().count() as u64),
            data: encoded,
        };
        let error = vault.restore(&candidate, PASSWORD).await.unwrap_err();
        assert_eq!(error.code(), "AgentVaultInvalidBackup");
        assert!(vault.is_locked().await);
        assert_eq!(snapshot(&store).await, before);
    }
}

// Covers: ENBOX-AGENT-005
#[tokio::test]
async fn reset_uses_the_stored_version_for_legacy_v1_v1_and_v2() {
    // Legacy V1: status has no version field.
    let network = Arc::new(RecordingNetwork::new(Outcome::Error, Outcome::Found));
    let (legacy, legacy_store) = new_vault(network);
    legacy
        .initialize_with_version(
            PASSWORD,
            Some(PHRASE),
            vec![],
            Some(VaultDerivationVersion::V1),
        )
        .await
        .unwrap();
    let status = stored_status(&legacy_store).await;
    let legacy_bytes = serde_json::json!({
        "initialized": status.initialized,
        "lastBackup": status.last_backup,
        "lastRestore": status.last_restore,
    });
    legacy_store
        .put(VAULT_STATUS_KEY, serde_json::to_vec(&legacy_bytes).unwrap())
        .await
        .unwrap();
    legacy
        .reset_password_with_recovery_phrase(PHRASE, PASSWORD_2, None)
        .await
        .unwrap();
    assert_eq!(stored_status(&legacy_store).await.derivation_version, None);

    // Explicit V1.
    let (v1, v1_store) = new_vault(Arc::new(RecordingNetwork::new(
        Outcome::Error,
        Outcome::Found,
    )));
    v1.initialize_with_version(
        PASSWORD,
        Some(PHRASE),
        vec![],
        Some(VaultDerivationVersion::V1),
    )
    .await
    .unwrap();
    v1.reset_password_with_recovery_phrase(PHRASE, PASSWORD_2, None)
        .await
        .unwrap();
    assert_eq!(
        stored_status(&v1_store).await.derivation_version,
        Some(VaultDerivationVersion::V1)
    );

    // V2.
    let (v2, v2_store) = new_vault(Arc::new(RecordingNetwork::new(
        Outcome::Found,
        Outcome::NotFound,
    )));
    v2.initialize(PASSWORD, Some(PHRASE), vec![]).await.unwrap();
    v2.reset_password_with_recovery_phrase(PHRASE, PASSWORD_2, None)
        .await
        .unwrap();
    assert_eq!(
        stored_status(&v2_store).await.derivation_version,
        Some(VaultDerivationVersion::V2)
    );
    v2.lock().await.unwrap();
    v2.unlock(PASSWORD_2).await.unwrap();
}

// Covers: ENBOX-AGENT-005
#[tokio::test]
async fn reset_mismatch_on_legacy_v1_keeps_the_store_unchanged() {
    let (vault, store) = new_vault(Arc::new(RecordingNetwork::new(
        Outcome::Error,
        Outcome::Found,
    )));
    vault
        .initialize_with_version(
            PASSWORD,
            Some(PHRASE),
            vec![],
            Some(VaultDerivationVersion::V1),
        )
        .await
        .unwrap();
    let status = stored_status(&store).await;
    store
        .put(
            VAULT_STATUS_KEY,
            serde_json::to_vec(&serde_json::json!({
                "initialized": status.initialized,
                "lastBackup": status.last_backup,
                "lastRestore": status.last_restore,
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let before = snapshot(&store).await;
    let error = vault
        .reset_password_with_recovery_phrase(OTHER_PHRASE, PASSWORD_2, None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "HD_IDENTITY_VAULT_RECOVERY_PHRASE_MISMATCH");
    assert!(vault.is_locked().await);
    assert_eq!(snapshot(&store).await, before);
}
