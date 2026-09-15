use std::collections::BTreeMap;
use std::sync::Arc;

use dwn_rs_agent::agent::{
    derive_agent_keys, AgentDidCreateRequest, AgentIdentityError, AgentIdentityInitializeRequest,
    AgentIdentityService, AgentKeyManager, DeterministicDidJwkProvider, DidProvider,
    IdentityMetadata, MemoryKeyManager, MemoryPortableDidStore, MemorySecretStore, PortableDid,
    PortableDidStore, PortableIdentity, SecretStore, VAULT_PORTABLE_DID_KEY,
};
use dwn_rs_agent::auth::connect::{
    derive_context_key, derive_delegate_keys, write_context_key_record, ConnectPermissionRequest,
    KeyDeliveryStore, MemoryKeyDeliveryStore,
};
use dwn_rs_agent::auth::setup::{
    install_protocol_if_needed, register_with_dwn_endpoints, run_restore_flow, DwnServerInfo,
    MemoryProtocolEndpoint, ProtocolEndpoint, RegistrationTokenData, SetupFuture,
    TenantRegistrationClient, TenantRegistrationRequest, TenantRegistrationResult,
};
use dwn_rs_core::interfaces::messages::protocols::{
    Action, ActionWho, Can, Definition, RuleSet, Type, Who,
};
use dwn_rs_core::permissions::{PermissionScope, RecordsMethod, RecordsScope, RecordsSelector};

const RECOVERY_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn derivation_golden_vector() {
    let keys = derive_agent_keys(RECOVERY_PHRASE).unwrap();
    assert_eq!(
        hex(&keys.vault_content_encryption_key),
        "b99ff78488da4c83cbe590b5374bfca38551eb47e65514667018cc33c91f4913"
    );
    assert_eq!(
        hex(&keys.vault_unlock_salt),
        "b19bdb50f65b597dd0b4b341dca2eeb00d0b8935854e9b800a7fb68f7b7fdc0f"
    );
}

#[tokio::test]
async fn recovery_golden_did_uri() {
    let service = concrete_service();
    let init = service
        .initialize_from_recovery(AgentIdentityInitializeRequest {
            recovery_phrase: Some(RECOVERY_PHRASE.to_string()),
            dwn_endpoints: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(
        init.portable_did.uri,
        "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImNXTC0zXzQ3Mk5LQ1dKRHJQdTJtMnRHRzVNT0p2SXZnMktIMS1nLWVoTU0ifQ"
    );
}

#[test]
fn invalid_mnemonic_keeps_code() {
    let error = derive_agent_keys("not a valid recovery phrase").unwrap_err();
    assert_eq!(error.code(), "AgentIdentityInvalidMnemonic");
    assert_eq!(
        error.to_string(),
        format!("AgentIdentityInvalidMnemonic: {}", error.detail())
    );
}

#[tokio::test]
async fn key_manager_failures_keep_codes_and_hide_secrets() {
    let manager = MemoryKeyManager::default();
    let derived = derive_agent_keys(RECOVERY_PHRASE).unwrap();
    let public_jwk = derived.signing_private_jwk.to_public();
    let public_json = serde_json::to_string(&derived.signing_private_jwk).unwrap();

    let error = manager.import_private_jwk(public_jwk).await.unwrap_err();
    assert_eq!(error.code(), "AgentIdentityKeyManagerError");
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains(&public_json));
    }

    let error = manager
        .derive_private_jwk("urn:jwk:missing", vec!["protocolPath".to_string()])
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentIdentityKeyManagerError");
    assert!(error.detail().contains("urn:jwk:missing"));
}

#[tokio::test]
async fn corrupt_stored_did_keeps_vault_code() {
    let store = MemorySecretStore::default();
    store
        .put(VAULT_PORTABLE_DID_KEY, b"not-json".to_vec())
        .await
        .unwrap();
    let service = AgentIdentityService::new(
        DeterministicDidJwkProvider::default(),
        MemoryKeyManager::default(),
        store,
        MemoryPortableDidStore::default(),
    );
    let error = service.stored_agent_did().await.unwrap_err();
    assert_eq!(error.code(), "AgentIdentityVaultError");
}

#[tokio::test]
async fn missing_key_agreement_keeps_codes() {
    let (mut portable_did, key_manager) = agent_did_with_keys().await;
    portable_did
        .document
        .verification_relationships
        .key_agreement
        .clear();

    let error = derive_delegate_keys(
        &key_manager,
        &portable_did,
        &[read_request("https://protocol.example/notes")],
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "DelegateKeyMissingKeyAgreement");

    let error = install_protocol_if_needed(
        &MemoryProtocolEndpoint::default(),
        &key_manager,
        &portable_did,
        encrypted_protocol(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "ProtocolInstallMissingKeyAgreement");
}

#[tokio::test]
async fn non_x25519_key_agreement_keeps_codes() {
    let (did, key_manager) = agent_did_with_non_x25519_agreement().await;

    let error = derive_delegate_keys(
        &key_manager,
        &did,
        &[read_request("https://protocol.example/notes")],
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "DelegateKeyMissingX25519");
    assert!(error.detail().contains("X25519"));

    let error = install_protocol_if_needed(
        &MemoryProtocolEndpoint::default(),
        &key_manager,
        &did,
        encrypted_protocol(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "ProtocolInstallMissingX25519");
    assert!(error.detail().contains("X25519"));
}

#[test]
fn implementor_defined_codes_pass_through() {
    for code in ["HttpRegistrationTransportFailed", "CustomHostCode"] {
        let error = AgentIdentityError::new(code, "host detail");
        assert_eq!(error.code(), code);
        assert_eq!(error.detail(), "host detail");
        assert_eq!(error.to_string(), format!("{code}: host detail"));
    }
}

#[tokio::test]
async fn backend_failure_from_registration_client_surfaces_unchanged() {
    let client = FailingRegistrationClient;
    let error = register_with_dwn_endpoints(
        &client,
        None::<&MemorySecretStore>,
        TenantRegistrationRequest {
            dwn_endpoints: vec!["https://dwn.example".to_string()],
            agent_did: "did:example:agent".to_string(),
            connected_did: "did:example:agent".to_string(),
            persist_tokens: false,
            registration_tokens: BTreeMap::new(),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "CustomBackendFailure");
    assert_eq!(error.detail(), "backend exploded");
}

#[tokio::test]
async fn arc_dyn_backends_match_concrete_backends() {
    let concrete = concrete_service()
        .initialize_from_recovery(AgentIdentityInitializeRequest {
            recovery_phrase: Some(RECOVERY_PHRASE.to_string()),
            dwn_endpoints: Vec::new(),
        })
        .await
        .unwrap();

    let provider: Arc<dyn DidProvider> = Arc::new(DeterministicDidJwkProvider::default());
    let key_manager: Arc<dyn AgentKeyManager> = Arc::new(MemoryKeyManager::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(MemorySecretStore::default());
    let did_store: Arc<dyn PortableDidStore> = Arc::new(MemoryPortableDidStore::default());
    let service = AgentIdentityService::new(provider, key_manager, secret_store.clone(), did_store);
    let dynamic = service
        .initialize_from_recovery(AgentIdentityInitializeRequest {
            recovery_phrase: Some(RECOVERY_PHRASE.to_string()),
            dwn_endpoints: Vec::new(),
        })
        .await
        .unwrap();

    assert_eq!(dynamic.portable_did.uri, concrete.portable_did.uri);
    assert_eq!(dynamic.key_uris.len(), concrete.key_uris.len());
    assert_eq!(
        dynamic.portable_did.document.verification_method.len(),
        concrete.portable_did.document.verification_method.len()
    );
    let stored = service.stored_agent_did().await.unwrap().unwrap();
    assert_eq!(stored.uri, concrete.portable_did.uri);

    let client: Arc<dyn TenantRegistrationClient> = Arc::new(EmptyRegistrationClient);
    let registration = register_with_dwn_endpoints(
        &client,
        Some(&secret_store),
        TenantRegistrationRequest {
            dwn_endpoints: vec!["https://dwn.example".to_string()],
            agent_did: dynamic.portable_did.uri.clone(),
            connected_did: dynamic.portable_did.uri.clone(),
            persist_tokens: false,
            registration_tokens: BTreeMap::new(),
        },
    )
    .await
    .unwrap();
    assert_eq!(registration.records.len(), 1);

    let local: Arc<dyn ProtocolEndpoint> = Arc::new(MemoryProtocolEndpoint::default());
    let remote: Arc<dyn ProtocolEndpoint> = Arc::new(MemoryProtocolEndpoint::default());
    let key_manager: Arc<dyn AgentKeyManager> = Arc::new(MemoryKeyManager::default());
    for private_jwk in &dynamic.portable_did.private_keys {
        key_manager
            .import_private_jwk(private_jwk.clone())
            .await
            .unwrap();
    }
    let restore = run_restore_flow(
        &local,
        &remote,
        &key_manager,
        &dynamic.portable_did,
        vec![encrypted_protocol()],
    )
    .await
    .unwrap();
    assert!(restore.local_installs[0].installed);
    assert!(restore.remote_pushes[0].installed);

    let delivery: Arc<dyn KeyDeliveryStore> = Arc::new(MemoryKeyDeliveryStore::default());
    let context_key = derive_context_key(
        &key_manager,
        &dynamic.portable_did,
        "https://protocol.example/notes",
        "context-1",
    )
    .await
    .unwrap();
    let id = write_context_key_record(
        &delivery,
        &dynamic.portable_did.uri,
        "did:example:delegate",
        "https://protocol.example/notes",
        "context-1",
        context_key.clone(),
    )
    .await
    .unwrap();
    assert!(!id.is_empty());
    let fetched = delivery
        .fetch_context_key(
            &dynamic.portable_did.uri,
            "did:example:delegate",
            "https://protocol.example/notes",
            "context-1",
        )
        .await
        .unwrap();
    assert_eq!(fetched, Some(context_key));
}

#[tokio::test]
async fn shared_key_manager_survives_concurrent_tasks() {
    let manager: Arc<dyn AgentKeyManager> = Arc::new(MemoryKeyManager::default());
    let derived = derive_agent_keys(RECOVERY_PHRASE).unwrap();
    let private_json = serde_json::to_value(&derived.signing_private_jwk).unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let manager = manager.clone();
        let jwk: ssi_jwk::JWK = serde_json::from_value(private_json.clone()).unwrap();
        handles.push(tokio::spawn(async move {
            let uri = manager.import_private_jwk(jwk).await.unwrap();
            assert!(manager.export_private_jwk(&uri).await.unwrap().is_some());
            assert!(manager.public_jwk(&uri).await.unwrap().is_some());
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn debug_omits_secrets_but_keeps_identifiers() {
    let keys = derive_agent_keys(RECOVERY_PHRASE).unwrap();
    let private_json = serde_json::to_string(&keys.signing_private_jwk).unwrap();
    let cek_rendered = format!("{:?}", keys.vault_content_encryption_key);

    let service = concrete_service();
    let init = service
        .initialize_from_recovery(AgentIdentityInitializeRequest {
            recovery_phrase: Some(RECOVERY_PHRASE.to_string()),
            dwn_endpoints: Vec::new(),
        })
        .await
        .unwrap();

    let did_debug = format!("{:?}", init.portable_did);
    assert!(!did_debug.contains(&private_json));
    assert!(!did_debug.contains("private_keys"));
    assert!(did_debug.contains(&init.portable_did.uri));

    let identity = PortableIdentity {
        portable_did: init.portable_did.clone(),
        metadata: IdentityMetadata {
            name: "Test".to_string(),
            tenant: init.portable_did.uri.clone(),
            uri: init.portable_did.uri.clone(),
            connected_did: None,
        },
    };
    let identity_debug = format!("{identity:?}");
    assert!(!identity_debug.contains(&private_json));
    assert!(identity_debug.contains(&init.portable_did.uri));

    let derived_debug = format!("{:?}", keys);
    assert!(!derived_debug.contains(&private_json));
    assert!(!derived_debug.contains(&cek_rendered));

    let init_debug = format!("{init:?}");
    assert!(!init_debug.contains(RECOVERY_PHRASE));
    assert!(!init_debug.contains(&cek_rendered));
    assert!(!init_debug.contains(&private_json));
    assert!(init_debug.contains(&init.portable_did.uri));
    assert!(init_debug.contains(&init.key_uris[0]));

    let request = AgentIdentityInitializeRequest {
        recovery_phrase: Some(RECOVERY_PHRASE.to_string()),
        dwn_endpoints: Vec::new(),
    };
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains(RECOVERY_PHRASE));

    let create = AgentDidCreateRequest {
        identity_private_jwk: keys.identity_private_jwk.clone(),
        signing_private_jwk: keys.signing_private_jwk.clone(),
        encryption_private_jwk: keys.encryption_private_jwk.clone(),
        dwn_endpoints: Vec::new(),
    };
    assert!(!format!("{create:?}").contains(&private_json));

    let context_key = derive_context_key(
        service.key_manager(),
        &init.portable_did,
        "https://protocol.example/notes",
        "context-1",
    )
    .await
    .unwrap();
    let derived_private_json =
        serde_json::to_string(&context_key.derived_private_key.derived_private_key).unwrap();
    let key_debug = format!("{context_key:?}");
    assert!(!key_debug.contains(&derived_private_json));
    assert!(key_debug.contains(&context_key.derived_private_key.root_key_id));

    let tokens = RegistrationTokenData {
        registration_token: "registration-secret".to_string(),
        refresh_token: Some("refresh-secret".to_string()),
        expires_at: Some(1),
        token_url: "https://auth.example/token".to_string(),
        refresh_url: Some("https://auth.example/refresh".to_string()),
    };
    let token_debug = format!("{tokens:?}");
    assert!(!token_debug.contains("registration-secret"));
    assert!(!token_debug.contains("refresh-secret"));
    assert!(token_debug.contains("https://auth.example/token"));

    let outer = TenantRegistrationResult {
        records: Vec::new(),
        registration_tokens: BTreeMap::from([("https://dwn.example".to_string(), tokens)]),
    };
    let outer_debug = format!("{outer:?}");
    assert!(!outer_debug.contains("registration-secret"));
    assert!(!outer_debug.contains("refresh-secret"));
}

#[test]
fn serde_still_carries_secrets() {
    let keys = derive_agent_keys(RECOVERY_PHRASE).unwrap();
    let json = serde_json::to_value(&keys).unwrap();
    assert!(json.get("identityPrivateJwk").is_some());
    assert!(json.get("vaultContentEncryptionKey").is_some());

    let tokens = RegistrationTokenData {
        registration_token: "registration-secret".to_string(),
        refresh_token: Some("refresh-secret".to_string()),
        expires_at: None,
        token_url: "https://auth.example/token".to_string(),
        refresh_url: None,
    };
    let json = serde_json::to_value(&tokens).unwrap();
    assert_eq!(json["registrationToken"], "registration-secret");
}

fn concrete_service() -> AgentIdentityService<
    DeterministicDidJwkProvider,
    MemoryKeyManager,
    MemorySecretStore,
    MemoryPortableDidStore,
> {
    AgentIdentityService::new(
        DeterministicDidJwkProvider::default(),
        MemoryKeyManager::default(),
        MemorySecretStore::default(),
        MemoryPortableDidStore::default(),
    )
}

async fn agent_did_with_keys() -> (PortableDid, MemoryKeyManager) {
    let key_manager = MemoryKeyManager::default();
    let service = AgentIdentityService::new(
        DeterministicDidJwkProvider::default(),
        key_manager.clone(),
        MemorySecretStore::default(),
        MemoryPortableDidStore::default(),
    );
    let init = service
        .initialize_from_recovery(AgentIdentityInitializeRequest {
            recovery_phrase: Some(RECOVERY_PHRASE.to_string()),
            dwn_endpoints: Vec::new(),
        })
        .await
        .unwrap();
    (init.portable_did, key_manager)
}

async fn agent_did_with_non_x25519_agreement() -> (PortableDid, MemoryKeyManager) {
    let key_manager = MemoryKeyManager::default();
    let service = AgentIdentityService::new(
        DeterministicDidJwkProvider::default(),
        key_manager.clone(),
        MemorySecretStore::default(),
        MemoryPortableDidStore::default(),
    );
    let init = service
        .initialize_from_recovery(AgentIdentityInitializeRequest {
            recovery_phrase: Some(RECOVERY_PHRASE.to_string()),
            dwn_endpoints: Vec::new(),
        })
        .await
        .unwrap();
    for private_jwk in &init.portable_did.private_keys {
        key_manager
            .import_private_jwk(private_jwk.clone())
            .await
            .unwrap();
    }
    let mut portable_did = init.portable_did;
    let agreement_id = portable_did
        .document
        .verification_relationships
        .key_agreement
        .first()
        .map(|id| id.id().resolve(&portable_did.document.id).to_string())
        .unwrap();
    let signing_public = derive_agent_keys(RECOVERY_PHRASE)
        .unwrap()
        .signing_private_jwk
        .to_public();
    for method in &mut portable_did.document.verification_method {
        if method.id.as_str() == agreement_id {
            method.properties.insert(
                "publicKeyJwk".to_string(),
                serde_json::to_value(&signing_public).unwrap(),
            );
        }
    }
    (portable_did, key_manager)
}

fn read_request(protocol: &str) -> ConnectPermissionRequest {
    ConnectPermissionRequest {
        protocol_definition: encrypted_protocol_for(protocol),
        permission_scopes: vec![PermissionScope::Records(RecordsScope {
            method: RecordsMethod::Read,
            protocol: protocol.to_string(),
            selector: Some(RecordsSelector::ProtocolPath(
                dwn_rs_core::permissions::ProtocolPath("note".to_string()),
            )),
        })],
    }
}

fn encrypted_protocol() -> Definition {
    encrypted_protocol_for("https://protocol.example/notes")
}

fn encrypted_protocol_for(protocol: &str) -> Definition {
    Definition {
        protocol: protocol.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([(
            "note".to_string(),
            Type {
                schema: None,
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: Some(true),
            },
        )]),
        structure: BTreeMap::from([(
            "note".to_string(),
            RuleSet {
                actions: vec![Action::Who(ActionWho {
                    who: Who::Anyone,
                    of: None,
                    can: vec![Can::Create],
                })],
                ..Default::default()
            },
        )]),
    }
}

#[derive(Clone, Default)]
struct EmptyRegistrationClient;

impl TenantRegistrationClient for EmptyRegistrationClient {
    fn server_info<'a>(&'a self, _endpoint: &'a str) -> SetupFuture<'a, DwnServerInfo> {
        Box::pin(async move { Ok(DwnServerInfo::default()) })
    }

    fn register_tenant<'a>(&'a self, _endpoint: &'a str, _did: &'a str) -> SetupFuture<'a, ()> {
        Box::pin(async move { Ok(()) })
    }

    fn register_tenant_with_token<'a>(
        &'a self,
        _endpoint: &'a str,
        _did: &'a str,
        _registration_token: &'a str,
    ) -> SetupFuture<'a, ()> {
        Box::pin(async move { Ok(()) })
    }

    fn refresh_registration_token<'a>(
        &'a self,
        _refresh_url: &'a str,
        _refresh_token: &'a str,
    ) -> SetupFuture<'a, RegistrationTokenData> {
        Box::pin(async move {
            Err(AgentIdentityError::new(
                "UnexpectedRefresh",
                "test does not use provider auth",
            ))
        })
    }
}

#[derive(Clone, Default)]
struct FailingRegistrationClient;

impl TenantRegistrationClient for FailingRegistrationClient {
    fn server_info<'a>(&'a self, _endpoint: &'a str) -> SetupFuture<'a, DwnServerInfo> {
        Box::pin(async move {
            Err(AgentIdentityError::new(
                "CustomBackendFailure",
                "backend exploded",
            ))
        })
    }

    fn register_tenant<'a>(&'a self, _endpoint: &'a str, _did: &'a str) -> SetupFuture<'a, ()> {
        Box::pin(async move { Ok(()) })
    }

    fn register_tenant_with_token<'a>(
        &'a self,
        _endpoint: &'a str,
        _did: &'a str,
        _registration_token: &'a str,
    ) -> SetupFuture<'a, ()> {
        Box::pin(async move { Ok(()) })
    }

    fn refresh_registration_token<'a>(
        &'a self,
        _refresh_url: &'a str,
        _refresh_token: &'a str,
    ) -> SetupFuture<'a, RegistrationTokenData> {
        Box::pin(async move {
            Err(AgentIdentityError::new(
                "UnexpectedRefresh",
                "test does not use provider auth",
            ))
        })
    }
}
