use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use chrono::{Duration, Utc};
use dwn_rs_core::identity::agent::{
    AgentIdentityInitializeRequest, AgentIdentityService, DeterministicDidJwkProvider,
    IdentityMetadata, MemoryDidResolverCache, MemoryKeyManager, MemorySecretStore,
    PortableIdentity,
};
use dwn_rs_core::identity::connect::{
    create_delegate_grant, derive_delegate_keys, load_delegate_decryption_keys,
    save_delegate_decryption_keys, ConnectPermissionRequest,
};
use dwn_rs_core::identity::setup::{
    install_protocol_if_needed, register_with_dwn_endpoints, run_restore_flow, DwnServerInfo,
    MemoryProtocolEndpoint, RegistrationMethod, TenantRegistrationClient,
    TenantRegistrationRequest,
};
use dwn_rs_core::identity::setup::{RegistrationTokenData, SetupFuture};
use dwn_rs_core::interfaces::messages::protocols::{
    Action, ActionWho, Can, Definition, RuleSet, Type, Who,
};
use dwn_rs_core::permissions::PermissionScope;

const RECOVERY_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[tokio::test]
async fn wallet_recovery_restores_encrypted_protocol_and_delegate_read_state() {
    let original = recovered_agent(RECOVERY_PHRASE).await;
    let protocol = encrypted_protocol();
    let local = MemoryProtocolEndpoint::default();
    let remote = MemoryProtocolEndpoint::default();
    let identities = IdentityTenantStore::default();
    let identity = PortableIdentity {
        portable_did: original.portable_did.clone(),
        metadata: IdentityMetadata {
            name: "Recovered Wallet".to_string(),
            tenant: original.portable_did.uri.clone(),
            uri: original.portable_did.uri.clone(),
            connected_did: None,
        },
    };
    identities.insert(&original.portable_did.uri, identity.clone());

    let setup = run_restore_flow(
        &local,
        &remote,
        &original.key_manager,
        &original.portable_did,
        vec![protocol.clone()],
    )
    .await
    .unwrap();
    assert_eq!(setup.local_installs.len(), 1);
    assert_eq!(setup.remote_pushes.len(), 1);
    let installed = local
        .protocol(&original.portable_did.uri, &protocol.protocol)
        .unwrap();
    assert!(installed.structure["note"].encryption.is_some());

    let delegate_read = derive_delegate_keys(
        &original.key_manager,
        &original.portable_did,
        &[ConnectPermissionRequest {
            protocol_definition: protocol.clone(),
            permission_scopes: vec![records_scope("Read", Some("note"))],
        }],
    )
    .await
    .unwrap();
    let delegate_write = derive_delegate_keys(
        &original.key_manager,
        &original.portable_did,
        &[ConnectPermissionRequest {
            protocol_definition: protocol.clone(),
            permission_scopes: vec![records_scope("Write", Some("note"))],
        }],
    )
    .await
    .unwrap();
    assert_eq!(delegate_read.decryption_keys.len(), 1);
    assert!(delegate_write.decryption_keys.is_empty());
    save_delegate_decryption_keys(&original.secret_store, &delegate_read.decryption_keys)
        .await
        .unwrap();

    let restored = recovered_agent(RECOVERY_PHRASE).await;
    assert_eq!(restored.portable_did.uri, original.portable_did.uri);
    let recovered_identities = identities.list(&restored.portable_did.uri);
    assert_eq!(recovered_identities.len(), 1);
    assert_eq!(recovered_identities[0].metadata.name, "Recovered Wallet");

    let registration_client = MockRegistrationClient::default();
    registration_client.set_server_info(
        "https://remote.example",
        DwnServerInfo {
            registration_requirements: vec!["proof-of-work".to_string()],
            provider_auth: None,
        },
    );
    let registration = register_with_dwn_endpoints(
        &registration_client,
        None::<&MemorySecretStore>,
        TenantRegistrationRequest {
            dwn_endpoints: vec!["https://remote.example".to_string()],
            agent_did: restored.portable_did.uri.clone(),
            connected_did: recovered_identities[0].portable_did.uri.clone(),
            persist_tokens: false,
            registration_tokens: BTreeMap::new(),
        },
    )
    .await
    .unwrap();
    assert!(registration
        .records
        .iter()
        .all(|record| record.method == RegistrationMethod::Anonymous));

    let pulled_remote_protocol = remote
        .protocol(&restored.portable_did.uri, &protocol.protocol)
        .unwrap();
    assert!(pulled_remote_protocol.structure["note"]
        .encryption
        .is_some());

    save_delegate_decryption_keys(&restored.secret_store, &delegate_read.decryption_keys)
        .await
        .unwrap();
    let restored_delegate_keys = load_delegate_decryption_keys(&restored.secret_store)
        .await
        .unwrap();
    assert_eq!(restored_delegate_keys, delegate_read.decryption_keys);

    let grant = create_delegate_grant(
        &restored.portable_did.uri,
        "did:example:delegate",
        records_scope("Read", Some("note")),
        Utc::now() + Duration::days(1),
        None,
    );
    assert_eq!(
        grant.scope.protocol.as_deref(),
        Some(protocol.protocol.as_str())
    );

    let mut no_encryption_did = restored.portable_did.clone();
    no_encryption_did.document.key_agreement.clear();
    let plaintext_fallback = install_protocol_if_needed(
        &MemoryProtocolEndpoint::default(),
        &restored.key_manager,
        &no_encryption_did,
        protocol,
    )
    .await;
    assert_eq!(
        plaintext_fallback.unwrap_err().code,
        "ProtocolInstallMissingKeyAgreement"
    );
}

struct RecoveredAgent {
    portable_did: dwn_rs_core::identity::agent::PortableDid,
    key_manager: MemoryKeyManager,
    secret_store: MemorySecretStore,
}

async fn recovered_agent(recovery_phrase: &str) -> RecoveredAgent {
    let key_manager = MemoryKeyManager::default();
    let secret_store = MemorySecretStore::default();
    let service = AgentIdentityService::new(
        DeterministicDidJwkProvider::default(),
        key_manager.clone(),
        secret_store.clone(),
        MemoryDidResolverCache::default(),
    );
    let initialization = service
        .initialize_from_recovery(AgentIdentityInitializeRequest {
            recovery_phrase: Some(recovery_phrase.to_string()),
            dwn_endpoints: Vec::new(),
        })
        .await
        .unwrap();
    RecoveredAgent {
        portable_did: initialization.portable_did,
        key_manager,
        secret_store,
    }
}

#[derive(Clone, Default)]
struct IdentityTenantStore {
    identities: Arc<RwLock<BTreeMap<String, Vec<PortableIdentity>>>>,
}

impl IdentityTenantStore {
    fn insert(&self, tenant: &str, identity: PortableIdentity) {
        self.identities
            .write()
            .unwrap()
            .entry(tenant.to_string())
            .or_default()
            .push(identity);
    }

    fn list(&self, tenant: &str) -> Vec<PortableIdentity> {
        self.identities
            .read()
            .unwrap()
            .get(tenant)
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Clone, Default)]
struct MockRegistrationClient {
    state: Arc<RwLock<MockRegistrationState>>,
}

#[derive(Default)]
struct MockRegistrationState {
    server_info: BTreeMap<String, DwnServerInfo>,
    registered: Vec<(String, String)>,
}

impl MockRegistrationClient {
    fn set_server_info(&self, endpoint: &str, server_info: DwnServerInfo) {
        self.state
            .write()
            .unwrap()
            .server_info
            .insert(endpoint.to_string(), server_info);
    }
}

impl TenantRegistrationClient for MockRegistrationClient {
    fn server_info<'a>(&'a self, endpoint: &'a str) -> SetupFuture<'a, DwnServerInfo> {
        Box::pin(async move {
            Ok(self
                .state
                .read()
                .unwrap()
                .server_info
                .get(endpoint)
                .cloned()
                .unwrap_or_default())
        })
    }

    fn register_tenant<'a>(&'a self, endpoint: &'a str, did: &'a str) -> SetupFuture<'a, ()> {
        Box::pin(async move {
            self.state
                .write()
                .unwrap()
                .registered
                .push((endpoint.to_string(), did.to_string()));
            Ok(())
        })
    }

    fn register_tenant_with_token<'a>(
        &'a self,
        endpoint: &'a str,
        did: &'a str,
        _registration_token: &'a str,
    ) -> SetupFuture<'a, ()> {
        self.register_tenant(endpoint, did)
    }

    fn refresh_registration_token<'a>(
        &'a self,
        _refresh_url: &'a str,
        _refresh_token: &'a str,
    ) -> SetupFuture<'a, RegistrationTokenData> {
        Box::pin(async move {
            Err(dwn_rs_core::identity::agent::AgentIdentityError::new(
                "UnexpectedRefresh",
                "test does not use provider auth",
            ))
        })
    }
}

fn records_scope(method: &str, protocol_path: Option<&str>) -> PermissionScope {
    PermissionScope {
        interface: "Records".to_string(),
        method: method.to_string(),
        protocol: Some("https://protocol.example/notes".to_string()),
        context_id: None,
        protocol_path: protocol_path.map(ToString::to_string),
    }
}

fn encrypted_protocol() -> Definition {
    Definition {
        protocol: "https://protocol.example/notes".to_string(),
        published: true,
        uses: None,
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
