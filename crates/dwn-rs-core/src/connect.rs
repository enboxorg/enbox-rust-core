use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::agent::{
    AgentIdentityError, AgentIdentityResult, AgentKeyManager, DidProvider, JsonWebKey, PortableDid,
    SecretStore,
};
use crate::interfaces::messages::protocols::{Action, Can, Definition, RuleSet, Who};
use crate::permissions::PermissionScope;
use crate::setup::protocol_requires_encryption;

pub type ConnectFuture<'a, T> = Pin<Box<dyn Future<Output = AgentIdentityResult<T>> + Send + 'a>>;

pub const DELEGATE_DECRYPTION_KEYS_KEY: &str = "enbox:auth:delegateDecryptionKeys";
pub const DELEGATE_CONTEXT_KEYS_KEY: &str = "enbox:auth:delegateContextKeys";
pub const DELEGATE_MULTI_PARTY_PROTOCOLS_KEY: &str = "enbox:auth:delegateMultiPartyProtocols";
pub const SESSION_REVOCATIONS_KEY: &str = "enbox:auth:sessionRevocations";

const PROTOCOL_PATH_DERIVATION_SCHEME: &str = "protocolPath";
const PROTOCOL_CONTEXT_DERIVATION_SCHEME: &str = "protocolContext";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectPermissionRequest {
    pub protocol_definition: Definition,
    pub permission_scopes: Vec<PermissionScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestRecord {
    pub id: String,
    pub requester: String,
    pub delegated: bool,
    pub scope: PermissionScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateGrant {
    pub id: String,
    pub grantor: String,
    pub grantee: String,
    pub date_granted: DateTime<Utc>,
    pub date_expires: DateTime<Utc>,
    pub delegated: bool,
    pub scope: PermissionScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRevocation {
    pub grant_id: String,
    pub revocation_grant_id: String,
    pub grantor: String,
    pub grantee: String,
    pub date_revoked: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedPrivateJwk {
    pub root_key_id: String,
    pub derivation_scheme: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derivation_path: Vec<String>,
    pub derived_private_key: JsonWebKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum DelegateDecryptionScope {
    Protocol,
    ProtocolPath {
        protocol_path: String,
        #[serde(rename = "match")]
        match_: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateDecryptionKey {
    pub protocol: String,
    pub scope: DelegateDecryptionScope,
    pub derived_private_key: DerivedPrivateJwk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateContextKey {
    pub protocol: String,
    pub context_id: String,
    pub derived_private_key: DerivedPrivateJwk,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateKeyDerivationResult {
    pub decryption_keys: Vec<DelegateDecryptionKey>,
    pub context_keys: Vec<DelegateContextKey>,
    pub multi_party_protocols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextKeyDeliveryRecord {
    pub id: String,
    pub tenant_did: String,
    pub recipient_did: String,
    pub source_protocol: String,
    pub source_context_id: String,
    pub context_key: DelegateContextKey,
}

pub trait KeyDeliveryStore: Clone + Send + Sync + 'static {
    fn write_context_key<'a>(
        &'a self,
        record: ContextKeyDeliveryRecord,
    ) -> ConnectFuture<'a, String>;

    fn fetch_context_key<'a>(
        &'a self,
        owner_did: &'a str,
        requester_did: &'a str,
        source_protocol: &'a str,
        source_context_id: &'a str,
    ) -> ConnectFuture<'a, Option<DelegateContextKey>>;

    fn delete_for_recipient<'a>(&'a self, recipient_did: &'a str) -> ConnectFuture<'a, usize>;
}

pub fn create_permission_request(
    requester: impl Into<String>,
    scope: PermissionScope,
    delegated: bool,
    description: Option<String>,
) -> PermissionRequestRecord {
    PermissionRequestRecord {
        id: Ulid::new().to_string(),
        requester: requester.into(),
        delegated,
        scope,
        description,
    }
}

pub fn create_delegate_grant(
    grantor: impl Into<String>,
    grantee: impl Into<String>,
    scope: PermissionScope,
    date_expires: DateTime<Utc>,
    description: Option<String>,
) -> DelegateGrant {
    DelegateGrant {
        id: Ulid::new().to_string(),
        grantor: grantor.into(),
        grantee: grantee.into(),
        date_granted: Utc::now(),
        date_expires,
        delegated: true,
        scope,
        description,
    }
}

pub fn create_grant_revocation(
    grant: &DelegateGrant,
    revocation_grant_id: impl Into<String>,
) -> GrantRevocation {
    GrantRevocation {
        grant_id: grant.id.clone(),
        revocation_grant_id: revocation_grant_id.into(),
        grantor: grant.grantor.clone(),
        grantee: grant.grantee.clone(),
        date_revoked: Utc::now(),
    }
}

pub async fn import_delegate_did<D, K>(
    did_provider: &D,
    key_manager: &K,
    portable_did: PortableDid,
) -> AgentIdentityResult<PortableDid>
where
    D: DidProvider,
    K: AgentKeyManager,
{
    let imported = did_provider.import_did(portable_did).await?;
    for private_jwk in &imported.private_keys {
        key_manager.import_private_jwk(private_jwk.clone()).await?;
    }
    Ok(imported)
}

pub async fn derive_delegate_keys<K>(
    key_manager: &K,
    owner_did: &PortableDid,
    requests: &[ConnectPermissionRequest],
) -> AgentIdentityResult<DelegateKeyDerivationResult>
where
    K: AgentKeyManager,
{
    let root_key_id = key_agreement_root_key_id(owner_did)?;
    let mut result = DelegateKeyDerivationResult::default();
    let mut multi_party_protocols = BTreeSet::new();

    for request in requests {
        if !protocol_requires_encryption(&request.protocol_definition) {
            continue;
        }
        let multi_party = is_multi_party_context(&request.protocol_definition);
        for scope in &request.permission_scopes {
            if !is_read_like_scope(scope) {
                continue;
            }
            if scope.context_id.is_some() {
                continue;
            }
            if multi_party {
                if scope.protocol_path.is_none() {
                    multi_party_protocols.insert(request.protocol_definition.protocol.clone());
                }
                continue;
            }
            let protocol = request.protocol_definition.protocol.clone();
            let (derivation_path, decryption_scope) = match &scope.protocol_path {
                Some(protocol_path) => {
                    let mut derivation_path = vec![
                        PROTOCOL_PATH_DERIVATION_SCHEME.to_string(),
                        protocol.clone(),
                    ];
                    derivation_path.extend(
                        protocol_path
                            .split('/')
                            .filter(|segment| !segment.is_empty())
                            .map(ToString::to_string),
                    );
                    (
                        derivation_path,
                        DelegateDecryptionScope::ProtocolPath {
                            protocol_path: protocol_path.clone(),
                            match_: "exact".to_string(),
                        },
                    )
                }
                None => (
                    vec![
                        PROTOCOL_PATH_DERIVATION_SCHEME.to_string(),
                        protocol.clone(),
                    ],
                    DelegateDecryptionScope::Protocol,
                ),
            };
            let derived_private_key = key_manager
                .derive_private_jwk(&root_key_id, derivation_path.clone())
                .await?;
            result.decryption_keys.push(DelegateDecryptionKey {
                protocol,
                scope: decryption_scope,
                derived_private_key: DerivedPrivateJwk {
                    root_key_id: root_key_id.clone(),
                    derivation_scheme: PROTOCOL_PATH_DERIVATION_SCHEME.to_string(),
                    derivation_path,
                    derived_private_key,
                },
            });
        }
    }

    result.multi_party_protocols = multi_party_protocols.into_iter().collect();
    Ok(result)
}

pub async fn derive_context_key<K>(
    key_manager: &K,
    owner_did: &PortableDid,
    protocol: impl Into<String>,
    context_id: impl Into<String>,
) -> AgentIdentityResult<DelegateContextKey>
where
    K: AgentKeyManager,
{
    let root_key_id = key_agreement_root_key_id(owner_did)?;
    let context_id = context_id.into();
    let derivation_path = vec![
        PROTOCOL_CONTEXT_DERIVATION_SCHEME.to_string(),
        context_id.clone(),
    ];
    let derived_private_key = key_manager
        .derive_private_jwk(&root_key_id, derivation_path.clone())
        .await?;
    Ok(DelegateContextKey {
        protocol: protocol.into(),
        context_id,
        derived_private_key: DerivedPrivateJwk {
            root_key_id,
            derivation_scheme: PROTOCOL_CONTEXT_DERIVATION_SCHEME.to_string(),
            derivation_path,
            derived_private_key,
        },
    })
}

pub async fn write_context_key_record<S>(
    store: &S,
    tenant_did: impl Into<String>,
    recipient_did: impl Into<String>,
    source_protocol: impl Into<String>,
    source_context_id: impl Into<String>,
    context_key: DelegateContextKey,
) -> AgentIdentityResult<String>
where
    S: KeyDeliveryStore,
{
    let record = ContextKeyDeliveryRecord {
        id: Ulid::new().to_string(),
        tenant_did: tenant_did.into(),
        recipient_did: recipient_did.into(),
        source_protocol: source_protocol.into(),
        source_context_id: source_context_id.into(),
        context_key,
    };
    store.write_context_key(record).await
}

pub async fn save_delegate_decryption_keys<S>(
    secret_store: &S,
    keys: &[DelegateDecryptionKey],
) -> AgentIdentityResult<()>
where
    S: SecretStore,
{
    save_json_secret(secret_store, DELEGATE_DECRYPTION_KEYS_KEY, keys).await
}

pub async fn load_delegate_decryption_keys<S>(
    secret_store: &S,
) -> AgentIdentityResult<Vec<DelegateDecryptionKey>>
where
    S: SecretStore,
{
    load_json_secret(secret_store, DELEGATE_DECRYPTION_KEYS_KEY).await
}

pub async fn save_delegate_context_keys<S>(
    secret_store: &S,
    keys: &[DelegateContextKey],
) -> AgentIdentityResult<()>
where
    S: SecretStore,
{
    save_json_secret(secret_store, DELEGATE_CONTEXT_KEYS_KEY, keys).await
}

pub async fn load_delegate_context_keys<S>(
    secret_store: &S,
) -> AgentIdentityResult<Vec<DelegateContextKey>>
where
    S: SecretStore,
{
    load_json_secret(secret_store, DELEGATE_CONTEXT_KEYS_KEY).await
}

async fn save_json_secret<S, T>(secret_store: &S, key: &str, value: &T) -> AgentIdentityResult<()>
where
    S: SecretStore,
    T: Serialize + Sync + ?Sized,
{
    secret_store
        .put(
            key,
            serde_json::to_vec(value)
                .map_err(|err| AgentIdentityError::new("DelegateSecretInvalid", err.to_string()))?,
        )
        .await
}

async fn load_json_secret<S, T>(secret_store: &S, key: &str) -> AgentIdentityResult<T>
where
    S: SecretStore,
    T: for<'de> Deserialize<'de> + Default,
{
    let Some(bytes) = secret_store.get(key).await? else {
        return Ok(T::default());
    };
    Ok(serde_json::from_slice(&bytes).unwrap_or_default())
}

#[derive(Clone, Default)]
pub struct DelegateSessionCache {
    state: Arc<RwLock<DelegateSessionState>>,
}

#[derive(Default)]
struct DelegateSessionState {
    grants: BTreeMap<String, DelegateGrant>,
    decryption_keys: Vec<DelegateDecryptionKey>,
    context_keys: Vec<DelegateContextKey>,
    multi_party_protocols: BTreeSet<String>,
    revocations: Vec<GrantRevocation>,
}

impl DelegateSessionCache {
    pub fn insert_grant(&self, grant: DelegateGrant) {
        self.state
            .write()
            .expect("DelegateSessionCache lock poisoned")
            .grants
            .insert(grant.id.clone(), grant);
    }

    pub fn set_decryption_keys(&self, keys: Vec<DelegateDecryptionKey>) {
        self.state
            .write()
            .expect("DelegateSessionCache lock poisoned")
            .decryption_keys = keys;
    }

    pub fn set_context_keys(&self, keys: Vec<DelegateContextKey>) {
        self.state
            .write()
            .expect("DelegateSessionCache lock poisoned")
            .context_keys = keys;
    }

    pub fn set_multi_party_protocols(&self, protocols: Vec<String>) {
        self.state
            .write()
            .expect("DelegateSessionCache lock poisoned")
            .multi_party_protocols = protocols.into_iter().collect();
    }

    pub fn decryption_keys(&self) -> Vec<DelegateDecryptionKey> {
        self.state
            .read()
            .expect("DelegateSessionCache lock poisoned")
            .decryption_keys
            .clone()
    }

    pub fn context_keys(&self) -> Vec<DelegateContextKey> {
        self.state
            .read()
            .expect("DelegateSessionCache lock poisoned")
            .context_keys
            .clone()
    }

    pub fn revoke_grant(&self, grant_id: &str, revocation_grant_id: &str) -> bool {
        let mut state = self
            .state
            .write()
            .expect("DelegateSessionCache lock poisoned");
        let Some(grant) = state.grants.remove(grant_id) else {
            return false;
        };
        let revoked_protocol = grant.scope.protocol.clone();
        state.decryption_keys.retain(|key| {
            revoked_protocol
                .as_ref()
                .is_some_and(|protocol| key.protocol != *protocol)
        });
        state.context_keys.retain(|key| {
            revoked_protocol
                .as_ref()
                .is_some_and(|protocol| key.protocol != *protocol)
        });
        if let Some(protocol) = &revoked_protocol {
            state.multi_party_protocols.remove(protocol);
        } else {
            state.multi_party_protocols.clear();
        }
        state
            .revocations
            .push(create_grant_revocation(&grant, revocation_grant_id));
        true
    }
}

/// In-memory `KeyDeliveryStore` for development and tests. Process-local;
/// records are lost on restart. Production deployments should back this with
/// the chosen DWN message store.
#[derive(Clone, Default)]
pub struct MemoryKeyDeliveryStore {
    records: Arc<RwLock<BTreeMap<String, ContextKeyDeliveryRecord>>>,
}

impl KeyDeliveryStore for MemoryKeyDeliveryStore {
    fn write_context_key<'a>(
        &'a self,
        record: ContextKeyDeliveryRecord,
    ) -> ConnectFuture<'a, String> {
        Box::pin(async move {
            let id = record.id.clone();
            self.records
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .insert(id.clone(), record);
            Ok(id)
        })
    }

    fn fetch_context_key<'a>(
        &'a self,
        owner_did: &'a str,
        requester_did: &'a str,
        source_protocol: &'a str,
        source_context_id: &'a str,
    ) -> ConnectFuture<'a, Option<DelegateContextKey>> {
        Box::pin(async move {
            Ok(self
                .records
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .values()
                .find(|record| {
                    record.tenant_did == owner_did
                        && record.recipient_did == requester_did
                        && record.source_protocol == source_protocol
                        && record.source_context_id == source_context_id
                })
                .map(|record| record.context_key.clone()))
        })
    }

    fn delete_for_recipient<'a>(&'a self, recipient_did: &'a str) -> ConnectFuture<'a, usize> {
        Box::pin(async move {
            let mut records = self
                .records
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?;
            let before = records.len();
            records.retain(|_, record| record.recipient_did != recipient_did);
            Ok(before - records.len())
        })
    }
}

pub fn is_read_like_scope(scope: &PermissionScope) -> bool {
    matches!(
        scope.method.as_str(),
        "Read" | "Query" | "Subscribe" | "Sync"
    )
}

pub fn is_multi_party_context(definition: &Definition) -> bool {
    definition
        .structure
        .values()
        .any(|rule_set| rule_set_has_multi_party_access(rule_set, None))
}

fn rule_set_has_multi_party_access(rule_set: &RuleSet, current_path: Option<&str>) -> bool {
    if rule_set.role == Some(true) {
        return true;
    }
    if rule_set.actions.iter().any(|action| match action {
        Action::Who(action) => {
            matches!(action.who, Who::Author | Who::Recipient)
                && action.can.contains(&Can::Read)
                && (current_path.is_none() || action.of.is_some())
        }
        Action::Role(_) => false,
    }) {
        return true;
    }
    rule_set
        .rules
        .iter()
        .any(|(path, child)| rule_set_has_multi_party_access(child, Some(path.as_str())))
}

fn key_agreement_root_key_id(tenant_did: &PortableDid) -> AgentIdentityResult<String> {
    let Some(root_key_id) = tenant_did.document.key_agreement.first() else {
        return Err(AgentIdentityError::new(
            "DelegateKeyMissingKeyAgreement",
            format!(
                "DID {} does not have a keyAgreement verification method",
                tenant_did.uri
            ),
        ));
    };
    let method = tenant_did
        .document
        .verification_method
        .iter()
        .find(|method| method.id == *root_key_id)
        .ok_or_else(|| {
            AgentIdentityError::new(
                "DelegateKeyMissingKeyAgreement",
                format!("keyAgreement method {root_key_id} is missing from the DID document"),
            )
        })?;
    let public_jwk = method.public_key_jwk.as_ref().ok_or_else(|| {
        AgentIdentityError::new(
            "DelegateKeyMissingKeyAgreement",
            format!("keyAgreement method {root_key_id} does not contain a public JWK"),
        )
    })?;
    if public_jwk.crv != "X25519" {
        return Err(AgentIdentityError::new(
            "DelegateKeyMissingX25519",
            format!(
                "keyAgreement method {root_key_id} uses {}, but delegate key delivery requires X25519",
                public_jwk.crv
            ),
        ));
    }
    Ok(root_key_id.clone())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Duration;

    use super::*;
    use crate::agent::{
        AgentIdentityInitializeRequest, AgentIdentityService, DeterministicDidJwkProvider,
        MemoryDidResolverCache, MemoryKeyManager, MemorySecretStore,
    };
    use crate::interfaces::messages::protocols::{ActionWho, Type};

    #[tokio::test]
    async fn read_like_scope_receives_decryption_key_and_write_only_does_not() {
        let (owner_did, key_manager) = owner_did_with_keys().await;
        let protocol_definition = encrypted_protocol(false);

        let read_result = derive_delegate_keys(
            &key_manager,
            &owner_did,
            &[ConnectPermissionRequest {
                protocol_definition: protocol_definition.clone(),
                permission_scopes: vec![records_scope("Read", Some("note"))],
            }],
        )
        .await
        .unwrap();
        let write_result = derive_delegate_keys(
            &key_manager,
            &owner_did,
            &[ConnectPermissionRequest {
                protocol_definition,
                permission_scopes: vec![records_scope("Write", Some("note"))],
            }],
        )
        .await
        .unwrap();

        assert_eq!(read_result.decryption_keys.len(), 1);
        assert!(matches!(
            read_result.decryption_keys[0].scope,
            DelegateDecryptionScope::ProtocolPath { .. }
        ));
        assert_eq!(
            read_result.decryption_keys[0]
                .derived_private_key
                .derived_private_key
                .crv,
            "X25519"
        );
        assert!(write_result.decryption_keys.is_empty());
    }

    #[tokio::test]
    async fn context_key_delivery_roundtrips_for_delegate() {
        let (owner_did, key_manager) = owner_did_with_keys().await;
        let context_key = derive_context_key(
            &key_manager,
            &owner_did,
            "https://protocol.example/notes",
            "context-1",
        )
        .await
        .unwrap();
        let store = MemoryKeyDeliveryStore::default();

        let record_id = write_context_key_record(
            &store,
            &owner_did.uri,
            "did:example:delegate",
            "https://protocol.example/notes",
            "context-1",
            context_key.clone(),
        )
        .await
        .unwrap();
        let fetched = store
            .fetch_context_key(
                &owner_did.uri,
                "did:example:delegate",
                "https://protocol.example/notes",
                "context-1",
            )
            .await
            .unwrap();

        assert!(!record_id.is_empty());
        assert_eq!(fetched, Some(context_key));
    }

    #[test]
    fn revocation_removes_access_and_clears_cached_key_state() {
        let cache = DelegateSessionCache::default();
        let grant = create_delegate_grant(
            "did:example:owner",
            "did:example:delegate",
            records_scope("Read", None),
            Utc::now() + Duration::days(1),
            None,
        );
        let protocol = grant.scope.protocol.clone().unwrap();
        cache.insert_grant(grant.clone());
        cache.set_decryption_keys(vec![sample_decryption_key(&protocol)]);
        cache.set_context_keys(vec![sample_context_key(&protocol)]);
        cache.set_multi_party_protocols(vec![protocol]);

        assert!(cache.revoke_grant(&grant.id, "revocation-grant"));

        assert!(cache.decryption_keys().is_empty());
        assert!(cache.context_keys().is_empty());
        assert!(!cache.revoke_grant(&grant.id, "revocation-grant"));
    }

    #[tokio::test]
    async fn delegate_did_import_imports_private_keys_into_key_manager() {
        let (delegate_did, _) = owner_did_with_keys().await;
        let provider = DeterministicDidJwkProvider::default();
        let key_manager = MemoryKeyManager::default();

        let imported = import_delegate_did(&provider, &key_manager, delegate_did)
            .await
            .unwrap();

        for private_jwk in imported.private_keys {
            let key_uri = private_jwk.kid.unwrap();
            assert!(key_manager
                .export_private_jwk(&key_uri)
                .await
                .unwrap()
                .is_some());
        }
    }

    async fn owner_did_with_keys() -> (PortableDid, MemoryKeyManager) {
        let key_manager = MemoryKeyManager::default();
        let service = AgentIdentityService::new(
            DeterministicDidJwkProvider::default(),
            key_manager.clone(),
            MemorySecretStore::default(),
            MemoryDidResolverCache::default(),
        );
        let initialization = service
            .initialize_from_recovery(AgentIdentityInitializeRequest {
                recovery_phrase: Some(
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                        .to_string(),
                ),
                dwn_endpoints: Vec::new(),
            })
            .await
            .unwrap();
        (initialization.portable_did, key_manager)
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

    fn encrypted_protocol(multi_party: bool) -> Definition {
        let mut note_rule = RuleSet {
            actions: vec![Action::Who(ActionWho {
                who: Who::Anyone,
                of: None,
                can: vec![Can::Create],
            })],
            ..Default::default()
        };
        if multi_party {
            note_rule.role = Some(true);
        }
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
            structure: BTreeMap::from([("note".to_string(), note_rule)]),
        }
    }

    fn sample_decryption_key(protocol: &str) -> DelegateDecryptionKey {
        DelegateDecryptionKey {
            protocol: protocol.to_string(),
            scope: DelegateDecryptionScope::Protocol,
            derived_private_key: sample_derived_private_key(),
        }
    }

    fn sample_context_key(protocol: &str) -> DelegateContextKey {
        DelegateContextKey {
            protocol: protocol.to_string(),
            context_id: "context-1".to_string(),
            derived_private_key: sample_derived_private_key(),
        }
    }

    fn sample_derived_private_key() -> DerivedPrivateJwk {
        DerivedPrivateJwk {
            root_key_id: "did:example:owner#enc".to_string(),
            derivation_scheme: PROTOCOL_PATH_DERIVATION_SCHEME.to_string(),
            derivation_path: vec!["protocolPath".to_string()],
            derived_private_key: JsonWebKey {
                kty: "OKP".to_string(),
                crv: "X25519".to_string(),
                x: "x".to_string(),
                d: Some("d".to_string()),
                y: None,
                kid: None,
                alg: None,
                extra: BTreeMap::new(),
            },
        }
    }
}
