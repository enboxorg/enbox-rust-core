use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use crate::agent::{
    AgentIdentityError, AgentIdentityResult, AgentKeyManager, JsonWebKey, PortableDid, SecretStore,
};
use crate::interfaces::messages::protocols::{Definition, PathEncryption, RuleSet};
use chrono::Utc;
use serde::{Deserialize, Serialize};

pub type SetupFuture<'a, T> = Pin<Box<dyn Future<Output = AgentIdentityResult<T>> + Send + 'a>>;

pub const REGISTRATION_TOKENS_KEY: &str = "enbox:auth:registrationTokens";
const PROVIDER_AUTH_V0: &str = "provider-auth-v0";
const PROTOCOL_PATH_DERIVATION_SCHEME: &str = "protocolPath";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTokenData {
    pub registration_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub token_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
}

impl RegistrationTokenData {
    fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at < now_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAuthConfig {
    pub authorize_url: String,
    pub token_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DwnServerInfo {
    #[serde(default)]
    pub registration_requirements: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_auth: Option<ProviderAuthConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMethod {
    /// The DWN endpoint did not advertise any registration requirement.
    NotRequired,
    /// The DWN endpoint advertised `provider-auth-v0` and the agent provided
    /// a registration token via [`TenantRegistrationClient`].
    ProviderAuthToken,
    /// The DWN endpoint advertised a registration requirement that this
    /// crate does not yet implement (the inherited TypeScript implementation
    /// computes a proof-of-work token; the Rust port is tracked as a
    /// follow-up). [`TenantRegistrationClient::register_tenant`] is invoked
    /// without a token; the server will reject the request unless it
    /// accepts unauthenticated registration.
    Anonymous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRegistrationRecord {
    pub endpoint: String,
    pub did: String,
    pub method: RegistrationMethod,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRegistrationRequest {
    pub dwn_endpoints: Vec<String>,
    pub agent_did: String,
    pub connected_did: String,
    #[serde(default)]
    pub persist_tokens: bool,
    #[serde(default)]
    pub registration_tokens: BTreeMap<String, RegistrationTokenData>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRegistrationResult {
    pub records: Vec<TenantRegistrationRecord>,
    pub registration_tokens: BTreeMap<String, RegistrationTokenData>,
}

pub trait TenantRegistrationClient: Clone + Send + Sync + 'static {
    fn server_info<'a>(&'a self, endpoint: &'a str) -> SetupFuture<'a, DwnServerInfo>;

    fn register_tenant<'a>(&'a self, endpoint: &'a str, did: &'a str) -> SetupFuture<'a, ()>;

    fn register_tenant_with_token<'a>(
        &'a self,
        endpoint: &'a str,
        did: &'a str,
        registration_token: &'a str,
    ) -> SetupFuture<'a, ()>;

    fn refresh_registration_token<'a>(
        &'a self,
        refresh_url: &'a str,
        refresh_token: &'a str,
    ) -> SetupFuture<'a, RegistrationTokenData>;
}

pub async fn load_registration_tokens<S>(
    secret_store: &S,
) -> AgentIdentityResult<BTreeMap<String, RegistrationTokenData>>
where
    S: SecretStore,
{
    let Some(bytes) = secret_store.get(REGISTRATION_TOKENS_KEY).await? else {
        return Ok(BTreeMap::new());
    };
    Ok(serde_json::from_slice(&bytes).unwrap_or_default())
}

pub async fn save_registration_tokens<S>(
    secret_store: &S,
    tokens: &BTreeMap<String, RegistrationTokenData>,
) -> AgentIdentityResult<()>
where
    S: SecretStore,
{
    let bytes = serde_json::to_vec(tokens)
        .map_err(|err| AgentIdentityError::new("RegistrationTokenStoreInvalid", err.to_string()))?;
    secret_store.put(REGISTRATION_TOKENS_KEY, bytes).await
}

pub async fn register_with_dwn_endpoints<C, S>(
    client: &C,
    secret_store: Option<&S>,
    request: TenantRegistrationRequest,
) -> AgentIdentityResult<TenantRegistrationResult>
where
    C: TenantRegistrationClient,
    S: SecretStore,
{
    let mut tokens = if request.persist_tokens {
        match secret_store {
            Some(secret_store) => load_registration_tokens(secret_store).await?,
            None => BTreeMap::new(),
        }
    } else {
        request.registration_tokens
    };
    let mut records = Vec::new();
    let now_ms = Utc::now().timestamp_millis();
    let dids = unique_dids([request.agent_did, request.connected_did]);

    for endpoint in request.dwn_endpoints {
        let server_info = client.server_info(&endpoint).await?;
        if server_info.registration_requirements.is_empty() {
            records.extend(dids.iter().map(|did| TenantRegistrationRecord {
                endpoint: endpoint.clone(),
                did: did.clone(),
                method: RegistrationMethod::NotRequired,
            }));
            continue;
        }

        let has_provider_auth = server_info
            .registration_requirements
            .iter()
            .any(|requirement| requirement == PROVIDER_AUTH_V0)
            && server_info.provider_auth.is_some();
        let token = if has_provider_auth {
            usable_or_refreshed_token(client, &mut tokens, &endpoint, now_ms).await?
        } else {
            None
        };

        for did in &dids {
            if let Some(token) = &token {
                client
                    .register_tenant_with_token(&endpoint, did, &token.registration_token)
                    .await?;
                records.push(TenantRegistrationRecord {
                    endpoint: endpoint.clone(),
                    did: did.clone(),
                    method: RegistrationMethod::ProviderAuthToken,
                });
            } else {
                client.register_tenant(&endpoint, did).await?;
                records.push(TenantRegistrationRecord {
                    endpoint: endpoint.clone(),
                    did: did.clone(),
                    method: RegistrationMethod::Anonymous,
                });
            }
        }
    }

    if request.persist_tokens {
        if let Some(secret_store) = secret_store {
            save_registration_tokens(secret_store, &tokens).await?;
        }
    }

    Ok(TenantRegistrationResult {
        records,
        registration_tokens: tokens,
    })
}

async fn usable_or_refreshed_token<C>(
    client: &C,
    tokens: &mut BTreeMap<String, RegistrationTokenData>,
    endpoint: &str,
    now_ms: i64,
) -> AgentIdentityResult<Option<RegistrationTokenData>>
where
    C: TenantRegistrationClient,
{
    let Some(existing) = tokens.get(endpoint).cloned() else {
        return Ok(None);
    };
    if !existing.is_expired(now_ms) {
        return Ok(Some(existing));
    }
    match (&existing.refresh_url, &existing.refresh_token) {
        (Some(refresh_url), Some(refresh_token)) => {
            let mut refreshed = client
                .refresh_registration_token(refresh_url, refresh_token)
                .await?;
            if refreshed.token_url.is_empty() {
                refreshed.token_url = existing.token_url;
            }
            if refreshed.refresh_url.is_none() {
                refreshed.refresh_url = existing.refresh_url;
            }
            tokens.insert(endpoint.to_string(), refreshed.clone());
            Ok(Some(refreshed))
        }
        _ => Ok(None),
    }
}

fn unique_dids(dids: [String; 2]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    dids.into_iter()
        .filter(|did| seen.insert(did.clone()))
        .collect()
}

pub trait ProtocolEndpoint: Clone + Send + Sync + 'static {
    fn query_protocol<'a>(
        &'a self,
        tenant: &'a str,
        protocol: &'a str,
    ) -> SetupFuture<'a, Option<Definition>>;

    fn configure_protocol<'a>(
        &'a self,
        tenant: &'a str,
        definition: Definition,
    ) -> SetupFuture<'a, ()>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolInstallResult {
    pub protocol: String,
    pub installed: bool,
    pub encryption_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreFlowStep {
    AgentDidSync,
    ProtocolInstall,
    ProtocolPush,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreFlowResult {
    pub steps: Vec<RestoreFlowStep>,
    pub local_installs: Vec<ProtocolInstallResult>,
    pub remote_pushes: Vec<ProtocolInstallResult>,
}

pub fn protocol_requires_encryption(definition: &Definition) -> bool {
    definition
        .types
        .values()
        .any(|protocol_type| protocol_type.encryption_required == Some(true))
}

pub fn protocol_has_encryption(definition: &Definition) -> bool {
    definition.structure.values().any(rule_set_has_encryption)
}

pub async fn install_protocol_if_needed<E, K>(
    endpoint: &E,
    key_manager: &K,
    tenant_did: &PortableDid,
    definition: Definition,
) -> AgentIdentityResult<ProtocolInstallResult>
where
    E: ProtocolEndpoint,
    K: AgentKeyManager,
{
    let installed = endpoint
        .query_protocol(&tenant_did.uri, &definition.protocol)
        .await?;
    let requires_encryption = protocol_requires_encryption(&definition);
    if let Some(installed) = installed {
        return Ok(ProtocolInstallResult {
            protocol: definition.protocol,
            installed: false,
            encryption_active: requires_encryption && protocol_has_encryption(&installed),
        });
    }

    let encryption_active = requires_encryption;
    let definition = if requires_encryption {
        inject_protocol_encryption(definition, key_manager, tenant_did).await?
    } else {
        definition
    };
    let protocol = definition.protocol.clone();
    endpoint
        .configure_protocol(&tenant_did.uri, definition)
        .await?;
    Ok(ProtocolInstallResult {
        protocol,
        installed: true,
        encryption_active,
    })
}

pub async fn push_protocol_if_needed<E, K>(
    endpoint: &E,
    key_manager: &K,
    tenant_did: &PortableDid,
    definition: Definition,
) -> AgentIdentityResult<ProtocolInstallResult>
where
    E: ProtocolEndpoint,
    K: AgentKeyManager,
{
    install_protocol_if_needed(endpoint, key_manager, tenant_did, definition).await
}

/// Replay protocol installs/pushes for a recovered agent.
///
/// This intentionally does **not** restore portable identities. The
/// TypeScript wallet recovery flow re-imports `PortableIdentity` records
/// into the connected agent's identity store; the Rust port does not yet
/// model that store. Until it does, callers are expected to manage
/// identity restoration outside this function (see
/// `tests/wallet_recovery.rs::IdentityTenantStore` for the current pattern).
pub async fn run_restore_flow<L, R, K>(
    local: &L,
    remote: &R,
    key_manager: &K,
    agent_did: &PortableDid,
    protocol_definitions: Vec<Definition>,
) -> AgentIdentityResult<RestoreFlowResult>
where
    L: ProtocolEndpoint,
    R: ProtocolEndpoint,
    K: AgentKeyManager,
{
    let mut result = RestoreFlowResult::default();
    result.steps.push(RestoreFlowStep::AgentDidSync);
    result.steps.push(RestoreFlowStep::ProtocolInstall);
    for definition in protocol_definitions.clone() {
        result
            .local_installs
            .push(install_protocol_if_needed(local, key_manager, agent_did, definition).await?);
    }
    result.steps.push(RestoreFlowStep::ProtocolPush);
    for definition in protocol_definitions {
        result
            .remote_pushes
            .push(push_protocol_if_needed(remote, key_manager, agent_did, definition).await?);
    }
    Ok(result)
}

pub async fn inject_protocol_encryption<K>(
    mut definition: Definition,
    key_manager: &K,
    tenant_did: &PortableDid,
) -> AgentIdentityResult<Definition>
where
    K: AgentKeyManager,
{
    let root_key_id = key_agreement_root_key_id(tenant_did)?;
    let mut paths = Vec::new();
    for (root, rule_set) in &definition.structure {
        collect_protocol_paths(rule_set, vec![root.clone()], &mut paths);
    }
    for relative_path in paths {
        let mut derivation_path = vec![
            PROTOCOL_PATH_DERIVATION_SCHEME.to_string(),
            definition.protocol.clone(),
        ];
        derivation_path.extend(relative_path.clone());
        let public_key_jwk = key_manager
            .derive_public_jwk(&root_key_id, derivation_path)
            .await?;
        set_path_encryption(
            &mut definition,
            &relative_path,
            &root_key_id,
            public_key_jwk,
        )?;
    }
    Ok(definition)
}

fn collect_protocol_paths(
    rule_set: &RuleSet,
    current_path: Vec<String>,
    paths: &mut Vec<Vec<String>>,
) {
    if rule_set.reference.is_none() {
        paths.push(current_path.clone());
    }
    for (child_name, child_rule_set) in &rule_set.rules {
        let mut child_path = current_path.clone();
        child_path.push(child_name.clone());
        collect_protocol_paths(child_rule_set, child_path, paths);
    }
}

fn set_path_encryption(
    definition: &mut Definition,
    relative_path: &[String],
    root_key_id: &str,
    public_key_jwk: JsonWebKey,
) -> AgentIdentityResult<()> {
    let Some((root, rest)) = relative_path.split_first() else {
        return Err(AgentIdentityError::new(
            "ProtocolInstallInvalidPath",
            "protocol path must not be empty",
        ));
    };
    let mut rule_set = definition.structure.get_mut(root).ok_or_else(|| {
        AgentIdentityError::new(
            "ProtocolInstallInvalidPath",
            format!("protocol path {} was not found", relative_path.join("/")),
        )
    })?;
    for segment in rest {
        rule_set = rule_set.rules.get_mut(segment).ok_or_else(|| {
            AgentIdentityError::new(
                "ProtocolInstallInvalidPath",
                format!("protocol path {} was not found", relative_path.join("/")),
            )
        })?;
    }
    rule_set.encryption = Some(PathEncryption {
        root_key_id: root_key_id.to_string(),
        public_key_jwk: json_web_key_to_ssi(public_key_jwk)?,
    });
    Ok(())
}

fn key_agreement_root_key_id(tenant_did: &PortableDid) -> AgentIdentityResult<String> {
    let Some(root_key_id) = tenant_did.document.key_agreement.first() else {
        return Err(AgentIdentityError::new(
            "ProtocolInstallMissingKeyAgreement",
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
                "ProtocolInstallMissingKeyAgreement",
                format!("keyAgreement method {root_key_id} is missing from the DID document"),
            )
        })?;
    let public_jwk = method.public_key_jwk.as_ref().ok_or_else(|| {
        AgentIdentityError::new(
            "ProtocolInstallMissingKeyAgreement",
            format!("keyAgreement method {root_key_id} does not contain a public JWK"),
        )
    })?;
    if public_jwk.crv != "X25519" {
        return Err(AgentIdentityError::new(
            "ProtocolInstallMissingX25519",
            format!(
                "keyAgreement method {root_key_id} uses {}, but protocol encryption requires X25519",
                public_jwk.crv
            ),
        ));
    }
    Ok(root_key_id.clone())
}

fn json_web_key_to_ssi(jwk: JsonWebKey) -> AgentIdentityResult<ssi_jwk::JWK> {
    serde_json::from_value::<ssi_jwk::JWK>(
        serde_json::to_value(jwk.public_jwk())
            .map_err(|err| AgentIdentityError::new("ProtocolInstallInvalidJwk", err.to_string()))?,
    )
    .map_err(|err| AgentIdentityError::new("ProtocolInstallInvalidJwk", err.to_string()))
}

fn rule_set_has_encryption(rule_set: &RuleSet) -> bool {
    rule_set.encryption.is_some() || rule_set.rules.values().any(rule_set_has_encryption)
}

#[derive(Clone, Default)]
pub struct MemoryProtocolEndpoint {
    protocols: Arc<RwLock<BTreeMap<String, Definition>>>,
}

impl MemoryProtocolEndpoint {
    pub fn protocol(&self, tenant: &str, protocol: &str) -> Option<Definition> {
        self.protocols
            .read()
            .expect("MemoryProtocolEndpoint lock poisoned")
            .get(&protocol_key(tenant, protocol))
            .cloned()
    }
}

impl ProtocolEndpoint for MemoryProtocolEndpoint {
    fn query_protocol<'a>(
        &'a self,
        tenant: &'a str,
        protocol: &'a str,
    ) -> SetupFuture<'a, Option<Definition>> {
        Box::pin(async move {
            Ok(self
                .protocols
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .get(&protocol_key(tenant, protocol))
                .cloned())
        })
    }

    fn configure_protocol<'a>(
        &'a self,
        tenant: &'a str,
        definition: Definition,
    ) -> SetupFuture<'a, ()> {
        Box::pin(async move {
            self.protocols
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .insert(protocol_key(tenant, &definition.protocol), definition);
            Ok(())
        })
    }
}

fn protocol_key(tenant: &str, protocol: &str) -> String {
    format!("{tenant}|{protocol}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{
        AgentIdentityInitializeRequest, AgentIdentityService, DeterministicDidJwkProvider,
        MemoryDidResolverCache, MemoryKeyManager, MemorySecretStore,
    };
    use crate::interfaces::messages::protocols::{Type, Who};
    use serde_json::Value as JsonValue;

    #[tokio::test]
    async fn registration_refreshes_provider_token_and_persists_to_secret_store() {
        let client = MockRegistrationClient::default();
        client.set_server_info(
            "https://dwn.example",
            DwnServerInfo {
                registration_requirements: vec![PROVIDER_AUTH_V0.to_string()],
                provider_auth: Some(ProviderAuthConfig {
                    authorize_url: "https://auth.example/authorize".to_string(),
                    token_url: "https://auth.example/token".to_string(),
                    refresh_url: Some("https://auth.example/refresh".to_string()),
                }),
            },
        );
        client.set_refresh_token(RegistrationTokenData {
            registration_token: "fresh-token".to_string(),
            refresh_token: Some("new-refresh".to_string()),
            expires_at: Some(Utc::now().timestamp_millis() + 60_000),
            token_url: String::new(),
            refresh_url: None,
        });
        let secret_store = MemorySecretStore::default();
        save_registration_tokens(
            &secret_store,
            &BTreeMap::from([(
                "https://dwn.example".to_string(),
                RegistrationTokenData {
                    registration_token: "expired-token".to_string(),
                    refresh_token: Some("old-refresh".to_string()),
                    expires_at: Some(1),
                    token_url: "https://auth.example/token".to_string(),
                    refresh_url: Some("https://auth.example/refresh".to_string()),
                },
            )]),
        )
        .await
        .unwrap();

        let result = register_with_dwn_endpoints(
            &client,
            Some(&secret_store),
            TenantRegistrationRequest {
                dwn_endpoints: vec!["https://dwn.example".to_string()],
                agent_did: "did:example:agent".to_string(),
                connected_did: "did:example:owner".to_string(),
                persist_tokens: true,
                registration_tokens: BTreeMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(result.records.len(), 2);
        assert!(result
            .records
            .iter()
            .all(|record| record.method == RegistrationMethod::ProviderAuthToken));
        assert_eq!(
            client.registered_with_tokens(),
            vec![
                (
                    "https://dwn.example".to_string(),
                    "did:example:agent".to_string(),
                    "fresh-token".to_string()
                ),
                (
                    "https://dwn.example".to_string(),
                    "did:example:owner".to_string(),
                    "fresh-token".to_string()
                ),
            ]
        );
        let saved = load_registration_tokens(&secret_store).await.unwrap();
        assert_eq!(
            saved["https://dwn.example"].registration_token,
            "fresh-token"
        );
    }

    #[tokio::test]
    async fn protocol_install_injects_encryption_keys_and_pushes_remote() {
        let (agent_did, key_manager) = agent_did_with_keys().await;
        let local = MemoryProtocolEndpoint::default();
        let remote = MemoryProtocolEndpoint::default();
        let definition = encrypted_protocol();

        let result = run_restore_flow(
            &local,
            &remote,
            &key_manager,
            &agent_did,
            vec![definition.clone()],
        )
        .await
        .unwrap();

        assert_eq!(
            result.steps,
            vec![
                RestoreFlowStep::AgentDidSync,
                RestoreFlowStep::ProtocolInstall,
                RestoreFlowStep::ProtocolPush,
            ]
        );
        assert!(result.local_installs[0].installed);
        assert!(result.remote_pushes[0].installed);
        let installed = local
            .protocol(&agent_did.uri, &definition.protocol)
            .unwrap();
        let rule = installed.structure.get("note").unwrap();
        let encryption = rule.encryption.as_ref().unwrap();
        assert!(encryption.root_key_id.ends_with("#enc"));
        assert_eq!(
            serde_json::to_value(&encryption.public_key_jwk).unwrap()["crv"],
            JsonValue::String("X25519".to_string())
        );
        assert!(remote
            .protocol(&agent_did.uri, &definition.protocol)
            .is_some());
    }

    #[tokio::test]
    async fn encrypted_protocol_install_fails_without_x25519_key_agreement() {
        let (mut agent_did, key_manager) = agent_did_with_keys().await;
        agent_did.document.key_agreement.clear();
        agent_did.private_keys.retain(|jwk| jwk.crv != "X25519");
        let endpoint = MemoryProtocolEndpoint::default();

        let error =
            install_protocol_if_needed(&endpoint, &key_manager, &agent_did, encrypted_protocol())
                .await
                .unwrap_err();

        assert_eq!(error.code, "ProtocolInstallMissingKeyAgreement");
    }

    #[derive(Clone, Default)]
    struct MockRegistrationClient {
        state: Arc<RwLock<MockRegistrationState>>,
    }

    #[derive(Default)]
    struct MockRegistrationState {
        server_info: BTreeMap<String, DwnServerInfo>,
        refresh_token: Option<RegistrationTokenData>,
        registered_pow: Vec<(String, String)>,
        registered_tokens: Vec<(String, String, String)>,
    }

    impl MockRegistrationClient {
        fn set_server_info(&self, endpoint: &str, server_info: DwnServerInfo) {
            self.state
                .write()
                .unwrap()
                .server_info
                .insert(endpoint.to_string(), server_info);
        }

        fn set_refresh_token(&self, token: RegistrationTokenData) {
            self.state.write().unwrap().refresh_token = Some(token);
        }

        fn registered_with_tokens(&self) -> Vec<(String, String, String)> {
            self.state.read().unwrap().registered_tokens.clone()
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
                    .registered_pow
                    .push((endpoint.to_string(), did.to_string()));
                Ok(())
            })
        }

        fn register_tenant_with_token<'a>(
            &'a self,
            endpoint: &'a str,
            did: &'a str,
            registration_token: &'a str,
        ) -> SetupFuture<'a, ()> {
            Box::pin(async move {
                self.state.write().unwrap().registered_tokens.push((
                    endpoint.to_string(),
                    did.to_string(),
                    registration_token.to_string(),
                ));
                Ok(())
            })
        }

        fn refresh_registration_token<'a>(
            &'a self,
            _refresh_url: &'a str,
            _refresh_token: &'a str,
        ) -> SetupFuture<'a, RegistrationTokenData> {
            Box::pin(async move {
                self.state
                    .read()
                    .unwrap()
                    .refresh_token
                    .clone()
                    .ok_or_else(|| {
                        AgentIdentityError::new(
                            "RegistrationRefreshFailed",
                            "missing refresh token",
                        )
                    })
            })
        }
    }

    async fn agent_did_with_keys() -> (PortableDid, MemoryKeyManager) {
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
                    actions: vec![crate::interfaces::messages::protocols::Action::Who(
                        crate::interfaces::messages::protocols::ActionWho {
                            who: Who::Anyone,
                            of: None,
                            can: vec![crate::interfaces::messages::protocols::Can::Create],
                        },
                    )],
                    ..Default::default()
                },
            )]),
        }
    }
}
