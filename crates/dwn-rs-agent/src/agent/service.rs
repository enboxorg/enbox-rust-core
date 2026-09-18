use super::{
    derive_agent_keys, validate_agent_did_key_requirements, validate_recovery_phrase,
    AgentDidCreateRequest, AgentIdentityError, AgentIdentityFuture, AgentIdentityResult,
    PortableDid, VAULT_CONTENT_ENCRYPTION_KEY, VAULT_PORTABLE_DID_KEY, VAULT_UNLOCK_SALT_KEY,
};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::{Arc, RwLock};

use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

/// Key/value secret backend for vault material (portable DID JSON, content-encryption key, salts, delegate keys).
///
/// Unencrypted by itself; durability and at-rest protection are the host's job.
///
/// Dyn-compatible so hosts supply backends at runtime as `Arc<dyn SecretStore>`.
pub trait SecretStore: Send + Sync + 'static {
    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>>;
    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> AgentIdentityFuture<'a, ()>;
    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool>;
}

impl<T: ?Sized + SecretStore> SecretStore for Arc<T> {
    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>> {
        (**self).get(key)
    }
    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> AgentIdentityFuture<'a, ()> {
        (**self).put(key, value)
    }
    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool> {
        (**self).delete(key)
    }
}

/// Host key manager: owns private JWKs and derives protocol/context keys.
///
/// Dyn-compatible so hosts supply backends at runtime as `Arc<dyn AgentKeyManager>`.
pub trait AgentKeyManager: Send + Sync + 'static {
    fn import_private_jwk<'a>(&'a self, jwk: JWK) -> AgentIdentityFuture<'a, String>;
    fn export_private_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JWK>>;
    fn public_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JWK>>;
    fn derive_public_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JWK> {
        Box::pin(async move {
            Ok(self
                .derive_private_jwk(key_uri, derivation_path)
                .await?
                .to_public())
        })
    }
    fn derive_private_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JWK>;
    fn delete_key<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, bool>;
}

impl<T: ?Sized + AgentKeyManager> AgentKeyManager for Arc<T> {
    fn import_private_jwk<'a>(&'a self, jwk: JWK) -> AgentIdentityFuture<'a, String> {
        (**self).import_private_jwk(jwk)
    }
    fn export_private_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JWK>> {
        (**self).export_private_jwk(key_uri)
    }
    fn public_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JWK>> {
        (**self).public_jwk(key_uri)
    }
    fn derive_public_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JWK> {
        (**self).derive_public_jwk(key_uri, derivation_path)
    }
    fn derive_private_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JWK> {
        (**self).derive_private_jwk(key_uri, derivation_path)
    }
    fn delete_key<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, bool> {
        (**self).delete_key(key_uri)
    }
}

/// Stores agent-owned portable identities.
///
/// This is not the cache for externally resolved DID documents, which keeps
/// freshness and version metadata for documents obtained from elsewhere.
///
/// Dyn-compatible so hosts supply backends at runtime as `Arc<dyn PortableDidStore>`.
pub trait PortableDidStore: Send + Sync + 'static {
    fn get_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>>;
    fn put_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, ()>;
    fn delete_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, bool>;
}

impl<T: ?Sized + PortableDidStore> PortableDidStore for Arc<T> {
    fn get_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>> {
        (**self).get_did(did_uri)
    }
    fn put_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, ()> {
        (**self).put_did(portable_did)
    }
    fn delete_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, bool> {
        (**self).delete_did(did_uri)
    }
}

/// Dyn-compatible so hosts supply backends at runtime as `Arc<dyn DidProvider>`.
pub trait DidProvider: Send + Sync + 'static {
    /// Create a fresh DID and document from caller-supplied private JWKs.
    fn create_did<'a>(
        &'a self,
        request: AgentDidCreateRequest,
    ) -> AgentIdentityFuture<'a, PortableDid>;
    /// Import an existing portable DID (e.g. from recovery).
    fn import_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, PortableDid>;
    /// Export a DID previously created or imported through this provider.
    fn export_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>>;
}

impl<T: ?Sized + DidProvider> DidProvider for Arc<T> {
    fn create_did<'a>(
        &'a self,
        request: AgentDidCreateRequest,
    ) -> AgentIdentityFuture<'a, PortableDid> {
        (**self).create_did(request)
    }
    fn import_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, PortableDid> {
        (**self).import_did(portable_did)
    }
    fn export_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>> {
        (**self).export_did(did_uri)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentityInitializeRequest {
    pub recovery_phrase: Option<String>,
    #[serde(default)]
    pub dwn_endpoints: Vec<String>,
}

impl Debug for AgentIdentityInitializeRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentIdentityInitializeRequest")
            .field("has_recovery_phrase", &self.recovery_phrase.is_some())
            .field("dwn_endpoints", &self.dwn_endpoints)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentityInitialization {
    pub recovery_phrase: String,
    pub portable_did: PortableDid,
    pub key_uris: Vec<String>,
    pub vault_content_encryption_key: Vec<u8>,
    pub vault_unlock_salt: Vec<u8>,
}

impl Debug for AgentIdentityInitialization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentIdentityInitialization")
            .field("portable_did", &self.portable_did)
            .field("key_uris", &self.key_uris)
            .finish_non_exhaustive()
    }
}

/// Agent identity orchestrator: derivation, vault persistence, and DID lifecycle.
///
/// Holds no process-global state; independently constructed services in one
/// process do not observe each other.
#[derive(Clone)]
pub struct AgentIdentityService<D, K, S, R> {
    did_provider: D,
    key_manager: K,
    secret_store: S,
    resolver_cache: R,
}

impl<D, K, S, R> AgentIdentityService<D, K, S, R>
where
    D: DidProvider,
    K: AgentKeyManager,
    S: SecretStore,
    R: PortableDidStore,
{
    pub fn new(did_provider: D, key_manager: K, secret_store: S, resolver_cache: R) -> Self {
        Self {
            did_provider,
            key_manager,
            secret_store,
            resolver_cache,
        }
    }

    pub async fn initialize_from_recovery(
        &self,
        request: AgentIdentityInitializeRequest,
    ) -> AgentIdentityResult<AgentIdentityInitialization> {
        let recovery_phrase = match request.recovery_phrase {
            Some(recovery_phrase) => {
                validate_recovery_phrase(&recovery_phrase)?;
                recovery_phrase
            }
            None => Mnemonic::generate_in(Language::English, 12)
                .map_err(|err| AgentIdentityError::invalid_mnemonic(err.to_string()))?
                .to_string(),
        };
        let derived_keys = derive_agent_keys(&recovery_phrase)?;
        let portable_did = self
            .did_provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived_keys.identity_private_jwk.clone(),
                signing_private_jwk: derived_keys.signing_private_jwk.clone(),
                encryption_private_jwk: derived_keys.encryption_private_jwk.clone(),
                dwn_endpoints: request.dwn_endpoints,
            })
            .await?;
        validate_agent_did_key_requirements(&portable_did)?;

        let mut key_uris = Vec::new();
        for private_jwk in &portable_did.private_keys {
            key_uris.push(
                self.key_manager
                    .import_private_jwk(private_jwk.clone())
                    .await?,
            );
        }
        self.secret_store
            .put(
                VAULT_PORTABLE_DID_KEY,
                serde_json::to_vec(&portable_did)
                    .map_err(|err| AgentIdentityError::vault(err.to_string()))?,
            )
            .await?;
        self.secret_store
            .put(
                VAULT_CONTENT_ENCRYPTION_KEY,
                derived_keys.vault_content_encryption_key.clone(),
            )
            .await?;
        self.secret_store
            .put(
                VAULT_UNLOCK_SALT_KEY,
                derived_keys.vault_unlock_salt.clone(),
            )
            .await?;
        self.resolver_cache.put_did(portable_did.clone()).await?;

        Ok(AgentIdentityInitialization {
            recovery_phrase,
            portable_did,
            key_uris,
            vault_content_encryption_key: derived_keys.vault_content_encryption_key,
            vault_unlock_salt: derived_keys.vault_unlock_salt,
        })
    }

    pub async fn stored_agent_did(&self) -> AgentIdentityResult<Option<PortableDid>> {
        let Some(bytes) = self.secret_store.get(VAULT_PORTABLE_DID_KEY).await? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes).map(Some).map_err(|err| {
            AgentIdentityError::vault(format!("stored portable DID is invalid: {err}"))
        })
    }

    pub fn key_manager(&self) -> &K {
        &self.key_manager
    }

    pub fn secret_store(&self) -> &S {
        &self.secret_store
    }

    pub fn resolver_cache(&self) -> &R {
        &self.resolver_cache
    }

    pub fn did_provider(&self) -> &D {
        &self.did_provider
    }
}

#[derive(Clone, Default)]
pub(crate) struct ProviderDidMap {
    dids: Arc<RwLock<BTreeMap<String, PortableDid>>>,
}

impl ProviderDidMap {
    pub(crate) fn insert(&self, portable_did: PortableDid) -> AgentIdentityResult<PortableDid> {
        self.dids
            .write()
            .map_err(AgentIdentityError::lock_poisoned)?
            .insert(portable_did.uri.clone(), portable_did.clone());
        Ok(portable_did)
    }

    pub(crate) fn get(&self, did_uri: &str) -> AgentIdentityResult<Option<PortableDid>> {
        Ok(self
            .dids
            .read()
            .map_err(AgentIdentityError::lock_poisoned)?
            .get(did_uri)
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;

    #[tokio::test]
    async fn initialize_from_recovery_creates_stable_agent_did_and_stores_boundaries() {
        let identity_service = service();

        let first = identity_service
            .initialize_from_recovery(AgentIdentityInitializeRequest {
                recovery_phrase: Some(RECOVERY_PHRASE.to_string()),
                dwn_endpoints: vec!["https://dwn.example".to_string()],
            })
            .await
            .unwrap();
        let second = service()
            .initialize_from_recovery(AgentIdentityInitializeRequest {
                recovery_phrase: Some(RECOVERY_PHRASE.to_string()),
                dwn_endpoints: vec!["https://dwn.example".to_string()],
            })
            .await
            .unwrap();

        assert_eq!(first.portable_did.uri, second.portable_did.uri);
        assert!(first.portable_did.uri.starts_with("did:jwk:"));
        assert_eq!(first.key_uris.len(), 3);
        assert_eq!(
            first
                .portable_did
                .document
                .verification_relationships
                .key_agreement
                .len(),
            1
        );
        assert_eq!(first.portable_did.document.service.len(), 1);
        assert!(identity_service.stored_agent_did().await.unwrap().is_some());
        assert!(identity_service
            .resolver_cache()
            .get_did(&first.portable_did.uri)
            .await
            .unwrap()
            .is_some());
        for key_uri in &first.key_uris {
            assert!(identity_service
                .key_manager()
                .export_private_jwk(key_uri)
                .await
                .unwrap()
                .is_some());
        }
    }

    #[tokio::test]
    async fn invalid_recovery_phrase_writes_nothing() {
        for phrase in [
            RECOVERY_PHRASE.to_uppercase(),
            RECOVERY_PHRASE.replacen(' ', "  ", 1),
            format!(" {RECOVERY_PHRASE}"),
            format!("{RECOVERY_PHRASE} "),
            RECOVERY_PHRASE.replacen(' ', "\t", 1),
            RECOVERY_PHRASE.replacen(' ', "\n", 1),
            format!("{RECOVERY_PHRASE} about"),
            RECOVERY_PHRASE.replace("about", "abandon"),
            RECOVERY_PHRASE.replace("about", "notaword"),
            String::new(),
            "  ".to_string(),
        ] {
            let identity_service = service();
            let error = identity_service
                .initialize_from_recovery(AgentIdentityInitializeRequest {
                    recovery_phrase: Some(phrase),
                    dwn_endpoints: Vec::new(),
                })
                .await
                .unwrap_err();
            assert_eq!(error.code(), "AgentIdentityInvalidMnemonic");
            assert!(identity_service.stored_agent_did().await.unwrap().is_none());
            assert!(identity_service
                .secret_store()
                .get(VAULT_CONTENT_ENCRYPTION_KEY)
                .await
                .unwrap()
                .is_none());
            assert!(identity_service
                .secret_store()
                .get(VAULT_UNLOCK_SALT_KEY)
                .await
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn missing_recovery_phrase_generates_twelve_words() {
        let result = service()
            .initialize_from_recovery(AgentIdentityInitializeRequest {
                recovery_phrase: None,
                dwn_endpoints: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(result.recovery_phrase.split(' ').count(), 12);
        assert!(derive_agent_keys(&result.recovery_phrase).is_ok());
        let recovered = service()
            .initialize_from_recovery(AgentIdentityInitializeRequest {
                recovery_phrase: Some(result.recovery_phrase),
                dwn_endpoints: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(result.portable_did.uri, recovered.portable_did.uri);
    }

    fn service() -> AgentIdentityService<
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
}
