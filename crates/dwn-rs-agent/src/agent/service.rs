use super::*;

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
    use super::*;

    const RECOVERY_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
