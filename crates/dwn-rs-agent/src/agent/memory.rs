use super::{
    AgentIdentityError, AgentIdentityFuture, AgentKeyManager, PortableDid, PortableDidStore,
    SecretStore, fixed_32, hkdf_sha256, key_uri_for_jwk, okp_params, x25519_private_jwk,
};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use ssi_jwk::JWK;

/// In-memory `SecretStore` for development, tests, and reference flows.
///
/// **Not a vault.** Values are held in a `BTreeMap<String, Vec<u8>>` with
/// no encryption at rest, no process isolation, and no platform-keychain
/// fallback. Production deployments should swap this out for a backend
/// that integrates with the OS keychain / Secure Enclave / TPM (e.g. an
/// `enbox-mobile` vault on iOS, `enbox-desktop` on macOS Keychain).
#[derive(Clone, Default)]
pub struct MemorySecretStore {
    values: Arc<RwLock<BTreeMap<String, Vec<u8>>>>,
}

impl SecretStore for MemorySecretStore {
    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            Ok(self
                .values
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .get(key)
                .cloned())
        })
    }

    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> AgentIdentityFuture<'a, ()> {
        Box::pin(async move {
            self.values
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .insert(key.to_string(), value);
            Ok(())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool> {
        Box::pin(async move {
            Ok(self
                .values
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .remove(key)
                .is_some())
        })
    }
}

/// In-memory `AgentKeyManager` for development, tests, and reference flows.
///
/// **Holds private JWKs in plaintext.** No platform keychain, no Secure
/// Enclave / Keystore-backed signing, no encryption at rest. Production
/// deployments should swap this out for a backend that delegates signing
/// to the host (iOS Keychain + Secure Enclave, Android Keystore, macOS
/// Keychain, OS-managed HSM).
#[derive(Clone, Default)]
pub struct MemoryKeyManager {
    keys: Arc<RwLock<BTreeMap<String, JWK>>>,
}

impl AgentKeyManager for MemoryKeyManager {
    fn import_private_jwk<'a>(&'a self, jwk: JWK) -> AgentIdentityFuture<'a, String> {
        Box::pin(async move {
            if jwk.is_public() {
                return Err(AgentIdentityError::key_manager(
                    "private JWK is missing private key material",
                ));
            }
            let key_uri = key_uri_for_jwk(&jwk)?;
            self.keys
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .insert(key_uri.clone(), jwk);
            Ok(key_uri)
        })
    }

    fn export_private_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JWK>> {
        Box::pin(async move {
            Ok(self
                .keys
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .get(key_uri)
                .cloned())
        })
    }

    fn public_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JWK>> {
        Box::pin(async move {
            Ok(self
                .keys
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .get(key_uri)
                .map(JWK::to_public))
        })
    }

    fn derive_private_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JWK> {
        Box::pin(async move {
            let private_jwk = self
                .keys
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .get(key_uri)
                .cloned()
                .ok_or_else(|| {
                    AgentIdentityError::key_manager(format!("key {key_uri} not found"))
                })?;
            let params = okp_params(&private_jwk)?;
            if params.curve != "X25519" {
                return Err(AgentIdentityError::key_manager(
                    "protocol encryption derivation requires an X25519 private key",
                ));
            }
            let Some(private_key) = params.private_key.as_ref() else {
                return Err(AgentIdentityError::key_manager(
                    "private JWK is missing private key material",
                ));
            };
            let mut key = fixed_32(&private_key.0)?;
            for segment in derivation_path {
                if segment.is_empty() {
                    return Err(AgentIdentityError::key_manager(
                        "derivation path segments must not be empty",
                    ));
                }
                key = fixed_32(&hkdf_sha256(&key, segment.as_bytes(), 32)?)?;
            }
            Ok(x25519_private_jwk(key))
        })
    }

    fn delete_key<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, bool> {
        Box::pin(async move {
            Ok(self
                .keys
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .remove(key_uri)
                .is_some())
        })
    }
}

/// In-memory `PortableDidStore` for development and tests.
///
/// Process-local; not durable across runs and not shared across processes.
/// Production deployments should back the cache with a SQLite
/// store and respect TTLs from the resolver itself.
#[derive(Clone, Default)]
pub struct MemoryPortableDidStore {
    dids: Arc<RwLock<BTreeMap<String, PortableDid>>>,
}

impl PortableDidStore for MemoryPortableDidStore {
    fn get_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>> {
        Box::pin(async move {
            Ok(self
                .dids
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .get(did_uri)
                .cloned())
        })
    }

    fn put_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, ()> {
        Box::pin(async move {
            self.dids
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .insert(portable_did.uri.clone(), portable_did);
            Ok(())
        })
    }

    fn delete_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, bool> {
        Box::pin(async move {
            Ok(self
                .dids
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .remove(did_uri)
                .is_some())
        })
    }
}

/// Deprecated name for [`PortableDidStore`].
#[deprecated(
    note = "use PortableDidStore; this stores agent-owned identities, not resolution results"
)]
pub use super::PortableDidStore as DidResolverCache;

/// Deprecated name for [`MemoryPortableDidStore`].
#[deprecated(note = "use MemoryPortableDidStore")]
pub type MemoryDidResolverCache = MemoryPortableDidStore;

#[cfg(test)]
mod tests {
    use super::super::*;


    #[tokio::test]
    async fn secret_store_is_pluggable_for_native_vaults() {
        let store = MemorySecretStore::default();
        store
            .put("biometric-sealed", b"secret".to_vec())
            .await
            .unwrap();

        assert_eq!(
            store.get("biometric-sealed").await.unwrap(),
            Some(b"secret".to_vec())
        );
        assert!(store.delete("biometric-sealed").await.unwrap());
        assert_eq!(store.get("biometric-sealed").await.unwrap(), None);
    }
}
