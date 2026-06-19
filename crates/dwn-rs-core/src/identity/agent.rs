use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub type AgentIdentityResult<T> = Result<T, AgentIdentityError>;
pub type AgentIdentityFuture<'a, T> =
    Pin<Box<dyn Future<Output = AgentIdentityResult<T>> + Send + 'a>>;

pub const VAULT_PORTABLE_DID_KEY: &str = "agent:vault:portableDid";
pub const VAULT_CONTENT_ENCRYPTION_KEY: &str = "agent:vault:contentEncryptionKey";
pub const VAULT_UNLOCK_SALT_KEY: &str = "agent:vault:unlockSalt";

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentityError {
    pub code: String,
    pub detail: String,
}

impl AgentIdentityError {
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }

    fn invalid_mnemonic(detail: impl Into<String>) -> Self {
        Self::new("AgentIdentityInvalidMnemonic", detail)
    }

    fn invalid_key_material(detail: impl Into<String>) -> Self {
        Self::new("AgentIdentityInvalidKeyMaterial", detail)
    }

    fn did(detail: impl Into<String>) -> Self {
        Self::new("AgentIdentityDidError", detail)
    }

    fn key_manager(detail: impl Into<String>) -> Self {
        Self::new("AgentIdentityKeyManagerError", detail)
    }

    fn vault(detail: impl Into<String>) -> Self {
        Self::new("AgentIdentityVaultError", detail)
    }

    pub(crate) fn lock_poisoned<E: Display>(err: E) -> Self {
        Self::new(
            "AgentIdentityLockPoisoned",
            format!("agent identity store lock poisoned: {err}"),
        )
    }
}

impl Display for AgentIdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for AgentIdentityError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonWebKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, JsonValue>,
}

impl JsonWebKey {
    pub fn public_jwk(&self) -> Self {
        let mut public = self.clone();
        public.d = None;
        public
    }

    fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<JsonWebKey>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidService {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub service_endpoint: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<JsonValue>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<DidVerificationMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DidService>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortableDid {
    pub uri: String,
    pub document: DidDocument,
    pub metadata: DidMetadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_keys: Vec<JsonWebKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityMetadata {
    pub name: String,
    pub tenant: String,
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_did: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortableIdentity {
    pub portable_did: PortableDid,
    pub metadata: IdentityMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDerivedKeys {
    pub identity_private_jwk: JsonWebKey,
    pub signing_private_jwk: JsonWebKey,
    pub encryption_private_jwk: JsonWebKey,
    pub vault_content_encryption_key: Vec<u8>,
    pub vault_unlock_salt: Vec<u8>,
}

impl AgentDerivedKeys {
    pub fn private_jwks(&self) -> Vec<JsonWebKey> {
        vec![
            self.identity_private_jwk.clone(),
            self.signing_private_jwk.clone(),
            self.encryption_private_jwk.clone(),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDidCreateRequest {
    pub identity_private_jwk: JsonWebKey,
    pub signing_private_jwk: JsonWebKey,
    pub encryption_private_jwk: JsonWebKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dwn_endpoints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentityInitializeRequest {
    pub recovery_phrase: Option<String>,
    #[serde(default)]
    pub dwn_endpoints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentityInitialization {
    pub recovery_phrase: String,
    pub portable_did: PortableDid,
    pub key_uris: Vec<String>,
    pub vault_content_encryption_key: Vec<u8>,
    pub vault_unlock_salt: Vec<u8>,
}

pub trait SecretStore: Clone + Send + Sync + 'static {
    fn get<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, Option<Vec<u8>>>;
    fn put<'a>(&'a self, key: &'a str, value: Vec<u8>) -> AgentIdentityFuture<'a, ()>;
    fn delete<'a>(&'a self, key: &'a str) -> AgentIdentityFuture<'a, bool>;
}

pub trait AgentKeyManager: Clone + Send + Sync + 'static {
    fn import_private_jwk<'a>(&'a self, jwk: JsonWebKey) -> AgentIdentityFuture<'a, String>;
    fn export_private_jwk<'a>(
        &'a self,
        key_uri: &'a str,
    ) -> AgentIdentityFuture<'a, Option<JsonWebKey>>;
    fn public_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JsonWebKey>>;
    fn derive_public_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JsonWebKey>;
    fn derive_private_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JsonWebKey>;
    fn delete_key<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, bool>;
}

pub trait DidResolverCache: Clone + Send + Sync + 'static {
    fn get_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>>;
    fn put_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, ()>;
    fn delete_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, bool>;
}

pub trait DidProvider: Clone + Send + Sync + 'static {
    fn create_did<'a>(
        &'a self,
        request: AgentDidCreateRequest,
    ) -> AgentIdentityFuture<'a, PortableDid>;
    fn import_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, PortableDid>;
    fn export_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>>;
}

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
    R: DidResolverCache,
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
pub struct DeterministicDidJwkProvider {
    dids: Arc<RwLock<BTreeMap<String, PortableDid>>>,
}

impl DidProvider for DeterministicDidJwkProvider {
    fn create_did<'a>(
        &'a self,
        request: AgentDidCreateRequest,
    ) -> AgentIdentityFuture<'a, PortableDid> {
        Box::pin(async move {
            let did_uri = did_jwk_uri(&request.identity_private_jwk.public_jwk())?;
            let sig_id = format!("{did_uri}#sig");
            let enc_id = format!("{did_uri}#enc");
            let identity_id = format!("{did_uri}#identity");
            let signing_private_jwk = request.signing_private_jwk.with_kid(sig_id.clone());
            let encryption_private_jwk = request.encryption_private_jwk.with_kid(enc_id.clone());
            let identity_private_jwk = request.identity_private_jwk.with_kid(identity_id);

            let mut document = DidDocument {
                context: Some(JsonValue::String(
                    "https://www.w3.org/ns/did/v1".to_string(),
                )),
                id: did_uri.clone(),
                verification_method: vec![
                    DidVerificationMethod {
                        id: sig_id.clone(),
                        type_: "JsonWebKey2020".to_string(),
                        controller: did_uri.clone(),
                        public_key_jwk: Some(signing_private_jwk.public_jwk()),
                    },
                    DidVerificationMethod {
                        id: enc_id.clone(),
                        type_: "JsonWebKey2020".to_string(),
                        controller: did_uri.clone(),
                        public_key_jwk: Some(encryption_private_jwk.public_jwk()),
                    },
                ],
                authentication: vec![sig_id.clone()],
                assertion_method: vec![sig_id],
                key_agreement: vec![enc_id],
                service: Vec::new(),
            };
            if !request.dwn_endpoints.is_empty() {
                document.service.push(DidService {
                    id: format!("{did_uri}#dwn"),
                    type_: "DecentralizedWebNode".to_string(),
                    service_endpoint: JsonValue::Array(
                        request
                            .dwn_endpoints
                            .into_iter()
                            .map(JsonValue::String)
                            .collect(),
                    ),
                });
            }

            let portable_did = PortableDid {
                uri: did_uri.clone(),
                document,
                metadata: DidMetadata {
                    published: Some(false),
                    extra: BTreeMap::new(),
                },
                private_keys: vec![
                    identity_private_jwk,
                    signing_private_jwk,
                    encryption_private_jwk,
                ],
            };
            self.dids
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .insert(did_uri, portable_did.clone());
            Ok(portable_did)
        })
    }

    fn import_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, PortableDid> {
        Box::pin(async move {
            validate_agent_did_key_requirements(&portable_did)?;
            self.dids
                .write()
                .map_err(AgentIdentityError::lock_poisoned)?
                .insert(portable_did.uri.clone(), portable_did.clone());
            Ok(portable_did)
        })
    }

    fn export_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>> {
        Box::pin(async move {
            Ok(self
                .dids
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .get(did_uri)
                .cloned())
        })
    }
}

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
    keys: Arc<RwLock<BTreeMap<String, JsonWebKey>>>,
}

impl AgentKeyManager for MemoryKeyManager {
    fn import_private_jwk<'a>(&'a self, jwk: JsonWebKey) -> AgentIdentityFuture<'a, String> {
        Box::pin(async move {
            if jwk.d.is_none() {
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

    fn export_private_jwk<'a>(
        &'a self,
        key_uri: &'a str,
    ) -> AgentIdentityFuture<'a, Option<JsonWebKey>> {
        Box::pin(async move {
            Ok(self
                .keys
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .get(key_uri)
                .cloned())
        })
    }

    fn public_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JsonWebKey>> {
        Box::pin(async move {
            Ok(self
                .keys
                .read()
                .map_err(AgentIdentityError::lock_poisoned)?
                .get(key_uri)
                .map(JsonWebKey::public_jwk))
        })
    }

    fn derive_public_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JsonWebKey> {
        Box::pin(async move {
            Ok(self
                .derive_private_jwk(key_uri, derivation_path)
                .await?
                .public_jwk())
        })
    }

    fn derive_private_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JsonWebKey> {
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
            if private_jwk.crv != "X25519" {
                return Err(AgentIdentityError::key_manager(
                    "protocol encryption derivation requires an X25519 private key",
                ));
            }
            let Some(private_key) = private_jwk.d.as_ref() else {
                return Err(AgentIdentityError::key_manager(
                    "private JWK is missing private key material",
                ));
            };
            let mut key = fixed_32(
                &URL_SAFE_NO_PAD
                    .decode(private_key)
                    .map_err(|err| AgentIdentityError::key_manager(err.to_string()))?,
            )?;
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

/// In-memory `DidResolverCache` for development and tests.
///
/// Process-local; not durable across runs and not shared across processes.
/// Production deployments should back the cache with a SQLite
/// store and respect TTLs from the resolver itself.
#[derive(Clone, Default)]
pub struct MemoryDidResolverCache {
    dids: Arc<RwLock<BTreeMap<String, PortableDid>>>,
}

impl DidResolverCache for MemoryDidResolverCache {
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

pub fn derive_agent_keys(recovery_phrase: &str) -> AgentIdentityResult<AgentDerivedKeys> {
    let mnemonic = Mnemonic::parse_in(Language::English, recovery_phrase)
        .map_err(|err| AgentIdentityError::invalid_mnemonic(err.to_string()))?;
    let seed = mnemonic.to_seed("");
    let vault = derive_slip10_ed25519(&seed, "m/44'/0'/0'/0'/0'")?;
    let identity = derive_slip10_ed25519(&seed, "m/44'/0'/1708523827'/0'/0'")?;
    let signing = derive_slip10_ed25519(&seed, "m/44'/0'/1708523827'/0'/1'")?;
    let encryption = derive_slip10_ed25519(&seed, "m/44'/0'/1708523827'/0'/2'")?;
    let vault_public = ed25519_public_key_bytes(vault.private_key);

    Ok(AgentDerivedKeys {
        identity_private_jwk: ed25519_private_jwk(identity.private_key, None),
        signing_private_jwk: ed25519_private_jwk(signing.private_key, Some("EdDSA")),
        encryption_private_jwk: x25519_private_jwk(encryption.private_key),
        vault_content_encryption_key: hkdf_sha512(&vault.private_key, b"vault_cek", 32)?,
        vault_unlock_salt: hkdf_sha512(&vault_public, b"vault_unlock_salt", 32)?,
    })
}

pub fn validate_agent_did_key_requirements(portable_did: &PortableDid) -> AgentIdentityResult<()> {
    let has_signing_method = portable_did
        .document
        .verification_method
        .iter()
        .any(|method| {
            method
                .public_key_jwk
                .as_ref()
                .is_some_and(|jwk| jwk.crv == "Ed25519")
                && (portable_did.document.authentication.contains(&method.id)
                    || portable_did.document.assertion_method.contains(&method.id))
        });
    let has_key_agreement_method = portable_did
        .document
        .verification_method
        .iter()
        .any(|method| {
            method
                .public_key_jwk
                .as_ref()
                .is_some_and(|jwk| jwk.crv == "X25519")
                && portable_did.document.key_agreement.contains(&method.id)
        });
    let has_ed25519_private = portable_did
        .private_keys
        .iter()
        .any(|jwk| jwk.crv == "Ed25519" && jwk.d.is_some());
    let has_x25519_private = portable_did
        .private_keys
        .iter()
        .any(|jwk| jwk.crv == "X25519" && jwk.d.is_some());

    if !has_signing_method || !has_ed25519_private {
        return Err(AgentIdentityError::invalid_key_material(
            "agent DID requires Ed25519 signing key material",
        ));
    }
    if !has_key_agreement_method || !has_x25519_private {
        return Err(AgentIdentityError::invalid_key_material(
            "agent DID requires X25519 key agreement material",
        ));
    }
    Ok(())
}

fn validate_recovery_phrase(recovery_phrase: &str) -> AgentIdentityResult<()> {
    Mnemonic::parse_in(Language::English, recovery_phrase)
        .map(|_| ())
        .map_err(|err| AgentIdentityError::invalid_mnemonic(err.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slip10Node {
    private_key: [u8; 32],
    chain_code: [u8; 32],
}

fn derive_slip10_ed25519(seed: &[u8], path: &str) -> AgentIdentityResult<Slip10Node> {
    let master = hmac_sha512(b"ed25519 seed", seed)?;
    let mut node = Slip10Node {
        private_key: fixed_32(&master[..32])?,
        chain_code: fixed_32(&master[32..])?,
    };
    if path == "m" {
        return Ok(node);
    }
    let Some(segments) = path.strip_prefix("m/") else {
        return Err(AgentIdentityError::invalid_key_material(format!(
            "invalid derivation path {path}"
        )));
    };
    for segment in segments.split('/') {
        let Some(index) = segment.strip_suffix('\'') else {
            return Err(AgentIdentityError::invalid_key_material(
                "SLIP-0010 Ed25519 derivation requires hardened path segments",
            ));
        };
        let index = index.parse::<u32>().map_err(|_| {
            AgentIdentityError::invalid_key_material(format!(
                "invalid derivation path index {index}"
            ))
        })?;
        if index >= 0x8000_0000 {
            return Err(AgentIdentityError::invalid_key_material(
                "derivation path index is out of range",
            ));
        }
        let mut data = Vec::with_capacity(37);
        data.push(0);
        data.extend_from_slice(&node.private_key);
        data.extend_from_slice(&(index | 0x8000_0000).to_be_bytes());
        let child = hmac_sha512(&node.chain_code, &data)?;
        node = Slip10Node {
            private_key: fixed_32(&child[..32])?,
            chain_code: fixed_32(&child[32..])?,
        };
    }
    Ok(node)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> AgentIdentityResult<[u8; 64]> {
    let mut mac = HmacSha512::new_from_slice(key)
        .map_err(|err| AgentIdentityError::invalid_key_material(err.to_string()))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&result);
    Ok(bytes)
}

fn hkdf_sha512(base_key: &[u8], info: &[u8], length: usize) -> AgentIdentityResult<Vec<u8>> {
    let hkdf = hkdf::Hkdf::<Sha512>::new(Some(&[]), base_key);
    let mut out = vec![0u8; length];
    hkdf.expand(info, &mut out)
        .map_err(|err| AgentIdentityError::invalid_key_material(err.to_string()))?;
    Ok(out)
}

fn hkdf_sha256(base_key: &[u8], info: &[u8], length: usize) -> AgentIdentityResult<Vec<u8>> {
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&[]), base_key);
    let mut out = vec![0u8; length];
    hkdf.expand(info, &mut out)
        .map_err(|err| AgentIdentityError::invalid_key_material(err.to_string()))?;
    Ok(out)
}

fn fixed_32(bytes: &[u8]) -> AgentIdentityResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(AgentIdentityError::invalid_key_material(
            "expected 32 bytes of key material",
        ));
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(bytes);
    Ok(fixed)
}

fn ed25519_private_jwk(private_key: [u8; 32], alg: Option<&str>) -> JsonWebKey {
    let public_key = ed25519_public_key_bytes(private_key);
    JsonWebKey {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: URL_SAFE_NO_PAD.encode(public_key),
        d: Some(URL_SAFE_NO_PAD.encode(private_key)),
        y: None,
        kid: None,
        alg: alg.map(ToString::to_string),
        extra: BTreeMap::new(),
    }
}

fn ed25519_public_key_bytes(private_key: [u8; 32]) -> [u8; 32] {
    Ed25519SigningKey::from_bytes(&private_key)
        .verifying_key()
        .to_bytes()
}

fn x25519_private_jwk(private_key: [u8; 32]) -> JsonWebKey {
    let static_secret = X25519StaticSecret::from(private_key);
    let public_key = X25519PublicKey::from(&static_secret).to_bytes();
    JsonWebKey {
        kty: "OKP".to_string(),
        crv: "X25519".to_string(),
        x: URL_SAFE_NO_PAD.encode(public_key),
        d: Some(URL_SAFE_NO_PAD.encode(private_key)),
        y: None,
        kid: None,
        alg: None,
        extra: BTreeMap::new(),
    }
}

fn did_jwk_uri(public_jwk: &JsonWebKey) -> AgentIdentityResult<String> {
    let mut jwk = public_jwk.clone();
    jwk.d = None;
    jwk.kid = None;
    jwk.alg = None;
    let encoded = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&jwk).map_err(|err| AgentIdentityError::did(err.to_string()))?);
    Ok(format!("did:jwk:{encoded}"))
}

fn key_uri_for_jwk(jwk: &JsonWebKey) -> AgentIdentityResult<String> {
    if let Some(kid) = &jwk.kid {
        return Ok(kid.clone());
    }
    let public_jwk = jwk.public_jwk();
    let bytes = serde_json::to_vec(&public_jwk)
        .map_err(|err| AgentIdentityError::key_manager(err.to_string()))?;
    Ok(format!(
        "urn:jwk:sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECOVERY_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn recovery_phrase_derives_stable_agent_key_material() {
        let first = derive_agent_keys(RECOVERY_PHRASE).unwrap();
        let second = derive_agent_keys(RECOVERY_PHRASE).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.signing_private_jwk.crv, "Ed25519");
        assert_eq!(first.encryption_private_jwk.crv, "X25519");
        assert_eq!(first.vault_content_encryption_key.len(), 32);
        assert_eq!(first.vault_unlock_salt.len(), 32);
    }

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
        assert_eq!(first.portable_did.document.key_agreement.len(), 1);
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
    async fn did_import_rejects_agent_did_without_x25519_key_agreement() {
        let provider = DeterministicDidJwkProvider::default();
        let derived = derive_agent_keys(RECOVERY_PHRASE).unwrap();
        let mut portable_did = provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived.identity_private_jwk,
                signing_private_jwk: derived.signing_private_jwk,
                encryption_private_jwk: derived.encryption_private_jwk,
                dwn_endpoints: Vec::new(),
            })
            .await
            .unwrap();
        portable_did.document.key_agreement.clear();
        portable_did.private_keys.retain(|jwk| jwk.crv != "X25519");

        let error = provider.import_did(portable_did).await.unwrap_err();

        assert_eq!(error.code, "AgentIdentityInvalidKeyMaterial");
        assert!(error.detail.contains("X25519"));
    }

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

    fn service() -> AgentIdentityService<
        DeterministicDidJwkProvider,
        MemoryKeyManager,
        MemorySecretStore,
        MemoryDidResolverCache,
    > {
        AgentIdentityService::new(
            DeterministicDidJwkProvider::default(),
            MemoryKeyManager::default(),
            MemorySecretStore::default(),
            MemoryDidResolverCache::default(),
        )
    }
}
