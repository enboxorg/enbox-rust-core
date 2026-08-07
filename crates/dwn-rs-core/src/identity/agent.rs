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
use ssi_dids_core::document::verification_method::ValueOrReference;
use ssi_dids_core::document::{DIDVerificationMethod, Service, VerificationRelationships};
use ssi_dids_core::{DIDBuf, Document};
use ssi_jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK};
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
    pub document: Document,
    pub metadata: DidMetadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_keys: Vec<JWK>,
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
    pub identity_private_jwk: JWK,
    pub signing_private_jwk: JWK,
    pub encryption_private_jwk: JWK,
    pub vault_content_encryption_key: Vec<u8>,
    pub vault_unlock_salt: Vec<u8>,
}

impl AgentDerivedKeys {
    pub fn private_jwks(&self) -> Vec<JWK> {
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
    pub identity_private_jwk: JWK,
    pub signing_private_jwk: JWK,
    pub encryption_private_jwk: JWK,
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
    fn import_private_jwk<'a>(&'a self, jwk: JWK) -> AgentIdentityFuture<'a, String>;
    fn export_private_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JWK>>;
    fn public_jwk<'a>(&'a self, key_uri: &'a str) -> AgentIdentityFuture<'a, Option<JWK>>;
    fn derive_public_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JWK>;
    fn derive_private_jwk<'a>(
        &'a self,
        key_uri: &'a str,
        derivation_path: Vec<String>,
    ) -> AgentIdentityFuture<'a, JWK>;
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
            let did_uri = did_jwk_uri(&request.identity_private_jwk.to_public())?;
            let sig_id = format!("{did_uri}#sig");
            let enc_id = format!("{did_uri}#enc");
            let identity_id = format!("{did_uri}#0");
            let signing_private_jwk = with_key_id(request.signing_private_jwk, sig_id.clone());
            let encryption_private_jwk =
                with_key_id(request.encryption_private_jwk, enc_id.clone());
            let identity_private_jwk = with_key_id(request.identity_private_jwk, identity_id);

            let did = parse_did(&did_uri)?;
            let sig_reference = parse_verification_reference(&sig_id)?;
            let enc_reference = parse_verification_reference(&enc_id)?;
            let mut document = Document::new(did.clone());
            // Keep the portable DID JSON-LD representation stable while using
            // SSI's DID Core data model for the document itself.
            document.property_set.insert(
                "@context".to_string(),
                JsonValue::String("https://www.w3.org/ns/did/v1".to_string()),
            );
            document.verification_method = vec![
                did_verification_method(&sig_id, &did, signing_private_jwk.to_public())?,
                did_verification_method(&enc_id, &did, encryption_private_jwk.to_public())?,
            ];
            document.verification_relationships = VerificationRelationships {
                authentication: vec![sig_reference.clone()],
                assertion_method: vec![sig_reference.clone()],
                key_agreement: vec![enc_reference],
                capability_invocation: vec![sig_reference.clone()],
                capability_delegation: vec![sig_reference],
            };
            if !request.dwn_endpoints.is_empty() {
                document.service.push(did_service(
                    &format!("{did_uri}#dwn"),
                    request.dwn_endpoints,
                )?);
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
            verification_method_jwk(method)
                .as_ref()
                .is_some_and(|jwk| jwk_curve(jwk) == Some("Ed25519"))
                && (relationship_contains(
                    &portable_did.document,
                    &portable_did
                        .document
                        .verification_relationships
                        .authentication,
                    method,
                ) || relationship_contains(
                    &portable_did.document,
                    &portable_did
                        .document
                        .verification_relationships
                        .assertion_method,
                    method,
                ))
        });
    let has_key_agreement_method = portable_did
        .document
        .verification_method
        .iter()
        .any(|method| {
            verification_method_jwk(method)
                .as_ref()
                .is_some_and(|jwk| jwk_curve(jwk) == Some("X25519"))
                && relationship_contains(
                    &portable_did.document,
                    &portable_did
                        .document
                        .verification_relationships
                        .key_agreement,
                    method,
                )
        });
    let has_ed25519_private = portable_did
        .private_keys
        .iter()
        .any(|jwk| jwk_curve(jwk) == Some("Ed25519") && !jwk.is_public());
    let has_x25519_private = portable_did
        .private_keys
        .iter()
        .any(|jwk| jwk_curve(jwk) == Some("X25519") && !jwk.is_public());

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

fn ed25519_private_jwk(private_key: [u8; 32], alg: Option<&str>) -> JWK {
    let public_key = ed25519_public_key_bytes(private_key);
    let mut jwk = JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(public_key.to_vec()),
        private_key: Some(Base64urlUInt(private_key.to_vec())),
    }));
    jwk.algorithm = alg.map(|_| Algorithm::EdDSA);
    jwk
}

fn ed25519_public_key_bytes(private_key: [u8; 32]) -> [u8; 32] {
    Ed25519SigningKey::from_bytes(&private_key)
        .verifying_key()
        .to_bytes()
}

fn x25519_private_jwk(private_key: [u8; 32]) -> JWK {
    let static_secret = X25519StaticSecret::from(private_key);
    let public_key = X25519PublicKey::from(&static_secret).to_bytes();
    JWK::from(Params::OKP(OctetParams {
        curve: "X25519".to_string(),
        public_key: Base64urlUInt(public_key.to_vec()),
        private_key: Some(Base64urlUInt(private_key.to_vec())),
    }))
}

fn did_jwk_uri(public_jwk: &JWK) -> AgentIdentityResult<String> {
    let mut jwk = public_jwk.to_public();
    jwk.key_id = None;
    jwk.algorithm = None;
    let encoded = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&jwk).map_err(|err| AgentIdentityError::did(err.to_string()))?);
    Ok(format!("did:jwk:{encoded}"))
}

fn key_uri_for_jwk(jwk: &JWK) -> AgentIdentityResult<String> {
    if let Some(kid) = &jwk.key_id {
        return Ok(kid.clone());
    }
    let public_jwk = jwk.to_public();
    let bytes = serde_json::to_vec(&public_jwk)
        .map_err(|err| AgentIdentityError::key_manager(err.to_string()))?;
    Ok(format!(
        "urn:jwk:sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
}

pub(crate) fn jwk_curve(jwk: &JWK) -> Option<&str> {
    match &jwk.params {
        Params::OKP(params) => Some(&params.curve),
        Params::EC(params) => params.curve.as_deref(),
        _ => None,
    }
}

pub(crate) fn verification_method_jwk(method: &DIDVerificationMethod) -> Option<JWK> {
    method
        .properties
        .get("publicKeyJwk")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

pub(crate) fn relationship_id(document: &Document, relationship: &ValueOrReference) -> String {
    relationship.id().resolve(&document.id).to_string()
}

fn relationship_contains(
    document: &Document,
    relationships: &[ValueOrReference],
    method: &DIDVerificationMethod,
) -> bool {
    relationships
        .iter()
        .any(|relationship| *relationship.id().resolve(&document.id) == *method.id)
}

fn okp_params(jwk: &JWK) -> AgentIdentityResult<&OctetParams> {
    match &jwk.params {
        Params::OKP(params) => Ok(params),
        _ => Err(AgentIdentityError::key_manager(
            "key is not an octet key pair JWK",
        )),
    }
}

fn with_key_id(mut jwk: JWK, key_id: impl Into<String>) -> JWK {
    jwk.key_id = Some(key_id.into());
    jwk
}

fn parse_did(value: &str) -> AgentIdentityResult<DIDBuf> {
    value
        .parse()
        .map_err(|err| AgentIdentityError::did(format!("invalid DID {value}: {err}")))
}

fn parse_verification_reference(value: &str) -> AgentIdentityResult<ValueOrReference> {
    value
        .parse::<ssi_dids_core::DIDURLBuf>()
        .map(|url| ValueOrReference::Reference(url.into()))
        .map_err(|err| AgentIdentityError::did(format!("invalid DID URL {value}: {err}")))
}

fn did_verification_method(
    id: &str,
    controller: &DIDBuf,
    public_jwk: JWK,
) -> AgentIdentityResult<DIDVerificationMethod> {
    let id = id
        .parse()
        .map_err(|err| AgentIdentityError::did(format!("invalid DID URL {id}: {err}")))?;
    let properties = BTreeMap::from([(
        "publicKeyJwk".to_string(),
        serde_json::to_value(public_jwk).map_err(|err| AgentIdentityError::did(err.to_string()))?,
    )]);
    Ok(DIDVerificationMethod::new(
        id,
        "JsonWebKey2020".to_string(),
        controller.clone(),
        properties,
    ))
}

fn did_service(id: &str, endpoints: Vec<String>) -> AgentIdentityResult<Service> {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "type": "DecentralizedWebNode",
        "serviceEndpoint": endpoints,
    }))
    .map_err(|err| AgentIdentityError::did(format!("invalid DID service: {err}")))
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
        assert_eq!(jwk_curve(&first.signing_private_jwk), Some("Ed25519"));
        assert_eq!(jwk_curve(&first.encryption_private_jwk), Some("X25519"));
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
        portable_did
            .document
            .verification_relationships
            .key_agreement
            .clear();
        portable_did
            .private_keys
            .retain(|jwk| jwk_curve(jwk) != Some("X25519"));

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
