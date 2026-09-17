use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256, Sha512};
use ssi_dids_core::document::verification_method::ValueOrReference;
use ssi_dids_core::document::{DIDVerificationMethod, Service, VerificationRelationships};
use ssi_dids_core::{DIDBuf, Document};
use ssi_jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

mod derivation;
mod did_jwk;
mod errors;
mod service;
mod traits;
mod types;

pub use self::derivation::*;
pub(crate) use self::did_jwk::*;
pub use self::errors::*;
pub use self::service::*;
pub use self::traits::*;
pub use self::types::*;




#[derive(Clone, Default)]
pub struct DeterministicDidJwkProvider {
    dids: ProviderDidMap,
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
            self.dids.insert(portable_did)
        })
    }

    fn import_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, PortableDid> {
        Box::pin(async move {
            validate_agent_did_key_requirements(&portable_did)?;
            self.dids.insert(portable_did)
        })
    }

    fn export_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>> {
        Box::pin(async move { self.dids.get(did_uri) })
    }
}

/// Builds the agent `did:dht` from caller-supplied keys.
///
/// Pure local construction: no resolution, signing, publication, or other
/// network access. Publication happens only through the gateway client.
/// Unlike the `did:jwk` provider above, the document carries no `@context` —
/// the DID DHT wire cannot represent it.
#[derive(Clone, Default)]
pub struct DidDhtProvider {
    dids: ProviderDidMap,
}

impl DidProvider for DidDhtProvider {
    fn create_did<'a>(
        &'a self,
        request: AgentDidCreateRequest,
    ) -> AgentIdentityFuture<'a, PortableDid> {
        Box::pin(async move {
            let identity_bytes = ed25519_public_bytes(&request.identity_private_jwk)?;
            ed25519_public_bytes(&request.signing_private_jwk)?;
            x25519_public_bytes(&request.encryption_private_jwk)?;

            let did_uri = format!("did:dht:{}", z32::encode(&identity_bytes));
            let did = parse_did(&did_uri)?;
            let identity_id = format!("{did_uri}#0");
            let sig_id = format!("{did_uri}#sig");
            let enc_id = format!("{did_uri}#enc");

            let mut document = Document::new(did.clone());
            document.verification_method = vec![
                did_method_with_jwk_value(
                    &identity_id,
                    "JsonWebKey",
                    &did,
                    dht_public_jwk(&request.identity_private_jwk, "EdDSA")?,
                )?,
                did_method_with_jwk_value(
                    &sig_id,
                    "JsonWebKey",
                    &did,
                    dht_public_jwk(&request.signing_private_jwk, "EdDSA")?,
                )?,
                did_method_with_jwk_value(
                    &enc_id,
                    "JsonWebKey",
                    &did,
                    dht_public_jwk(&request.encryption_private_jwk, "ECDH-ES+A256KW")?,
                )?,
            ];
            let identity_reference = parse_verification_reference(&identity_id)?;
            let sig_reference = parse_verification_reference(&sig_id)?;
            let enc_reference = parse_verification_reference(&enc_id)?;
            document.verification_relationships = VerificationRelationships {
                authentication: vec![identity_reference.clone(), sig_reference.clone()],
                assertion_method: vec![identity_reference.clone(), sig_reference.clone()],
                key_agreement: vec![enc_reference],
                capability_invocation: vec![identity_reference.clone()],
                capability_delegation: vec![identity_reference],
            };
            if !request.dwn_endpoints.is_empty() {
                document.service.push(did_service(
                    &format!("{did_uri}#dwn"),
                    request.dwn_endpoints,
                )?);
            }
            did_dht::validate_publishable_document(&document, &[])
                .map_err(|err| AgentIdentityError::did(err.to_string()))?;

            let portable_did = PortableDid {
                uri: did_uri.clone(),
                document,
                metadata: DidMetadata {
                    published: Some(false),
                    extra: BTreeMap::new(),
                },
                private_keys: vec![
                    with_key_id(request.identity_private_jwk, identity_id),
                    with_key_id(request.signing_private_jwk, sig_id),
                    with_key_id(request.encryption_private_jwk, enc_id),
                ],
            };
            self.dids.insert(portable_did)
        })
    }

    fn import_did<'a>(&'a self, portable_did: PortableDid) -> AgentIdentityFuture<'a, PortableDid> {
        Box::pin(async move {
            validate_agent_did_key_requirements(&portable_did)?;
            self.dids.insert(portable_did)
        })
    }

    fn export_did<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, Option<PortableDid>> {
        Box::pin(async move { self.dids.get(did_uri) })
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
pub use PortableDidStore as DidResolverCache;

/// Deprecated name for [`MemoryPortableDidStore`].
#[deprecated(note = "use MemoryPortableDidStore")]
pub type MemoryDidResolverCache = MemoryPortableDidStore;



#[cfg(test)]
mod tests {
    use super::*;

    const RECOVERY_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[tokio::test]
    // Covers: DID-DHT-001, DID-DHT-006
    async fn did_dht_provider_builds_agent_shape_with_vault_uri() {
        let provider = DidDhtProvider::default();
        let derived = derive_agent_keys(RECOVERY_PHRASE).unwrap();
        let portable_did = provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived.identity_private_jwk,
                signing_private_jwk: derived.signing_private_jwk,
                encryption_private_jwk: derived.encryption_private_jwk,
                dwn_endpoints: vec!["https://dwn.example".to_string()],
            })
            .await
            .unwrap();

        let uri = "did:dht:qftx7z968xcpfy1a1diu75pg5meap3gdtg6ezagaw849wdh6oubo";
        assert_eq!(portable_did.uri, uri);
        let id0 = format!("{uri}#0");
        let sig = format!("{uri}#sig");
        let enc = format!("{uri}#enc");

        let document = serde_json::to_value(&portable_did.document).unwrap();
        assert_eq!(document["id"], uri);
        assert_eq!(document["authentication"], serde_json::json!([id0, sig]));
        assert_eq!(document["assertionMethod"], serde_json::json!([id0, sig]));
        assert_eq!(document["capabilityInvocation"], serde_json::json!([id0]));
        assert_eq!(document["capabilityDelegation"], serde_json::json!([id0]));
        assert_eq!(document["keyAgreement"], serde_json::json!([enc]));
        assert_eq!(
            document["service"],
            serde_json::json!([{
                "id": format!("{uri}#dwn"),
                "type": "DecentralizedWebNode",
                "serviceEndpoint": ["https://dwn.example"],
            }])
        );

        let methods = document["verificationMethod"].as_array().unwrap();
        assert_eq!(methods.len(), 3);
        for (method, fragment, alg) in [
            (&methods[0], "0", "EdDSA"),
            (&methods[1], "sig", "EdDSA"),
            (&methods[2], "enc", "ECDH-ES+A256KW"),
        ] {
            assert_eq!(method["id"], format!("{uri}#{fragment}"));
            assert_eq!(method["type"], "JsonWebKey");
            assert_eq!(method["controller"], uri);
            let jwk = &method["publicKeyJwk"];
            assert_eq!(jwk["alg"], alg);
            let mut bare = jwk.clone();
            bare.as_object_mut().unwrap().remove("alg");
            let parsed: JWK = serde_json::from_value(bare).unwrap();
            assert_eq!(jwk["kid"], parsed.thumbprint().unwrap());
        }

        assert_eq!(portable_did.private_keys.len(), 3);
        for (key, fragment) in [
            (&portable_did.private_keys[0], "0"),
            (&portable_did.private_keys[1], "sig"),
            (&portable_did.private_keys[2], "enc"),
        ] {
            assert!(!key.is_public());
            assert_eq!(key.key_id, Some(format!("{uri}#{fragment}")));
        }
        assert_eq!(portable_did.metadata.published, Some(false));

        validate_agent_did_key_requirements(&portable_did).unwrap();
        assert_eq!(
            provider.export_did(&portable_did.uri).await.unwrap(),
            Some(portable_did)
        );
    }

    #[tokio::test]
    // Covers: DID-DHT-006
    async fn did_dht_provider_omits_dwn_service_without_endpoints() {
        let provider = DidDhtProvider::default();
        let derived = derive_agent_keys(RECOVERY_PHRASE).unwrap();
        let portable_did = provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived.identity_private_jwk,
                signing_private_jwk: derived.signing_private_jwk,
                encryption_private_jwk: derived.encryption_private_jwk,
                dwn_endpoints: Vec::new(),
            })
            .await
            .unwrap();

        let document = serde_json::to_value(&portable_did.document).unwrap();
        assert!(document.get("service").is_none());
    }

    #[tokio::test]
    // Covers: DID-DHT-001
    async fn did_dht_provider_rejects_non_ed25519_identity() {
        let provider = DidDhtProvider::default();
        let derived = derive_agent_keys(RECOVERY_PHRASE).unwrap();
        let error = provider
            .create_did(AgentDidCreateRequest {
                identity_private_jwk: derived.encryption_private_jwk.clone(),
                signing_private_jwk: derived.signing_private_jwk,
                encryption_private_jwk: derived.encryption_private_jwk,
                dwn_endpoints: Vec::new(),
            })
            .await
            .unwrap_err();

        assert_eq!(error.code(), "AgentIdentityInvalidKeyMaterial");
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

}
