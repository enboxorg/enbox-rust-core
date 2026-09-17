use super::{AgentDidCreateRequest, AgentIdentityFuture, PortableDid};
use std::sync::Arc;

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
