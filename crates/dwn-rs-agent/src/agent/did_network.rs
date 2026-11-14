//! Agent DID publication and fresh resolution seams.
//!
//! The vault reaches the network only through an injected [`AgentDidNetwork`];
//! publication signs through an injected [`AgentDidSigner`] or the derived
//! identity key, and time comes from an injected clock closure.

use super::{
    fixed_32, now_utc, okp_params, AgentIdentityError, AgentIdentityFuture, AgentIdentityResult,
    DidMetadata,
};

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use did_dht::{DhtPublishError, DhtResolver, DhtResolverConfig, JwsSigner};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use ssi_claims_core::SignatureError;
use ssi_dids_core::{DIDBuf, Document};
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::JwsSignerInfo;

/// The vault clock. One closure keeps the tests offline and injectable.
pub type AgentClock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

pub(crate) fn system_clock() -> AgentClock {
    Arc::new(now_utc)
}

pub(crate) fn clock_system_time(clock: &AgentClock) -> SystemTime {
    SystemTime::from(clock())
}

fn did_error(error: DhtPublishError) -> AgentIdentityError {
    AgentIdentityError::did(error.to_string())
}

/// A document obtained by a fresh resolution, never from a cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAgentDid {
    pub document: Document,
    pub sequence: u64,
    pub types: Option<Vec<u64>>,
}

impl ResolvedAgentDid {
    /// Resolution metadata recorded when the resolved document is adopted
    /// without a republication.
    pub fn metadata(&self) -> DidMetadata {
        let mut extra = BTreeMap::new();
        extra.insert("versionId".to_string(), json!(self.sequence.to_string()));
        if let Some(types) = &self.types {
            extra.insert("types".to_string(), json!(types));
        }
        DidMetadata {
            published: Some(true),
            extra,
        }
    }
}

/// Outcome of a fresh agent DID lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidResolution {
    Found(Box<ResolvedAgentDid>),
    NotFound,
}

/// Signs the BEP44 preimage with the DID's identity key.
///
/// Dyn-compatible so the vault can hold a host-supplied signer.
pub trait AgentDidSigner: Send + Sync + 'static {
    fn sign<'a>(&'a self, bytes: &'a [u8]) -> AgentIdentityFuture<'a, Vec<u8>>;
}

/// Host-supplied agent DID resolution and publication.
pub trait AgentDidNetwork: Send + Sync + 'static {
    /// Resolve the DID directly; a cache must never answer this call.
    fn resolve<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, DidResolution>;

    /// Publish `document` at `sequence`, signed through `signer`.
    fn publish<'a>(
        &'a self,
        document: &'a Document,
        types: &'a [u64],
        sequence: u64,
        signer: &'a dyn AgentDidSigner,
    ) -> AgentIdentityFuture<'a, u64>;
}

/// Signs with the identity private key derived from the recovery phrase.
pub struct DerivedIdentitySigner {
    key: SigningKey,
}

impl DerivedIdentitySigner {
    pub fn from_jwk(private_jwk: &JWK) -> AgentIdentityResult<Self> {
        let params = okp_params(private_jwk)?;
        if params.curve != "Ed25519" {
            return Err(AgentIdentityError::invalid_key_material(
                "agent identity key must be Ed25519",
            ));
        }
        let private_key = params.private_key.as_ref().ok_or_else(|| {
            AgentIdentityError::invalid_key_material(
                "agent identity key is missing private key material",
            )
        })?;
        Ok(Self {
            key: SigningKey::from_bytes(&fixed_32(&private_key.0)?),
        })
    }
}

impl AgentDidSigner for DerivedIdentitySigner {
    fn sign<'a>(&'a self, bytes: &'a [u8]) -> AgentIdentityFuture<'a, Vec<u8>> {
        Box::pin(async move { Ok(self.key.sign(bytes).to_bytes().to_vec()) })
    }
}

struct DynSigner<'a>(&'a dyn AgentDidSigner);

impl JwsSigner for DynSigner<'_> {
    async fn fetch_info(&self) -> Result<JwsSignerInfo, SignatureError> {
        Ok(JwsSignerInfo::new(None, Algorithm::EdDSA))
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        self.0
            .sign(signing_bytes)
            .await
            .map_err(SignatureError::other)
    }
}

/// `did:dht` gateway client over the method crate's resolver.
pub struct DidDhtNetwork {
    resolver: DhtResolver,
}

impl DidDhtNetwork {
    pub fn new(resolver: DhtResolver) -> Self {
        Self { resolver }
    }

    /// A client over the process's native HTTP transport.
    pub fn native() -> Self {
        Self::new(dwn_rs_core::auth::resolver::new_dht_resolver(
            DhtResolverConfig::default(),
        ))
    }
}

impl AgentDidNetwork for DidDhtNetwork {
    fn resolve<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, DidResolution> {
        Box::pin(async move {
            let did: DIDBuf = did_uri.parse().map_err(|error| {
                AgentIdentityError::did(format!("invalid DID {did_uri}: {error}"))
            })?;
            match self.resolver.resolve(&did).await {
                Ok(resolved) => Ok(DidResolution::Found(Box::new(ResolvedAgentDid {
                    document: resolved.document,
                    sequence: resolved.sequence,
                    types: resolved.types,
                }))),
                Err(DhtPublishError::NotFound) => Ok(DidResolution::NotFound),
                Err(error) => Err(did_error(error)),
            }
        })
    }

    fn publish<'a>(
        &'a self,
        document: &'a Document,
        types: &'a [u64],
        sequence: u64,
        signer: &'a dyn AgentDidSigner,
    ) -> AgentIdentityFuture<'a, u64> {
        Box::pin(async move {
            self.resolver
                .publish(document, types, sequence, &DynSigner(signer))
                .await
                .map_err(did_error)
        })
    }
}
