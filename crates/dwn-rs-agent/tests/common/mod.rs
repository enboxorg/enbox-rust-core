//! Offline DID network shared by the vault integration tests.

use std::sync::Arc;

use dwn_rs_agent::agent::{
    AgentDidNetwork, AgentDidSigner, AgentIdentityFuture, DidProvider, DidResolution,
    IdentityVault, ResolvedAgentDid, SecretStore,
};
use ssi_dids_core::Document;

pub struct ReadyNetwork;

impl AgentDidNetwork for ReadyNetwork {
    fn resolve<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, DidResolution> {
        Box::pin(async move {
            Ok(DidResolution::Found(Box::new(ResolvedAgentDid {
                document: ready_document(did_uri),
                sequence: 1,
                types: None,
            })))
        })
    }

    fn publish<'a>(
        &'a self,
        _document: &'a Document,
        _types: &'a [u64],
        _sequence: u64,
        _signer: &'a dyn AgentDidSigner,
    ) -> AgentIdentityFuture<'a, u64> {
        Box::pin(async move { Ok(1) })
    }
}

pub fn ready_document(did_uri: &str) -> Document {
    serde_json::from_value(serde_json::json!({
        "id": did_uri,
        "service": [{
            "id": format!("{did_uri}#dwn"),
            "type": "DecentralizedWebNode",
            "serviceEndpoint": ["https://dwn.example"],
        }],
    }))
    .unwrap()
}

pub fn offline_vault(
    store: Arc<dyn SecretStore>,
    did_provider: Arc<dyn DidProvider>,
    work_factor: u32,
) -> IdentityVault {
    IdentityVault::with_did_network(store, did_provider, work_factor, Arc::new(ReadyNetwork))
}
