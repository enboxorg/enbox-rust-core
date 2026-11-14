mod derivation;
mod did_endpoints;
mod did_jwk;
mod did_network;
mod errors;
mod memory;
mod providers;
mod secret_store;
mod service;
mod vault;
mod vault_jwe;

pub use self::derivation::*;
pub(crate) use self::did_endpoints::*;
pub(crate) use self::did_jwk::*;
pub use self::did_network::*;
pub use self::errors::*;
pub use self::memory::*;
pub use self::providers::*;
pub use self::secret_store::*;
pub use self::service::*;
pub use self::vault::*;
pub use self::vault_jwe::*;

#[cfg(test)]
pub(crate) const RECOVERY_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Arc;

    pub(crate) struct ReadyNetwork;

    impl AgentDidNetwork for ReadyNetwork {
        fn resolve<'a>(&'a self, did_uri: &'a str) -> AgentIdentityFuture<'a, DidResolution> {
            Box::pin(async move {
                Ok(DidResolution::Found(ResolvedAgentDid {
                    document: ready_document(did_uri),
                    sequence: 1,
                    types: None,
                }))
            })
        }

        fn publish<'a>(
            &'a self,
            _document: &'a ssi_dids_core::Document,
            _types: &'a [u64],
            _sequence: u64,
            _signer: &'a dyn AgentDidSigner,
        ) -> AgentIdentityFuture<'a, u64> {
            Box::pin(async move { Ok(1) })
        }
    }

    pub(crate) fn ready_document(did_uri: &str) -> ssi_dids_core::Document {
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

    pub(crate) fn offline_vault(
        store: Arc<dyn SecretStore>,
        did_provider: Arc<dyn DidProvider>,
        work_factor: u32,
    ) -> IdentityVault {
        IdentityVault::with_did_network(store, did_provider, work_factor, Arc::new(ReadyNetwork))
    }
}
