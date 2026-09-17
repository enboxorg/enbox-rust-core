use super::{
    dht_public_jwk, did_jwk_uri, did_method_with_jwk_value, did_service, did_verification_method,
    ed25519_public_bytes, parse_did, parse_verification_reference,
    validate_agent_did_key_requirements, with_key_id, x25519_public_bytes, AgentDidCreateRequest,
    AgentIdentityError, AgentIdentityFuture, DidMetadata, DidProvider, PortableDid, ProviderDidMap,
};
use std::collections::BTreeMap;

use serde_json::Value as JsonValue;
use ssi_dids_core::document::VerificationRelationships;
use ssi_dids_core::Document;

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

#[cfg(test)]
mod tests {
    use super::super::*;
    use ssi_jwk::JWK;

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
}
