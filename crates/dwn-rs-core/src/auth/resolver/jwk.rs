use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::json;
use ssi_dids_core::document::verification_method::ValueOrReference;
use ssi_dids_core::document::VerificationRelationships;
use ssi_dids_core::{DIDURLBuf, Document, DID};
use ssi_jwk::JWK;

use super::{
    jwk_verification_method, DidMethodResolver, Resolution, ResolverError, ResolverFuture,
};

const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

#[derive(Debug, Default, Clone, Copy)]
pub struct JwkResolver;

impl DidMethodResolver for JwkResolver {
    fn method_name(&self) -> &str {
        "jwk"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
        Box::pin(async move { resolve_document(did) })
    }
}

fn resolve_document(did: &DID) -> Result<Resolution, ResolverError> {
    if did.method_name() != "jwk" {
        return Err(ResolverError::MethodNotSupported(
            did.method_name().to_string(),
        ));
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(did.method_specific_id())
        .map_err(|_| ResolverError::InvalidDid)?;
    let jwk = serde_json::from_slice::<JWK>(&decoded).map_err(|_| ResolverError::InvalidDid)?;
    let verification_method_id = format!("{did}#0");
    let verification_method = jwk_verification_method(
        &verification_method_id,
        "JsonWebKey",
        &did.to_owned(),
        jwk.clone(),
    )?;
    let reference = verification_method_id
        .parse::<DIDURLBuf>()
        .map(ValueOrReference::from)
        .map_err(|_| ResolverError::InvalidDid)?;

    let mut document = Document::new(did.to_owned());
    document
        .property_set
        .insert("@context".to_string(), json!([DID_CONTEXT]));
    document.verification_method = vec![verification_method];
    document.verification_relationships = VerificationRelationships {
        authentication: vec![reference.clone()],
        assertion_method: vec![reference.clone()],
        key_agreement: vec![reference.clone()],
        capability_invocation: vec![reference.clone()],
        capability_delegation: vec![reference],
    };

    match jwk.public_key_use.as_deref() {
        Some("sig") => document.verification_relationships.key_agreement.clear(),
        Some("enc") => {
            document.verification_relationships.authentication.clear();
            document.verification_relationships.assertion_method.clear();
            document
                .verification_relationships
                .capability_invocation
                .clear();
            document
                .verification_relationships
                .capability_delegation
                .clear();
        }
        _ => {}
    }

    Ok(Resolution::new(document))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi_jwk::{Algorithm, Base64urlUInt, OctetParams, Params};

    fn did_jwk(use_: Option<&str>) -> String {
        let mut jwk = JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(vec![7; 32]),
            private_key: None,
        }));
        jwk.algorithm = Some(Algorithm::EdDSA);
        jwk.public_key_use = use_.map(str::to_string);
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&jwk).unwrap());
        format!("did:jwk:{encoded}")
    }

    async fn resolve(use_: Option<&str>) -> serde_json::Value {
        let did = did_jwk(use_);
        let did = did.parse::<ssi_dids_core::DIDBuf>().unwrap();
        let resolution = JwkResolver.resolve(&did).await.unwrap();
        serde_json::to_value(resolution.document).unwrap()
    }

    #[tokio::test]
    async fn produces_enbox_document_shape() {
        let document = resolve(None).await;
        let did = document["id"].as_str().unwrap();
        let vm_id = format!("{did}#0");

        assert_eq!(document["@context"], json!([DID_CONTEXT]));
        assert_eq!(document["verificationMethod"][0]["id"], vm_id);
        assert_eq!(document["verificationMethod"][0]["type"], "JsonWebKey");
        assert_eq!(document["verificationMethod"][0]["controller"], did);
        for relationship in [
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            assert_eq!(document[relationship], json!([vm_id]));
        }
    }

    #[tokio::test]
    async fn use_sig_removes_only_key_agreement() {
        let document = resolve(Some("sig")).await;
        assert!(document.get("keyAgreement").is_none());
        for relationship in [
            "authentication",
            "assertionMethod",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            assert!(document.get(relationship).is_some());
        }
    }

    #[tokio::test]
    async fn use_enc_removes_only_signing_relationships() {
        let document = resolve(Some("enc")).await;
        assert!(document.get("keyAgreement").is_some());
        for relationship in [
            "authentication",
            "assertionMethod",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            assert!(document.get(relationship).is_none());
        }
    }

    #[tokio::test]
    async fn preserves_private_jwk_parameters() {
        let mut jwk = JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(vec![7; 32]),
            private_key: Some(Base64urlUInt(vec![9; 32])),
        }));
        jwk.algorithm = Some(Algorithm::EdDSA);
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&jwk).unwrap());
        let did = format!("did:jwk:{encoded}")
            .parse::<ssi_dids_core::DIDBuf>()
            .unwrap();

        let resolution = JwkResolver.resolve(&did).await.unwrap();
        let value = &resolution.document.verification_method[0].properties["publicKeyJwk"];
        assert_eq!(serde_json::from_value::<JWK>(value.clone()).unwrap(), jwk);
    }

    #[tokio::test]
    async fn rejects_invalid_encoded_jwk() {
        let did = "did:jwk:e30".parse::<ssi_dids_core::DIDBuf>().unwrap();
        assert!(matches!(
            JwkResolver.resolve(&did).await,
            Err(ResolverError::InvalidDid)
        ));
    }
}
