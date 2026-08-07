use serde_json::json;
use ssi_dids_core::document::verification_method::ValueOrReference;
use ssi_dids_core::document::VerificationRelationships;
use ssi_dids_core::{DIDURLBuf, Document, DID};
use ssi_jwk::{ed25519_parse, secp256k1_parse};

use super::{
    verification_method_from_jwk, DidMethodResolver, Resolution, ResolverError, ResolverFuture,
};

const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const JWS_2020_CONTEXT: &str = "https://w3id.org/security/suites/jws-2020/v1";
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const SECP256K1_MULTICODEC: [u8; 2] = [0xe7, 0x01];
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const SECP256K1_PUBLIC_KEY_LEN: usize = 33;

#[derive(Debug, Default, Clone, Copy)]
pub struct KeyResolver;

impl DidMethodResolver for KeyResolver {
    fn method_name(&self) -> &str {
        "key"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
        Box::pin(async move { resolve_document(did) })
    }
}

fn resolve_document(did: &DID) -> Result<Resolution, ResolverError> {
    if did.method_name() != "key" {
        return Err(ResolverError::MethodNotSupported(
            did.method_name().to_string(),
        ));
    }

    let identifier = did.method_specific_id();
    let (base, decoded) = multibase::decode(identifier).map_err(|_| ResolverError::InvalidDid)?;
    if base != multibase::Base::Base58Btc {
        return Err(ResolverError::InvalidDid);
    }

    let mut jwk = if let Some(public_key) = decoded.strip_prefix(&ED25519_MULTICODEC) {
        if public_key.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(ResolverError::InvalidDid);
        }
        ed25519_parse(public_key).map_err(|_| ResolverError::InvalidDid)?
    } else if let Some(public_key) = decoded.strip_prefix(&SECP256K1_MULTICODEC) {
        if public_key.len() != SECP256K1_PUBLIC_KEY_LEN {
            return Err(ResolverError::InvalidDid);
        }
        secp256k1_parse(public_key).map_err(|_| ResolverError::InvalidDid)?
    } else {
        return Err(ResolverError::InvalidDid);
    };

    let verification_method_id = format!("{did}#{identifier}");
    jwk.key_id = Some(jwk.thumbprint().map_err(|_| ResolverError::InvalidDid)?);
    let verification_method = verification_method_from_jwk(
        &verification_method_id,
        "JsonWebKey2020",
        &did.to_owned(),
        jwk,
    )?;
    let reference = verification_method_id
        .parse::<DIDURLBuf>()
        .map(ValueOrReference::from)
        .map_err(|_| ResolverError::InvalidDid)?;

    let mut document = Document::new(did.to_owned());
    document.property_set.insert(
        "@context".to_string(),
        json!([DID_CONTEXT, JWS_2020_CONTEXT]),
    );
    document.verification_method = vec![verification_method];
    document.verification_relationships = VerificationRelationships {
        authentication: vec![reference.clone()],
        assertion_method: vec![reference.clone()],
        key_agreement: Vec::new(),
        capability_invocation: vec![reference.clone()],
        capability_delegation: vec![reference],
    };

    Ok(Resolution::new(document))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use ssi_jwk::{Algorithm, Params};

    const ED25519_IDENTIFIER: &str = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

    #[tokio::test]
    async fn produces_enbox_ed25519_document_shape() {
        let did_string = format!("did:key:{ED25519_IDENTIFIER}");
        let did = did_string.parse::<ssi_dids_core::DIDBuf>().unwrap();
        let resolution = KeyResolver.resolve(&did).await.unwrap();
        let document = serde_json::to_value(resolution.document).unwrap();
        let vm_id = format!("{did_string}#{ED25519_IDENTIFIER}");

        assert_eq!(document["@context"], json!([DID_CONTEXT, JWS_2020_CONTEXT]));
        assert_eq!(document["verificationMethod"][0]["id"], vm_id);
        assert_eq!(document["verificationMethod"][0]["type"], "JsonWebKey2020");
        assert_eq!(document["verificationMethod"][0]["controller"], did_string);
        let jwk = serde_json::from_value::<ssi_jwk::JWK>(
            document["verificationMethod"][0]["publicKeyJwk"].clone(),
        )
        .unwrap();
        assert_eq!(jwk.algorithm, None);
        assert_eq!(jwk.key_id, Some(jwk.thumbprint().unwrap()));
        assert_eq!(jwk.get_algorithm(), Some(Algorithm::EdDSA));
        assert!(document.get("keyAgreement").is_none());
        for relationship in [
            "authentication",
            "assertionMethod",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            assert_eq!(document[relationship], json!([vm_id]));
        }
    }

    #[tokio::test]
    async fn resolves_secp256k1() {
        let secret_key = k256::SecretKey::from_slice(&[1; 32]).unwrap();
        let public_key = secret_key.public_key().to_encoded_point(true);
        let mut bytes = SECP256K1_MULTICODEC.to_vec();
        bytes.extend_from_slice(public_key.as_bytes());
        let identifier = multibase::encode(multibase::Base::Base58Btc, bytes);
        let did = format!("did:key:{identifier}")
            .parse::<ssi_dids_core::DIDBuf>()
            .unwrap();

        let resolution = KeyResolver.resolve(&did).await.unwrap();
        let value = &resolution.document.verification_method[0].properties["publicKeyJwk"];
        let jwk = serde_json::from_value::<ssi_jwk::JWK>(value.clone()).unwrap();
        assert_eq!(jwk.algorithm, None);
        assert_eq!(jwk.key_id, Some(jwk.thumbprint().unwrap()));
        assert_eq!(jwk.get_algorithm(), Some(Algorithm::ES256K));
        assert!(matches!(jwk.params, Params::EC(_)));
    }

    #[tokio::test]
    async fn rejects_x25519_and_invalid_key_material() {
        for bytes in [
            {
                let mut bytes = vec![0xec, 0x01];
                bytes.extend_from_slice(&[1; 32]);
                bytes
            },
            {
                let mut bytes = ED25519_MULTICODEC.to_vec();
                bytes.extend_from_slice(&[1; 16]);
                bytes
            },
            {
                let invalid_point = (0..=u8::MAX)
                    .map(|byte| [byte; ED25519_PUBLIC_KEY_LEN])
                    .find(|point| ed25519_parse(point).is_err())
                    .expect("at least one repeated-byte encoding is not an Edwards point");
                let mut bytes = ED25519_MULTICODEC.to_vec();
                bytes.extend_from_slice(&invalid_point);
                bytes
            },
            {
                let mut bytes = SECP256K1_MULTICODEC.to_vec();
                bytes.extend_from_slice(&[0; 33]);
                bytes
            },
        ] {
            let identifier = multibase::encode(multibase::Base::Base58Btc, bytes);
            let did = format!("did:key:{identifier}")
                .parse::<ssi_dids_core::DIDBuf>()
                .unwrap();
            assert!(matches!(
                KeyResolver.resolve(&did).await,
                Err(ResolverError::InvalidDid)
            ));
        }
    }

    #[tokio::test]
    async fn rejects_non_base58btc_identifier() {
        let mut bytes = ED25519_MULTICODEC.to_vec();
        bytes.extend_from_slice(&[7; 32]);
        let identifier = multibase::encode(multibase::Base::Base64Url, bytes);
        let did = format!("did:key:{identifier}")
            .parse::<ssi_dids_core::DIDBuf>()
            .unwrap();
        assert!(matches!(
            KeyResolver.resolve(&did).await,
            Err(ResolverError::InvalidDid)
        ));
    }
}
