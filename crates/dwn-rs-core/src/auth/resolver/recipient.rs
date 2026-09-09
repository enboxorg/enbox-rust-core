use ed25519_dalek::VerifyingKey;
use ssi_dids_core::{
    document::{verification_method::ValueOrReference, DIDVerificationMethod},
    DIDURLReferenceBuf, Document,
};
use ssi_jwk::{OctetParams, Params, JWK};

use crate::{
    auth::resolver::{DidResolver, Resolution, ResolverError},
    encryption::x25519::public_jwk,
};

const CURVE_X25519: &str = "X25519";
const CURVE_ED25519: &str = "Ed25519";

pub struct RecipientKey {
    pub key_id: String,
    pub public_key: JWK,
}

pub async fn resolve_key_agreement_key(
    did: &str,
    resolver: &dyn DidResolver,
) -> Result<Vec<RecipientKey>, ResolverError> {
    let Resolution {
        document,
        document_metadata,
        resolution_metadata: _,
    } = resolver.resolve(did).await?;

    if document_metadata.deactivated.unwrap_or(false) {
        return Err(ResolverError::InvalidDid);
    }

    if document.id != did {
        return Err(ResolverError::InvalidDid);
    }

    let key_agreements = get_key_agreements(&document, resolver)
        .await?
        .iter()
        .map(|vm| {
            let jwk = key_agreement_jwk(vm)
                .ok_or(ResolverError::InvalidDocument(
                    "invalid public jwk material".to_string(),
                ))?
                .to_public();

            Ok((&vm.id, jwk))
        })
        .filter_map(
            |vm_key: Result<(&ssi_dids_core::DIDURLBuf, JWK), ResolverError>| match vm_key {
                Ok((vm_id, jwk)) => match jwk.params {
                    Params::OKP(ref p) => {
                        if p.curve == CURVE_X25519 {
                            Some(Ok(RecipientKey {
                                key_id: vm_id.to_string(),
                                public_key: jwk,
                            }))
                        } else if p.curve == CURVE_ED25519 {
                            Some(convert_ed25519(p).map(|jwk| RecipientKey {
                                key_id: vm_id.to_string(),
                                public_key: jwk,
                            }))
                        } else {
                            None
                        }
                    }

                    _ => None,
                },
                Err(err) => Some(Err(err)),
            },
        )
        .collect::<Result<Vec<RecipientKey>, ResolverError>>()?;

    if key_agreements.is_empty() {
        return Err(ResolverError::KeyAgreementNotFound {
            did: document.id.to_string(),
        });
    }

    Ok(key_agreements)
}

async fn get_key_agreements(
    document: &Document,
    resolver: &dyn DidResolver,
) -> Result<Vec<DIDVerificationMethod>, ResolverError> {
    let mut vms = Vec::new();

    for key_agreement in document.verification_relationships.key_agreement.clone() {
        let vm = match key_agreement {
            ValueOrReference::Value(vm) => Ok(vm),
            ValueOrReference::Reference(didref) => match didref {
                DIDURLReferenceBuf::Absolute(absolute) => {
                    let (base_did, _) = absolute.without_fragment();
                    let doc = resolver.resolve(base_did).await?;

                    if doc.document_metadata.deactivated.unwrap_or(false) {
                        return Err(ResolverError::InvalidDid);
                    }

                    let vm = doc
                        .document
                        .verification_method
                        .iter()
                        .find(|vm| vm.id == absolute)
                        .ok_or(ResolverError::InvalidDocument(absolute.to_string()))?;

                    Ok(vm.clone())
                }
                DIDURLReferenceBuf::Relative(relative) => {
                    let vm = document
                        .verification_method
                        .iter()
                        .find(|vm| vm.id == relative.resolve(&document.id))
                        .ok_or(ResolverError::InvalidDocument(relative.to_string()))?;
                    Ok(vm.clone())
                }
            },
        }?;

        vms.push(vm);
    }

    if vms.is_empty() {
        return Err(ResolverError::KeyAgreementNotFound {
            did: document.id.to_string(),
        });
    }

    Ok(vms)
}

/// Parses a verification method's `publicKeyJwk` for key-agreement use.
///
/// Unlike [`verification_method_jwk`], this drops the `alg` member before
/// parsing. Key-agreement keys carry key-agreement algorithms — did:dht
/// publishes `ECDH-ES+A256KW` on X25519 keys, and this crate's own did:dht
/// resolver emits the same — none of which `ssi_jwk::Algorithm` models, so
/// leaving `alg` in place fails the whole document. The member is advisory
/// here regardless: the wrapping algorithm for DWN encryption is fixed at
/// `X25519-HKDF-SHA256+A256KW`, and the curve is what selection gates on.
fn key_agreement_jwk(method: &DIDVerificationMethod) -> Option<JWK> {
    let mut value = method.properties.get("publicKeyJwk")?.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("alg");
    }
    serde_json::from_value(value).ok()
}

fn convert_ed25519(params: &OctetParams) -> Result<JWK, ResolverError> {
    if params.curve == CURVE_ED25519 {
        let bytes: [u8; 32] = params.public_key.0.as_slice().try_into().map_err(|_| {
            ResolverError::InvalidDocument("invalid public jwk material".to_string())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
            ResolverError::InvalidDocument("invalid public jwk material".to_string())
        })?;

        Ok(public_jwk(&verifying_key.to_montgomery().to_bytes()))
    } else {
        Err(ResolverError::InvalidPublicKeyType {
            found: params.curve.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{json, Value};
    use ssi_dids_core::DIDBuf;

    use super::*;
    use crate::auth::resolver::ResolverFuture;

    const X25519_A: &str = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";
    const X25519_B: &str = "3POE0_i2mGeZ2qiQCA3KcLfi1fZo0311CXFSIwt1nB4";
    /// did:key spec Ed25519/X25519 worked example, and the X25519 counterpart
    /// the same example publishes. See
    /// `fixtures/spec/did/did-key-ed25519-key-agreement.json`.
    const ED25519_SPEC: &str = "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY";
    const X25519_SPEC_COUNTERPART: &str = "bl_3kgKpz9jgsg350CNuHa_kQL3B60Gi-98WmdQW2h8";

    /// Resolves from a fixed set of documents, so reference following can be
    /// exercised without a network or a method implementation.
    #[derive(Default)]
    struct StubResolver {
        documents: BTreeMap<String, Value>,
        deactivated: Vec<String>,
        override_id: Option<String>,
    }

    impl StubResolver {
        fn with(did: &str, document: Value) -> Self {
            Self {
                documents: BTreeMap::from([(did.to_string(), document)]),
                ..Default::default()
            }
        }

        fn and(mut self, did: &str, document: Value) -> Self {
            self.documents.insert(did.to_string(), document);
            self
        }

        fn deactivate(mut self, did: &str) -> Self {
            self.deactivated.push(did.to_string());
            self
        }

        /// Makes the resolver answer with a document whose `id` is some other
        /// DID, modelling a resolver that returns the wrong subject.
        fn answering_with_id(mut self, id: &str) -> Self {
            self.override_id = Some(id.to_string());
            self
        }
    }

    impl DidResolver for StubResolver {
        fn resolve<'a>(
            &'a self,
            did: &'a str,
        ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
            Box::pin(async move {
                let mut value = self
                    .documents
                    .get(did)
                    .cloned()
                    .ok_or(ResolverError::InvalidDid)?;
                if let Some(id) = &self.override_id {
                    value["id"] = json!(id);
                }
                let document: Document = serde_json::from_value(value)
                    .map_err(|error| ResolverError::InvalidDocument(error.to_string()))?;
                let mut resolution = Resolution::new(document);
                if self.deactivated.iter().any(|entry| entry == did) {
                    resolution.document_metadata.deactivated = Some(true);
                }
                Ok(resolution)
            })
        }
    }

    fn okp_method(id: &str, controller: &str, curve: &str, x: &str) -> Value {
        json!({
            "id": id,
            "type": "JsonWebKey2020",
            "controller": controller,
            "publicKeyJwk": { "kty": "OKP", "crv": curve, "x": x },
        })
    }

    fn document_with(key_agreement: Value, methods: Vec<Value>) -> Value {
        json!({
            "id": "did:example:alice",
            "verificationMethod": methods,
            "keyAgreement": key_agreement,
        })
    }

    async fn resolve(document: Value) -> Result<Vec<RecipientKey>, ResolverError> {
        let resolver = StubResolver::with("did:example:alice", document);
        resolve_key_agreement_key("did:example:alice", &resolver).await
    }

    /// Covers: DWN-ENC-001
    #[tokio::test]
    async fn resolves_every_reference_shape_to_the_same_method() {
        let method = okp_method(
            "did:example:alice#enc",
            "did:example:alice",
            CURVE_X25519,
            X25519_A,
        );

        for reference in [
            json!(["did:example:alice#enc"]),
            json!(["#enc"]),
            json!([method.clone()]),
        ] {
            let keys = resolve(document_with(reference, vec![method.clone()]))
                .await
                .expect("reference shape must resolve");

            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0].key_id, "did:example:alice#enc");
            assert_eq!(
                keys[0].public_key.thumbprint().unwrap(),
                method_jwk(&method).thumbprint().unwrap()
            );
        }
    }

    fn method_jwk(method: &Value) -> JWK {
        serde_json::from_value(method["publicKeyJwk"].clone()).unwrap()
    }

    /// `keyAgreement` is a DID Core set, so an unsupported curve occupying the
    /// first position must not decide the outcome.
    ///
    /// Covers: DWN-ENC-001
    #[tokio::test]
    async fn skips_unsupported_curves_regardless_of_position() {
        let p256 = json!({
            "id": "did:example:alice#p256",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice",
            "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" },
        });
        let x25519 = okp_method(
            "did:example:alice#enc",
            "did:example:alice",
            CURVE_X25519,
            X25519_A,
        );

        let keys = resolve(document_with(
            json!(["did:example:alice#p256", "did:example:alice#enc"]),
            vec![p256, x25519],
        ))
        .await
        .expect("a usable key behind an unsupported one must still be found");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "did:example:alice#enc");
    }

    /// Covers: DWN-ENC-002
    #[tokio::test]
    async fn returns_every_declared_key_for_multi_key_recipients() {
        let first = okp_method(
            "did:example:alice#phone",
            "did:example:alice",
            CURVE_X25519,
            X25519_A,
        );
        let second = okp_method(
            "did:example:alice#laptop",
            "did:example:alice",
            CURVE_X25519,
            X25519_B,
        );

        let keys = resolve(document_with(
            json!(["did:example:alice#phone", "did:example:alice#laptop"]),
            vec![first, second],
        ))
        .await
        .expect("both declared keys must be returned");

        let ids = keys
            .iter()
            .map(|key| key.key_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["did:example:alice#phone", "did:example:alice#laptop"]);
    }

    /// The conversion is checked against the X25519 key the did:key spec
    /// publishes for this Ed25519 key, not against our own output.
    ///
    /// Covers: DWN-ENC-002
    #[tokio::test]
    async fn converts_ed25519_to_the_spec_published_x25519_counterpart() {
        let method = okp_method(
            "did:example:alice#sig",
            "did:example:alice",
            CURVE_ED25519,
            ED25519_SPEC,
        );

        let keys = resolve(document_with(
            json!(["did:example:alice#sig"]),
            vec![method],
        ))
        .await
        .expect("Ed25519 key agreement converts rather than failing");

        let expected: JWK = serde_json::from_value(json!({
            "kty": "OKP", "crv": "X25519", "x": X25519_SPEC_COUNTERPART,
        }))
        .unwrap();
        assert!(keys[0].public_key.equals_public(&expected));
        // The source verification-method id survives conversion.
        assert_eq!(keys[0].key_id, "did:example:alice#sig");
    }

    /// A DID that declares no key agreement — every `did:key`, and `did:jwk`
    /// with `use: "sig"` — must fail rather than fall back to a signing key.
    ///
    /// Covers: DWN-ID-001
    #[tokio::test]
    async fn errors_when_no_key_agreement_is_declared() {
        let signing = okp_method(
            "did:example:alice#0",
            "did:example:alice",
            CURVE_ED25519,
            ED25519_SPEC,
        );
        let document = json!({
            "id": "did:example:alice",
            "verificationMethod": [signing],
            "authentication": ["did:example:alice#0"],
        });

        assert!(matches!(
            resolve(document).await,
            Err(ResolverError::KeyAgreementNotFound { did }) if did == "did:example:alice"
        ));
    }

    /// Covers: DWN-ENC-001
    #[tokio::test]
    async fn errors_when_no_declared_curve_is_usable() {
        let p256 = json!({
            "id": "did:example:alice#p256",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice",
            "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" },
        });

        assert!(matches!(
            resolve(document_with(json!(["did:example:alice#p256"]), vec![p256])).await,
            Err(ResolverError::KeyAgreementNotFound { .. })
        ));
    }

    /// A malformed document is not the same as an unsupported curve: it must
    /// fail rather than silently shrink the returned set.
    #[tokio::test]
    async fn errors_on_a_method_without_public_key_material() {
        let method = json!({
            "id": "did:example:alice#enc",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice",
        });

        assert!(matches!(
            resolve(document_with(
                json!(["did:example:alice#enc"]),
                vec![method]
            ))
            .await,
            Err(ResolverError::InvalidDocument(_))
        ));
    }

    #[tokio::test]
    async fn errors_on_a_dangling_fragment() {
        let method = okp_method(
            "did:example:alice#enc",
            "did:example:alice",
            CURVE_X25519,
            X25519_A,
        );

        assert!(matches!(
            resolve(document_with(json!(["#missing"]), vec![method])).await,
            Err(ResolverError::InvalidDocument(_))
        ));
    }

    /// Covers: DWN-ENC-001
    #[tokio::test]
    async fn returns_public_only_key_material() {
        let mut method = okp_method(
            "did:example:alice#enc",
            "did:example:alice",
            CURVE_X25519,
            X25519_A,
        );
        method["publicKeyJwk"]["d"] = json!("cmVjaXBpZW50LXByb3RvY29sLXBhdGhYWFhYWFhYWFg");

        let keys = resolve(document_with(
            json!(["did:example:alice#enc"]),
            vec![method],
        ))
        .await
        .unwrap();

        assert!(keys[0].public_key.is_public());
    }

    /// A reference naming another DID resolves against that DID's document,
    /// never against a same-fragment method in the referring one.
    ///
    /// Covers: DWN-ID-001
    #[tokio::test]
    async fn dereferences_a_foreign_did_reference() {
        let alice_local = okp_method(
            "did:example:alice#enc",
            "did:example:alice",
            CURVE_X25519,
            X25519_A,
        );
        let alice = json!({
            "id": "did:example:alice",
            "verificationMethod": [alice_local],
            "keyAgreement": ["did:example:bob#enc"],
        });
        let bob = json!({
            "id": "did:example:bob",
            "verificationMethod": [okp_method(
                "did:example:bob#enc",
                "did:example:bob",
                CURVE_X25519,
                X25519_B,
            )],
            "keyAgreement": ["did:example:bob#enc"],
        });

        let resolver = StubResolver::with("did:example:alice", alice).and("did:example:bob", bob);
        let keys = resolve_key_agreement_key("did:example:alice", &resolver)
            .await
            .unwrap();

        assert_eq!(keys.len(), 1);
        // Bob's key, not Alice's same-fragment method.
        assert_eq!(keys[0].key_id, "did:example:bob#enc");
        let expected: JWK =
            serde_json::from_value(json!({"kty": "OKP", "crv": "X25519", "x": X25519_B})).unwrap();
        assert!(keys[0].public_key.equals_public(&expected));
    }

    #[tokio::test]
    async fn errors_when_a_foreign_reference_cannot_be_resolved() {
        let alice = json!({
            "id": "did:example:alice",
            "verificationMethod": [okp_method(
                "did:example:alice#enc",
                "did:example:alice",
                CURVE_X25519,
                X25519_A,
            )],
            "keyAgreement": ["did:example:bob#enc"],
        });

        // Bob is absent, and Alice's own `#enc` must not be used as a fallback.
        assert!(resolve(alice).await.is_err());
    }

    #[tokio::test]
    async fn errors_when_a_foreign_document_lacks_the_fragment() {
        let alice = json!({
            "id": "did:example:alice",
            "verificationMethod": [],
            "keyAgreement": ["did:example:bob#enc"],
        });
        let bob = json!({
            "id": "did:example:bob",
            "verificationMethod": [okp_method(
                "did:example:bob#other",
                "did:example:bob",
                CURVE_X25519,
                X25519_B,
            )],
        });

        let resolver = StubResolver::with("did:example:alice", alice).and("did:example:bob", bob);
        assert!(matches!(
            resolve_key_agreement_key("did:example:alice", &resolver).await,
            Err(ResolverError::InvalidDocument(_))
        ));
    }

    /// Covers: DWN-ID-001
    #[tokio::test]
    async fn rejects_deactivated_subject_and_deactivated_reference_target() {
        let method = okp_method(
            "did:example:alice#enc",
            "did:example:alice",
            CURVE_X25519,
            X25519_A,
        );
        let alice = document_with(json!(["did:example:alice#enc"]), vec![method.clone()]);

        let resolver =
            StubResolver::with("did:example:alice", alice.clone()).deactivate("did:example:alice");
        assert!(matches!(
            resolve_key_agreement_key("did:example:alice", &resolver).await,
            Err(ResolverError::InvalidDid)
        ));

        let referring = json!({
            "id": "did:example:alice",
            "verificationMethod": [method],
            "keyAgreement": ["did:example:bob#enc"],
        });
        let bob = json!({
            "id": "did:example:bob",
            "verificationMethod": [okp_method(
                "did:example:bob#enc",
                "did:example:bob",
                CURVE_X25519,
                X25519_B,
            )],
        });
        let resolver = StubResolver::with("did:example:alice", referring)
            .and("did:example:bob", bob)
            .deactivate("did:example:bob");
        assert!(matches!(
            resolve_key_agreement_key("did:example:alice", &resolver).await,
            Err(ResolverError::InvalidDid)
        ));
    }

    /// Covers: DWN-ID-001
    #[tokio::test]
    async fn rejects_a_document_answering_for_a_different_did() {
        let method = okp_method(
            "did:example:alice#enc",
            "did:example:alice",
            CURVE_X25519,
            X25519_A,
        );
        let resolver = StubResolver::with(
            "did:example:alice",
            document_with(json!(["did:example:alice#enc"]), vec![method]),
        )
        .answering_with_id("did:example:mallory");

        assert!(matches!(
            resolve_key_agreement_key("did:example:alice", &resolver).await,
            Err(ResolverError::InvalidDid)
        ));
    }

    /// did:dht publishes `alg: ECDH-ES+A256KW` on key-agreement keys, which
    /// `ssi_jwk::Algorithm` does not model. Selection must not fail on it.
    #[tokio::test]
    async fn accepts_key_agreement_algorithms_ssi_jwk_does_not_model() {
        let mut method = okp_method(
            "did:example:alice#enc",
            "did:example:alice",
            CURVE_X25519,
            X25519_A,
        );
        method["publicKeyJwk"]["alg"] = json!("ECDH-ES+A256KW");

        let keys = resolve(document_with(
            json!(["did:example:alice#enc"]),
            vec![method],
        ))
        .await
        .expect("a key-agreement alg must not fail document parsing");
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn convert_ed25519_rejects_a_non_ed25519_curve() {
        let jwk: JWK =
            serde_json::from_value(json!({"kty": "OKP", "crv": "X25519", "x": X25519_A})).unwrap();
        let Params::OKP(params) = &jwk.params else {
            unreachable!("constructed as OKP")
        };

        assert!(matches!(
            convert_ed25519(params),
            Err(ResolverError::InvalidPublicKeyType { found }) if found == CURVE_X25519
        ));
    }

    #[test]
    fn document_ids_used_by_the_stub_are_well_formed() {
        // Guards the fixtures above against silently becoming unparseable DIDs.
        for did in ["did:example:alice", "did:example:bob"] {
            assert!(did.parse::<DIDBuf>().is_ok(), "{did} must parse");
        }
    }
}
