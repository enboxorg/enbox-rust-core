use ed25519_dalek::VerifyingKey;
use ssi_dids_core::{
    document::{verification_method::ValueOrReference, DIDVerificationMethod},
    DIDURLReferenceBuf, Document,
};
use ssi_jwk::{OctetParams, Params, JWK};

use crate::{
    auth::resolver::{verification_method_jwk, DidResolver, Resolution, ResolverError},
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
            let jwk = verification_method_jwk(vm)
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
