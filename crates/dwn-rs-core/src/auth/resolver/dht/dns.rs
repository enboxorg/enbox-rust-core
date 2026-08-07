use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{Map, Value};
use simple_dns::rdata::RData;
use ssi_dids_core::{Document, DID};
use ssi_jwk::{
    ed25519_parse, p256_parse, secp256k1_parse, Algorithm, Base64urlUInt, OctetParams, Params, JWK,
};

use crate::auth::resolver::{Resolution, ResolverError};

const ED25519_KEY_TYPE: &str = "0";
const SECP256K1_KEY_TYPE: &str = "1";
const P256_KEY_TYPE: &str = "2";
const X25519_KEY_TYPE: &str = "3";
const OKP_PUBLIC_KEY_LEN: usize = 32;
const EC_PUBLIC_KEY_LEN: usize = 33;

struct TxtRecord {
    id: String,
    data: String,
}

pub(super) fn decode_document(did: &DID, dns_bytes: &[u8]) -> Result<Resolution, ResolverError> {
    if did.method_name() != "dht" {
        return Err(ResolverError::MethodNotSupported(
            did.method_name().to_string(),
        ));
    }

    let packet = simple_dns::Packet::parse(dns_bytes)
        .map_err(|error| invalid_document(format!("invalid DNS packet: {error}")))?;
    let records = txt_records(&packet)?;
    let did_string = did.to_string();
    let mut document = Map::from_iter([("id".to_string(), Value::String(did_string.clone()))]);
    let mut verification_methods = Vec::new();
    let mut services = Vec::new();
    let mut id_lookup = BTreeMap::new();
    let mut root_records = Vec::new();
    let mut metadata_types = None;

    for record in &records {
        if record.id.starts_with("aka") {
            document.insert(
                "alsoKnownAs".to_string(),
                Value::Array(string_values(&record.data)),
            );
        } else if record.id.starts_with("cnt") {
            let mut controllers = string_values(&record.data);
            let controller = if controllers.len() == 1 {
                controllers.remove(0)
            } else {
                Value::Array(controllers)
            };
            document.insert("controller".to_string(), controller);
        } else if record.id.starts_with('k') {
            let (method, method_id) = verification_method(did, &record.id, &record.data)?;
            verification_methods.push(method);
            id_lookup.insert(record.id.clone(), method_id);
        } else if record.id.starts_with('s') {
            services.push(service(did, &record.data)?);
        } else if record.id.starts_with("typ") {
            metadata_types = Some(did_types(&record.data)?);
        } else if record.id.starts_with("did") {
            root_records.push(&record.data);
        }
    }

    if !verification_methods.is_empty() {
        document.insert(
            "verificationMethod".to_string(),
            Value::Array(verification_methods),
        );
    }
    if !services.is_empty() {
        document.insert("service".to_string(), Value::Array(services));
    }

    for data in root_records {
        apply_relationships(&mut document, data, &id_lookup);
    }

    let document = serde_json::from_value::<Document>(Value::Object(document))
        .map_err(|error| invalid_document(error.to_string()))?;
    let mut resolution = Resolution::new(document);
    resolution
        .document_metadata
        .properties
        .insert("published".to_string(), Value::Bool(true));
    if let Some(types) = metadata_types {
        resolution
            .document_metadata
            .properties
            .insert("types".to_string(), Value::Array(types));
    }

    Ok(resolution)
}

fn txt_records(packet: &simple_dns::Packet<'_>) -> Result<Vec<TxtRecord>, ResolverError> {
    packet
        .answers
        .iter()
        .filter_map(|answer| match &answer.rdata {
            RData::TXT(txt) => Some((answer, txt)),
            _ => None,
        })
        .map(|(answer, txt)| {
            let data = String::try_from(txt.clone())
                .map_err(|error| invalid_document(format!("invalid DNS TXT data: {error}")))?;
            let name = answer.name.to_string();
            let id = name
                .split('.')
                .next()
                .unwrap_or_default()
                .strip_prefix('_')
                .unwrap_or_default()
                .to_string();
            Ok(TxtRecord { id, data })
        })
        .collect()
}

fn properties(data: &str) -> BTreeMap<String, String> {
    data.split(';')
        .map(|pair| {
            let mut parts = pair.split('=');
            (
                parts.next().unwrap_or_default().to_string(),
                parts.next().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn verification_method(
    did: &DID,
    record_id: &str,
    data: &str,
) -> Result<(Value, String), ResolverError> {
    let values = properties(data);
    let key_type = values.get("t").map(String::as_str).unwrap_or_default();
    let encoded_key = values.get("k").ok_or(ResolverError::InvalidPublicKey)?;
    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| ResolverError::InvalidPublicKey)?;

    let (mut jwk, default_algorithm) = match key_type {
        ED25519_KEY_TYPE => {
            require_length(&key_bytes, OKP_PUBLIC_KEY_LEN)?;
            (
                ed25519_parse(&key_bytes).map_err(|_| ResolverError::InvalidPublicKey)?,
                Algorithm::EdDSA.as_str(),
            )
        }
        SECP256K1_KEY_TYPE => {
            require_length(&key_bytes, EC_PUBLIC_KEY_LEN)?;
            (
                secp256k1_parse(&key_bytes).map_err(|_| ResolverError::InvalidPublicKey)?,
                Algorithm::ES256K.as_str(),
            )
        }
        P256_KEY_TYPE => {
            require_length(&key_bytes, EC_PUBLIC_KEY_LEN)?;
            (
                p256_parse(&key_bytes).map_err(|_| ResolverError::InvalidPublicKey)?,
                Algorithm::ES256.as_str(),
            )
        }
        X25519_KEY_TYPE => {
            require_length(&key_bytes, OKP_PUBLIC_KEY_LEN)?;
            (
                JWK::from(Params::OKP(OctetParams {
                    curve: "X25519".to_string(),
                    public_key: Base64urlUInt(key_bytes),
                    private_key: None,
                })),
                "ECDH-ES+A256KW",
            )
        }
        found => {
            return Err(ResolverError::InvalidPublicKeyType {
                found: found.to_string(),
            });
        }
    };

    let thumbprint = jwk
        .thumbprint()
        .map_err(|_| ResolverError::InvalidPublicKey)?;
    jwk.key_id = Some(thumbprint.clone());
    let mut jwk = serde_json::to_value(jwk)
        .map_err(|error| invalid_document(format!("could not encode public JWK: {error}")))?;
    jwk.as_object_mut()
        .expect("SSI JWK serializes as an object")
        .insert(
            "alg".to_string(),
            Value::String(
                values
                    .get("a")
                    .cloned()
                    .unwrap_or_else(|| default_algorithm.to_string()),
            ),
        );

    let fragment = if record_id == "k0" {
        "0"
    } else {
        values.get("id").map(String::as_str).unwrap_or(&thumbprint)
    };
    let method_id = format!("{did}#{fragment}");
    let controller = values.get("c").cloned().unwrap_or_else(|| did.to_string());
    let method = serde_json::json!({
        "id": method_id,
        "type": "JsonWebKey",
        "controller": controller,
        "publicKeyJwk": jwk,
    });

    Ok((method, method_id))
}

fn require_length(bytes: &[u8], expected: usize) -> Result<(), ResolverError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(ResolverError::InvalidPublicKeyLength {
            expected,
            found: bytes.len(),
        })
    }
}

fn service(did: &DID, data: &str) -> Result<Value, ResolverError> {
    let mut values = properties(data);
    let id = values
        .remove("id")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_document("service record is missing id"))?;
    let type_ = values
        .remove("t")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_document("service record is missing type"))?;
    let endpoint = values
        .remove("se")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_document("service record is missing endpoint"))?;

    let mut service = Map::from_iter([
        ("id".to_string(), Value::String(format!("{did}#{id}"))),
        ("type".to_string(), Value::String(type_)),
        (
            "serviceEndpoint".to_string(),
            Value::Array(string_values(&endpoint)),
        ),
    ]);
    service.extend(values.into_iter().map(|(key, value)| {
        let value = if value.contains(',') {
            Value::Array(string_values(&value))
        } else {
            Value::String(value)
        };
        (key, value)
    }));

    Ok(Value::Object(service))
}

fn did_types(data: &str) -> Result<Vec<Value>, ResolverError> {
    let values = properties(data);
    let types = values
        .get("id")
        .ok_or_else(|| invalid_document("DID type record is missing id"))?;
    types
        .split(',')
        .map(|value| {
            value
                .parse::<u64>()
                .map(serde_json::Number::from)
                .map(Value::Number)
                .map_err(|_| invalid_document(format!("invalid DID type: {value}")))
        })
        .collect()
}

fn apply_relationships(
    document: &mut Map<String, Value>,
    data: &str,
    id_lookup: &BTreeMap<String, String>,
) {
    let values = properties(data);
    for (record_property, document_property) in [
        ("auth", "authentication"),
        ("asm", "assertionMethod"),
        ("del", "capabilityDelegation"),
        ("inv", "capabilityInvocation"),
        ("agm", "keyAgreement"),
    ] {
        let Some(record_ids) = values.get(record_property) else {
            continue;
        };
        let method_ids = record_ids
            .split(',')
            .filter_map(|record_id| id_lookup.get(record_id))
            .cloned()
            .map(Value::String)
            .collect();
        document.insert(document_property.to_string(), Value::Array(method_ids));
    }
}

fn string_values(value: &str) -> Vec<Value> {
    value
        .split(',')
        .map(|value| Value::String(value.to_string()))
        .collect()
}

fn invalid_document(message: impl Into<String>) -> ResolverError {
    ResolverError::InvalidDocument(message.into())
}

#[cfg(test)]
mod tests {
    use simple_dns::rdata::{RData, TXT};
    use simple_dns::{Name, Packet, ResourceRecord, CLASS};
    use ssi_dids_core::DIDBuf;

    use super::*;

    const IDENTIFIER: &str = "cyuoqaf7itop8ohww4yn5ojg13qaq83r9zihgqntc5i9zwrfdfoo";
    const DID: &str = "did:dht:cyuoqaf7itop8ohww4yn5ojg13qaq83r9zihgqntc5i9zwrfdfoo";
    const ED25519_KEY: &str = "YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE";
    const ED25519_KID: &str = "HP6bkG6mv-YPsU3Vi5Coi5wGYSVW9abFBwBSQwLQ7PU";

    fn did() -> DIDBuf {
        DID.parse().unwrap()
    }

    fn packet(records: &[(&str, &str)]) -> Vec<u8> {
        let mut packet = Packet::new_reply(0);
        for (name, data) in records {
            packet.answers.push(ResourceRecord::new(
                Name::new(name).unwrap(),
                CLASS::IN,
                7200,
                RData::TXT(TXT::try_from(*data).unwrap()),
            ));
        }
        packet.build_bytes_vec_compressed().unwrap()
    }

    fn encoded(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn decodes_official_vector_one_shape() {
        let bytes = packet(&[
            (
                &format!("_did.{IDENTIFIER}."),
                "v=0;vm=k0;auth=k0;asm=k0;inv=k0;del=k0",
            ),
            ("_k0._did.", &format!("t=0;k={ED25519_KEY}")),
        ]);

        let resolution = decode_document(&did(), &bytes).unwrap();
        let document = serde_json::to_value(resolution.document).unwrap();
        let method_id = format!("{DID}#0");

        assert_eq!(document["id"], DID);
        assert_eq!(document["verificationMethod"][0]["id"], method_id);
        assert_eq!(document["verificationMethod"][0]["type"], "JsonWebKey");
        assert_eq!(document["verificationMethod"][0]["controller"], DID);
        assert_eq!(
            document["verificationMethod"][0]["publicKeyJwk"],
            serde_json::json!({
                "alg": "EdDSA",
                "crv": "Ed25519",
                "kid": ED25519_KID,
                "kty": "OKP",
                "x": ED25519_KEY,
            })
        );
        for relationship in [
            "authentication",
            "assertionMethod",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            assert_eq!(document[relationship], serde_json::json!([method_id]));
        }
        assert!(document.get("keyAgreement").is_none());
        assert_eq!(resolution.document_metadata.properties["published"], true);
    }

    #[test]
    fn decodes_all_registered_key_types_and_order_independent_relationships() {
        let secp256k1 = encoded(&[
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ]);
        let p256 = encoded(&[
            0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96,
        ]);
        let x25519 = encoded(&[
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        let root_name = format!("_did.{IDENTIFIER}.");
        let k0 = format!("t=0;k={ED25519_KEY}");
        let k1 = format!("t=1;k={secp256k1};id=sig");
        let k2 = format!("t=2;k={p256};id=p256;a=ES256");
        let k3 = format!("t=3;k={x25519};id=enc");
        let bytes = packet(&[
            (&root_name, "v=0;auth=k0,k1,missing;asm=k2;agm=k3"),
            ("_k0._did.", &k0),
            ("_k1._did.", &k1),
            ("_k2._did.", &k2),
            ("_k3._did.", &k3),
        ]);

        let document =
            serde_json::to_value(decode_document(&did(), &bytes).unwrap().document).unwrap();

        assert_eq!(document["verificationMethod"].as_array().unwrap().len(), 4);
        assert_eq!(
            document["verificationMethod"][1]["id"],
            format!("{DID}#sig")
        );
        assert_eq!(
            document["verificationMethod"][1]["publicKeyJwk"]["crv"],
            "secp256k1"
        );
        assert_eq!(
            document["verificationMethod"][1]["publicKeyJwk"]["alg"],
            "ES256K"
        );
        assert_eq!(
            document["verificationMethod"][2]["publicKeyJwk"]["crv"],
            "P-256"
        );
        assert_eq!(
            document["verificationMethod"][2]["publicKeyJwk"]["alg"],
            "ES256"
        );
        assert_eq!(
            document["verificationMethod"][3]["publicKeyJwk"]["crv"],
            "X25519"
        );
        assert_eq!(
            document["verificationMethod"][3]["publicKeyJwk"]["alg"],
            "ECDH-ES+A256KW"
        );
        assert_eq!(
            document["authentication"],
            serde_json::json!([format!("{DID}#0"), format!("{DID}#sig")])
        );
        assert_eq!(
            document["assertionMethod"],
            serde_json::json!([format!("{DID}#p256")])
        );
        assert_eq!(
            document["keyAgreement"],
            serde_json::json!([format!("{DID}#enc")])
        );
    }

    #[test]
    fn decodes_document_properties_services_and_metadata() {
        let root_name = format!("_did.{IDENTIFIER}.");
        let k0 = format!("t=0;k={ED25519_KEY}");
        let bytes = packet(&[
            ("_aka._did.", "did:example:one,did:example:two"),
            ("_cnt._did.", "did:example:controller"),
            (
                "_s0._did.",
                "id=dwn;t=DecentralizedWebNode;se=https://one.example,https://two.example;enc=#enc;sig=#sig,#backup",
            ),
            ("_typ._did.", "id=1,2,3"),
            ("_k0._did.", &k0),
            (&root_name, "v=0;auth=k0"),
        ]);

        let resolution = decode_document(&did(), &bytes).unwrap();
        let document = serde_json::to_value(resolution.document).unwrap();

        assert_eq!(
            document["alsoKnownAs"],
            serde_json::json!(["did:example:one", "did:example:two"])
        );
        assert_eq!(document["controller"], "did:example:controller");
        assert_eq!(document["service"][0]["id"], format!("{DID}#dwn"));
        assert_eq!(document["service"][0]["type"], "DecentralizedWebNode");
        assert_eq!(
            document["service"][0]["serviceEndpoint"],
            serde_json::json!(["https://one.example", "https://two.example"])
        );
        assert_eq!(document["service"][0]["enc"], "#enc");
        assert_eq!(
            document["service"][0]["sig"],
            serde_json::json!(["#sig", "#backup"])
        );
        assert_eq!(
            resolution.document_metadata.properties["types"],
            serde_json::json!([1, 2, 3])
        );
        assert_eq!(resolution.document_metadata.properties["published"], true);
    }

    #[test]
    fn derives_additional_method_id_from_jwk_thumbprint() {
        let root_name = format!("_did.{IDENTIFIER}.");
        let key = format!("t=0;k={ED25519_KEY};c=did:example:controller;a=EdDSA");
        let bytes = packet(&[("_k1._did.", &key), (&root_name, "v=0;asm=k1")]);

        let document =
            serde_json::to_value(decode_document(&did(), &bytes).unwrap().document).unwrap();

        assert_eq!(
            document["verificationMethod"][0]["id"],
            format!("{DID}#{ED25519_KID}")
        );
        assert_eq!(
            document["verificationMethod"][0]["controller"],
            "did:example:controller"
        );
        assert_eq!(
            document["assertionMethod"],
            serde_json::json!([format!("{DID}#{ED25519_KID}")])
        );
    }

    #[test]
    fn decodes_upstream_parity_vector_two() {
        let fixture: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/parity/did/did-dht-vector-2.json"
        )))
        .unwrap();
        assert_eq!(fixture["schemaVersion"], 1);
        assert_eq!(fixture["oracle"], "enbox");
        assert_eq!(fixture["source"]["repository"], "enboxorg/enbox");
        assert_eq!(
            fixture["source"]["commit"],
            include_str!("../../../../../../.enbox-version")
                .lines()
                .find(|line| !line.starts_with('#') && !line.trim().is_empty())
                .unwrap()
                .trim()
        );
        assert_eq!(
            fixture["source"]["path"],
            "packages/dids/tests/fixtures/test-vectors/did-dht/vector-2.json"
        );

        let vector = &fixture["vector"];
        let did: DIDBuf = vector["didDocument"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let mut packet = Packet::new_reply(0);
        for record in vector["dnsRecords"].as_array().unwrap() {
            if record["type"] != "TXT" {
                continue;
            }
            packet.answers.push(ResourceRecord::new(
                Name::new(record["name"].as_str().unwrap()).unwrap(),
                CLASS::IN,
                record["ttl"].as_u64().unwrap() as u32,
                RData::TXT(TXT::try_from(record["rdata"].as_str().unwrap()).unwrap()),
            ));
        }

        let bytes = packet.build_bytes_vec_compressed().unwrap();
        let resolution = decode_document(&did, &bytes).unwrap();
        assert_eq!(
            serde_json::to_value(resolution.document).unwrap(),
            vector["didDocument"]
        );
        assert_eq!(
            resolution.document_metadata.properties,
            BTreeMap::from([
                ("published".to_string(), Value::Bool(true)),
                ("types".to_string(), serde_json::json!([1, 2, 3])),
            ])
        );
    }

    #[test]
    fn reassembles_chunked_txt_data() {
        let long_property = "x".repeat(300);
        let service = format!("id=test;t=Test;se=https://example.com;long={long_property}");
        let bytes = packet(&[("_s0._did.", &service)]);

        let document =
            serde_json::to_value(decode_document(&did(), &bytes).unwrap().document).unwrap();

        assert_eq!(document["service"][0]["long"], long_property);
        assert_eq!(
            document["service"][0]["serviceEndpoint"],
            serde_json::json!(["https://example.com"])
        );
    }

    #[test]
    fn rejects_wrong_method_and_malformed_dns() {
        let web = "did:web:example.com".parse::<DIDBuf>().unwrap();
        assert_eq!(
            decode_document(&web, &[]),
            Err(ResolverError::MethodNotSupported("web".to_string()))
        );
        assert!(matches!(
            decode_document(&did(), &[0]),
            Err(ResolverError::InvalidDocument(_))
        ));
    }

    #[test]
    fn rejects_invalid_key_records() {
        let invalid_cases = [
            ("t=9;k=AA", "type"),
            ("t=0;k=not+base64", "encoding"),
            ("t=0;k=AA", "length"),
        ];

        for (record, expected) in invalid_cases {
            let bytes = packet(&[("_k0._did.", record)]);
            let error = decode_document(&did(), &bytes).unwrap_err();
            match expected {
                "type" => assert_eq!(
                    error,
                    ResolverError::InvalidPublicKeyType {
                        found: "9".to_string()
                    }
                ),
                "encoding" => assert_eq!(error, ResolverError::InvalidPublicKey),
                "length" => assert_eq!(
                    error,
                    ResolverError::InvalidPublicKeyLength {
                        expected: 32,
                        found: 1
                    }
                ),
                _ => unreachable!(),
            }
        }

        let invalid_curve = format!("t=1;k={}", encoded(&[0; EC_PUBLIC_KEY_LEN]));
        let bytes = packet(&[("_k0._did.", &invalid_curve)]);
        assert_eq!(
            decode_document(&did(), &bytes).unwrap_err(),
            ResolverError::InvalidPublicKey
        );
    }

    #[test]
    fn rejects_malformed_service_and_type_records() {
        for record in ["id=test;t=Test", "id=test;se=https://example.com"] {
            let bytes = packet(&[("_s0._did.", record)]);
            assert!(matches!(
                decode_document(&did(), &bytes),
                Err(ResolverError::InvalidDocument(_))
            ));
        }

        let bytes = packet(&[("_typ._did.", "id=one")]);
        assert!(matches!(
            decode_document(&did(), &bytes),
            Err(ResolverError::InvalidDocument(_))
        ));
    }

    #[test]
    fn ignores_non_txt_answers() {
        let mut packet = Packet::new_reply(0);
        packet.answers.push(ResourceRecord::new(
            Name::new("_k0._did.").unwrap(),
            CLASS::IN,
            7200,
            RData::CNAME(Name::new("ignored.example.").unwrap().into()),
        ));
        let bytes = packet.build_bytes_vec_compressed().unwrap();

        let resolution = decode_document(&did(), &bytes).unwrap();

        assert!(resolution.document.verification_method.is_empty());
        assert_eq!(resolution.document_metadata.properties["published"], true);
    }
}
