//! DID DHT v0 document-to-DNS encoder.
//!
//! Inverse of [`decode_document`](super::codec::decode_document) up to that
//! function's lossy normalizations, so the round-trip contract is the decoder
//! fixpoint: `decode(encode(decode(x))) == decode(x)`.
//!
//! The wire cannot represent everything a typed [`Document`] can, and this
//! module rejects those inputs instead of silently dropping data: foreign VM
//! or service ID bases, non-`JsonWebKey` method types, embedded relationship
//! values, dangling references, duplicate fragments, non-string service
//! properties, map endpoints, and extra top-level or method properties.
//! Delimiter-unsafe values (`=`, `;`, `,`) are rejected so output stays
//! accepted by the pinned TypeScript decoder.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;
use simple_dns::{
    rdata::{RData, NS, TXT},
    CharacterString, Name, Packet, PacketFlag, ResourceRecord, CLASS,
};
use ssi_dids_core::{
    document::{verification_method::ValueOrReference, DIDVerificationMethod},
    Document,
};
use ssi_jwk::{Base64urlUInt, JWK};
use url::{Host, Url};

use super::bep44::decode_identity_key;
use super::error::DhtPublishError;

const DNS_TTL: u32 = 7200;
const SPEC_VERSION: u8 = 0;
const MAX_SEGMENT_BYTES: usize = 255;

struct EncodedVm {
    fragment: String,
    key_type: u8,
    key_base64: String,
    thumbprint: String,
    algorithm: Option<String>,
    controller: String,
}

/// Validate `document` with `types` for publication without any gateway input.
///
/// Runs the same code path as [`encode_document`] with an empty gateway list;
/// gateway-URI validation happens at publish time, when the target is known.
pub fn validate_publishable_document(
    document: &Document,
    types: &[u64],
) -> Result<(), DhtPublishError> {
    encode_document(document, types, &[]).map(|_| ())
}

pub(crate) fn encode_document(
    document: &Document,
    types: &[u64],
    gateways: &[Url],
) -> Result<Vec<u8>, DhtPublishError> {
    let did = &document.id;
    if did.method_name() != "dht" {
        return Err(DhtPublishError::MethodNotSupported(
            did.method_name().to_string(),
        ));
    }
    let did_string = did.to_string();
    let identity_key = decode_identity_key(did)?;

    if !document.property_set.is_empty() {
        return Err(invalid(format!(
            "unsupported document properties: {}",
            property_names(&document.property_set)
        )));
    }
    if !document.public_key.is_empty() {
        return Err(invalid(
            "deprecated publicKey entries are not representable".to_string(),
        ));
    }

    let mut vms = encode_verification_methods(document, &did_string)?;
    let identity_position = vms
        .iter()
        .position(|vm| vm.fragment == "0")
        .ok_or_else(|| invalid("missing identity verification method #0".to_string()))?;
    if vms[identity_position].key_base64 != base64_key(identity_key.as_bytes()) {
        return Err(invalid(
            "identity verification method #0 does not hold the DID identity key".to_string(),
        ));
    }
    // The wire addresses the identity key as _k0 regardless of document
    // order; decoding any other key there as #0 would break the fixpoint.
    if identity_position != 0 {
        let identity = vms.remove(identity_position);
        vms.insert(0, identity);
    }
    let identity_controller = vms[0].controller.clone();
    let doc_controllers = controller_strings(document)?;
    if identity_controller != did_string {
        let represented = doc_controllers
            .as_ref()
            .is_some_and(|controllers| controllers.contains(&identity_controller));
        if !represented {
            return Err(invalid(
                "identity controller must be represented by the document controller".to_string(),
            ));
        }
    }
    let lookup: BTreeMap<String, String> = vms
        .iter()
        .enumerate()
        .map(|(index, vm)| (format!("{did_string}#{}", vm.fragment), format!("k{index}")))
        .collect();

    let mut packet = Packet::new_reply(0);
    packet.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    let suffix = did.method_specific_id();
    let root_name = format!("_did.{suffix}.");

    let mut txt_records: Vec<(String, String)> = Vec::new();
    if !document.also_known_as.is_empty() {
        let mut values = Vec::new();
        for aka in &document.also_known_as {
            check_scalar(aka.as_str())?;
            values.push(aka.as_str().to_string());
        }
        txt_records.push(("_aka._did.".to_string(), values.join(",")));
    }
    if let Some(controller) = &doc_controllers {
        txt_records.push(("_cnt._did.".to_string(), controller.join(",")));
    }

    let mut vm_ids = Vec::new();
    for (index, vm) in vms.iter().enumerate() {
        let mut fields = vec![format!("t={}", vm.key_type), format!("k={}", vm.key_base64)];
        if vm.fragment != "0" && vm.thumbprint != vm.fragment {
            fields.insert(0, format!("id={}", vm.fragment));
        }
        if let Some(algorithm) = &vm.algorithm {
            fields.push(format!("a={algorithm}"));
        }
        if vm.controller != did_string {
            fields.push(format!("c={}", vm.controller));
        }
        txt_records.push((format!("_k{index}._did."), fields.join(";")));
        vm_ids.push(format!("k{index}"));
    }

    let mut service_ids = Vec::new();
    let mut seen_services = BTreeSet::new();
    for (index, service) in document.service.iter().enumerate() {
        if !seen_services.insert(service.id.as_str().to_string()) {
            return Err(invalid(format!(
                "duplicate service id {}",
                service.id.as_str()
            )));
        }
        txt_records.push((
            format!("_s{index}._did."),
            encode_service(service, &did_string)?,
        ));
        service_ids.push(format!("s{index}"));
    }

    let mut root = vec![
        format!("v={SPEC_VERSION}"),
        format!("vm={}", vm_ids.join(",")),
    ];
    let relationships = &document.verification_relationships;
    let mut resolved = Vec::new();
    for (name, code, entries) in [
        ("authentication", "auth", &relationships.authentication),
        ("assertionMethod", "asm", &relationships.assertion_method),
        (
            "capabilityInvocation",
            "inv",
            &relationships.capability_invocation,
        ),
        (
            "capabilityDelegation",
            "del",
            &relationships.capability_delegation,
        ),
        ("keyAgreement", "agm", &relationships.key_agreement),
    ] {
        let mut full_ids = Vec::new();
        for entry in entries {
            full_ids.push(relationship_full_id(entry, &document.id)?);
        }
        resolved.push((name, code, full_ids));
    }
    let identity_id = format!("{did_string}#0");
    for (name, _, full_ids) in &resolved {
        if matches!(
            *name,
            "authentication" | "assertionMethod" | "capabilityInvocation" | "capabilityDelegation"
        ) && !full_ids.contains(&identity_id)
        {
            return Err(invalid(format!(
                "identity method #0 is missing from {name}"
            )));
        }
    }
    for (_, code, full_ids) in &resolved {
        if full_ids.is_empty() {
            continue;
        }
        let mut ids = Vec::new();
        for id in full_ids {
            ids.push(
                lookup
                    .get(id)
                    .cloned()
                    .ok_or_else(|| invalid(format!("dangling relationship reference {id}")))?,
            );
        }
        root.push(format!("{code}={}", ids.join(",")));
    }
    if !service_ids.is_empty() {
        root.push(format!("svc={}", service_ids.join(",")));
    }
    txt_records.push((root_name.clone(), root.join(";")));

    if !types.is_empty() {
        let ids = types
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        txt_records.push(("_typ._did.".to_string(), format!("id={ids}")));
    }

    let mut ns_hosts = Vec::new();
    for gateway in gateways {
        if let Some(host) = gateway_ns_host(gateway)? {
            ns_hosts.push(host);
        }
    }

    for (name, value) in &txt_records {
        push_txt(&mut packet, name, value)?;
    }
    for host in &ns_hosts {
        let target =
            Name::new(host).map_err(|_| DhtPublishError::InvalidGatewayUri(host.clone()))?;
        packet.answers.push(ResourceRecord::new(
            Name::new(&root_name)
                .map_err(|error| invalid(format!("invalid root record name: {error}")))?,
            CLASS::IN,
            DNS_TTL,
            RData::NS(NS(target)),
        ));
    }

    packet
        .build_bytes_vec_compressed()
        .map_err(|error| invalid(format!("cannot serialize DNS packet: {error}")))
}

fn encode_verification_methods(
    document: &Document,
    did: &str,
) -> Result<Vec<EncodedVm>, DhtPublishError> {
    let mut vms = Vec::new();
    let mut fragments = BTreeSet::new();
    for method in &document.verification_method {
        vms.push(encode_verification_method(method, did, &mut fragments)?);
    }
    Ok(vms)
}

fn encode_verification_method(
    method: &DIDVerificationMethod,
    did: &str,
    fragments: &mut BTreeSet<String>,
) -> Result<EncodedVm, DhtPublishError> {
    let fragment = method
        .id
        .as_str()
        .strip_prefix(&format!("{did}#"))
        .ok_or_else(|| {
            invalid(format!(
                "verification method {} is not under {did}",
                method.id.as_str()
            ))
        })?;
    if fragment.is_empty() {
        return Err(invalid("verification method fragment is empty".to_string()));
    }
    check_scalar(fragment)?;
    if !fragments.insert(fragment.to_string()) {
        return Err(invalid(format!(
            "duplicate verification method fragment {fragment}"
        )));
    }
    if method.type_ != "JsonWebKey" {
        return Err(invalid(format!(
            "verification method type {} is not representable",
            method.type_
        )));
    }
    let public_jwk = method
        .properties
        .get("publicKeyJwk")
        .ok_or_else(|| invalid("verification method is missing publicKeyJwk".to_string()))?;
    if method.properties.keys().any(|key| key != "publicKeyJwk") {
        return Err(invalid(
            "verification method has unrepresentable properties".to_string(),
        ));
    }
    // The JWK stays stringly-typed on purpose: `ssi_jwk::Algorithm` is a
    // closed JOSE enum, so parsing here would reject decoder-normal X25519
    // keys carrying `ECDH-ES+A256KW`. Only the wire fields are read.
    let shape: WireKeyShape = serde_json::from_value(public_jwk.clone())
        .map_err(|_| invalid("verification method publicKeyJwk is invalid".to_string()))?;

    let (key_type, raw_key) = wire_key(&shape)?;
    // `alg` and `kid` play no part in the RFC 7638 thumbprint, so the typed
    // parse below cannot fail on the decoder-normal algorithm strings above.
    let thumbprint = {
        let mut value = public_jwk.clone();
        if let Some(object) = value.as_object_mut() {
            object.remove("alg");
        }
        let jwk: JWK = serde_json::from_value(value)
            .map_err(|_| invalid("cannot read verification method key".to_string()))?;
        jwk.thumbprint()
            .map_err(|_| invalid("cannot thumbprint verification method key".to_string()))?
    };
    let default_algorithm = default_algorithm(key_type);
    let algorithm = match shape.alg {
        Some(name) if name != default_algorithm => {
            check_scalar(&name)?;
            Some(name)
        }
        _ => None,
    };

    let controller = method.controller.as_str().to_string();
    check_scalar(&controller)?;

    Ok(EncodedVm {
        fragment: fragment.to_string(),
        key_type,
        key_base64: base64_key(&raw_key),
        thumbprint,
        algorithm,
        controller,
    })
}

/// The wire-visible subset of a public JWK. `alg` rides through as a plain
/// string so decoder-normal keys with non-JOSE algorithm names survive.
#[derive(Deserialize)]
struct WireKeyShape {
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    kty: Option<String>,
    #[serde(default)]
    x: Option<Base64urlUInt>,
    #[serde(default)]
    y: Option<Base64urlUInt>,
    #[serde(default)]
    alg: Option<String>,
}

fn wire_key(shape: &WireKeyShape) -> Result<(u8, Vec<u8>), DhtPublishError> {
    let curve = shape
        .crv
        .clone()
        .or_else(|| shape.kty.clone())
        .unwrap_or_else(|| "unknown".to_string());
    match curve.as_str() {
        "Ed25519" => wire_bytes(shape.x.as_ref(), 32).map(|raw| (0, raw)),
        "X25519" => wire_bytes(shape.x.as_ref(), 32).map(|raw| (3, raw)),
        "secp256k1" | "P-256" | "secp256r1" => {
            let key_type = if curve == "secp256k1" { 1 } else { 2 };
            let x = wire_bytes(shape.x.as_ref(), 32)?;
            let y = wire_bytes(shape.y.as_ref(), 32)?;
            let mut raw = Vec::with_capacity(33);
            raw.push(0x02 | (y[31] & 1));
            raw.extend_from_slice(&x);
            Ok((key_type, raw))
        }
        found => Err(DhtPublishError::InvalidPublicKeyType {
            found: found.to_string(),
        }),
    }
}

fn wire_bytes(
    coordinate: Option<&Base64urlUInt>,
    expected: usize,
) -> Result<Vec<u8>, DhtPublishError> {
    let raw = coordinate
        .ok_or_else(|| invalid("key is missing coordinates".to_string()))?
        .0
        .clone();
    if raw.len() == expected {
        Ok(raw)
    } else {
        Err(invalid(format!(
            "key must be {expected} bytes for wire encoding, found {}",
            raw.len()
        )))
    }
}

fn default_algorithm(key_type: u8) -> &'static str {
    match key_type {
        0 => "EdDSA",
        1 => "ES256K",
        2 => "ES256",
        _ => "ECDH-ES+A256KW",
    }
}

fn relationship_full_id(
    entry: &ValueOrReference,
    document_id: &ssi_dids_core::DIDBuf,
) -> Result<String, DhtPublishError> {
    if entry.as_value().is_some() {
        return Err(invalid(
            "embedded verification methods are not representable".to_string(),
        ));
    }
    Ok(entry.id().resolve(document_id).to_string())
}

fn encode_service(
    service: &ssi_dids_core::document::Service,
    did: &str,
) -> Result<String, DhtPublishError> {
    let fragment = service
        .id
        .as_str()
        .strip_prefix(&format!("{did}#"))
        .ok_or_else(|| {
            invalid(format!(
                "service {} is not under {did}",
                service.id.as_str()
            ))
        })?;
    if fragment.is_empty() {
        return Err(invalid("service fragment is empty".to_string()));
    }
    check_scalar(fragment)?;

    let service_type = match serde_json::to_value(&service.type_)
        .map_err(|_| invalid("service type is invalid".to_string()))?
    {
        Value::String(single) => single,
        _ => {
            return Err(invalid("service type must be a single string".to_string()));
        }
    };
    if service_type.is_empty() {
        return Err(invalid("service type is empty".to_string()));
    }
    check_scalar(&service_type)?;

    let endpoints = match serde_json::to_value(&service.service_endpoint)
        .map_err(|_| invalid("service endpoint is invalid".to_string()))?
    {
        Value::Null => Vec::new(),
        Value::String(single) => vec![single],
        Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                Value::String(endpoint) => Ok(endpoint),
                _ => Err(invalid("service endpoints must be strings".to_string())),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(invalid("service endpoints must be strings".to_string()));
        }
    };
    if endpoints.is_empty() {
        return Err(invalid("service is missing its endpoint".to_string()));
    }
    for endpoint in &endpoints {
        check_scalar(endpoint)?;
    }

    let mut pairs = vec![
        format!("id={fragment}"),
        format!("t={service_type}"),
        format!("se={}", endpoints.join(",")),
    ];
    for (name, value) in &service.property_set {
        if matches!(name.as_str(), "id" | "t" | "se") {
            return Err(invalid(format!("reserved service property {name}")));
        }
        check_scalar(name)?;
        match value {
            Value::String(single) => {
                check_scalar(single)?;
                pairs.push(format!("{name}={single}"));
            }
            Value::Array(values) if !values.is_empty() => {
                let mut items = Vec::new();
                for value in values {
                    match value {
                        Value::String(item) => {
                            check_scalar(item)?;
                            items.push(item.clone());
                        }
                        _ => {
                            return Err(invalid(format!(
                                "service property {name} must hold strings"
                            )));
                        }
                    }
                }
                pairs.push(format!("{name}={}", items.join(",")));
            }
            _ => {
                return Err(invalid(format!(
                    "service property {name} must be a string or non-empty string array"
                )));
            }
        }
    }
    Ok(pairs.join(";"))
}

fn controller_strings(document: &Document) -> Result<Option<Vec<String>>, DhtPublishError> {
    let Some(controller) = &document.controller else {
        return Ok(None);
    };
    match serde_json::to_value(controller)
        .map_err(|_| invalid("controller is invalid".to_string()))?
    {
        Value::String(single) => {
            check_scalar(&single)?;
            Ok(Some(vec![single]))
        }
        Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                Value::String(controller) => {
                    check_scalar(&controller)?;
                    Ok(controller)
                }
                _ => Err(invalid("controllers must be DIDs".to_string())),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(invalid("controllers must be DIDs".to_string())),
    }
}

/// Owned `host.` NS target for a DNS-hosted gateway, or `None` for IP
/// literals, which carry no NS metadata.
fn gateway_ns_host(gateway: &Url) -> Result<Option<String>, DhtPublishError> {
    match gateway.host() {
        None => Err(DhtPublishError::InvalidGatewayUri(gateway.to_string())),
        Some(Host::Domain(_)) => {
            let host = gateway.host_str().unwrap_or_default();
            Ok(Some(format!("{host}.")))
        }
        // An NS record names a host; IP literals carry no NS metadata.
        Some(_) => Ok(None),
    }
}

fn push_txt<'a>(
    packet: &mut Packet<'a>,
    name: &'a str,
    value: &'a str,
) -> Result<(), DhtPublishError> {
    let record_name =
        Name::new(name).map_err(|error| invalid(format!("invalid record name {name}: {error}")))?;
    let mut txt = TXT::new();
    for segment in char_boundary_segments(value) {
        let character_string = CharacterString::new(segment.as_bytes())
            .map_err(|_| invalid("TXT segment exceeds 255 bytes".to_string()))?;
        txt.add_char_string(character_string);
    }
    packet.answers.push(ResourceRecord::new(
        record_name,
        CLASS::IN,
        DNS_TTL,
        RData::TXT(txt),
    ));
    Ok(())
}

fn char_boundary_segments(value: &str) -> Vec<&str> {
    if value.is_empty() {
        return vec![value];
    }
    let mut segments = Vec::new();
    let mut start = 0;
    while start < value.len() {
        let mut end = (start + MAX_SEGMENT_BYTES).min(value.len());
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        segments.push(&value[start..end]);
        start = end;
    }
    segments
}

fn check_scalar(value: &str) -> Result<(), DhtPublishError> {
    if value.chars().any(|c| c == '=' || c == ';' || c == ',') {
        return Err(invalid(format!(
            "value {value:?} contains a reserved delimiter"
        )));
    }
    Ok(())
}

fn base64_key(raw: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(raw)
}

fn property_names(properties: &BTreeMap<String, Value>) -> String {
    properties.keys().cloned().collect::<Vec<_>>().join(", ")
}

fn invalid(message: impl Into<String>) -> DhtPublishError {
    DhtPublishError::InvalidDocument(message.into())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use simple_dns::rdata::{RData, TXT};
    use simple_dns::{Name, Packet, ResourceRecord, CLASS};
    use ssi_dids_core::DIDBuf;
    use ssi_jwk::{Algorithm, OctetParams, Params, JWK};
    use url::Url;

    use super::super::codec::decode_document;
    use super::*;

    const IDENTIFIER: &str = "cyuoqaf7itop8ohww4yn5ojg13qaq83r9zihgqntc5i9zwrfdfoo";
    const DID: &str = "did:dht:cyuoqaf7itop8ohww4yn5ojg13qaq83r9zihgqntc5i9zwrfdfoo";
    const ED25519_KEY: &str = "YCcHYL2sYNPDlKaALcEmll2HHyT968M4UWbr-9CFGWE";

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

    fn base_doc() -> Document {
        let bytes = packet(&[
            (
                &format!("_did.{IDENTIFIER}."),
                "v=0;vm=k0;auth=k0;asm=k0;inv=k0;del=k0",
            ),
            ("_k0._did.", &format!("t=0;k={ED25519_KEY}")),
        ]);
        decode_document(&did(), &bytes).unwrap().0
    }

    fn doc_value(document: &Document) -> Value {
        serde_json::to_value(document).unwrap()
    }

    fn doc_from(value: Value) -> Document {
        serde_json::from_value(value).unwrap()
    }

    fn encoded(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn assert_fixpoint(did: &DIDBuf, dns: &[u8]) {
        let (first, first_types) = decode_document(did, dns).unwrap();
        let encoded =
            encode_document(&first, &first_types.clone().unwrap_or_default(), &[]).unwrap();
        // Wire shape: ID 0 with the Authoritative Answer bit set.
        assert_eq!(&encoded[0..2], &[0, 0]);
        assert_ne!(encoded[2] & 0x04, 0);
        let reparsed = Packet::parse(&encoded).unwrap();
        assert!(reparsed.answers.iter().all(|answer| answer.ttl == 7200));
        let (second, second_types) = decode_document(did, &encoded).unwrap();
        assert_eq!(doc_value(&first), doc_value(&second));
        assert_eq!(first_types, second_types);
    }

    #[test]
    fn decoder_outputs_are_a_fixpoint() {
        let did = did();
        assert_fixpoint(
            &did,
            &packet(&[
                (
                    &format!("_did.{IDENTIFIER}."),
                    "v=0;vm=k0;auth=k0;asm=k0;inv=k0;del=k0",
                ),
                ("_k0._did.", &format!("t=0;k={ED25519_KEY}")),
            ]),
        );
        assert_fixpoint(
            &did,
            &packet(&[
                ("_aka._did.", "did:example:one,did:example:two"),
                ("_cnt._did.", "did:example:controller"),
                (
                    "_s0._did.",
                    "id=dwn;t=DecentralizedWebNode;se=https://one.example,https://two.example;enc=#enc;sig=#sig,#backup",
                ),
                ("_typ._did.", "id=1,2,3"),
                ("_k0._did.", &format!("t=0;k={ED25519_KEY}")),
                (
                    &format!("_did.{IDENTIFIER}."),
                    "v=0;auth=k0;asm=k0;inv=k0;del=k0",
                ),
            ]),
        );

        // Every registered key type, including X25519 whose decoder-normal
        // `ECDH-ES+A256KW` algorithm no JOSE enum names.
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
        assert_fixpoint(
            &did,
            &packet(&[
                (&root_name, "v=0;auth=k0,k1;asm=k0,k2;inv=k0;del=k0;agm=k3"),
                ("_k0._did.", &format!("t=0;k={ED25519_KEY}")),
                ("_k1._did.", &format!("t=1;k={secp256k1};id=sig")),
                ("_k2._did.", &format!("t=2;k={p256};id=p256;a=ES256")),
                ("_k3._did.", &format!("t=3;k={x25519};id=enc")),
            ]),
        );

        let fixture: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/parity/did/did-dht-vector-2.json"
        )))
        .unwrap();
        let vector = &fixture["vector"];
        let vector_did: DIDBuf = vector["didDocument"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let mut vector_packet = Packet::new_reply(0);
        for record in vector["dnsRecords"].as_array().unwrap() {
            if record["type"] != "TXT" {
                continue;
            }
            vector_packet.answers.push(ResourceRecord::new(
                Name::new(record["name"].as_str().unwrap()).unwrap(),
                CLASS::IN,
                record["ttl"].as_u64().unwrap() as u32,
                RData::TXT(TXT::try_from(record["rdata"].as_str().unwrap()).unwrap()),
            ));
        }
        assert_fixpoint(
            &vector_did,
            &vector_packet.build_bytes_vec_compressed().unwrap(),
        );
    }

    fn agent_document() -> (String, Document) {
        let identity = SigningKey::from_bytes(&[1; 32]);
        let signing = SigningKey::from_bytes(&[2; 32]);
        let did_string = format!(
            "did:dht:{}",
            z32::encode(identity.verifying_key().as_bytes())
        );

        let public_jwk = |verifying: &[u8; 32], kid: &str| {
            let mut jwk = JWK::from(Params::OKP(OctetParams {
                curve: "Ed25519".to_string(),
                public_key: ssi_jwk::Base64urlUInt(verifying.to_vec()),
                private_key: None,
            }));
            jwk.key_id = Some(kid.to_string());
            jwk.algorithm = Some(Algorithm::EdDSA);
            serde_json::to_value(jwk).unwrap()
        };
        let thumbprint = |verifying: &[u8; 32]| {
            JWK::from(Params::OKP(OctetParams {
                curve: "Ed25519".to_string(),
                public_key: ssi_jwk::Base64urlUInt(verifying.to_vec()),
                private_key: None,
            }))
            .thumbprint()
            .unwrap()
        };
        let enc_jwk = {
            let mut jwk = JWK::from(Params::OKP(OctetParams {
                curve: "X25519".to_string(),
                public_key: ssi_jwk::Base64urlUInt(vec![4; 32]),
                private_key: None,
            }));
            let kid = jwk.thumbprint().unwrap();
            jwk.key_id = Some(kid);
            // Decoder-normal form carries the default algorithm explicitly,
            // which `ssi_jwk::Algorithm` cannot name; keep it a raw string.
            let mut value = serde_json::to_value(jwk).unwrap();
            value["alg"] = serde_json::json!("ECDH-ES+A256KW");
            value
        };

        let id_bytes = identity.verifying_key().to_bytes();
        let sig_bytes = signing.verifying_key().to_bytes();
        let document: Document = serde_json::from_value(serde_json::json!({
            "id": did_string,
            "verificationMethod": [
                {"id": format!("{did_string}#0"), "type": "JsonWebKey", "controller": did_string,
                 "publicKeyJwk": public_jwk(&id_bytes, &thumbprint(&id_bytes))},
                {"id": format!("{did_string}#sig"), "type": "JsonWebKey", "controller": did_string,
                 "publicKeyJwk": public_jwk(&sig_bytes, &thumbprint(&sig_bytes))},
                {"id": format!("{did_string}#enc"), "type": "JsonWebKey", "controller": did_string,
                 "publicKeyJwk": enc_jwk},
            ],
            "authentication": [format!("{did_string}#0"), format!("{did_string}#sig")],
            "assertionMethod": [format!("{did_string}#0"), format!("{did_string}#sig")],
            "capabilityInvocation": [format!("{did_string}#0")],
            "capabilityDelegation": [format!("{did_string}#0")],
            "keyAgreement": [format!("{did_string}#enc")],
            "service": [{"id": format!("{did_string}#dwn"), "type": "DecentralizedWebNode",
                         "serviceEndpoint": ["https://dwn.example"]}],
        }))
        .unwrap();
        (did_string, document)
    }

    #[test]
    fn agent_shaped_documents_encode_decoder_normal() {
        let (did_string, document) = agent_document();

        validate_publishable_document(&document, &[]).unwrap();
        let encoded = encode_document(&document, &[], &[]).unwrap();
        let did: DIDBuf = did_string.parse().unwrap();
        let (decoded, types) = decode_document(&did, &encoded).unwrap();
        assert_eq!(doc_value(&document), doc_value(&decoded));
        assert_eq!(types, None);
    }

    #[test]
    fn txt_segments_never_split_utf8() {
        for (value, expected_segments) in [
            ("x".repeat(255), 1),
            ("x".repeat(256), 2),
            ("é".repeat(200), 2),
            ("🦀".repeat(100), 2),
        ] {
            let segments = char_boundary_segments(&value);
            assert_eq!(segments.len(), expected_segments, "{value:?}");
            assert!(segments.iter().all(|s| s.len() <= 255));
            assert_eq!(segments.join(""), value);
        }
    }

    #[test]
    fn multibyte_values_round_trip() {
        let mut value = doc_value(&base_doc());
        value["service"] = serde_json::json!([{
            "id": format!("{DID}#dwn"),
            "type": "DecentralizedWebNode",
            "serviceEndpoint": ["https://dwn.example"],
            "note": "é".repeat(200),
        }]);
        value["alsoKnownAs"] = serde_json::json!(["did:example:🦀".repeat(20)]);
        let document = doc_from(value);

        let encoded = encode_document(&document, &[], &[]).unwrap();
        let (decoded, _) = decode_document(&did(), &encoded).unwrap();
        assert_eq!(doc_value(&document), doc_value(&decoded));
    }

    #[test]
    fn gateway_ns_rules() {
        let document = base_doc();
        let ns_targets = |bytes: &[u8]| {
            Packet::parse(bytes)
                .unwrap()
                .answers
                .iter()
                .filter_map(|answer| match &answer.rdata {
                    RData::NS(name) => Some(name.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        let bytes = encode_document(
            &document,
            &[],
            &["https://gateway.example:8443/some/path?q=1#frag"
                .parse::<Url>()
                .unwrap()],
        )
        .unwrap();
        // `Name` displays without the trailing dot; parsing `host.` above is
        // what validates the FQDN form.
        assert_eq!(ns_targets(&bytes), ["gateway.example"]);

        let bytes = encode_document(
            &document,
            &[],
            &["http://127.0.0.1:7527".parse::<Url>().unwrap()],
        )
        .unwrap();
        assert!(ns_targets(&bytes).is_empty());

        let bytes = encode_document(&document, &[], &[]).unwrap();
        assert!(ns_targets(&bytes).is_empty());

        assert!(matches!(
            encode_document(&document, &[], &["mailto:someone".parse::<Url>().unwrap()]),
            Err(DhtPublishError::InvalidGatewayUri(_))
        ));
    }

    #[test]
    fn types_round_trip_through_typ_record() {
        let document = base_doc();
        let encoded = encode_document(&document, &[1, 2], &[]).unwrap();
        let (decoded, types) = decode_document(&did(), &encoded).unwrap();
        assert_eq!(doc_value(&document), doc_value(&decoded));
        assert_eq!(types, Some(vec![1, 2]));
    }

    #[test]
    fn rejects_unrepresentable_documents() {
        let document = base_doc();
        let mutate = |f: fn(&mut Value)| {
            let mut value = doc_value(&document);
            f(&mut value);
            doc_from(value)
        };

        for (name, document) in [
            (
                "foreign method base",
                mutate(|v| v["verificationMethod"][0]["id"] = serde_json::json!("did:dht:other#0")),
            ),
            (
                "missing identity",
                mutate(|v| {
                    v["verificationMethod"] = serde_json::json!([]);
                    v["authentication"] = serde_json::json!([]);
                    v["assertionMethod"] = serde_json::json!([]);
                    v["capabilityInvocation"] = serde_json::json!([]);
                    v["capabilityDelegation"] = serde_json::json!([]);
                }),
            ),
            (
                "dangling reference",
                mutate(|v| v["authentication"] = serde_json::json!([format!("{DID}#nope")])),
            ),
            (
                "embedded relationship value",
                mutate(|v| {
                    v["authentication"] = serde_json::json!([v["verificationMethod"][0].clone()]);
                }),
            ),
            (
                "non JsonWebKey type",
                mutate(|v| {
                    v["verificationMethod"][0]["type"] = serde_json::json!("JsonWebKey2020")
                }),
            ),
            (
                "missing publicKeyJwk",
                mutate(|v| {
                    v["verificationMethod"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("publicKeyJwk");
                }),
            ),
            (
                "extra method property",
                mutate(|v| v["verificationMethod"][0]["custom"] = serde_json::json!(1)),
            ),
            (
                "extra document property",
                mutate(|v| v["custom"] = serde_json::json!(1)),
            ),
        ] {
            assert!(
                matches!(
                    validate_publishable_document(&document, &[]),
                    Err(DhtPublishError::InvalidDocument(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_mismatched_identity_key() {
        let mut value = doc_value(&base_doc());
        let other_x =
            URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes());
        value["verificationMethod"][0]["publicKeyJwk"]["x"] = serde_json::json!(other_x);
        let document = doc_from(value);
        assert!(matches!(
            validate_publishable_document(&document, &[]),
            Err(DhtPublishError::InvalidDocument(_))
        ));
    }

    #[test]
    fn rejects_duplicate_fragments() {
        let mut value = doc_value(&base_doc());
        let first = value["verificationMethod"][0].clone();
        value["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(first);
        let document = doc_from(value);
        assert!(matches!(
            validate_publishable_document(&document, &[]),
            Err(DhtPublishError::InvalidDocument(_))
        ));
    }

    #[test]
    fn rejects_unsafe_delimiters_and_shapes() {
        let service_doc = |service: Value| {
            let mut value = doc_value(&base_doc());
            value["service"] = serde_json::json!([service]);
            value["authentication"] = serde_json::json!([format!("{DID}#0")]);
            doc_from(value)
        };
        let service = |endpoint: &str, extra: Value| {
            serde_json::json!({
                "id": format!("{DID}#dwn"),
                "type": "DecentralizedWebNode",
                "serviceEndpoint": [endpoint],
                "custom": extra,
            })
        };

        for (name, document) in [
            (
                "equals in endpoint",
                service_doc(service("https://dwn.example/?a=b", serde_json::json!("ok"))),
            ),
            (
                "comma in endpoint",
                service_doc(service("https://dwn.example/a,b", serde_json::json!("ok"))),
            ),
            (
                "semicolon in custom value",
                service_doc(service("https://dwn.example", serde_json::json!("a;b"))),
            ),
            (
                "empty custom array",
                service_doc(service("https://dwn.example", serde_json::json!([]))),
            ),
            (
                "non-string custom value",
                service_doc(service("https://dwn.example", serde_json::json!(1))),
            ),
            (
                "reserved custom name",
                service_doc({
                    let mut svc = service("https://dwn.example", serde_json::json!("ok"));
                    svc["t"] = serde_json::json!("Other");
                    svc
                }),
            ),
        ] {
            assert!(
                matches!(
                    validate_publishable_document(&document, &[]),
                    Err(DhtPublishError::InvalidDocument(_))
                ),
                "{name}"
            );
        }

        let mut value = doc_value(&base_doc());
        value["alsoKnownAs"] = serde_json::json!(["did:example:a,b"]);
        assert!(matches!(
            validate_publishable_document(&doc_from(value), &[]),
            Err(DhtPublishError::InvalidDocument(_))
        ));
    }

    #[test]
    fn rejects_non_dht_method() {
        let mut value = doc_value(&base_doc());
        value["id"] = serde_json::json!("did:web:example.com");
        // verification methods stay under the old DID on purpose: the method
        // check fires first.
        let document = doc_from(value);
        assert_eq!(
            validate_publishable_document(&document, &[]),
            Err(DhtPublishError::MethodNotSupported("web".to_string()))
        );
    }

    #[test]
    fn identity_vm_encodes_first_regardless_of_input_order() {
        let (did_string, document) = agent_document();
        let mut value = doc_value(&document);
        let methods = value["verificationMethod"].as_array().unwrap().clone();
        // Input order [sig, enc, 0]: the wire must still address the
        // identity key as _k0.
        value["verificationMethod"] =
            serde_json::json!([methods[1].clone(), methods[2].clone(), methods[0].clone()]);
        let reordered = doc_from(value);

        let encoded = encode_document(&reordered, &[], &[]).unwrap();
        let parsed = Packet::parse(&encoded).unwrap();
        let identity_b64 =
            URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes());
        let k0 = parsed
            .answers
            .iter()
            .find(|answer| answer.name.to_string() == "_k0._did")
            .expect("identity record");
        let k0_data = match &k0.rdata {
            RData::TXT(txt) => String::try_from(txt.clone()).unwrap(),
            _ => panic!("_k0 must be a TXT record"),
        };
        assert!(k0_data.contains(&format!("k={identity_b64}")), "{k0_data}");

        let did: DIDBuf = did_string.parse().unwrap();
        let (decoded, _) = decode_document(&did, &encoded).unwrap();
        let decoded_value = serde_json::to_value(&decoded).unwrap();
        let methods = &decoded.verification_method;
        assert!(methods[0].id.as_str().ends_with("#0"));
        assert_eq!(
            serde_json::to_value(&methods[0]).unwrap()["publicKeyJwk"]["x"],
            serde_json::json!(identity_b64)
        );
        assert_eq!(
            decoded_value["authentication"],
            serde_json::json!([format!("{did_string}#0"), format!("{did_string}#sig")])
        );
    }

    #[test]
    fn controllers_cannot_carry_delimiters() {
        // DID syntax already excludes `,`, `;`, and `=` from controller
        // values, so no typed document can smuggle them in; the encoder's
        // check_scalar on both controller paths is defense in depth for
        // binding rule 10.
        for controller in ["did:example:a,b", "did:example:a;b", "did:example:a=b"] {
            assert!(controller.parse::<DIDBuf>().is_err(), "{controller}");
        }
    }

    #[test]
    fn identity_controller_must_be_represented() {
        let (_, document) = agent_document();

        let mut value = doc_value(&document);
        value["verificationMethod"][0]["controller"] = serde_json::json!("did:example:ctrl");
        assert!(matches!(
            validate_publishable_document(&doc_from(value.clone()), &[]),
            Err(DhtPublishError::InvalidDocument(_))
        ));

        value["controller"] = serde_json::json!("did:example:ctrl");
        let represented = doc_from(value);
        validate_publishable_document(&represented, &[]).unwrap();
        let encoded = encode_document(&represented, &[], &[]).unwrap();
        let did: DIDBuf = represented.id.clone();
        let (decoded, _) = decode_document(&did, &encoded).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(represented).unwrap()
        );
    }

    #[test]
    fn identity_is_required_in_mandatory_relationships() {
        let document = base_doc();
        for relationship in [
            "authentication",
            "assertionMethod",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            let mut value = doc_value(&document);
            value[relationship] = serde_json::json!([]);
            assert!(
                matches!(
                    validate_publishable_document(&doc_from(value), &[]),
                    Err(DhtPublishError::InvalidDocument(_))
                ),
                "{relationship}"
            );
        }
        // keyAgreement carries the agreement key, never the identity key.
        validate_publishable_document(&document, &[]).unwrap();
    }

    #[test]
    fn duplicate_service_ids_are_rejected() {
        let (_, document) = agent_document();
        let mut value = doc_value(&document);
        let service = value["service"][0].clone();
        value["service"] = serde_json::json!([service.clone(), service]);
        assert!(matches!(
            validate_publishable_document(&doc_from(value), &[]),
            Err(DhtPublishError::InvalidDocument(_))
        ));
    }
}

#[cfg(test)]
mod blob_tests {
    use super::super::codec::decode_document;
    use super::*;

    /// Checked-in Rust-encoded bytes for the pinned TypeScript decoder test.
    ///
    /// Run with `BLESS_DID_DHT_FIXTURES=1` to regenerate after an intended
    /// encoding change; otherwise the checked-in bytes must match exactly.
    /// Inputs mirror the TypeScript publish fixture shape (agent VMs plus a
    /// DWN service) without sharing its seeds: the blob carries its own
    /// document, so the consumer only proves decode acceptance.
    #[test]
    fn rust_publish_bytes_fixture() {
        let blob = rust_publish_blob();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rust-publish-bytes.json"
        );
        if std::env::var("BLESS_DID_DHT_FIXTURES").is_ok() {
            std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
                .unwrap();
            std::fs::write(path, serde_json::to_string_pretty(&blob).unwrap() + "\n").unwrap();
        }
        let checked_in: Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(checked_in, blob);
    }

    fn rust_publish_blob() -> Value {
        let identity = ed25519_key(&[0x51; 32]);
        let signing = ed25519_key(&[0x52; 32]);
        let document: Document = serde_json::from_value(serde_json::json!({
            "id": did_string(&identity),
            "verificationMethod": [
                verification_jwk(&did_string(&identity), "0", &identity, "EdDSA"),
                verification_jwk(&did_string(&identity), "sig", &signing, "EdDSA"),
                x25519_jwk(&did_string(&identity)),
            ],
            "authentication": [format!("{}#0", did_string(&identity)), format!("{}#sig", did_string(&identity))],
            "assertionMethod": [format!("{}#0", did_string(&identity)), format!("{}#sig", did_string(&identity))],
            "capabilityInvocation": [format!("{}#0", did_string(&identity))],
            "capabilityDelegation": [format!("{}#0", did_string(&identity))],
            "keyAgreement": [format!("{}#enc", did_string(&identity))],
            "service": [{"id": format!("{}#dwn", did_string(&identity)), "type": "DecentralizedWebNode",
                         "serviceEndpoint": ["https://dwn.example"]}],
        }))
        .unwrap();
        let gateways = ["https://gateway.example".parse().unwrap()];
        let encoded = encode_document(&document, &[1, 2, 3], &gateways).unwrap();
        // Self-check: the blob must decode to its own document.
        let did: ssi_dids_core::DIDBuf = did_string(&identity).parse().unwrap();
        let (decoded, types) = decode_document(&did, &encoded).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(&document).unwrap()
        );
        assert_eq!(types, Some(vec![1, 2, 3]));
        serde_json::json!({
            "description": "Rust-encoded agent-shape did:dht document for the pinned TypeScript decoder test. Regenerate with BLESS_DID_DHT_FIXTURES=1.",
            "didDocument": document,
            "dnsBytes": base64_key(&encoded),
            "types": [1, 2, 3],
        })
    }

    fn ed25519_key(seed: &[u8; 32]) -> [u8; 32] {
        use ed25519_dalek::SigningKey;
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    fn did_string(identity: &[u8; 32]) -> String {
        format!("did:dht:{}", z32::encode(identity))
    }

    fn verification_jwk(did: &str, fragment: &str, public: &[u8; 32], alg: &str) -> Value {
        serde_json::json!({
            "id": format!("{did}#{fragment}"),
            "type": "JsonWebKey",
            "controller": did,
            "publicKeyJwk": {
                "kty": "OKP", "crv": "Ed25519",
                "x": base64_key(public),
                "kid": thumbprint_ed25519(public),
                "alg": alg,
            },
        })
    }

    fn x25519_jwk(did: &str) -> Value {
        let public = [0x53; 32];
        serde_json::json!({
            "id": format!("{did}#enc"),
            "type": "JsonWebKey",
            "controller": did,
            "publicKeyJwk": {
                "kty": "OKP", "crv": "X25519",
                "x": base64_key(&public),
                "kid": thumbprint_x25519(&public),
                "alg": "ECDH-ES+A256KW",
            },
        })
    }

    fn thumbprint_ed25519(public: &[u8; 32]) -> String {
        use ssi_jwk::{OctetParams, Params, JWK};
        JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: ssi_jwk::Base64urlUInt(public.to_vec()),
            private_key: None,
        }))
        .thumbprint()
        .unwrap()
    }

    fn thumbprint_x25519(public: &[u8; 32]) -> String {
        use ssi_jwk::{OctetParams, Params, JWK};
        JWK::from(Params::OKP(OctetParams {
            curve: "X25519".to_string(),
            public_key: ssi_jwk::Base64urlUInt(public.to_vec()),
            private_key: None,
        }))
        .thumbprint()
        .unwrap()
    }
}
