use dwn_rs_core::cid::generate_cid_from_serialized;
use dwn_rs_core::descriptors::{
    MessagesReadDescriptor, ProtocolQueryDescriptor, ReadDescriptor, RecordsQueryDescriptor,
};
use serde::Deserialize;
use serde_json::Value;

const BASIC_MESSAGES: &str =
    include_str!("../../../fixtures/dwn/messages/basic-interface-messages.json");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureSet {
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureCase {
    id: String,
    rust_status: RustStatus,
    descriptor_cid: String,
    message_cid: String,
    message: Value,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RustStatus {
    Supported,
    KnownGap,
}

#[test]
fn fixture_message_cids_match_typescript() {
    let fixtures = load_basic_messages();

    for case in fixtures.cases {
        assert_eq!(compute_cid(&case.message), case.message_cid, "{}", case.id);

        let descriptor = descriptor(&case);
        assert_eq!(compute_cid(descriptor), case.descriptor_cid, "{}", case.id);
    }
}

#[test]
fn supported_fixture_descriptors_roundtrip_through_rust_models() {
    let fixtures = load_basic_messages();

    for case in fixtures
        .cases
        .iter()
        .filter(|case| case.rust_status == RustStatus::Supported)
    {
        assert_supported_descriptor_roundtrip(case);
    }
}

fn load_basic_messages() -> FixtureSet {
    serde_json::from_str(BASIC_MESSAGES).expect("fixture file must be valid JSON")
}

fn compute_cid(value: &Value) -> String {
    generate_cid_from_serialized(value)
        .expect("fixture value must be DAG-CBOR encodable")
        .to_string()
}

fn descriptor(case: &FixtureCase) -> &Value {
    case.message
        .get("descriptor")
        .unwrap_or_else(|| panic!("{} must include a descriptor", case.id))
}

fn assert_supported_descriptor_roundtrip(case: &FixtureCase) {
    let descriptor = descriptor(case);
    let interface = descriptor
        .get("interface")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} descriptor must include interface", case.id));
    let method = descriptor
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} descriptor must include method", case.id));

    let roundtrip = match (interface, method) {
        ("Records", "Read") => roundtrip_descriptor::<ReadDescriptor>(descriptor),
        ("Records", "Query") => roundtrip_descriptor::<RecordsQueryDescriptor>(descriptor),
        ("Protocols", "Query") => roundtrip_descriptor::<ProtocolQueryDescriptor>(descriptor),
        ("Messages", "Read") => roundtrip_descriptor::<MessagesReadDescriptor>(descriptor),
        _ => panic!("{} has no Rust descriptor roundtrip mapping", case.id),
    };

    assert_eq!(roundtrip, *descriptor, "{}", case.id);
}

fn roundtrip_descriptor<T>(descriptor: &Value) -> Value
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let typed: T = serde_json::from_value(descriptor.clone()).expect("descriptor must deserialize");
    serde_json::to_value(typed).expect("descriptor must serialize")
}
