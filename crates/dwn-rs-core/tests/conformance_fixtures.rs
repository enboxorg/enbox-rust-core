use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use dwn_rs_core::cid::{
    generate_cid_from_json, generate_dag_pb_cid_from_bytes, generate_dag_pb_cid_from_stream,
};
use dwn_rs_core::descriptors::{
    ConfigureDescriptor, DeleteDescriptor, MessagesQueryDescriptor, MessagesReadDescriptor,
    MessagesSubscribeDescriptor, ProtocolQueryDescriptor, ReadDescriptor, RecordsQueryDescriptor,
    RecordsWriteDescriptor, SubscribeDescriptor as RecordsSubscribeDescriptor,
};
use futures_util::stream;
use serde::Deserialize;
use serde_json::Value;
use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};

const CID_MESSAGE_ASSERTION: &str = "cid.message";
const CID_DESCRIPTOR_ASSERTION: &str = "cid.descriptor";
const CID_JSON_ASSERTION: &str = "cid.json";
const CID_DAG_PB_BYTES_ASSERTION: &str = "cid.dagpb.bytes";
const CID_DAG_PB_STREAM_ASSERTION: &str = "cid.dagpb.stream";
const DESCRIPTOR_ROUNDTRIP_ASSERTION: &str = "descriptor.roundtrip";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureManifest {
    schema_version: u64,
    suites: Vec<FixtureSuiteRef>,
}

#[derive(Debug, Deserialize)]
struct FixtureSuiteRef {
    id: String,
    path: String,
    assertions: Vec<String>,
}

#[derive(Debug)]
struct LoadedFixtureSuite {
    suite_ref: FixtureSuiteRef,
    fixture_set: FixtureSet,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureSet {
    schema_version: u64,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureCase {
    id: String,
    rust_status: RustStatus,
    descriptor_cid: Option<String>,
    message_cid: Option<String>,
    message: Option<Value>,
    cid: Option<String>,
    data: Option<FixtureData>,
    value: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "encoding")]
enum FixtureData {
    #[serde(rename = "base64url")]
    Base64Url { value: String },
    #[serde(rename = "hex")]
    Hex { value: String },
    #[serde(rename = "repeatByte")]
    RepeatByte { byte: u8, length: usize },
    #[serde(rename = "utf8")]
    Utf8 { value: String },
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RustStatus {
    Supported,
    KnownGap,
}

#[test]
fn fixture_message_cids_match_typescript() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(CID_MESSAGE_ASSERTION)
            && !suite.has_assertion(CID_DESCRIPTOR_ASSERTION)
        {
            continue;
        }

        let check_message_cid = suite.has_assertion(CID_MESSAGE_ASSERTION);
        let check_descriptor_cid = suite.has_assertion(CID_DESCRIPTOR_ASSERTION);

        for case in &suite.fixture_set.cases {
            if check_message_cid {
                assert_eq!(
                    compute_cid(message(case)),
                    expected_message_cid(case),
                    "{}",
                    case.id
                );
            }

            if check_descriptor_cid {
                let descriptor = descriptor(case);
                assert_eq!(
                    compute_cid(descriptor),
                    expected_descriptor_cid(case),
                    "{}",
                    case.id
                );
            }
        }
    }
}

#[test]
fn fixture_json_cids_match_typescript() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(CID_JSON_ASSERTION) {
            continue;
        }

        for case in &suite.fixture_set.cases {
            assert_eq!(
                compute_cid(json_value(case)),
                expected_json_cid(case),
                "{}",
                case.id
            );
        }
    }
}

#[tokio::test]
async fn fixture_dag_pb_cids_match_typescript() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(CID_DAG_PB_BYTES_ASSERTION)
            && !suite.has_assertion(CID_DAG_PB_STREAM_ASSERTION)
        {
            continue;
        }

        let check_bytes_cid = suite.has_assertion(CID_DAG_PB_BYTES_ASSERTION);
        let check_stream_cid = suite.has_assertion(CID_DAG_PB_STREAM_ASSERTION);

        for case in suite
            .fixture_set
            .cases
            .iter()
            .filter(|case| case.rust_status == RustStatus::Supported)
        {
            let data = fixture_data(case);

            if check_bytes_cid {
                assert_eq!(
                    generate_dag_pb_cid_from_bytes(&data).to_string(),
                    expected_cid(case),
                    "{}",
                    case.id
                );
            }

            if check_stream_cid {
                let stream = stream::iter(
                    data.chunks(65_536)
                        .map(|chunk| Ok::<_, Infallible>(Bytes::copy_from_slice(chunk)))
                        .collect::<Vec<_>>(),
                );
                assert_eq!(
                    generate_dag_pb_cid_from_stream(stream)
                        .await
                        .expect("infallible fixture stream")
                        .to_string(),
                    expected_cid(case),
                    "{}",
                    case.id
                );
            }
        }
    }
}

#[test]
fn supported_fixture_descriptors_roundtrip_through_rust_models() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(DESCRIPTOR_ROUNDTRIP_ASSERTION) {
            continue;
        }

        for case in suite
            .fixture_set
            .cases
            .iter()
            .filter(|case| case.rust_status == RustStatus::Supported)
        {
            assert_supported_descriptor_roundtrip(case);
        }
    }
}

impl LoadedFixtureSuite {
    fn has_assertion(&self, assertion: &str) -> bool {
        self.suite_ref
            .assertions
            .iter()
            .any(|candidate| candidate == assertion)
    }
}

fn load_fixture_suites() -> Vec<LoadedFixtureSuite> {
    let root = fixtures_root();
    let manifest_path = root.join("manifest.json");
    let manifest = read_json::<FixtureManifest>(&manifest_path);

    assert_eq!(
        manifest.schema_version, 1,
        "fixture manifest schema version"
    );

    manifest
        .suites
        .into_iter()
        .map(|suite_ref| {
            let fixture_path = root.join(&suite_ref.path);
            let fixture_set = read_json::<FixtureSet>(&fixture_path);

            assert_eq!(
                fixture_set.schema_version, 1,
                "{} schema version",
                suite_ref.id
            );

            LoadedFixtureSuite {
                suite_ref,
                fixture_set,
            }
        })
        .collect()
}

fn read_json<T>(path: &Path) -> T
where
    T: serde::de::DeserializeOwned,
{
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {}", path.display(), err));
    serde_json::from_str(&contents)
        .unwrap_or_else(|err| panic!("failed to parse {}: {}", path.display(), err))
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn compute_cid(value: &Value) -> String {
    generate_cid_from_json(value)
        .expect("fixture value must be DAG-CBOR encodable")
        .to_string()
}

fn message(case: &FixtureCase) -> &Value {
    case.message
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include a message", case.id))
}

fn descriptor(case: &FixtureCase) -> &Value {
    message(case)
        .get("descriptor")
        .unwrap_or_else(|| panic!("{} must include a descriptor", case.id))
}

fn json_value(case: &FixtureCase) -> &Value {
    case.value
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include a JSON value", case.id))
}

fn fixture_data(case: &FixtureCase) -> Vec<u8> {
    match case
        .data
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include byte data", case.id))
    {
        FixtureData::Base64Url { value } => URL_SAFE_NO_PAD
            .decode(value)
            .unwrap_or_else(|err| panic!("{} must include valid base64url data: {}", case.id, err)),
        FixtureData::Hex { value } => decode_hex(value, &case.id),
        FixtureData::RepeatByte { byte, length } => vec![*byte; *length],
        FixtureData::Utf8 { value } => value.as_bytes().to_vec(),
    }
}

fn decode_hex(value: &str, case_id: &str) -> Vec<u8> {
    assert_eq!(
        value.len() % 2,
        0,
        "{} hex data length must be even",
        case_id
    );

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| (hex_digit(chunk[0], case_id) << 4) | hex_digit(chunk[1], case_id))
        .collect()
}

fn hex_digit(value: u8, case_id: &str) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("{} hex data contains an invalid digit", case_id),
    }
}

fn expected_message_cid(case: &FixtureCase) -> &str {
    case.message_cid
        .as_deref()
        .unwrap_or_else(|| panic!("{} must include a messageCid", case.id))
}

fn expected_descriptor_cid(case: &FixtureCase) -> &str {
    case.descriptor_cid
        .as_deref()
        .unwrap_or_else(|| panic!("{} must include a descriptorCid", case.id))
}

fn expected_json_cid(case: &FixtureCase) -> &str {
    expected_cid(case)
}

fn expected_cid(case: &FixtureCase) -> &str {
    case.cid
        .as_deref()
        .unwrap_or_else(|| panic!("{} must include a cid", case.id))
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
        ("Records", "Write") => roundtrip_descriptor::<RecordsWriteDescriptor>(descriptor),
        ("Records", "Delete") => roundtrip_descriptor::<DeleteDescriptor>(descriptor),
        ("Records", "Subscribe") => roundtrip_descriptor::<RecordsSubscribeDescriptor>(descriptor),
        ("Protocols", "Configure") => roundtrip_descriptor::<ConfigureDescriptor>(descriptor),
        ("Protocols", "Query") => roundtrip_descriptor::<ProtocolQueryDescriptor>(descriptor),
        ("Messages", "Read") => roundtrip_descriptor::<MessagesReadDescriptor>(descriptor),
        ("Messages", "Query") => roundtrip_descriptor::<MessagesQueryDescriptor>(descriptor),
        ("Messages", "Subscribe") => {
            roundtrip_descriptor::<MessagesSubscribeDescriptor>(descriptor)
        }
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
