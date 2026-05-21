use dwn_rs_core::cid::generate_cid_from_json;
use dwn_rs_core::descriptors::{
    ConfigureDescriptor, DeleteDescriptor, MessagesQueryDescriptor, MessagesReadDescriptor,
    MessagesSubscribeDescriptor, ProtocolQueryDescriptor, ReadDescriptor, RecordsQueryDescriptor,
    RecordsWriteDescriptor, SubscribeDescriptor as RecordsSubscribeDescriptor,
};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const CID_MESSAGE_ASSERTION: &str = "cid.message";
const CID_DESCRIPTOR_ASSERTION: &str = "cid.descriptor";
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
                assert_eq!(compute_cid(&case.message), case.message_cid, "{}", case.id);
            }

            if check_descriptor_cid {
                let descriptor = descriptor(case);
                assert_eq!(compute_cid(descriptor), case.descriptor_cid, "{}", case.id);
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
