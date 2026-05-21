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
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures_util::stream;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};

const CID_MESSAGE_ASSERTION: &str = "cid.message";
const CID_DESCRIPTOR_ASSERTION: &str = "cid.descriptor";
const CID_JSON_ASSERTION: &str = "cid.json";
const CID_DAG_PB_BYTES_ASSERTION: &str = "cid.dagpb.bytes";
const CID_DAG_PB_STREAM_ASSERTION: &str = "cid.dagpb.stream";
const JWS_GENERAL_SIGN_ASSERTION: &str = "jws.general.sign";
const JWS_GENERAL_VERIFY_ASSERTION: &str = "jws.general.verify";
const JWS_GENERAL_PAYLOAD_ASSERTION: &str = "jws.general.payload";
const DESCRIPTOR_ROUNDTRIP_ASSERTION: &str = "descriptor.roundtrip";

const JWS_ERROR_INVALID_SIGNATURE: &str = "GeneralJwsVerifierInvalidSignature";
const JWS_ERROR_MISSING_ALG: &str = "GeneralJwsVerifierMissingAlg";
const JWS_ERROR_MISSING_KID: &str = "GeneralJwsVerifierMissingKid";
const JWS_ERROR_PUBLIC_KEY_NOT_FOUND: &str = "GeneralJwsVerifierGetPublicKeyNotFound";

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
    keys: Option<BTreeMap<String, FixtureJwsKey>>,
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
    expected_error_code: Option<String>,
    expected_signers: Option<Vec<String>>,
    jws: Option<FixtureJws>,
    payload: Option<FixtureJwsPayload>,
    signer_ids: Option<Vec<String>>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureJwsKey {
    kid: String,
    algorithm: String,
    public_jwk: FixtureEd25519PublicJwk,
    private_jwk: Option<FixtureEd25519PrivateJwk>,
}

#[derive(Debug, Deserialize)]
struct FixtureEd25519PublicJwk {
    alg: String,
    kty: String,
    crv: String,
    x: String,
}

#[derive(Debug, Deserialize)]
struct FixtureEd25519PrivateJwk {
    alg: String,
    kty: String,
    crv: String,
    x: String,
    d: String,
}

#[derive(Debug, Deserialize)]
struct FixtureJws {
    payload: String,
    signatures: Vec<FixtureJwsSignature>,
}

#[derive(Debug, Deserialize)]
struct FixtureJwsSignature {
    protected: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "encoding")]
enum FixtureJwsPayload {
    #[serde(rename = "base64url")]
    Base64Url { value: String },
    #[serde(rename = "json")]
    Json { value: Value },
    #[serde(rename = "utf8")]
    Utf8 { value: String },
}

#[derive(Debug, Deserialize)]
struct FixtureJwsProtectedHeader {
    alg: Option<String>,
    kid: Option<String>,
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
fn fixture_general_jws_matches_typescript() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(JWS_GENERAL_SIGN_ASSERTION)
            && !suite.has_assertion(JWS_GENERAL_VERIFY_ASSERTION)
            && !suite.has_assertion(JWS_GENERAL_PAYLOAD_ASSERTION)
        {
            continue;
        }

        let check_signing = suite.has_assertion(JWS_GENERAL_SIGN_ASSERTION);
        let check_verification = suite.has_assertion(JWS_GENERAL_VERIFY_ASSERTION);
        let check_payload = suite.has_assertion(JWS_GENERAL_PAYLOAD_ASSERTION);

        for case in suite
            .fixture_set
            .cases
            .iter()
            .filter(|case| case.rust_status == RustStatus::Supported)
        {
            if check_payload {
                assert_eq!(
                    URL_SAFE_NO_PAD.encode(jws_payload_bytes(case)),
                    jws(case).payload,
                    "{}",
                    case.id
                );
            }

            if check_signing && case.expected_error_code.is_none() {
                assert_general_jws_signing(&suite.fixture_set, case);
            }

            if check_verification {
                match case.expected_error_code.as_deref() {
                    Some(expected_error_code) => assert_eq!(
                        verify_general_jws(&suite.fixture_set, case).unwrap_err(),
                        expected_error_code,
                        "{}",
                        case.id
                    ),
                    None => assert_eq!(
                        verify_general_jws(&suite.fixture_set, case).unwrap(),
                        expected_signers(case),
                        "{}",
                        case.id
                    ),
                }
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

fn jws_payload_bytes(case: &FixtureCase) -> Vec<u8> {
    match case
        .payload
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include a JWS payload", case.id))
    {
        FixtureJwsPayload::Base64Url { value } => {
            URL_SAFE_NO_PAD.decode(value).unwrap_or_else(|err| {
                panic!("{} must include valid base64url payload: {}", case.id, err)
            })
        }
        FixtureJwsPayload::Json { value } => {
            serde_json::to_vec(value).expect("JWS JSON payload must serialize")
        }
        FixtureJwsPayload::Utf8 { value } => value.as_bytes().to_vec(),
    }
}

fn assert_general_jws_signing(fixture_set: &FixtureSet, case: &FixtureCase) {
    let jws = jws(case);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(jws_payload_bytes(case)),
        jws.payload,
        "{} payload",
        case.id
    );
    assert_eq!(
        signer_ids(case).len(),
        jws.signatures.len(),
        "{} signer count",
        case.id
    );

    for (signature, signer_id) in jws.signatures.iter().zip(signer_ids(case)) {
        let key = fixture_jws_key(fixture_set, case, signer_id);
        let protected = format!(
            "{{\"kid\":{},\"alg\":{}}}",
            serde_json::to_string(&key.kid).expect("kid must serialize"),
            serde_json::to_string(&key.algorithm).expect("algorithm must serialize")
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(protected.as_bytes()),
            signature.protected,
            "{} protected header",
            case.id
        );

        let signing_key = signing_key_from_fixture(key, &case.id);
        let signing_input = signing_input(jws, signature);
        let expected_signature = signing_key.sign(signing_input.as_bytes());
        assert_eq!(
            URL_SAFE_NO_PAD.encode(expected_signature.to_bytes()),
            signature.signature,
            "{} signature",
            case.id
        );
    }
}

fn verify_general_jws(
    fixture_set: &FixtureSet,
    case: &FixtureCase,
) -> Result<Vec<String>, &'static str> {
    let jws = jws(case);
    let mut signers = Vec::new();

    for signature in &jws.signatures {
        let protected_header = protected_header(case, signature);
        let kid = protected_header
            .kid
            .as_deref()
            .ok_or(JWS_ERROR_MISSING_KID)?;

        if protected_header.alg.is_none() {
            return Err(JWS_ERROR_MISSING_ALG);
        }

        let did = did_from_kid(kid).to_string();
        let key = signer_ids(case)
            .iter()
            .map(|signer_id| fixture_jws_key(fixture_set, case, signer_id))
            .find(|key| kid.ends_with(&key.kid))
            .ok_or(JWS_ERROR_PUBLIC_KEY_NOT_FOUND)?;

        if verify_jws_signature(jws, signature, key, &case.id) {
            signers.push(did);
        } else {
            return Err(JWS_ERROR_INVALID_SIGNATURE);
        }
    }

    Ok(signers)
}

fn verify_jws_signature(
    jws: &FixtureJws,
    fixture_signature: &FixtureJwsSignature,
    key: &FixtureJwsKey,
    case_id: &str,
) -> bool {
    let verifying_key = verifying_key_from_fixture(key, case_id);
    let signature_bytes = decode_base64url(&fixture_signature.signature, case_id, "signature");
    let ed25519_signature = Signature::from_slice(&signature_bytes).unwrap_or_else(|err| {
        panic!(
            "{} must include a valid Ed25519 signature: {}",
            case_id, err
        )
    });

    verifying_key
        .verify(
            signing_input(jws, fixture_signature).as_bytes(),
            &ed25519_signature,
        )
        .is_ok()
}

fn protected_header(
    case: &FixtureCase,
    signature: &FixtureJwsSignature,
) -> FixtureJwsProtectedHeader {
    let protected = decode_base64url(&signature.protected, &case.id, "protected header");
    serde_json::from_slice(&protected)
        .unwrap_or_else(|err| panic!("{} must include a valid protected header: {}", case.id, err))
}

fn signing_input(jws: &FixtureJws, signature: &FixtureJwsSignature) -> String {
    format!("{}.{}", signature.protected, jws.payload)
}

fn signing_key_from_fixture(key: &FixtureJwsKey, case_id: &str) -> SigningKey {
    let private_jwk = key
        .private_jwk
        .as_ref()
        .unwrap_or_else(|| panic!("{} key {} must include a privateJwk", case_id, key.kid));
    assert_ed25519_private_jwk(private_jwk, case_id);

    let private_key = decode_base64url(&private_jwk.d, case_id, "private key");
    SigningKey::from_bytes(&ed25519_key_bytes(private_key, case_id, "private key"))
}

fn verifying_key_from_fixture(key: &FixtureJwsKey, case_id: &str) -> VerifyingKey {
    assert_ed25519_public_jwk(&key.public_jwk, case_id);

    let public_key = decode_base64url(&key.public_jwk.x, case_id, "public key");
    VerifyingKey::from_bytes(&ed25519_key_bytes(public_key, case_id, "public key")).unwrap_or_else(
        |err| {
            panic!(
                "{} must include a valid Ed25519 public key: {}",
                case_id, err
            )
        },
    )
}

fn assert_ed25519_public_jwk(jwk: &FixtureEd25519PublicJwk, case_id: &str) {
    assert_eq!(jwk.alg, "EdDSA", "{} JWK alg", case_id);
    assert_eq!(jwk.kty, "OKP", "{} JWK kty", case_id);
    assert_eq!(jwk.crv, "Ed25519", "{} JWK crv", case_id);
}

fn assert_ed25519_private_jwk(jwk: &FixtureEd25519PrivateJwk, case_id: &str) {
    assert_eq!(jwk.alg, "EdDSA", "{} private JWK alg", case_id);
    assert_eq!(jwk.kty, "OKP", "{} private JWK kty", case_id);
    assert_eq!(jwk.crv, "Ed25519", "{} private JWK crv", case_id);
    assert!(!jwk.x.is_empty(), "{} private JWK x", case_id);
}

fn ed25519_key_bytes(value: Vec<u8>, case_id: &str, label: &str) -> [u8; 32] {
    value
        .try_into()
        .unwrap_or_else(|_| panic!("{} {} must be 32 bytes", case_id, label))
}

fn decode_base64url(value: &str, case_id: &str, label: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).unwrap_or_else(|err| {
        panic!(
            "{} must include valid base64url {}: {}",
            case_id, label, err
        )
    })
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

fn expected_signers(case: &FixtureCase) -> Vec<String> {
    case.expected_signers
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include expectedSigners", case.id))
        .clone()
}

fn signer_ids(case: &FixtureCase) -> &[String] {
    case.signer_ids
        .as_deref()
        .unwrap_or_else(|| panic!("{} must include signerIds", case.id))
}

fn fixture_jws_key<'a>(
    fixture_set: &'a FixtureSet,
    case: &FixtureCase,
    signer_id: &str,
) -> &'a FixtureJwsKey {
    fixture_set
        .keys
        .as_ref()
        .and_then(|keys| keys.get(signer_id))
        .unwrap_or_else(|| panic!("{} references missing signer {}", case.id, signer_id))
}

fn jws(case: &FixtureCase) -> &FixtureJws {
    case.jws
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include a JWS", case.id))
}

fn did_from_kid(kid: &str) -> &str {
    kid.split('#')
        .next()
        .expect("split always returns one item")
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
