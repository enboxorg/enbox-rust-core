use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, Nonce as AesGcmNonce, Tag as AesGcmTag};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use chacha20poly1305::{Tag as XChaCha20Poly1305Tag, XChaCha20Poly1305, XNonce};
use dwn_rs_core::auth::{
    GeneralJws, GeneralJwsPrivateJwk, GeneralJwsPublicJwk, PrivateJwkSigner,
    StaticPublicKeyResolver,
};
use dwn_rs_core::cid::{
    generate_cid_from_json, generate_dag_pb_cid_from_bytes, generate_dag_pb_cid_from_stream,
};
use dwn_rs_core::descriptors::{
    ConfigureDescriptor, DeleteDescriptor, MessagesQueryDescriptor, MessagesReadDescriptor,
    MessagesSubscribeDescriptor, ProtocolQueryDescriptor, ReadDescriptor, RecordsQueryDescriptor,
    RecordsWriteDescriptor, SubscribeDescriptor as RecordsSubscribeDescriptor,
};
use dwn_rs_core::state_index::MemoryStateIndex;
use dwn_rs_core::stores::EnboxStateIndex;
use futures_util::stream;
use k256::sha2::{Digest, Sha256};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
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
const JWE_PROTECTED_ASSERTION: &str = "jwe.protected";
const JWE_AEAD_ASSERTION: &str = "jwe.aead";
const JWE_KEYWRAP_ASSERTION: &str = "jwe.keywrap";
const JWE_DECRYPT_ASSERTION: &str = "jwe.decrypt";
const STATE_INDEX_OPERATIONS_ASSERTION: &str = "state-index.operations";
const MESSAGES_SYNC_REPLIES_ASSERTION: &str = "messages-sync.replies";
const DESCRIPTOR_ROUNDTRIP_ASSERTION: &str = "descriptor.roundtrip";

const JWE_ERROR_DECRYPT_FAILED: &str = "JweDecryptFailed";
const MAX_INLINE_DATA_SIZE: usize = 30_000;

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
    seed_sets: Option<BTreeMap<String, Vec<MessagesSyncSeedEntry>>>,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureCase {
    id: String,
    rust_status: RustStatus,
    cek: Option<FixtureData>,
    ciphertext: Option<FixtureData>,
    content_encryption_algorithm: Option<String>,
    descriptor_cid: Option<String>,
    derivation_scheme: Option<String>,
    derived_private_jwk: Option<FixtureDerivedPrivateJwk>,
    ephemeral_private_jwk: Option<FixtureX25519PrivateJwk>,
    ephemeral_public_jwk: Option<FixtureX25519PublicJwk>,
    message_cid: Option<String>,
    message: Option<Value>,
    cid: Option<String>,
    data: Option<FixtureData>,
    expected_error_code: Option<String>,
    expected_signers: Option<Vec<String>>,
    iv: Option<FixtureData>,
    jwe: Option<FixtureJwe>,
    jws: Option<GeneralJws>,
    key_agreement_algorithm: Option<String>,
    payload: Option<FixtureJwsPayload>,
    plaintext: Option<FixtureData>,
    recipient_private_jwk: Option<FixtureX25519PrivateJwk>,
    recipient_public_jwk: Option<FixtureX25519PublicJwk>,
    record: Option<Value>,
    signer_ids: Option<Vec<String>>,
    tag: Option<FixtureData>,
    tenants: Option<Vec<String>>,
    operations: Option<Vec<StateIndexOperation>>,
    sync: Option<MessagesSyncFixture>,
    value: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessagesSyncSeedEntry {
    id: String,
    #[serde(rename = "messageCid")]
    message_cid: String,
    indexes: BTreeMap<String, Value>,
    message: Value,
    encoded_data: Option<String>,
    data: Option<FixtureData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessagesSyncFixture {
    tenant: String,
    seed_set: String,
    request: Value,
    reply: Value,
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
    public_jwk: GeneralJwsPublicJwk,
    private_jwk: Option<GeneralJwsPrivateJwk>,
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
#[serde(rename_all = "camelCase")]
struct FixtureJwe {
    protected: String,
    iv: String,
    tag: String,
    recipients: Vec<FixtureJweRecipient>,
}

#[derive(Debug, Deserialize)]
struct FixtureJweRecipient {
    header: FixtureJweRecipientHeader,
    encrypted_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureJweRecipientHeader {
    kid: String,
    epk: FixtureX25519PublicJwk,
    derivation_scheme: String,
    derived_public_key: Option<FixtureX25519PublicJwk>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
enum StateIndexOperation {
    #[serde(rename = "insert")]
    Insert {
        tenant: String,
        #[serde(rename = "messageCid")]
        message_cid: String,
        indexes: BTreeMap<String, Value>,
    },
    #[serde(rename = "delete")]
    Delete {
        tenant: String,
        #[serde(rename = "messageCids")]
        message_cids: Vec<String>,
    },
    #[serde(rename = "getRoot")]
    GetRoot { tenant: String, expected: String },
    #[serde(rename = "getProtocolRoot")]
    GetProtocolRoot {
        tenant: String,
        protocol: String,
        expected: String,
    },
    #[serde(rename = "getSubtreeHash")]
    GetSubtreeHash {
        tenant: String,
        prefix: String,
        expected: String,
    },
    #[serde(rename = "getProtocolSubtreeHash")]
    GetProtocolSubtreeHash {
        tenant: String,
        protocol: String,
        prefix: String,
        expected: String,
    },
    #[serde(rename = "getLeaves")]
    GetLeaves {
        tenant: String,
        prefix: String,
        expected: Vec<String>,
    },
    #[serde(rename = "getProtocolLeaves")]
    GetProtocolLeaves {
        tenant: String,
        protocol: String,
        prefix: String,
        expected: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureDerivedPrivateJwk {
    root_key_id: String,
    derivation_scheme: String,
    derivation_path: Vec<String>,
    derived_private_key: FixtureX25519PrivateJwk,
}

#[derive(Debug, Deserialize)]
struct FixtureX25519PublicJwk {
    kty: String,
    crv: String,
    x: String,
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureX25519PrivateJwk {
    kty: String,
    crv: String,
    d: String,
    x: String,
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureJweProtectedHeader {
    alg: String,
    enc: String,
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
fn fixture_jwe_matches_typescript() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(JWE_PROTECTED_ASSERTION)
            && !suite.has_assertion(JWE_AEAD_ASSERTION)
            && !suite.has_assertion(JWE_KEYWRAP_ASSERTION)
            && !suite.has_assertion(JWE_DECRYPT_ASSERTION)
        {
            continue;
        }

        let check_protected = suite.has_assertion(JWE_PROTECTED_ASSERTION);
        let check_aead = suite.has_assertion(JWE_AEAD_ASSERTION);
        let check_keywrap = suite.has_assertion(JWE_KEYWRAP_ASSERTION);
        let check_decrypt = suite.has_assertion(JWE_DECRYPT_ASSERTION);

        for case in suite
            .fixture_set
            .cases
            .iter()
            .filter(|case| case.rust_status == RustStatus::Supported)
        {
            assert_jwe_production_model(case);

            if check_protected {
                assert_jwe_protected_header(case);
            }

            if check_aead && case.expected_error_code.is_none() {
                assert_jwe_aead(case);
            }

            if check_keywrap {
                assert_jwe_keywrap(case);
            }

            if check_decrypt {
                assert_jwe_decrypt(case);
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

#[tokio::test]
async fn fixture_state_index_operations_match_typescript() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(STATE_INDEX_OPERATIONS_ASSERTION) {
            continue;
        }

        for case in &suite.fixture_set.cases {
            assert_state_index_operation_fixture_shape(case);
            if case.rust_status == RustStatus::Supported {
                assert_state_index_operations(case).await;
            }
        }
    }
}

#[tokio::test]
async fn fixture_messages_sync_replies_match_typescript() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(MESSAGES_SYNC_REPLIES_ASSERTION) {
            continue;
        }

        for case in &suite.fixture_set.cases {
            assert_messages_sync_fixture_shape(&suite.fixture_set, case);
            if case.rust_status == RustStatus::Supported {
                assert_messages_sync_reply(&suite.fixture_set, case).await;
            }
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

fn assert_state_index_operation_fixture_shape(case: &FixtureCase) {
    let tenants = case
        .tenants
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include StateIndex tenants", case.id));
    assert!(
        !tenants.is_empty(),
        "{} must include at least one StateIndex tenant",
        case.id
    );
    for tenant in tenants {
        assert!(!tenant.is_empty(), "{} tenant must not be empty", case.id);
    }

    let operations = case
        .operations
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include StateIndex operations", case.id));
    assert!(
        !operations.is_empty(),
        "{} must include at least one StateIndex operation",
        case.id
    );

    for operation in operations {
        match operation {
            StateIndexOperation::Insert {
                tenant,
                message_cid,
                indexes,
            } => {
                assert_state_index_tenant(case, tenants, tenant);
                assert!(
                    !message_cid.is_empty(),
                    "{} insert messageCid must not be empty",
                    case.id
                );
                assert!(
                    !indexes.is_empty(),
                    "{} insert indexes must not be empty",
                    case.id
                );
            }
            StateIndexOperation::Delete {
                tenant,
                message_cids,
            } => {
                assert_state_index_tenant(case, tenants, tenant);
                assert!(
                    !message_cids.is_empty(),
                    "{} delete messageCids must not be empty",
                    case.id
                );
                for message_cid in message_cids {
                    assert!(
                        !message_cid.is_empty(),
                        "{} delete messageCid must not be empty",
                        case.id
                    );
                }
            }
            StateIndexOperation::GetRoot { tenant, expected } => {
                assert_state_index_tenant(case, tenants, tenant);
                assert_state_hash_hex(case, expected);
            }
            StateIndexOperation::GetProtocolRoot {
                tenant,
                protocol,
                expected,
            } => {
                assert_state_index_tenant(case, tenants, tenant);
                assert_state_index_protocol(case, protocol);
                assert_state_hash_hex(case, expected);
            }
            StateIndexOperation::GetSubtreeHash {
                tenant,
                prefix,
                expected,
            } => {
                assert_state_index_tenant(case, tenants, tenant);
                assert_bit_prefix(case, prefix);
                assert_state_hash_hex(case, expected);
            }
            StateIndexOperation::GetProtocolSubtreeHash {
                tenant,
                protocol,
                prefix,
                expected,
            } => {
                assert_state_index_tenant(case, tenants, tenant);
                assert_state_index_protocol(case, protocol);
                assert_bit_prefix(case, prefix);
                assert_state_hash_hex(case, expected);
            }
            StateIndexOperation::GetLeaves {
                tenant,
                prefix,
                expected,
            } => {
                assert_state_index_tenant(case, tenants, tenant);
                assert_bit_prefix(case, prefix);
                assert_state_index_leaves(case, expected);
            }
            StateIndexOperation::GetProtocolLeaves {
                tenant,
                protocol,
                prefix,
                expected,
            } => {
                assert_state_index_tenant(case, tenants, tenant);
                assert_state_index_protocol(case, protocol);
                assert_bit_prefix(case, prefix);
                assert_state_index_leaves(case, expected);
            }
        }
    }
}

fn assert_state_index_tenant(case: &FixtureCase, tenants: &[String], tenant: &str) {
    assert!(
        tenants.iter().any(|candidate| candidate == tenant),
        "{} operation tenant {} must be listed in case tenants",
        case.id,
        tenant
    );
}

fn assert_state_index_protocol(case: &FixtureCase, protocol: &str) {
    assert!(
        !protocol.is_empty(),
        "{} StateIndex protocol must not be empty",
        case.id
    );
}

fn assert_state_hash_hex(case: &FixtureCase, value: &str) {
    assert_eq!(
        value.len(),
        64,
        "{} StateIndex hash must be 32-byte hex",
        case.id
    );
    assert!(
        value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{} StateIndex hash must be hex",
        case.id
    );
}

fn assert_bit_prefix(case: &FixtureCase, prefix: &str) {
    assert!(
        prefix.bytes().all(|byte| byte == b'0' || byte == b'1'),
        "{} StateIndex prefix must be a bit string",
        case.id
    );
    assert!(
        prefix.len() <= 256,
        "{} StateIndex prefix must be no longer than 256 bits",
        case.id
    );
}

fn assert_state_index_leaves(case: &FixtureCase, leaves: &[String]) {
    for leaf in leaves {
        assert!(
            !leaf.is_empty(),
            "{} StateIndex leaf CID must not be empty",
            case.id
        );
    }
}

async fn assert_state_index_operations(case: &FixtureCase) {
    let mut state_index = MemoryStateIndex::default();
    state_index
        .open()
        .await
        .unwrap_or_else(|err| panic!("{} StateIndex open failed: {}", case.id, err));

    for operation in state_index_operations(case) {
        match operation {
            StateIndexOperation::Insert {
                tenant,
                message_cid,
                indexes,
            } => {
                state_index
                    .insert(tenant, message_cid, state_index_indexes(case, indexes))
                    .await
                    .unwrap_or_else(|err| panic!("{} StateIndex insert failed: {}", case.id, err));
            }
            StateIndexOperation::Delete {
                tenant,
                message_cids,
            } => {
                state_index
                    .delete(tenant, message_cids)
                    .await
                    .unwrap_or_else(|err| panic!("{} StateIndex delete failed: {}", case.id, err));
            }
            StateIndexOperation::GetRoot { tenant, expected } => {
                assert_eq!(
                    state_hash_hex(&state_index.get_root(tenant).await.unwrap_or_else(|err| {
                        panic!("{} StateIndex getRoot failed: {}", case.id, err)
                    })),
                    *expected,
                    "{} getRoot {}",
                    case.id,
                    tenant
                );
            }
            StateIndexOperation::GetProtocolRoot {
                tenant,
                protocol,
                expected,
            } => {
                assert_eq!(
                    state_hash_hex(
                        &state_index
                            .get_protocol_root(tenant, protocol)
                            .await
                            .unwrap_or_else(|err| {
                                panic!("{} StateIndex getProtocolRoot failed: {}", case.id, err)
                            })
                    ),
                    *expected,
                    "{} getProtocolRoot {} {}",
                    case.id,
                    tenant,
                    protocol
                );
            }
            StateIndexOperation::GetSubtreeHash {
                tenant,
                prefix,
                expected,
            } => {
                assert_eq!(
                    state_hash_hex(
                        &state_index
                            .get_subtree_hash(tenant, &bit_prefix(prefix))
                            .await
                            .unwrap_or_else(|err| {
                                panic!("{} StateIndex getSubtreeHash failed: {}", case.id, err)
                            })
                    ),
                    *expected,
                    "{} getSubtreeHash {} {}",
                    case.id,
                    tenant,
                    prefix
                );
            }
            StateIndexOperation::GetProtocolSubtreeHash {
                tenant,
                protocol,
                prefix,
                expected,
            } => {
                assert_eq!(
                    state_hash_hex(
                        &state_index
                            .get_protocol_subtree_hash(tenant, protocol, &bit_prefix(prefix))
                            .await
                            .unwrap_or_else(|err| {
                                panic!(
                                    "{} StateIndex getProtocolSubtreeHash failed: {}",
                                    case.id, err
                                )
                            })
                    ),
                    *expected,
                    "{} getProtocolSubtreeHash {} {} {}",
                    case.id,
                    tenant,
                    protocol,
                    prefix
                );
            }
            StateIndexOperation::GetLeaves {
                tenant,
                prefix,
                expected,
            } => {
                let mut leaves = state_index
                    .get_leaves(tenant, &bit_prefix(prefix))
                    .await
                    .unwrap_or_else(|err| {
                        panic!("{} StateIndex getLeaves failed: {}", case.id, err)
                    });
                leaves.sort();
                assert_eq!(
                    leaves, *expected,
                    "{} getLeaves {} {}",
                    case.id, tenant, prefix
                );
            }
            StateIndexOperation::GetProtocolLeaves {
                tenant,
                protocol,
                prefix,
                expected,
            } => {
                let mut leaves = state_index
                    .get_protocol_leaves(tenant, protocol, &bit_prefix(prefix))
                    .await
                    .unwrap_or_else(|err| {
                        panic!("{} StateIndex getProtocolLeaves failed: {}", case.id, err)
                    });
                leaves.sort();
                assert_eq!(
                    leaves, *expected,
                    "{} getProtocolLeaves {} {} {}",
                    case.id, tenant, protocol, prefix
                );
            }
        }
    }
}

fn state_index_operations(case: &FixtureCase) -> &[StateIndexOperation] {
    case.operations
        .as_deref()
        .unwrap_or_else(|| panic!("{} must include StateIndex operations", case.id))
}

fn state_index_indexes(
    case: &FixtureCase,
    indexes: &BTreeMap<String, Value>,
) -> dwn_rs_core::MapValue {
    let value = serde_json::to_value(indexes)
        .unwrap_or_else(|err| panic!("{} StateIndex indexes must serialize: {}", case.id, err));
    serde_json::from_value(value)
        .unwrap_or_else(|err| panic!("{} StateIndex indexes must deserialize: {}", case.id, err))
}

fn bit_prefix(prefix: &str) -> Vec<bool> {
    prefix.bytes().map(|byte| byte == b'1').collect()
}

fn state_hash_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_messages_sync_fixture_shape(fixture_set: &FixtureSet, case: &FixtureCase) {
    let sync = messages_sync_fixture(case);
    assert!(
        !sync.tenant.is_empty(),
        "{} MessagesSync tenant must not be empty",
        case.id
    );

    let seed = messages_sync_seed(fixture_set, case, sync);
    assert!(
        !seed.is_empty(),
        "{} MessagesSync seed set must not be empty",
        case.id
    );

    for entry in seed {
        assert!(
            !entry.id.is_empty(),
            "{} MessagesSync seed entry id must not be empty",
            case.id
        );
        assert!(
            !entry.message_cid.is_empty(),
            "{} MessagesSync seed messageCid must not be empty",
            case.id
        );
        assert!(
            !entry.indexes.is_empty(),
            "{} MessagesSync seed indexes must not be empty",
            case.id
        );
        assert_eq!(
            compute_cid(&entry.message),
            entry.message_cid,
            "{} MessagesSync seed {} messageCid",
            case.id,
            entry.id
        );
        assert_messages_sync_seed_data(case, entry);
    }

    let descriptor = messages_sync_descriptor(case, sync);
    assert_eq!(
        descriptor
            .get("interface")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "Messages",
        "{} MessagesSync request interface",
        case.id
    );
    assert_eq!(
        descriptor
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "Sync",
        "{} MessagesSync request method",
        case.id
    );

    match messages_sync_action(case, descriptor) {
        "root" => {}
        "subtree" | "leaves" => assert_bit_prefix(case, messages_sync_prefix(case, descriptor)),
        "diff" => {
            let depth = messages_sync_depth(case, descriptor);
            assert!(
                depth <= 16,
                "{} MessagesSync diff fixture depth must be <= 16 for exhaustive native checking",
                case.id
            );
            for (prefix, hash) in messages_sync_hashes(case, descriptor) {
                assert_bit_prefix(case, prefix);
                assert_state_hash_hex(
                    case,
                    hash.as_str()
                        .unwrap_or_else(|| panic!("{} diff hash must be a string", case.id)),
                );
            }
        }
        action => panic!("{} unsupported MessagesSync action {}", case.id, action),
    }

    assert_eq!(
        sync.reply
            .get("status")
            .and_then(|status| status.get("code"))
            .and_then(Value::as_u64),
        Some(200),
        "{} MessagesSync reply must be a successful reply",
        case.id
    );
}

async fn assert_messages_sync_reply(fixture_set: &FixtureSet, case: &FixtureCase) {
    let sync = messages_sync_fixture(case);
    let seed = messages_sync_seed(fixture_set, case, sync);
    let mut state_index = MemoryStateIndex::default();
    state_index
        .open()
        .await
        .unwrap_or_else(|err| panic!("{} MessagesSync StateIndex open failed: {}", case.id, err));

    for entry in seed {
        state_index
            .insert(
                &sync.tenant,
                &entry.message_cid,
                state_index_indexes(case, &entry.indexes),
            )
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "{} MessagesSync StateIndex seed insert {} failed: {}",
                    case.id, entry.id, err
                )
            });
    }

    let actual = messages_sync_reply(case, &state_index, seed, sync).await;
    assert_eq!(actual, sync.reply, "{} MessagesSync reply", case.id);
}

async fn messages_sync_reply(
    case: &FixtureCase,
    state_index: &MemoryStateIndex,
    seed: &[MessagesSyncSeedEntry],
    sync: &MessagesSyncFixture,
) -> Value {
    let descriptor = messages_sync_descriptor(case, sync);
    let protocol = descriptor.get("protocol").and_then(Value::as_str);

    match messages_sync_action(case, descriptor) {
        "root" => {
            let root = match protocol {
                Some(protocol) => state_index
                    .get_protocol_root(&sync.tenant, protocol)
                    .await
                    .unwrap_or_else(|err| {
                        panic!("{} MessagesSync getProtocolRoot failed: {}", case.id, err)
                    }),
                None => state_index
                    .get_root(&sync.tenant)
                    .await
                    .unwrap_or_else(|err| {
                        panic!("{} MessagesSync getRoot failed: {}", case.id, err)
                    }),
            };
            serde_json::json!({
                "status": { "code": 200, "detail": "OK" },
                "root": state_hash_hex(&root),
            })
        }
        "subtree" => {
            let prefix = bit_prefix(messages_sync_prefix(case, descriptor));
            let hash =
                messages_sync_subtree_hash(case, state_index, &sync.tenant, protocol, &prefix)
                    .await;
            serde_json::json!({
                "status": { "code": 200, "detail": "OK" },
                "hash": hash,
            })
        }
        "leaves" => {
            let prefix = bit_prefix(messages_sync_prefix(case, descriptor));
            let entries =
                messages_sync_leaves(case, state_index, &sync.tenant, protocol, &prefix).await;
            serde_json::json!({
                "status": { "code": 200, "detail": "OK" },
                "entries": entries,
            })
        }
        "diff" => messages_sync_diff_reply(case, state_index, seed, sync, descriptor).await,
        action => panic!("{} unsupported MessagesSync action {}", case.id, action),
    }
}

async fn messages_sync_diff_reply(
    case: &FixtureCase,
    state_index: &MemoryStateIndex,
    seed: &[MessagesSyncSeedEntry],
    sync: &MessagesSyncFixture,
    descriptor: &Value,
) -> Value {
    let protocol = descriptor.get("protocol").and_then(Value::as_str);
    let depth = messages_sync_depth(case, descriptor);
    let client_hashes = messages_sync_hashes(case, descriptor);
    let default_hash = default_messages_sync_hash_hex(depth).await;
    let server_hashes = collect_messages_sync_subtree_hashes(
        case,
        state_index,
        &sync.tenant,
        protocol,
        depth,
        &default_hash,
    )
    .await;

    let mut all_prefixes = BTreeSet::new();
    for (prefix, hash) in client_hashes {
        let hash = hash
            .as_str()
            .unwrap_or_else(|| panic!("{} diff hash must be a string", case.id));
        if hash != default_hash {
            all_prefixes.insert(prefix.clone());
        }
    }
    all_prefixes.extend(server_hashes.keys().cloned());

    let mut only_remote_cids = Vec::new();
    let mut only_local = Vec::new();
    for prefix in all_prefixes {
        let client_hash = client_hashes.get(&prefix).and_then(Value::as_str);
        let server_hash = server_hashes.get(&prefix).map(String::as_str);

        if client_hash == server_hash {
            continue;
        }

        if server_hash.is_none() {
            only_local.push(prefix);
            continue;
        }

        if client_hash.is_none() {
            only_remote_cids.extend(
                messages_sync_leaves(
                    case,
                    state_index,
                    &sync.tenant,
                    protocol,
                    &bit_prefix(&prefix),
                )
                .await,
            );
            continue;
        }

        only_remote_cids.extend(
            messages_sync_leaves(
                case,
                state_index,
                &sync.tenant,
                protocol,
                &bit_prefix(&prefix),
            )
            .await,
        );
        only_local.push(prefix);
    }

    serde_json::json!({
        "status": { "code": 200, "detail": "OK" },
        "onlyRemote": messages_sync_diff_entries(case, seed, &only_remote_cids),
        "onlyLocal": only_local,
    })
}

async fn collect_messages_sync_subtree_hashes(
    case: &FixtureCase,
    state_index: &MemoryStateIndex,
    tenant: &str,
    protocol: Option<&str>,
    depth: usize,
    default_hash: &str,
) -> BTreeMap<String, String> {
    let mut hashes = BTreeMap::new();
    for prefix in bit_prefixes(depth) {
        let hash =
            messages_sync_subtree_hash(case, state_index, tenant, protocol, &bit_prefix(&prefix))
                .await;
        if hash != default_hash {
            hashes.insert(prefix, hash);
        }
    }
    hashes
}

async fn messages_sync_subtree_hash(
    case: &FixtureCase,
    state_index: &MemoryStateIndex,
    tenant: &str,
    protocol: Option<&str>,
    prefix: &[bool],
) -> String {
    let hash = match protocol {
        Some(protocol) => state_index
            .get_protocol_subtree_hash(tenant, protocol, prefix)
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "{} MessagesSync getProtocolSubtreeHash failed: {}",
                    case.id, err
                )
            }),
        None => state_index
            .get_subtree_hash(tenant, prefix)
            .await
            .unwrap_or_else(|err| {
                panic!("{} MessagesSync getSubtreeHash failed: {}", case.id, err)
            }),
    };
    state_hash_hex(&hash)
}

async fn messages_sync_leaves(
    case: &FixtureCase,
    state_index: &MemoryStateIndex,
    tenant: &str,
    protocol: Option<&str>,
    prefix: &[bool],
) -> Vec<String> {
    match protocol {
        Some(protocol) => state_index
            .get_protocol_leaves(tenant, protocol, prefix)
            .await
            .unwrap_or_else(|err| {
                panic!("{} MessagesSync getProtocolLeaves failed: {}", case.id, err)
            }),
        None => state_index
            .get_leaves(tenant, prefix)
            .await
            .unwrap_or_else(|err| panic!("{} MessagesSync getLeaves failed: {}", case.id, err)),
    }
}

async fn default_messages_sync_hash_hex(depth: usize) -> String {
    let mut state_index = MemoryStateIndex::default();
    state_index
        .open()
        .await
        .expect("default MessagesSync StateIndex must open");
    let prefix = vec![false; depth];
    state_hash_hex(
        &state_index
            .get_subtree_hash("did:example:empty", &prefix)
            .await
            .expect("default MessagesSync subtree hash"),
    )
}

fn messages_sync_diff_entries(
    case: &FixtureCase,
    seed: &[MessagesSyncSeedEntry],
    message_cids: &[String],
) -> Vec<Value> {
    let seed_by_cid = seed
        .iter()
        .map(|entry| (entry.message_cid.as_str(), entry))
        .collect::<BTreeMap<_, _>>();

    message_cids
        .iter()
        .map(|message_cid| {
            let entry = seed_by_cid.get(message_cid.as_str()).unwrap_or_else(|| {
                panic!(
                    "{} MessagesSync diff seed missing messageCid {}",
                    case.id, message_cid
                )
            });
            let mut value = serde_json::Map::new();
            value.insert("messageCid".to_string(), Value::String(message_cid.clone()));
            value.insert("message".to_string(), entry.message.clone());
            if let Some(encoded_data) = messages_sync_inline_data(case, entry) {
                value.insert("encodedData".to_string(), Value::String(encoded_data));
            }
            Value::Object(value)
        })
        .collect()
}

fn messages_sync_inline_data(case: &FixtureCase, entry: &MessagesSyncSeedEntry) -> Option<String> {
    if let Some(encoded_data) = &entry.encoded_data {
        return Some(encoded_data.clone());
    }

    let data = entry
        .data
        .as_ref()
        .map(|data| fixture_data_bytes(data, &case.id))?;
    (data.len() <= MAX_INLINE_DATA_SIZE).then(|| URL_SAFE_NO_PAD.encode(data))
}

fn assert_messages_sync_seed_data(case: &FixtureCase, entry: &MessagesSyncSeedEntry) {
    let Some(data) = messages_sync_seed_data(case, entry) else {
        return;
    };

    if let Some(data_size) = messages_sync_descriptor_data_size(&entry.message) {
        assert_eq!(
            data.len(),
            data_size,
            "{} MessagesSync seed {} dataSize",
            case.id,
            entry.id
        );
    }

    if let Some(data_cid) = messages_sync_descriptor_data_cid(&entry.message) {
        assert_eq!(
            generate_dag_pb_cid_from_bytes(&data).to_string(),
            data_cid,
            "{} MessagesSync seed {} dataCid",
            case.id,
            entry.id
        );
    }
}

fn messages_sync_seed_data(case: &FixtureCase, entry: &MessagesSyncSeedEntry) -> Option<Vec<u8>> {
    if let Some(encoded_data) = &entry.encoded_data {
        return Some(URL_SAFE_NO_PAD.decode(encoded_data).unwrap_or_else(|err| {
            panic!(
                "{} MessagesSync seed {} encodedData must be base64url: {}",
                case.id, entry.id, err
            )
        }));
    }

    entry
        .data
        .as_ref()
        .map(|data| fixture_data_bytes(data, &case.id))
}

fn messages_sync_fixture(case: &FixtureCase) -> &MessagesSyncFixture {
    case.sync
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include MessagesSync fixture data", case.id))
}

fn messages_sync_seed<'a>(
    fixture_set: &'a FixtureSet,
    case: &FixtureCase,
    sync: &MessagesSyncFixture,
) -> &'a [MessagesSyncSeedEntry] {
    fixture_set
        .seed_sets
        .as_ref()
        .and_then(|seed_sets| seed_sets.get(&sync.seed_set))
        .map(Vec::as_slice)
        .unwrap_or_else(|| {
            panic!(
                "{} must reference an existing MessagesSync seed set {}",
                case.id, sync.seed_set
            )
        })
}

fn messages_sync_descriptor<'a>(case: &FixtureCase, sync: &'a MessagesSyncFixture) -> &'a Value {
    sync.request
        .get("descriptor")
        .unwrap_or_else(|| panic!("{} MessagesSync request must include descriptor", case.id))
}

fn messages_sync_action<'a>(case: &FixtureCase, descriptor: &'a Value) -> &'a str {
    descriptor
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} MessagesSync descriptor must include action", case.id))
}

fn messages_sync_prefix<'a>(case: &FixtureCase, descriptor: &'a Value) -> &'a str {
    descriptor
        .get("prefix")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} MessagesSync descriptor must include prefix", case.id))
}

fn messages_sync_depth(case: &FixtureCase, descriptor: &Value) -> usize {
    descriptor
        .get("depth")
        .and_then(Value::as_u64)
        .and_then(|depth| usize::try_from(depth).ok())
        .unwrap_or_else(|| {
            panic!(
                "{} MessagesSync diff descriptor must include depth",
                case.id
            )
        })
}

fn messages_sync_hashes<'a>(
    case: &FixtureCase,
    descriptor: &'a Value,
) -> &'a serde_json::Map<String, Value> {
    descriptor
        .get("hashes")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!(
                "{} MessagesSync diff descriptor must include hashes",
                case.id
            )
        })
}

fn messages_sync_descriptor_data_cid(message: &Value) -> Option<&str> {
    message
        .get("descriptor")
        .and_then(|descriptor| descriptor.get("dataCid"))
        .and_then(Value::as_str)
}

fn messages_sync_descriptor_data_size(message: &Value) -> Option<usize> {
    message
        .get("descriptor")
        .and_then(|descriptor| descriptor.get("dataSize"))
        .and_then(Value::as_u64)
        .and_then(|size| usize::try_from(size).ok())
}

fn bit_prefixes(depth: usize) -> Vec<String> {
    if depth == 0 {
        return vec![String::new()];
    }

    (0..(1usize << depth))
        .map(|value| format!("{value:0depth$b}"))
        .collect()
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
    fixture_data_bytes(
        case.data
            .as_ref()
            .unwrap_or_else(|| panic!("{} must include byte data", case.id)),
        &case.id,
    )
}

fn fixture_data_bytes(data: &FixtureData, fixture_id: &str) -> Vec<u8> {
    match data {
        FixtureData::Base64Url { value } => URL_SAFE_NO_PAD
            .decode(value)
            .unwrap_or_else(|err| panic!("{fixture_id} must include valid base64url data: {err}")),
        FixtureData::Hex { value } => decode_hex(value, fixture_id),
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

fn assert_jwe_production_model(case: &FixtureCase) {
    let encryption_value = record(case)
        .get("encryption")
        .unwrap_or_else(|| panic!("{} record must include encryption", case.id));
    let encryption: dwn_rs_core::encryption::Encryption =
        serde_json::from_value(encryption_value.clone())
            .unwrap_or_else(|err| panic!("{} production JWE model decode failed: {err}", case.id));
    assert_eq!(
        serde_json::to_value(&encryption).unwrap(),
        *encryption_value,
        "{} production JWE model roundtrip",
        case.id
    );

    let protected = encryption
        .protected_header()
        .unwrap_or_else(|err| panic!("{} production JWE protected parse failed: {err}", case.id));
    assert_eq!(
        serde_json::to_value(protected).unwrap(),
        serde_json::json!({
            "alg": key_agreement_algorithm(case),
            "enc": content_encryption_algorithm(case),
        }),
        "{} production JWE protected header",
        case.id
    );

    let ciphertext = fixture_value_bytes(case, &case.ciphertext, "ciphertext");
    let private_jwk = fixture_private_jwk_to_jwk(&derived_private_jwk(case).derived_private_key);
    let decrypt_result = encryption.decrypt(&private_jwk, &ciphertext);
    match case.expected_error_code.as_deref() {
        Some(JWE_ERROR_DECRYPT_FAILED) => assert!(
            decrypt_result.is_err(),
            "{} production JWE decrypt must fail",
            case.id
        ),
        Some(error_code) => panic!("{} unsupported JWE error code {}", case.id, error_code),
        None => assert_eq!(
            decrypt_result
                .unwrap_or_else(|err| panic!("{} production JWE decrypt failed: {err}", case.id)),
            fixture_value_bytes(case, &case.plaintext, "plaintext"),
            "{} production JWE decrypt",
            case.id
        ),
    }
}

fn assert_jwe_protected_header(case: &FixtureCase) {
    let protected = decode_base64url(&jwe(case).protected, &case.id, "JWE protected header");
    let header: FixtureJweProtectedHeader =
        serde_json::from_slice(&protected).unwrap_or_else(|err| {
            panic!(
                "{} must include a valid JWE protected header: {}",
                case.id, err
            )
        });

    assert_eq!(
        header.alg,
        key_agreement_algorithm(case),
        "{} JWE alg",
        case.id
    );
    assert_eq!(
        header.enc,
        content_encryption_algorithm(case),
        "{} JWE enc",
        case.id
    );

    let expected_protected = format!(
        "{{\"alg\":{},\"enc\":{}}}",
        serde_json::to_string(key_agreement_algorithm(case)).expect("alg must serialize"),
        serde_json::to_string(content_encryption_algorithm(case)).expect("enc must serialize")
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(expected_protected.as_bytes()),
        jwe(case).protected,
        "{} protected header encoding",
        case.id
    );
}

fn assert_jwe_aead(case: &FixtureCase) {
    let cek = fixture_value_bytes(case, &case.cek, "CEK");
    let iv = fixture_value_bytes(case, &case.iv, "IV");
    let plaintext = fixture_value_bytes(case, &case.plaintext, "plaintext");
    let (ciphertext, tag) =
        jwe_aead_encrypt(content_encryption_algorithm(case), &cek, &iv, &plaintext)
            .unwrap_or_else(|err| panic!("{} AEAD encrypt failed: {}", case.id, err));

    assert_eq!(
        URL_SAFE_NO_PAD.encode(&ciphertext),
        fixture_value_base64url(case, &case.ciphertext, "ciphertext"),
        "{} ciphertext",
        case.id
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(&tag),
        fixture_value_base64url(case, &case.tag, "tag"),
        "{} tag",
        case.id
    );

    let decrypted = jwe_aead_decrypt(
        content_encryption_algorithm(case),
        &cek,
        &iv,
        &ciphertext,
        &tag,
    )
    .unwrap_or_else(|err| panic!("{} AEAD decrypt failed: {}", case.id, err));
    assert_eq!(decrypted, plaintext, "{} plaintext", case.id);
}

fn assert_jwe_keywrap(case: &FixtureCase) {
    let recipient = single_jwe_recipient(case);
    let cek = fixture_value_bytes(case, &case.cek, "CEK");
    let wrapped = ecdh_es_wrap_key(
        ephemeral_private_jwk(case),
        recipient_public_jwk(case),
        &cek,
    )
    .unwrap_or_else(|err| panic!("{} ECDH-ES wrap failed: {}", case.id, err));

    assert_eq!(
        URL_SAFE_NO_PAD.encode(&wrapped),
        recipient.encrypted_key,
        "{} encrypted_key",
        case.id
    );
    assert_eq!(
        recipient.header.epk.x,
        ephemeral_public_jwk(case).x,
        "{} ephemeral public key",
        case.id
    );
    match derivation_scheme(case) {
        "protocolContext" => assert_eq!(
            recipient
                .header
                .derived_public_key
                .as_ref()
                .unwrap_or_else(|| panic!("{} must include derivedPublicKey", case.id))
                .x,
            recipient_public_jwk(case).x,
            "{} derived public key",
            case.id
        ),
        _ => assert!(
            recipient.header.derived_public_key.is_none(),
            "{} must not include derivedPublicKey",
            case.id
        ),
    }

    let unwrapped =
        ecdh_es_unwrap_key(recipient_private_jwk(case), &recipient.header.epk, &wrapped)
            .unwrap_or_else(|err| panic!("{} ECDH-ES unwrap failed: {}", case.id, err));
    assert_eq!(unwrapped, cek, "{} unwrapped CEK", case.id);
}

fn assert_jwe_decrypt(case: &FixtureCase) {
    let decrypt_result = decrypt_jwe_case(case);

    match case.expected_error_code.as_deref() {
        Some(JWE_ERROR_DECRYPT_FAILED) => assert!(
            decrypt_result.is_err(),
            "{} must fail JWE decryption",
            case.id
        ),
        Some(error_code) => panic!("{} unsupported JWE error code {}", case.id, error_code),
        None => assert_eq!(
            decrypt_result.unwrap_or_else(|err| panic!("{} JWE decrypt failed: {}", case.id, err)),
            fixture_value_bytes(case, &case.plaintext, "plaintext"),
            "{} decrypted plaintext",
            case.id
        ),
    }
}

fn decrypt_jwe_case(case: &FixtureCase) -> Result<Vec<u8>, String> {
    let recipient = single_jwe_recipient(case);
    let derived_private_jwk = derived_private_jwk(case);

    assert_eq!(
        recipient.header.kid, derived_private_jwk.root_key_id,
        "{} recipient kid",
        case.id
    );
    assert_eq!(
        recipient.header.derivation_scheme, derived_private_jwk.derivation_scheme,
        "{} recipient derivationScheme",
        case.id
    );
    assert_eq!(
        construct_jwe_derivation_path(case),
        derived_private_jwk.derivation_path,
        "{} derivation path",
        case.id
    );

    let encrypted_key = decode_base64url(&recipient.encrypted_key, &case.id, "encrypted_key");
    let cek = ecdh_es_unwrap_key(
        &derived_private_jwk.derived_private_key,
        &recipient.header.epk,
        &encrypted_key,
    )?;
    assert_eq!(
        cek,
        fixture_value_bytes(case, &case.cek, "CEK"),
        "{} unwrapped decrypt CEK",
        case.id
    );

    jwe_aead_decrypt(
        content_encryption_algorithm(case),
        &cek,
        &decode_base64url(&jwe(case).iv, &case.id, "JWE IV"),
        &fixture_value_bytes(case, &case.ciphertext, "ciphertext"),
        &decode_base64url(&jwe(case).tag, &case.id, "JWE tag"),
    )
}

fn jwe_aead_encrypt(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    match algorithm {
        "A256GCM" => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|err| err.to_string())?;
            let mut ciphertext = plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(AesGcmNonce::from_slice(iv), b"", &mut ciphertext)
                .map_err(|err| err.to_string())?;

            Ok((ciphertext, tag.to_vec()))
        }
        "XC20P" => {
            let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|err| err.to_string())?;
            let mut ciphertext = plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(XNonce::from_slice(iv), b"", &mut ciphertext)
                .map_err(|err| err.to_string())?;

            Ok((ciphertext, tag.to_vec()))
        }
        _ => Err(format!(
            "unsupported content encryption algorithm {algorithm}"
        )),
    }
}

fn jwe_aead_decrypt(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, String> {
    match algorithm {
        "A256GCM" => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|err| err.to_string())?;
            let mut plaintext = ciphertext.to_vec();
            cipher
                .decrypt_in_place_detached(
                    AesGcmNonce::from_slice(iv),
                    b"",
                    &mut plaintext,
                    AesGcmTag::from_slice(tag),
                )
                .map_err(|err| err.to_string())?;

            Ok(plaintext)
        }
        "XC20P" => {
            let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|err| err.to_string())?;
            let mut plaintext = ciphertext.to_vec();
            cipher
                .decrypt_in_place_detached(
                    XNonce::from_slice(iv),
                    b"",
                    &mut plaintext,
                    XChaCha20Poly1305Tag::from_slice(tag),
                )
                .map_err(|err| err.to_string())?;

            Ok(plaintext)
        }
        _ => Err(format!(
            "unsupported content encryption algorithm {algorithm}"
        )),
    }
}

fn ecdh_es_wrap_key(
    ephemeral_private_jwk: &FixtureX25519PrivateJwk,
    recipient_public_jwk: &FixtureX25519PublicJwk,
    cek: &[u8],
) -> Result<Vec<u8>, String> {
    let shared_secret = x25519_shared_secret(ephemeral_private_jwk, recipient_public_jwk)?;
    let kek = concat_kdf_a256kw(&shared_secret);
    aes_key_wrap(&kek, cek)
}

fn ecdh_es_unwrap_key(
    recipient_private_jwk: &FixtureX25519PrivateJwk,
    ephemeral_public_jwk: &FixtureX25519PublicJwk,
    wrapped_key: &[u8],
) -> Result<Vec<u8>, String> {
    let shared_secret = x25519_shared_secret(recipient_private_jwk, ephemeral_public_jwk)?;
    let kek = concat_kdf_a256kw(&shared_secret);
    aes_key_unwrap(&kek, wrapped_key)
}

fn x25519_shared_secret(
    private_jwk: &FixtureX25519PrivateJwk,
    public_jwk: &FixtureX25519PublicJwk,
) -> Result<Vec<u8>, String> {
    assert_x25519_private_jwk(private_jwk);
    assert_x25519_public_jwk(public_jwk);

    let private_key = decode_base64url(&private_jwk.d, "JWE", "X25519 private key");
    let public_key = decode_base64url(&public_jwk.x, "JWE", "X25519 public key");
    let private_key: [u8; 32] = private_key
        .try_into()
        .map_err(|_| "X25519 private key must be 32 bytes".to_string())?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "X25519 public key must be 32 bytes".to_string())?;

    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(public_key);
    Ok(secret.diffie_hellman(&public).as_bytes().to_vec())
}

fn concat_kdf_a256kw(shared_secret: &[u8]) -> Vec<u8> {
    let mut fixed_info = Vec::new();
    append_length_prefixed(&mut fixed_info, b"A256KW");
    append_length_prefixed(&mut fixed_info, b"");
    append_length_prefixed(&mut fixed_info, b"");
    fixed_info.extend_from_slice(&256u32.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(1u32.to_be_bytes());
    hasher.update(shared_secret);
    hasher.update(fixed_info);
    hasher.finalize()[..32].to_vec()
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn aes_key_wrap(kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.len() < 16 || plaintext.len() % 8 != 0 {
        return Err("AES-KW plaintext must be at least 16 bytes and 64-bit aligned".to_string());
    }

    let cipher = aes::Aes256::new_from_slice(kek).map_err(|err| err.to_string())?;
    let n = plaintext.len() / 8;
    let mut a = [0xa6; 8];
    let mut r = plaintext
        .chunks_exact(8)
        .map(|chunk| {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            block
        })
        .collect::<Vec<_>>();

    for j in 0..6 {
        for (i, block) in r.iter_mut().enumerate() {
            let mut input = [0u8; 16];
            input[..8].copy_from_slice(&a);
            input[8..].copy_from_slice(block);

            let mut encrypted = GenericArray::clone_from_slice(&input);
            cipher.encrypt_block(&mut encrypted);

            a.copy_from_slice(&encrypted[..8]);
            xor_aes_kw_counter(&mut a, (n * j + i + 1) as u64);
            block.copy_from_slice(&encrypted[8..]);
        }
    }

    let mut wrapped = Vec::with_capacity(8 + plaintext.len());
    wrapped.extend_from_slice(&a);
    for block in r {
        wrapped.extend_from_slice(&block);
    }

    Ok(wrapped)
}

fn aes_key_unwrap(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, String> {
    if wrapped_key.len() < 24 || wrapped_key.len() % 8 != 0 {
        return Err("AES-KW ciphertext must be at least 24 bytes and 64-bit aligned".to_string());
    }

    let cipher = aes::Aes256::new_from_slice(kek).map_err(|err| err.to_string())?;
    let n = wrapped_key.len() / 8 - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped_key[..8]);
    let mut r = wrapped_key[8..]
        .chunks_exact(8)
        .map(|chunk| {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            block
        })
        .collect::<Vec<_>>();

    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let mut block_a = a;
            xor_aes_kw_counter(&mut block_a, (n * j + i + 1) as u64);

            let mut input = [0u8; 16];
            input[..8].copy_from_slice(&block_a);
            input[8..].copy_from_slice(&r[i]);

            let mut decrypted = GenericArray::clone_from_slice(&input);
            cipher.decrypt_block(&mut decrypted);

            a.copy_from_slice(&decrypted[..8]);
            r[i].copy_from_slice(&decrypted[8..]);
        }
    }

    if a != [0xa6; 8] {
        return Err("AES-KW integrity check failed".to_string());
    }

    let mut plaintext = Vec::with_capacity(wrapped_key.len() - 8);
    for block in r {
        plaintext.extend_from_slice(&block);
    }

    Ok(plaintext)
}

fn xor_aes_kw_counter(a: &mut [u8; 8], counter: u64) {
    for (left, right) in a.iter_mut().zip(counter.to_be_bytes()) {
        *left ^= right;
    }
}

fn construct_jwe_derivation_path(case: &FixtureCase) -> Vec<String> {
    let record = record(case);
    let descriptor = record
        .get("descriptor")
        .unwrap_or_else(|| panic!("{} JWE record must include descriptor", case.id));

    match derivation_scheme(case) {
        "protocolPath" => {
            let protocol = descriptor
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{} descriptor must include protocol", case.id));
            let protocol_path = descriptor
                .get("protocolPath")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{} descriptor must include protocolPath", case.id));
            let mut path = vec!["protocolPath".to_string(), protocol.to_string()];
            path.extend(protocol_path.split('/').map(str::to_string));
            path
        }
        "protocolContext" => {
            let context_id = record
                .get("contextId")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{} JWE record must include contextId", case.id));
            vec![
                "protocolContext".to_string(),
                context_id
                    .split('/')
                    .next()
                    .expect("split always returns one item")
                    .to_string(),
            ]
        }
        scheme => panic!("{} unsupported derivation scheme {}", case.id, scheme),
    }
}

fn assert_x25519_public_jwk(jwk: &FixtureX25519PublicJwk) {
    assert_eq!(jwk.kty, "OKP", "X25519 public JWK kty");
    assert_eq!(jwk.crv, "X25519", "X25519 public JWK crv");
    assert_eq!(
        decode_base64url(&jwk.x, "JWE", "X25519 public key").len(),
        32,
        "X25519 public key length"
    );
    assert!(jwk.kid.as_deref().unwrap_or_default().len() <= 128);
}

fn assert_x25519_private_jwk(jwk: &FixtureX25519PrivateJwk) {
    assert_eq!(jwk.kty, "OKP", "X25519 private JWK kty");
    assert_eq!(jwk.crv, "X25519", "X25519 private JWK crv");
    assert_eq!(
        decode_base64url(&jwk.d, "JWE", "X25519 private key").len(),
        32,
        "X25519 private key length"
    );
    assert_eq!(
        decode_base64url(&jwk.x, "JWE", "X25519 private public key").len(),
        32,
        "X25519 private public key length"
    );
    assert!(jwk.kid.as_deref().unwrap_or_default().len() <= 128);
}

fn fixture_value_bytes(case: &FixtureCase, data: &Option<FixtureData>, label: &str) -> Vec<u8> {
    match data
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include {}", case.id, label))
    {
        FixtureData::Base64Url { value } => URL_SAFE_NO_PAD.decode(value).unwrap_or_else(|err| {
            panic!(
                "{} must include valid base64url {}: {}",
                case.id, label, err
            )
        }),
        FixtureData::Hex { value } => decode_hex(value, &case.id),
        FixtureData::RepeatByte { byte, length } => vec![*byte; *length],
        FixtureData::Utf8 { value } => value.as_bytes().to_vec(),
    }
}

fn fixture_value_base64url(case: &FixtureCase, data: &Option<FixtureData>, label: &str) -> String {
    URL_SAFE_NO_PAD.encode(fixture_value_bytes(case, data, label))
}

fn assert_general_jws_signing(fixture_set: &FixtureSet, case: &FixtureCase) {
    let actual = GeneralJws::create(&jws_payload_bytes(case), &signing_keys(fixture_set, case))
        .unwrap_or_else(|err| panic!("{} General JWS signing failed: {}", case.id, err));

    assert_eq!(actual, *jws(case), "{}", case.id);
}

fn verify_general_jws(
    fixture_set: &FixtureSet,
    case: &FixtureCase,
) -> Result<Vec<String>, &'static str> {
    let resolver = public_key_resolver(fixture_set, case);
    jws(case)
        .verify_signatures(&resolver)
        .map_err(|err| err.code())
}

fn signing_keys(fixture_set: &FixtureSet, case: &FixtureCase) -> Vec<PrivateJwkSigner> {
    signer_ids(case)
        .iter()
        .map(|signer_id| {
            let key = fixture_jws_key(fixture_set, case, signer_id);
            let private_jwk = key.private_jwk.clone().unwrap_or_else(|| {
                panic!("{} signer {} must include a privateJwk", case.id, signer_id)
            });

            PrivateJwkSigner::new(key.kid.clone(), key.algorithm.clone(), private_jwk)
        })
        .collect()
}

fn public_key_resolver(fixture_set: &FixtureSet, case: &FixtureCase) -> StaticPublicKeyResolver {
    let public_keys = signer_ids(case)
        .iter()
        .map(|signer_id| {
            let key = fixture_jws_key(fixture_set, case, signer_id);
            (key.kid.clone(), key.public_jwk.clone())
        })
        .collect();

    StaticPublicKeyResolver::new(public_keys)
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

fn jws(case: &FixtureCase) -> &GeneralJws {
    case.jws
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include a JWS", case.id))
}

fn jwe(case: &FixtureCase) -> &FixtureJwe {
    case.jwe
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include a JWE", case.id))
}

fn single_jwe_recipient(case: &FixtureCase) -> &FixtureJweRecipient {
    let recipients = &jwe(case).recipients;
    assert_eq!(recipients.len(), 1, "{} JWE recipient count", case.id);
    &recipients[0]
}

fn recipient_private_jwk(case: &FixtureCase) -> &FixtureX25519PrivateJwk {
    case.recipient_private_jwk
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include recipientPrivateJwk", case.id))
}

fn recipient_public_jwk(case: &FixtureCase) -> &FixtureX25519PublicJwk {
    case.recipient_public_jwk
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include recipientPublicJwk", case.id))
}

fn ephemeral_private_jwk(case: &FixtureCase) -> &FixtureX25519PrivateJwk {
    case.ephemeral_private_jwk
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include ephemeralPrivateJwk", case.id))
}

fn ephemeral_public_jwk(case: &FixtureCase) -> &FixtureX25519PublicJwk {
    case.ephemeral_public_jwk
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include ephemeralPublicJwk", case.id))
}

fn derived_private_jwk(case: &FixtureCase) -> &FixtureDerivedPrivateJwk {
    case.derived_private_jwk
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include derivedPrivateJwk", case.id))
}

fn key_agreement_algorithm(case: &FixtureCase) -> &str {
    case.key_agreement_algorithm
        .as_deref()
        .unwrap_or_else(|| panic!("{} must include keyAgreementAlgorithm", case.id))
}

fn content_encryption_algorithm(case: &FixtureCase) -> &str {
    case.content_encryption_algorithm
        .as_deref()
        .unwrap_or_else(|| panic!("{} must include contentEncryptionAlgorithm", case.id))
}

fn derivation_scheme(case: &FixtureCase) -> &str {
    case.derivation_scheme
        .as_deref()
        .unwrap_or_else(|| panic!("{} must include derivationScheme", case.id))
}

fn record(case: &FixtureCase) -> &Value {
    case.record
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include a record", case.id))
}

fn fixture_private_jwk_to_jwk(jwk: &FixtureX25519PrivateJwk) -> ssi_jwk::JWK {
    let mut value = serde_json::json!({
        "kty": jwk.kty.clone(),
        "crv": jwk.crv.clone(),
        "d": jwk.d.clone(),
        "x": jwk.x.clone(),
    });
    if let Some(kid) = &jwk.kid {
        value
            .as_object_mut()
            .expect("private JWK must be an object")
            .insert("kid".to_string(), Value::String(kid.clone()));
    }
    serde_json::from_value(value).expect("fixture private JWK must deserialize")
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
