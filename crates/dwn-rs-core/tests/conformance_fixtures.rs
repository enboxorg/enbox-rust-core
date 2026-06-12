use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, Nonce as AesGcmNonce, Tag as AesGcmTag};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use chacha20poly1305::{Tag as XChaCha20Poly1305Tag, XChaCha20Poly1305, XNonce};
use dwn_rs_core::auth::{
    Jws, JwsPrivateJwk, JwsPublicJwk, JwsPublicKeyResolver, JwsSignature, PrivateJwkSigner,
    StaticPublicKeyResolver, UniversalResolver,
};
use dwn_rs_core::cid::{
    generate_cid_from_json, generate_dag_pb_cid_from_bytes, generate_dag_pb_cid_from_stream,
};
use dwn_rs_core::descriptors::{
    ConfigureDescriptor, DeleteDescriptor, MessagesQueryDescriptor, MessagesReadDescriptor,
    MessagesSubscribeDescriptor, MessagesSyncDescriptor, ProtocolQueryDescriptor, ReadDescriptor,
    RecordsCountDescriptor, RecordsQueryDescriptor, RecordsWriteDescriptor,
    SubscribeDescriptor as RecordsSubscribeDescriptor,
};
use dwn_rs_core::dwn::{
    current_handler_kinds, Dwn, DwnReply, MessageKind, MethodHandler, MethodHandlerRequest,
};
use dwn_rs_core::interfaces::messages::protocols as protocol_types;
use dwn_rs_core::message_validation;
use dwn_rs_core::state_index::MemoryStateIndex;
use dwn_rs_core::stores::StateIndex;
use dwn_rs_stores::SqliteNativeDwn;
use futures_util::stream;
use k256::sha2::{Digest, Sha256};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

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
const MESSAGE_PROCESS_ASSERTION: &str = "message.process";
const PROTOCOL_AUTHORIZATION_CORPUS_ASSERTION: &str = "protocol.authorization-corpus";
const DESCRIPTOR_ROUNDTRIP_ASSERTION: &str = "descriptor.roundtrip";

mod conformance_helpers;
use conformance_helpers::read_fixture;

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
    jws: Option<Jws>,
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
    process: Option<MessageProcessFixture>,
    protocol_authorization: Option<ProtocolAuthorizationFixture>,
    grant_authorization: Option<GrantAuthorizationFixture>,
    sync: Option<MessagesSyncFixture>,
    value: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageProcessFixture {
    tenant: String,
    handler: Option<String>,
    valid: bool,
    #[serde(default)]
    register_handler: bool,
    #[serde(default)]
    stub_reply: bool,
    reply: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProtocolAuthorizationFixture {
    directives: Vec<String>,
    definition: Value,
    expected_status_code: u16,
    expected_error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantAuthorizationFixture {
    grant_id: String,
    grantor: String,
    grantee: String,
    delegated: bool,
    revoked: Option<bool>,
    revocation_id: Option<String>,
    revoked_at: Option<String>,
    date_granted: Option<String>,
    date_expires: Option<String>,
    message_timestamp: Option<String>,
    scope: GrantScopeFixture,
    conditions: Option<Value>,
    incoming_message: Value,
    expected_status_code: u16,
    expected_error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantScopeFixture {
    interface: String,
    method: String,
    protocol: Option<String>,
    protocol_path: Option<String>,
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
    public_jwk: JwsPublicJwk,
    private_jwk: Option<JwsPrivateJwk>,
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
async fn fixture_messages_route_through_dwn_dispatch() {
    let mut dwn = Dwn::default();
    let current_kinds = current_handler_kinds();
    for kind in current_kinds.clone() {
        dwn.register_handler(kind, RouteEchoHandler);
    }

    let mut routed = 0usize;
    for suite in load_fixture_suites() {
        for case in &suite.fixture_set.cases {
            let Some(message) = &case.message else {
                continue;
            };
            let kind = match MessageKind::from_message(message) {
                Ok(kind) => kind,
                Err(_)
                    if case
                        .process
                        .as_ref()
                        .is_some_and(|process| !process.register_handler) =>
                {
                    continue;
                }
                Err(err) => panic!("{} fixture message must have route: {err:?}", case.id),
            };
            if !current_kinds.contains(&kind) {
                continue;
            }
            if message_validation::validate_message(message).is_err() {
                continue;
            }

            let reply = dwn
                .process_message("did:example:alice", message.clone())
                .await;
            assert_eq!(reply.status.code, 200, "{} route status", case.id);
            assert_eq!(
                reply.body.get("handler"),
                Some(&Value::String(kind.handler_key())),
                "{} route handler",
                case.id
            );
            routed += 1;
        }
    }

    assert!(routed > 0, "at least one fixture message must route");
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
                    Some(URL_SAFE_NO_PAD.encode(jws_payload_bytes(case))),
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

#[tokio::test]
async fn fixture_process_replies_are_measurable_by_handler() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(MESSAGE_PROCESS_ASSERTION) {
            continue;
        }

        let expected_handlers = current_handler_keys();
        let mut valid_handlers = BTreeSet::new();
        let mut invalid_handlers = BTreeSet::new();

        for case in &suite.fixture_set.cases {
            assert_message_process_fixture_shape(case);
            let process = message_process_fixture(case);
            if let Some(handler) = &process.handler {
                if process.valid {
                    valid_handlers.insert(handler.clone());
                } else {
                    invalid_handlers.insert(handler.clone());
                }
            }

            if case.rust_status == RustStatus::Supported {
                assert_message_process_reply(case).await;
            }
        }

        assert_handler_coverage(
            &suite.suite_ref.id,
            "valid",
            &expected_handlers,
            &valid_handlers,
        );
        assert_handler_coverage(
            &suite.suite_ref.id,
            "invalid",
            &expected_handlers,
            &invalid_handlers,
        );
    }
}

#[test]
fn fixture_protocol_authorization_corpus_matches_expected_validation() {
    for suite in load_fixture_suites() {
        if !suite.has_assertion(PROTOCOL_AUTHORIZATION_CORPUS_ASSERTION) {
            continue;
        }

        let mut directives = BTreeSet::new();
        let mut grant_interfaces = BTreeSet::new();
        let mut grant_behavior_set = BTreeSet::new();
        let mut valid_protocol_cases = 0usize;
        let mut invalid_protocol_cases = 0usize;

        for case in &suite.fixture_set.cases {
            if let Some(protocol) = &case.protocol_authorization {
                assert_protocol_authorization_fixture(case, protocol);
                directives.extend(protocol.directives.iter().cloned());
                if protocol.expected_status_code < 400 {
                    valid_protocol_cases += 1;
                } else {
                    invalid_protocol_cases += 1;
                }
            }

            if let Some(grant) = &case.grant_authorization {
                assert_grant_authorization_fixture(case, grant);
                grant_interfaces.insert(grant.scope.interface.clone());
                grant_behavior_set.extend(grant_behaviors(case, grant));
            }
        }

        assert_protocol_directive_coverage(&suite.suite_ref.id, &directives);
        assert!(
            valid_protocol_cases > 0,
            "{} must include valid protocol cases",
            suite.suite_ref.id
        );
        assert!(
            invalid_protocol_cases > 0,
            "{} must include invalid protocol cases",
            suite.suite_ref.id
        );
        assert_grant_scope_coverage(&suite.suite_ref.id, &grant_interfaces);
        assert_grant_behavior_coverage(&suite.suite_ref.id, &grant_behavior_set);
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
    read_fixture(path)
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

#[derive(Clone, Copy)]
struct RouteEchoHandler;

impl MethodHandler for RouteEchoHandler {
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        let handler_key = request.kind.handler_key();
        Box::pin(async move { DwnReply::ok().with_body("handler", Value::String(handler_key)) })
    }
}

#[derive(Clone)]
struct FixtureReplyHandler {
    reply: DwnReply,
}

impl MethodHandler for FixtureReplyHandler {
    fn handle<'a>(
        &'a self,
        _request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        let reply = self.reply.clone();
        Box::pin(async move { reply })
    }
}

fn assert_message_process_fixture_shape(case: &FixtureCase) {
    let process = message_process_fixture(case);
    assert!(
        !process.tenant.is_empty(),
        "{} process tenant must not be empty",
        case.id
    );
    if let Some(handler) = &process.handler {
        assert!(
            !handler.is_empty(),
            "{} process handler must not be empty",
            case.id
        );
    }
    assert!(
        process.reply.get("status").is_some(),
        "{} process reply must include status",
        case.id
    );
    assert!(
        process
            .reply
            .get("status")
            .and_then(|status| status.get("code"))
            .and_then(Value::as_u64)
            .is_some(),
        "{} process reply status.code must be numeric",
        case.id
    );
    assert!(
        process
            .reply
            .get("status")
            .and_then(|status| status.get("detail"))
            .and_then(Value::as_str)
            .is_some(),
        "{} process reply status.detail must be a string",
        case.id
    );
}

async fn assert_message_process_reply(case: &FixtureCase) {
    let process = message_process_fixture(case);
    let raw_message = message(case).clone();
    let mut node = SqliteNativeDwn::open_in_memory(conformance_process_resolver())
        .await
        .unwrap_or_else(|err| panic!("{} failed to open SqliteNativeDwn: {err}", case.id));

    if let Err(schema_error) = message_validation::validate_message(&raw_message) {
        let reply = node
            .dwn()
            .process_message(&process.tenant, raw_message)
            .await;
        assert_eq!(
            reply.status.code, 400,
            "{} schema validation status",
            case.id
        );
        assert_eq!(
            reply.status.detail,
            schema_error.to_string(),
            "{} schema validation detail",
            case.id
        );
        return;
    }

    if process.register_handler || process.stub_reply {
        let kind = MessageKind::from_message(message(case)).unwrap_or_else(|err| {
            panic!(
                "{} process fixture with registerHandler/stubReply must route: {err:?}",
                case.id
            )
        });
        if let Some(handler) = &process.handler {
            assert_eq!(
                kind.handler_key(),
                *handler,
                "{} process handler key",
                case.id
            );
        }
        node.dwn_mut().register_handler(
            kind,
            FixtureReplyHandler {
                reply: process_reply(case),
            },
        );
    }

    let reply = node
        .dwn()
        .process_message(&process.tenant, raw_message)
        .await;
    assert_eq!(
        serde_json::to_value(reply).expect("DwnReply must serialize"),
        process.reply,
        "{} process reply",
        case.id
    );
}

fn conformance_process_resolver() -> StaticPublicKeyResolver {
    StaticPublicKeyResolver::new(BTreeMap::new())
}

fn assert_handler_coverage(
    suite_id: &str,
    label: &str,
    expected_handlers: &BTreeSet<String>,
    actual_handlers: &BTreeSet<String>,
) {
    let missing = expected_handlers
        .difference(actual_handlers)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{} missing {} process fixtures for handlers: {:?}",
        suite_id,
        label,
        missing
    );
}

fn current_handler_keys() -> BTreeSet<String> {
    current_handler_kinds()
        .into_iter()
        .map(|kind| kind.handler_key())
        .collect()
}

fn message_process_fixture(case: &FixtureCase) -> &MessageProcessFixture {
    case.process
        .as_ref()
        .unwrap_or_else(|| panic!("{} must include process fixture", case.id))
}

fn process_reply(case: &FixtureCase) -> DwnReply {
    serde_json::from_value(message_process_fixture(case).reply.clone())
        .unwrap_or_else(|err| panic!("{} process reply must deserialize: {}", case.id, err))
}

fn assert_protocol_authorization_fixture(
    case: &FixtureCase,
    protocol: &ProtocolAuthorizationFixture,
) {
    assert!(
        !protocol.directives.is_empty(),
        "{} protocol directives must not be empty",
        case.id
    );
    assert!(
        matches!(protocol.expected_status_code, 200..=299 | 400..=499),
        "{} protocol expectedStatusCode must be explicit",
        case.id
    );

    let definition: protocol_types::Definition =
        serde_json::from_value(protocol.definition.clone()).unwrap_or_else(|err| {
            panic!("{} protocol definition must deserialize: {}", case.id, err)
        });
    let validation = protocol_types::validate_definition(&definition);

    if protocol.expected_status_code < 400 {
        validation.unwrap_or_else(|err| {
            panic!(
                "{} protocol definition should validate, got {}",
                case.id, err
            )
        });
    } else {
        let err = match validation {
            Ok(()) => panic!(
                "{} protocol definition should fail with {:?}",
                case.id, protocol.expected_error_code
            ),
            Err(err) => err,
        };
        if let Some(expected_error_code) = &protocol.expected_error_code {
            assert_eq!(
                err.code,
                expected_error_code.as_str(),
                "{} protocol error",
                case.id
            );
        }
    }
}

fn assert_grant_authorization_fixture(case: &FixtureCase, grant: &GrantAuthorizationFixture) {
    assert!(!grant.grant_id.is_empty(), "{} grantId", case.id);
    assert!(!grant.grantor.is_empty(), "{} grantor", case.id);
    assert!(!grant.grantee.is_empty(), "{} grantee", case.id);
    assert!(
        matches!(
            grant.scope.interface.as_str(),
            "Records" | "Protocols" | "Messages"
        ),
        "{} grant scope interface must be a DWN interface",
        case.id
    );
    assert!(
        !grant.scope.method.is_empty(),
        "{} grant scope method must not be empty",
        case.id
    );
    assert!(
        grant.incoming_message.get("interface").is_some(),
        "{} incomingMessage.interface must be present",
        case.id
    );
    assert!(
        grant.incoming_message.get("method").is_some(),
        "{} incomingMessage.method must be present",
        case.id
    );
    assert!(
        matches!(grant.expected_status_code, 200..=299 | 400..=499),
        "{} grant expectedStatusCode must be explicit",
        case.id
    );
    if grant.expected_status_code >= 400 {
        assert!(
            grant.expected_error_code.is_some(),
            "{} rejected grant cases must include expectedErrorCode",
            case.id
        );
    }
    if grant.revoked == Some(true) {
        assert!(
            grant
                .revocation_id
                .as_ref()
                .is_some_and(|value| !value.is_empty()),
            "{} revoked grant cases must include revocationId",
            case.id
        );
        assert!(
            grant
                .revoked_at
                .as_ref()
                .is_some_and(|value| !value.is_empty()),
            "{} revoked grant cases must include revokedAt",
            case.id
        );
    }
    if grant.date_expires.is_some() {
        assert!(
            grant
                .message_timestamp
                .as_ref()
                .is_some_and(|value| !value.is_empty()),
            "{} expiry cases must include messageTimestamp",
            case.id
        );
    }
    match evaluate_grant_authorization_fixture(case, grant) {
        Ok(()) => assert!(
            grant.expected_status_code < 400,
            "{} grant fixture should have failed with {:?}",
            case.id,
            grant.expected_error_code
        ),
        Err(actual_error_code) => {
            assert!(
                grant.expected_status_code >= 400,
                "{} grant fixture failed unexpectedly with {}",
                case.id,
                actual_error_code
            );
            assert_eq!(
                Some(actual_error_code.as_str()),
                grant.expected_error_code.as_deref(),
                "{} grant error",
                case.id
            );
        }
    }
}

fn evaluate_grant_authorization_fixture(
    case: &FixtureCase,
    grant: &GrantAuthorizationFixture,
) -> Result<(), String> {
    let incoming_timestamp = grant_timestamp(
        case,
        grant
            .message_timestamp
            .as_deref()
            .unwrap_or("2025-01-01T12:00:00.000000Z"),
        "messageTimestamp",
    );
    let date_granted = grant_timestamp(
        case,
        grant
            .date_granted
            .as_deref()
            .unwrap_or("2025-01-01T00:00:00.000000Z"),
        "dateGranted",
    );
    let date_expires = grant_timestamp(
        case,
        grant
            .date_expires
            .as_deref()
            .unwrap_or("2026-01-01T00:00:00.000000Z"),
        "dateExpires",
    );

    if incoming_timestamp < date_granted {
        return Err("GrantAuthorizationGrantNotYetActive".to_string());
    }
    if incoming_timestamp >= date_expires {
        return Err("GrantAuthorizationGrantExpired".to_string());
    }
    if grant.revoked == Some(true) {
        let revoked_at = grant_timestamp(
            case,
            grant.revoked_at.as_deref().unwrap_or_default(),
            "revokedAt",
        );
        if revoked_at <= incoming_timestamp {
            return Err("GrantAuthorizationGrantRevoked".to_string());
        }
    }

    let incoming_interface = incoming_message_str(case, grant, "interface");
    let incoming_method = incoming_message_str(case, grant, "method");
    if incoming_interface != grant.scope.interface {
        return Err("GrantAuthorizationInterfaceMismatch".to_string());
    }
    if grant.scope.interface == "Messages" {
        if grant.scope.method != "Read" || !matches!(incoming_method, "Read" | "Subscribe" | "Sync")
        {
            return Err("GrantAuthorizationMethodMismatch".to_string());
        }
    } else if incoming_method != grant.scope.method {
        return Err("GrantAuthorizationMethodMismatch".to_string());
    }

    match grant.scope.interface.as_str() {
        "Records" => evaluate_records_grant_authorization(case, grant),
        "Protocols" => evaluate_protocols_grant_authorization(case, grant),
        "Messages" => evaluate_messages_grant_authorization(case, grant),
        _ => Ok(()),
    }
}

fn evaluate_records_grant_authorization(
    case: &FixtureCase,
    grant: &GrantAuthorizationFixture,
) -> Result<(), String> {
    if grant.scope.protocol.as_deref() != incoming_message_str_optional(grant, "protocol") {
        return Err("RecordsGrantAuthorizationScopeProtocolMismatch".to_string());
    }
    if let Some(scope_protocol_path) = grant.scope.protocol_path.as_deref() {
        if incoming_message_str_optional(grant, "protocolPath") != Some(scope_protocol_path) {
            return Err("RecordsGrantAuthorizationScopeProtocolPathMismatch".to_string());
        }
    }

    match grant
        .conditions
        .as_ref()
        .and_then(|conditions| conditions.get("publication"))
        .and_then(Value::as_str)
    {
        Some("Required") if incoming_message_bool(grant, "published") != Some(true) => {
            Err("RecordsGrantAuthorizationConditionPublicationRequired".to_string())
        }
        Some("Prohibited") if incoming_message_bool(grant, "published") == Some(true) => {
            Err("RecordsGrantAuthorizationConditionPublicationProhibited".to_string())
        }
        Some(value) if !matches!(value, "Required" | "Prohibited") => {
            panic!("{} unsupported publication condition {}", case.id, value)
        }
        _ => Ok(()),
    }
}

fn evaluate_protocols_grant_authorization(
    _case: &FixtureCase,
    grant: &GrantAuthorizationFixture,
) -> Result<(), String> {
    let Some(scope_protocol) = grant.scope.protocol.as_deref() else {
        return Ok(());
    };
    if incoming_message_str_optional(grant, "protocol")
        .is_some_and(|protocol| protocol != scope_protocol)
    {
        return Err("ProtocolsGrantAuthorizationQueryProtocolScopeMismatch".to_string());
    }
    Ok(())
}

fn evaluate_messages_grant_authorization(
    _case: &FixtureCase,
    grant: &GrantAuthorizationFixture,
) -> Result<(), String> {
    let Some(scope_protocol) = grant.scope.protocol.as_deref() else {
        return Ok(());
    };
    let incoming_protocols = incoming_message_protocols(grant);
    if incoming_protocols.is_empty()
        || incoming_protocols
            .iter()
            .any(|protocol| *protocol != scope_protocol)
    {
        return Err("MessagesGrantAuthorizationMismatchedProtocol".to_string());
    }
    Ok(())
}

fn incoming_message_str<'a>(
    case: &FixtureCase,
    grant: &'a GrantAuthorizationFixture,
    field: &str,
) -> &'a str {
    incoming_message_str_optional(grant, field)
        .unwrap_or_else(|| panic!("{} incomingMessage.{} must be a string", case.id, field))
}

fn incoming_message_str_optional<'a>(
    grant: &'a GrantAuthorizationFixture,
    field: &str,
) -> Option<&'a str> {
    grant.incoming_message.get(field).and_then(Value::as_str)
}

fn incoming_message_bool(grant: &GrantAuthorizationFixture, field: &str) -> Option<bool> {
    grant.incoming_message.get(field).and_then(Value::as_bool)
}

fn incoming_message_protocols(grant: &GrantAuthorizationFixture) -> Vec<&str> {
    let mut protocols = Vec::new();
    if let Some(protocol) = incoming_message_str_optional(grant, "protocol") {
        protocols.push(protocol);
    }
    if let Some(filters) = grant
        .incoming_message
        .get("filters")
        .and_then(Value::as_array)
    {
        protocols.extend(
            filters
                .iter()
                .filter_map(|filter| filter.get("protocol"))
                .filter_map(Value::as_str),
        );
    }
    protocols
}

fn grant_timestamp(case: &FixtureCase, value: &str, field: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(value)
        .unwrap_or_else(|err| panic!("{} invalid {}: {}", case.id, field, err))
        .with_timezone(&chrono::Utc)
}

fn assert_protocol_directive_coverage(suite_id: &str, actual: &BTreeSet<String>) {
    let expected = [
        "uses",
        "$ref",
        "crossProtocolRole",
        "$role",
        "$size",
        "$tags",
        "$recordLimit",
        "$immutable",
        "$delivery",
        "$squash",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
    let missing = expected.difference(actual).cloned().collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{} missing protocol directive fixtures: {:?}",
        suite_id,
        missing
    );
}

fn assert_grant_scope_coverage(suite_id: &str, actual: &BTreeSet<String>) {
    let expected = ["Records", "Protocols", "Messages"]
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let missing = expected.difference(actual).cloned().collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{} missing grant scope fixtures: {:?}",
        suite_id,
        missing
    );
}

fn assert_grant_behavior_coverage(suite_id: &str, actual: &BTreeSet<String>) {
    let expected = ["scope", "condition", "expiry", "revocation", "delegate"]
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let missing = expected.difference(actual).cloned().collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{} missing grant behavior fixtures: {:?}",
        suite_id,
        missing
    );
}

fn grant_behaviors(case: &FixtureCase, grant: &GrantAuthorizationFixture) -> BTreeSet<String> {
    let mut behaviors = BTreeSet::from(["scope".to_string()]);
    if grant.conditions.is_some() {
        behaviors.insert("condition".to_string());
    }
    if grant.date_expires.is_some() {
        behaviors.insert("expiry".to_string());
    }
    if grant.revoked == Some(true) {
        behaviors.insert("revocation".to_string());
    }
    if grant.delegated {
        behaviors.insert("delegate".to_string());
    }
    if grant.scope.protocol_path.is_some() {
        behaviors.insert("scope".to_string());
    }
    if grant.scope.protocol.is_none() && grant.scope.interface == "Records" {
        panic!("{} Records grants must include protocol scope", case.id);
    }
    behaviors
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
    let actual = Jws::create_general(&jws_payload_bytes(case), &signing_keys(fixture_set, case))
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

fn jws(case: &FixtureCase) -> &Jws {
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
        ("Records", "Count") => roundtrip_descriptor::<RecordsCountDescriptor>(descriptor),
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
        ("Messages", "Sync") => roundtrip_descriptor::<MessagesSyncDescriptor>(descriptor),
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

// ---------------------------------------------------------------------------
// Track A: spec-conformance floor (fixtures/spec)
//
// This is a SEPARATE oracle from the TS-parity fixtures above. Spec fixtures
// declare `oracle: "spec"` and carry their expected values from an external
// published specification or test vector — never from the enbox TypeScript
// implementation. They are intentionally NOT forced through `FixtureCase`.
// ---------------------------------------------------------------------------

const SPEC_DESCRIPTOR_CID_ASSERTION: &str = "spec.descriptorCid";
const SPEC_CID_DAGCBOR_ASSERTION: &str = "spec.cid.dagcbor";
const SPEC_DID_RESOLVE_ASSERTION: &str = "spec.did.resolve";
const SPEC_JWS_VERIFY_ASSERTION: &str = "spec.jws.verify";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpecFixtureManifest {
    schema_version: u64,
    oracle: String,
    sets: Vec<SpecFixtureSetRef>,
}

#[derive(Debug, Deserialize)]
struct SpecFixtureSetRef {
    id: String,
    path: String,
    assertions: Vec<String>,
}

#[derive(Debug)]
struct LoadedSpecFixtureSet {
    set_ref: SpecFixtureSetRef,
    fixture_set: SpecFixtureSet,
}

impl LoadedSpecFixtureSet {
    fn has_assertion(&self, assertion: &str) -> bool {
        self.set_ref
            .assertions
            .iter()
            .any(|candidate| candidate == assertion)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpecFixtureSet {
    schema_version: u64,
    oracle: String,
    source: SpecSource,
    cases: Vec<SpecFixtureCase>,
}

#[derive(Debug, Deserialize)]
struct SpecSource {
    spec: SpecReference,
}

#[derive(Debug, Deserialize)]
struct SpecReference {
    name: String,
    url: String,
    section: String,
}

#[derive(Debug, Deserialize)]
struct SpecFixtureCase {
    id: String,
    #[serde(default)]
    descriptor: Option<Value>,
    #[serde(default)]
    object: Option<Value>,
    #[serde(default)]
    did: Option<String>,
    #[serde(default)]
    jws: Option<SpecJwsInput>,
    #[serde(default, rename = "publicJwk")]
    public_jwk: Option<JwsPublicJwk>,
    expected: SpecExpected,
}

/// Raw compact-JWS segments for a `spec.jws.verify` case: the base64url
/// protected header, the base64url payload, and the base64url signature. The
/// test reassembles these into a [`Jws`] and verifies it against `publicJwk`.
#[derive(Debug, Deserialize)]
struct SpecJwsInput {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpecExpected {
    #[serde(default)]
    descriptor_cid: Option<String>,
    #[serde(default)]
    cid: Option<String>,
    #[serde(default)]
    public_key: Option<SpecExpectedPublicKey>,
    #[serde(default)]
    verify: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SpecExpectedPublicKey {
    kty: String,
    crv: String,
    x: String,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
}

fn load_spec_fixture_sets() -> Vec<LoadedSpecFixtureSet> {
    let root = fixtures_root().join("spec");
    let manifest_path = root.join("manifest.json");
    let manifest = read_json::<SpecFixtureManifest>(&manifest_path);

    assert_eq!(
        manifest.schema_version, 1,
        "spec fixture manifest schema version"
    );
    assert_eq!(
        manifest.oracle, "spec",
        "spec fixture manifest must declare oracle=spec"
    );

    manifest
        .sets
        .into_iter()
        .map(|set_ref| {
            let fixture_path = root.join(&set_ref.path);
            let fixture_set = read_json::<SpecFixtureSet>(&fixture_path);

            assert_eq!(
                fixture_set.schema_version, 1,
                "{} spec set schema version",
                set_ref.id
            );
            assert_eq!(
                fixture_set.oracle, "spec",
                "{} spec set must declare oracle=spec",
                set_ref.id
            );

            LoadedSpecFixtureSet {
                set_ref,
                fixture_set,
            }
        })
        .collect()
}

/// Track A conformance: the impl's DAG-CBOR CID of a RecordsWrite descriptor
/// must equal the descriptorCid literal independently derived from the DWN
/// spec's CIDv1/DAG-CBOR/sha2-256/base32 algorithm. The expected side is a
/// hardcoded spec-derived literal — it is NOT recomputed by the impl, so this
/// is a genuine spec assertion rather than a tautology.
#[test]
fn fixture_descriptor_cid_match_spec() {
    let mut checked = 0usize;
    for set in load_spec_fixture_sets() {
        if !set.has_assertion(SPEC_DESCRIPTOR_CID_ASSERTION) {
            continue;
        }

        // Spec provenance must be present and meaningful.
        let source = &set.fixture_set.source.spec;
        assert!(!source.name.is_empty(), "{} spec name", set.set_ref.id);
        assert!(!source.url.is_empty(), "{} spec url", set.set_ref.id);
        assert!(!source.section.is_empty(), "{} spec section", set.set_ref.id);

        for case in &set.fixture_set.cases {
            let descriptor = case
                .descriptor
                .as_ref()
                .unwrap_or_else(|| panic!("{} descriptorCid case must include a descriptor", case.id));
            let expected_cid = case.expected.descriptor_cid.as_deref().unwrap_or_else(|| {
                panic!("{} descriptorCid case must include expected.descriptorCid", case.id)
            });
            assert_eq!(
                compute_cid(descriptor),
                expected_cid,
                "{} descriptorCid must match the spec-derived literal",
                case.id
            );
            checked += 1;
        }
    }

    assert!(
        checked > 0,
        "at least one spec descriptorCid case must be checked"
    );
}

/// Track A conformance: the impl's DAG-CBOR CIDv1 of an arbitrary IPLD map must
/// equal the CID literal independently derived from the IPLD DAG-CBOR spec
/// (length-first canonical map-key ordering, sha2-256, CIDv1, base32-lower). The
/// expected side is a hardcoded spec-derived literal produced by a separate
/// pure-Python encoder — NOT recomputed by the impl — so this is a genuine spec
/// assertion, not a tautology.
///
/// The corpus deliberately includes ORDERING-DIVERGENT maps whose keys sort
/// differently under length-first canonical ordering than under plain bytewise
/// lexicographic ordering (e.g. `{"z":1,"aa":2}`: canonical "z" before "aa",
/// lexicographic "aa" before "z"). These pin down that `serde_ipld_dagcbor`
/// emits canonical length-first ordering even though the impl feeds it a Rust
/// `BTreeMap` (byte-lexicographic). A regression to lexicographic encoding would
/// flip these CIDs and fail loudly here.
#[test]
fn fixture_cid_dagcbor_match_spec() {
    let mut checked = 0usize;
    let mut divergent_checked = 0usize;
    for set in load_spec_fixture_sets() {
        if !set.has_assertion(SPEC_CID_DAGCBOR_ASSERTION) {
            continue;
        }

        // Spec provenance must be present and meaningful.
        let source = &set.fixture_set.source.spec;
        assert!(!source.name.is_empty(), "{} spec name", set.set_ref.id);
        assert!(!source.url.is_empty(), "{} spec url", set.set_ref.id);
        assert!(!source.section.is_empty(), "{} spec section", set.set_ref.id);

        for case in &set.fixture_set.cases {
            let object = case
                .object
                .as_ref()
                .unwrap_or_else(|| panic!("{} dagcbor case must include an object", case.id));
            let expected_cid = case.expected.cid.as_deref().unwrap_or_else(|| {
                panic!("{} dagcbor case must include expected.cid", case.id)
            });
            assert_eq!(
                compute_cid(object),
                expected_cid,
                "{} DAG-CBOR CIDv1 must match the spec-derived literal",
                case.id
            );
            checked += 1;
            if case.id.contains("divergent") {
                divergent_checked += 1;
            }
        }
    }

    assert!(
        checked > 0,
        "at least one spec DAG-CBOR CID case must be checked"
    );
    assert!(
        divergent_checked > 0,
        "the DAG-CBOR corpus must include at least one ordering-divergent vector"
    );
}

/// Track A conformance: the `UniversalResolver` must resolve a `did:key`
/// (Ed25519) and a `did:jwk` DID to exactly the public-key JWK fixed by the
/// respective external method specifications. The expected JWK material on each
/// case is a hardcoded spec-vector literal (the did:key Ed25519/X25519 worked
/// example from W3C-CCG, and the did:jwk Examples), NOT recomputed by the impl
/// on the expected side — so this is a genuine spec assertion, not a tautology.
#[test]
fn fixture_did_resolution_match_spec() {
    let resolver = UniversalResolver::new();
    let mut checked = 0usize;
    for set in load_spec_fixture_sets() {
        if !set.has_assertion(SPEC_DID_RESOLVE_ASSERTION) {
            continue;
        }

        // Spec provenance must be present and meaningful.
        let source = &set.fixture_set.source.spec;
        assert!(!source.name.is_empty(), "{} spec name", set.set_ref.id);
        assert!(!source.url.is_empty(), "{} spec url", set.set_ref.id);
        assert!(!source.section.is_empty(), "{} spec section", set.set_ref.id);

        for case in &set.fixture_set.cases {
            let did = case
                .did
                .as_deref()
                .unwrap_or_else(|| panic!("{} DID resolution case must include a did", case.id));
            let expected = case.expected.public_key.as_ref().unwrap_or_else(|| {
                panic!("{} DID resolution case must include expected.publicKey", case.id)
            });

            let expected_jwk = JwsPublicJwk {
                kty: expected.kty.clone(),
                crv: expected.crv.clone(),
                x: expected.x.clone(),
                y: expected.y.clone(),
                kid: expected.kid.clone(),
                alg: expected.alg.clone(),
            };

            let resolved = resolver
                .resolve_public_jwk(did)
                .unwrap_or_else(|| panic!("{} resolver yielded no key for {did}", case.id));

            assert_eq!(
                resolved, expected_jwk,
                "{} resolved public key must match the spec-vector literal",
                case.id
            );
            checked += 1;
        }
    }

    assert!(
        checked > 0,
        "at least one spec DID resolution case must be checked"
    );
}

/// Track A conformance: `Jws::verify_signatures_public_jwk` must accept the
/// Ed25519 (EdDSA) JWS example published in RFC 8037 Appendix A.4 and reject a
/// one-character-tampered copy of its signature. The compact segments, the
/// signature, and the public JWK (RFC 8037 A.2) are spec literals; the expected
/// accept/reject boolean is fixed by the RFC, not computed by the impl on the
/// expected side — so this is a genuine spec assertion, not a tautology.
#[test]
fn fixture_jws_ed25519_match_spec() {
    let mut checked = 0usize;
    for set in load_spec_fixture_sets() {
        if !set.has_assertion(SPEC_JWS_VERIFY_ASSERTION) {
            continue;
        }

        // Spec provenance must be present and meaningful.
        let source = &set.fixture_set.source.spec;
        assert!(!source.name.is_empty(), "{} spec name", set.set_ref.id);
        assert!(!source.url.is_empty(), "{} spec url", set.set_ref.id);
        assert!(!source.section.is_empty(), "{} spec section", set.set_ref.id);

        for case in &set.fixture_set.cases {
            let input = case
                .jws
                .as_ref()
                .unwrap_or_else(|| panic!("{} jws.verify case must include jws segments", case.id));
            let public_jwk = case
                .public_jwk
                .as_ref()
                .unwrap_or_else(|| panic!("{} jws.verify case must include publicJwk", case.id));
            let expected = case.expected.verify.unwrap_or_else(|| {
                panic!("{} jws.verify case must include expected.verify", case.id)
            });

            let jws = Jws {
                payload: Some(input.payload.clone()),
                signatures: Some(vec![JwsSignature {
                    protected: Some(input.protected.clone()),
                    signature: Some(input.signature.clone()),
                    ..Default::default()
                }]),
                ..Default::default()
            };

            let verified = jws.verify_signatures_public_jwk(public_jwk).unwrap_or_else(|err| {
                panic!("{} verify_signatures_public_jwk errored: {err:?}", case.id)
            });
            assert_eq!(
                verified, expected,
                "{} verification result must match the RFC 8037 expectation",
                case.id
            );
            checked += 1;
        }
    }

    assert!(checked > 0, "at least one spec JWS verify case must be checked");
}

// ---------------------------------------------------------------------------
// Track B: spec-vs-impl divergence ledger (fixtures/spec/divergence/ledger.json)
//
// The ledger catalogs places where the DIF DWN prose spec is wrong, silent, or
// an explicit TODO and the impl is the de-facto truth. This test is a
// REGRESSION MARKER, not a conformance test: for entries with an executable
// proof it recomputes both the spec-prose-derived value and the impl value and
// asserts they STILL differ. If upstream ever fixes the spec — or someone
// "fixes" the impl to match the broken prose — these assertions FAIL LOUD,
// forcing the ledger entry to be re-evaluated and the divergence retired.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DivergenceLedger {
    schema_version: u64,
    oracle: String,
    entries: Vec<DivergenceEntry>,
}

#[derive(Debug, Deserialize)]
struct DivergenceEntry {
    id: String,
    surface: String,
    #[serde(rename = "impl")]
    impl_side: DivergenceImpl,
    spec: DivergenceSpec,
    proof: DivergenceProof,
    disposition: String,
    upstream: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct DivergenceImpl {
    behavior: String,
    #[allow(dead_code)]
    #[serde(rename = "ref")]
    reference: String,
}

#[derive(Debug, Deserialize)]
struct DivergenceSpec {
    says: String,
    class: String,
    #[allow(dead_code)]
    #[serde(rename = "ref")]
    reference: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DivergenceProof {
    executable: bool,
    // Populated only for executable proofs (e.g. recordId).
    algorithm: Option<String>,
    descriptor: Option<Value>,
    author: Option<String>,
    descriptor_cid: Option<String>,
    impl_record_id: Option<String>,
    spec_record_id: Option<String>,
}

fn load_divergence_ledger() -> DivergenceLedger {
    let path = fixtures_root()
        .join("spec")
        .join("divergence")
        .join("ledger.json");
    let ledger = read_json::<DivergenceLedger>(&path);
    assert_eq!(ledger.schema_version, 1, "divergence ledger schema version");
    assert_eq!(
        ledger.oracle, "spec",
        "divergence ledger must declare oracle=spec"
    );
    ledger
}

#[test]
fn ledger_divergences_still_hold() {
    let ledger = load_divergence_ledger();

    // Every seeded RecordsWrite-ID divergence must be present and well-formed.
    // entryId is no longer a standalone entry: the spec DOES define it (by
    // reference to the Record ID Generation Process), so it folds into the
    // recordId entry. A new entry records the contextId protocol-guard
    // impl/fork divergence.
    let expected_ids = [
        "records-write-recordid-author",
        "records-write-contextid-todo",
        "records-write-contextid-protocol-guard",
    ];
    let actual_ids = ledger
        .entries
        .iter()
        .map(|entry| entry.id.as_str())
        .collect::<BTreeSet<_>>();
    for id in expected_ids {
        assert!(
            actual_ids.contains(id),
            "divergence ledger must contain entry {id}"
        );
    }

    let mut executable_checked = 0usize;
    for entry in &ledger.entries {
        assert!(!entry.surface.is_empty(), "{} surface", entry.id);
        assert!(!entry.impl_side.behavior.is_empty(), "{} impl behavior", entry.id);
        assert!(!entry.spec.says.is_empty(), "{} spec says", entry.id);
        assert!(
            matches!(
                entry.spec.class.as_str(),
                "spec-wrong" | "spec-silent" | "spec-todo" | "impl-extension"
            ),
            "{} spec class must be a known divergence class",
            entry.id
        );
        // Spec-side entries are upstream-contribution backlog; the impl/fork
        // divergence (impl-extension) awaits an owner decision instead.
        let expected_disposition = if entry.spec.class == "impl-extension" {
            "needs-owner-decision"
        } else {
            "contribute-upstream"
        };
        assert_eq!(
            entry.disposition, expected_disposition,
            "{} disposition",
            entry.id
        );
        assert!(
            entry.upstream.is_none(),
            "{} upstream link should be null until contributed",
            entry.id
        );

        if !entry.proof.executable {
            // spec-silent / spec-todo: prose has no algorithm to recompute, so
            // the ledger entry is documentation-only. Just assert it is intact.
            assert!(
                entry.proof.algorithm.is_none(),
                "{} non-executable proof must not claim an algorithm",
                entry.id
            );
            continue;
        }

        // Executable proof: recompute both sides with the IMPL's CID code and
        // assert the divergence still holds, pinned to the recorded literals.
        assert_eq!(
            entry.proof.algorithm.as_deref(),
            Some("recordId"),
            "{} only the recordId algorithm is executable",
            entry.id
        );
        let descriptor = entry
            .proof
            .descriptor
            .as_ref()
            .unwrap_or_else(|| panic!("{} executable proof must include descriptor", entry.id));
        let author = entry
            .proof
            .author
            .as_deref()
            .unwrap_or_else(|| panic!("{} executable proof must include author", entry.id));
        let descriptor_cid = entry
            .proof
            .descriptor_cid
            .as_deref()
            .unwrap_or_else(|| panic!("{} executable proof must include descriptorCid", entry.id));
        let expected_impl = entry
            .proof
            .impl_record_id
            .as_deref()
            .unwrap_or_else(|| panic!("{} executable proof must include implRecordId", entry.id));
        let expected_spec = entry
            .proof
            .spec_record_id
            .as_deref()
            .unwrap_or_else(|| panic!("{} executable proof must include specRecordId", entry.id));

        // descriptorCid the proof carries must itself be correct per the impl.
        assert_eq!(
            compute_cid(descriptor),
            descriptor_cid,
            "{} proof descriptorCid",
            entry.id
        );

        // impl recordId = CID({ ...descriptor, author }).
        let mut impl_input = descriptor.clone();
        impl_input
            .as_object_mut()
            .expect("descriptor must be an object")
            .insert("author".to_string(), Value::String(author.to_string()));
        let impl_record_id = compute_cid(&impl_input);

        // spec-prose recordId = CID({ descriptorCid }) — author omitted (the bug).
        let spec_input = serde_json::json!({ "descriptorCid": descriptor_cid });
        let spec_record_id = compute_cid(&spec_input);

        assert_eq!(
            impl_record_id, expected_impl,
            "{} impl recordId drifted from the recorded literal — update the ledger",
            entry.id
        );
        assert_eq!(
            spec_record_id, expected_spec,
            "{} spec-prose recordId drifted from the recorded literal — update the ledger",
            entry.id
        );
        // The whole point of the divergence: these must still differ. If this
        // ever passes (impl == spec), upstream or the impl converged — retire it.
        assert_ne!(
            impl_record_id, spec_record_id,
            "{} divergence resolved (impl recordId now equals spec-prose recordId) — retire the ledger entry",
            entry.id
        );
        executable_checked += 1;
    }

    assert!(
        executable_checked > 0,
        "at least one executable divergence proof must be exercised"
    );
}
