//! Grant-key delivery admission: representation, tags, grant, activity,
//! Author, recipient, and scope. Mirrors the control-plane test layout; each
//! case names the invariant it proves.

use std::collections::BTreeMap;

use bytes::Bytes;
use serde_json::json;

use crate::cid::generate_dag_pb_cid_from_bytes;
use crate::dwn::Handler;
use crate::encryption::{
    EncryptionEnvelope, ENCRYPTION_PROTOCOL_GRANT_KEY_PATH, ENCRYPTION_PROTOCOL_URI,
    ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
};
use crate::interfaces::messages::protocols::{
    Action, ActionRole, Can, Definition, ProtocolKeyAgreement, RuleSet, Type,
};
use crate::interfaces::replies::records::Write;
use crate::interfaces::replies::Response;
use crate::testing::{
    bob_signer, put_protocol_definition, signed_write_message, test_signer, WriteSpec,
};
use crate::{MapValue, Value};

use super::{enc_test_handler, open_stores, RecordsWriteHandler, TestDataStore, TestMessageStore};

const TENANT: &str = "did:example:alice";
const GRANTEE: &str = "did:example:bob";
const APP_PROTOCOL: &str = "http://example.com/threads";
const GRANT_TIME: &str = "2024-12-01T00:00:00.000000Z";
const DELIVERY_TIME: &str = "2025-01-03T00:00:00.000000Z";
const FAR_FUTURE: &str = "2099-01-01T00:00:00.000000Z";
/// 43 base64url chars, the delivery key identifier shape.
const KEY_ID: &str = "Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI";

struct DeliveryFixture {
    handler: RecordsWriteHandler<TestMessageStore, TestDataStore>,
    message_store: TestMessageStore,
}

async fn fixture() -> DeliveryFixture {
    let (message_store, data_store) = open_stores().await;
    let handler = enc_test_handler(message_store.clone(), data_store).await;
    DeliveryFixture {
        handler,
        message_store,
    }
}

/// Application protocol under test: `team` reads through the keyed `member`
/// role and nests the keyed `team/lead` role beside the plain `team/doc`.
fn app_definition() -> Definition {
    let keyed = || ProtocolKeyAgreement {
        public_key_jwk: super::path_key_jwk(),
    };
    Definition {
        protocol: APP_PROTOCOL.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([
            (
                "doc".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["application/json".to_string()]),
                    encryption_required: None,
                },
            ),
            (
                "member".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["application/json".to_string()]),
                    encryption_required: None,
                },
            ),
        ]),
        structure: BTreeMap::from([
            (
                "member".to_string(),
                RuleSet {
                    role: Some(true),
                    key_agreement: Some(keyed()),
                    ..Default::default()
                },
            ),
            (
                "team".to_string(),
                RuleSet {
                    actions: vec![Action::Role(ActionRole {
                        role: "member".to_string(),
                        can: vec![Can::Read],
                    })],
                    rules: BTreeMap::from([
                        ("doc".to_string(), RuleSet::default()),
                        (
                            "lead".to_string(),
                            RuleSet {
                                role: Some(true),
                                key_agreement: Some(keyed()),
                                ..Default::default()
                            },
                        ),
                    ]),
                    ..Default::default()
                },
            ),
        ]),
    }
}

async fn install_app(fixture: &DeliveryFixture) {
    put_protocol_definition(TENANT, &fixture.message_store, app_definition(), GRANT_TIME).await;
}

/// Issues a tenant grant to `GRANTEE`; `scope` is the grant scope JSON.
async fn issue_grant(
    fixture: &DeliveryFixture,
    scope: serde_json::Value,
    granted: &str,
    expires: &str,
) -> String {
    let data = Bytes::from(
        serde_json::to_vec(&json!({
            "dateExpires": expires,
            "scope": scope,
            "delegated": true,
        }))
        .unwrap(),
    );
    let grant = signed_write_message(WriteSpec {
        protocol: crate::permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: crate::permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some(GRANTEE.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String(APP_PROTOCOL.to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new(granted)
    })
    .await;
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    let reply = fixture.handler.run(TENANT, &grant, Some(data)).await;
    assert_eq!(
        reply.status.code, 202,
        "grant must admit: {}",
        reply.status.detail
    );
    grant_id
}

async fn revoke_grant(fixture: &DeliveryFixture, grant_id: &str, timestamp: &str) {
    let data = Bytes::from_static(br#"{"description":"revoke"}"#);
    let revocation = signed_write_message(WriteSpec {
        protocol: crate::permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: crate::permissions::PERMISSIONS_REVOCATION_PATH.to_string(),
        parent_id: Some(grant_id.to_string()),
        parent_context_id: Some(grant_id.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String(APP_PROTOCOL.to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new(timestamp)
    })
    .await;
    let reply = fixture.handler.run(TENANT, &revocation, Some(data)).await;
    assert_eq!(
        reply.status.code, 202,
        "revocation must admit: {}",
        reply.status.detail
    );
}

fn scope_json(method: &str, path: Option<&str>, context: Option<&str>) -> serde_json::Value {
    let mut scope = json!({
        "interface": "Records",
        "method": method,
        "protocol": APP_PROTOCOL,
    });
    if let Some(path) = path {
        scope["protocolPath"] = json!(path);
    }
    if let Some(context) = context {
        scope["contextId"] = json!(context);
    }
    scope
}

fn delivery_tags(grant_id: &str, protocol_path: Option<&str>) -> MapValue {
    let mut tags = MapValue::from([
        ("grantId".to_string(), Value::String(grant_id.to_string())),
        (
            "protocol".to_string(),
            Value::String(APP_PROTOCOL.to_string()),
        ),
        ("keyId".to_string(), Value::String(KEY_ID.to_string())),
    ]);
    if let Some(path) = protocol_path {
        tags.insert("protocolPath".to_string(), Value::String(path.to_string()));
    }
    tags
}

#[allow(clippy::too_many_arguments)]
async fn deliver(
    fixture: &DeliveryFixture,
    path: &str,
    tags: MapValue,
    author_bob: bool,
    recipient: Option<&str>,
    data: Option<Bytes>,
    timestamp: &str,
    envelope: Option<EncryptionEnvelope>,
) -> Response<Write> {
    let data = data.unwrap_or_else(|| Bytes::from_static(b"{\"wrapped\":true}"));
    let (author, signer) = if author_bob {
        ("did:example:bob".to_string(), bob_signer())
    } else {
        (TENANT.to_string(), test_signer())
    };
    let write = signed_write_message(WriteSpec {
        protocol: ENCRYPTION_PROTOCOL_URI.to_string(),
        protocol_path: path.to_string(),
        recipient: recipient.map(str::to_string),
        tags: Some(tags),
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        data_format: "application/json".to_string(),
        author,
        signer,
        encryption: envelope,
        ..WriteSpec::new(timestamp)
    })
    .await;
    fixture.handler.run(TENANT, &write, Some(data)).await
}

fn grant_key_envelope() -> EncryptionEnvelope {
    super::envelope_with_entries(vec![super::protocol_path_entry("recipient-kid")])
}

/// Asserts rejection identity through the typed error code.
fn assert_code(reply: &Response<Write>, code: i32, error: &str) {
    assert_eq!(reply.status.code, code, "{}", reply.status.detail);
    assert_eq!(reply.status.error_code.as_deref(), Some(error));
}

// Covers: ENBOX-ENC-002
#[tokio::test]
async fn accepts_valid_read_delivery() {
    let fixture = fixture().await;
    let grant_id = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&grant_id, None),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: ENBOX-ENC-002
#[tokio::test]
async fn rejects_plaintext_grant_key() {
    let fixture = fixture().await;
    let grant_id = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&grant_id, None),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        None,
    )
    .await;
    // The generic encryption-required gate fires before the grant-key hook;
    // that earlier precedence is upstream behaviour, not a missed check.
    assert_code(&reply, 400, "ProtocolAuthorizationEncryptionRequired");
}

// Covers: ENBOX-ENC-002
#[tokio::test]
async fn rejects_encrypted_wrapped_delivery() {
    let fixture = fixture().await;
    let grant_id = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
        delivery_tags(&grant_id, None),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_code(&reply, 400, "ProtocolAuthorizationEncryptionNotAllowed");
}

// Covers: ENBOX-ENC-002
#[tokio::test]
async fn rejects_oversized_wrapped_delivery() {
    let fixture = fixture().await;
    let grant_id = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    let big = Bytes::from(vec![0u8; 30_001]);
    let write = signed_write_message(WriteSpec {
        protocol: ENCRYPTION_PROTOCOL_URI.to_string(),
        protocol_path: ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH.to_string(),
        recipient: Some(GRANTEE.to_string()),
        tags: Some(delivery_tags(&grant_id, None)),
        data_cid: generate_dag_pb_cid_from_bytes(&big).to_string(),
        data_size: big.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new(DELIVERY_TIME)
    })
    .await;
    let reply = fixture.handler.run(TENANT, &write, Some(big)).await;
    assert_code(
        &reply,
        400,
        "EncryptionProtocolValidateEncryptedDeliveryMissingEncryption",
    );
}

// Covers: ENBOX-ENC-002
#[tokio::test]
async fn rejects_malformed_tags() {
    let fixture = fixture().await;
    let grant_id = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;

    let mut no_grant_id = delivery_tags(&grant_id, None);
    no_grant_id.remove("grantId");
    let mut numeric_protocol = delivery_tags(&grant_id, None);
    numeric_protocol.insert("protocol".to_string(), Value::Number(7.into()));
    let mut short_key = delivery_tags(&grant_id, None);
    short_key.insert("keyId".to_string(), Value::String("x".repeat(42)));
    let mut symbols_key = delivery_tags(&grant_id, None);
    symbols_key.insert("keyId".to_string(), Value::String("!".repeat(43)));

    for (why, tags) in [
        ("missing grantId", no_grant_id),
        ("non-string protocol", numeric_protocol),
        ("42-char keyId", short_key),
        ("non-base64url keyId", symbols_key),
    ] {
        let reply = deliver(
            &fixture,
            ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
            tags,
            false,
            Some(GRANTEE),
            None,
            DELIVERY_TIME,
            Some(grant_key_envelope()),
        )
        .await;
        assert_eq!(reply.status.code, 400, "{why}: {}", reply.status.detail);
        assert_eq!(
            reply.status.error_code.as_deref(),
            Some("EncryptionProtocolValidateGrantKeyMissingRequiredTag"),
            "{why}"
        );
    }
}

// Covers: ENBOX-ENC-002, DWN-AUTH-006
#[tokio::test]
async fn missing_grant_is_not_a_scope_denial() {
    let fixture = fixture().await;
    // A delivery naming an unknown grant fails closed, and stays
    // distinguishable from an established scope denial so dependency repair
    // can retry once the grant arrives.
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(
            "bafyreibsau7v7ewevad2flcgvuxet2fvpidnt5kabzb2urerpg2oa2qlmu",
            None,
        ),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_code(&reply, 400, "GrantAuthorizationGrantMissing");
}

// Covers: DWN-AUTH-004, ENBOX-ENC-002
#[tokio::test]
async fn rejects_inactive_grant() {
    let fixture = fixture().await;
    install_app(&fixture).await;

    // Not yet active: delivery predates the grant.
    let future_grant = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        "2025-02-01T00:00:00.000000Z",
        FAR_FUTURE,
    )
    .await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&future_grant, None),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_code(&reply, 400, "GrantAuthorizationGrantNotYetActive");

    // Expired: delivery at or past expiry.
    let short_grant = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        "2024-12-15T00:00:00.000000Z",
    )
    .await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&short_grant, None),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_code(&reply, 400, "GrantAuthorizationGrantExpired");
}

// Covers: DWN-AUTH-004, ENBOX-ENC-002
#[tokio::test]
async fn revocation_is_not_retroactive() {
    let fixture = fixture().await;
    let grant_id = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;

    // Revocation after the delivery timestamp does not invalidate it.
    revoke_grant(&fixture, &grant_id, "2025-02-01T00:00:00.000000Z").await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&grant_id, None),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // Revocation at or before the delivery timestamp rejects.
    revoke_grant(&fixture, &grant_id, DELIVERY_TIME).await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&grant_id, None),
        false,
        Some(GRANTEE),
        None,
        "2025-03-01T00:00:00.000000Z",
        Some(grant_key_envelope()),
    )
    .await;
    assert_code(&reply, 400, "GrantAuthorizationGrantRevoked");
}

// Covers: DWN-AUTH-001, DWN-AUTH-002, DWN-AUTH-003
#[tokio::test]
async fn rejects_wrong_author_and_recipient() {
    let fixture = fixture().await;
    let grant_id = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;

    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&grant_id, None),
        true,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    // Writer-authorization failures are 401, classified by variant.
    assert_code(
        &reply,
        401,
        "EncryptionProtocolValidateGrantKeyAuthorMismatch",
    );

    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&grant_id, None),
        false,
        Some("did:example:carol"),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_code(
        &reply,
        401,
        "EncryptionProtocolValidateGrantKeyRecipientMismatch",
    );
}

// Covers: ENBOX-ENC-002
#[tokio::test]
async fn rejects_ineligible_grants() {
    let fixture = fixture().await;
    install_app(&fixture).await;

    // Records/Query grants cannot exist: the scope parser rejects the pair
    // at issuance, so the ineligible cases below use issuable scopes.
    for (_why, scope) in [
        ("delete method", scope_json("Delete", None, None)),
        ("context scope", scope_json("Read", None, Some("thread-1"))),
        (
            "messages interface",
            json!({
                "interface": "Messages",
                "method": "Read",
                "protocol": APP_PROTOCOL,
            }),
        ),
    ] {
        let grant_id = issue_grant(&fixture, scope, GRANT_TIME, FAR_FUTURE).await;
        let reply = deliver(
            &fixture,
            ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
            delivery_tags(&grant_id, None),
            false,
            Some(GRANTEE),
            None,
            DELIVERY_TIME,
            Some(grant_key_envelope()),
        )
        .await;
        assert_code(
            &reply,
            400,
            "EncryptionProtocolValidateGrantKeyGrantScopeMismatch",
        );
    }

    let grant_id = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    let mut foreign = delivery_tags(&grant_id, None);
    foreign.insert(
        "protocol".to_string(),
        Value::String("http://example.com/other".to_string()),
    );
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        foreign,
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_code(
        &reply,
        400,
        "EncryptionProtocolValidateGrantKeyGrantScopeMismatch",
    );
}

// Covers: ENBOX-ENC-003
#[tokio::test]
async fn read_coverage_follows_the_directional_table() {
    let fixture = fixture().await;
    install_app(&fixture).await;

    // Path grant covers its subtree without definition evidence.
    let team_grant = issue_grant(
        &fixture,
        scope_json("Read", Some("team"), None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    for path in ["team", "team/doc", "team/lead"] {
        let reply = deliver(
            &fixture,
            ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
            delivery_tags(&team_grant, Some(path)),
            false,
            Some(GRANTEE),
            None,
            DELIVERY_TIME,
            Some(grant_key_envelope()),
        )
        .await;
        assert_eq!(reply.status.code, 202, "{path}: {}", reply.status.detail);
    }

    // ... but not siblings, ancestors, the protocol key, or prefix collisions.
    for path in [None, Some("teaming"), Some("other")] {
        let reply = deliver(
            &fixture,
            ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
            delivery_tags(&team_grant, path),
            false,
            Some(GRANTEE),
            None,
            DELIVERY_TIME,
            Some(grant_key_envelope()),
        )
        .await;
        assert_code(
            &reply,
            400,
            "EncryptionProtocolValidateGrantKeyGrantScopeMismatch",
        );
    }

    // The keyed-role exception reaches roles the subtree reads through.
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&team_grant, Some("member")),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: ENBOX-ENC-003
#[tokio::test]
async fn write_coverage_reaches_keyed_roles_only() {
    let fixture = fixture().await;
    install_app(&fixture).await;

    let write_grant = issue_grant(
        &fixture,
        scope_json("Write", Some("team"), None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&write_grant, Some("team/lead")),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    for path in [None, Some("team/doc"), Some("member")] {
        let reply = deliver(
            &fixture,
            ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
            delivery_tags(&write_grant, path),
            false,
            Some(GRANTEE),
            None,
            DELIVERY_TIME,
            Some(grant_key_envelope()),
        )
        .await;
        assert_code(
            &reply,
            400,
            "EncryptionProtocolValidateGrantKeyGrantScopeMismatch",
        );
    }

    // A protocol-wide Write grant reaches any keyed role.
    let wide_grant = issue_grant(
        &fixture,
        scope_json("Write", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&wide_grant, Some("member")),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: ENBOX-ENC-002
#[tokio::test]
async fn missing_history_stays_distinguishable_from_scope_denial() {
    let fixture = fixture().await;
    // No application definition installed: the role exception is undecidable,
    // which must read as missing history rather than scope denial so repair
    // can retry once the configuration arrives.
    let team_grant = issue_grant(
        &fixture,
        scope_json("Read", Some("team"), None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        delivery_tags(&team_grant, Some("member")),
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_code(&reply, 400, "ProtocolAuthorizationProtocolNotFound");
}

// Covers: ENBOX-ENC-002
#[tokio::test]
async fn representation_precedes_grant_lookup() {
    let fixture = fixture().await;
    let mut tags = delivery_tags("does-not-exist", None);
    tags.remove("grantId");
    let reply = deliver(
        &fixture,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        tags,
        false,
        Some(GRANTEE),
        None,
        DELIVERY_TIME,
        Some(grant_key_envelope()),
    )
    .await;
    assert_code(
        &reply,
        400,
        "EncryptionProtocolValidateGrantKeyMissingRequiredTag",
    );
}

// Covers: DWN-REC-003
#[tokio::test]
async fn exact_replay_of_an_accepted_delivery_is_duplicate() {
    let fixture = fixture().await;
    let grant_id = issue_grant(
        &fixture,
        scope_json("Read", None, None),
        GRANT_TIME,
        FAR_FUTURE,
    )
    .await;
    let data = Bytes::from_static(b"{\"wrapped\":true}");
    let write = signed_write_message(WriteSpec {
        protocol: ENCRYPTION_PROTOCOL_URI.to_string(),
        protocol_path: ENCRYPTION_PROTOCOL_GRANT_KEY_PATH.to_string(),
        recipient: Some(GRANTEE.to_string()),
        tags: Some(delivery_tags(&grant_id, None)),
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        data_format: "application/json".to_string(),
        encryption: Some(grant_key_envelope()),
        ..WriteSpec::new(DELIVERY_TIME)
    })
    .await;
    let reply = fixture
        .handler
        .run(TENANT, &write, Some(data.clone()))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let replay = fixture.handler.run(TENANT, &write, Some(data)).await;
    assert_eq!(replay.status.code, 409, "{}", replay.status.detail);
}
