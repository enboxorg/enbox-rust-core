//! Who may write a control record, and how a role that cannot be resolved is
//! classified.

use super::*;

// Covers: DWN-AUTH-001, ENBOX-ENC-001
// Minting a role's key material requires authority to create that role. The
// tenant has it inherently; anyone else needs a grant that actually covers the
// role path, and a grant over a neighbouring path is not a way in. Scope
// comparison is by path boundary, so `member` is not reachable from `plain`.
#[tokio::test]
async fn minting_an_audience_requires_authority_over_that_role() {
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    let data = audience_payload("member", "", &key_id, &fixture.seal_key_id);

    let bob_writes = |grant_id: Option<String>, timestamp: &'static str| {
        let key_id = key_id.clone();
        let data = data.clone();
        async move {
            control_write(
                AUDIENCE_PATH,
                audience_tags("member", "", &key_id),
                &data,
                timestamp,
                |spec| {
                    spec.author = "did:example:bob".to_string();
                    spec.signer = bob_signer();
                    spec.permission_grant_id = grant_id;
                },
            )
            .await
        }
    };

    // No authority at all.
    let reply = fixture
        .handler
        .run(
            CONTROL_TENANT,
            &bob_writes(None, "2025-01-01T00:01:00.000000Z").await,
            Some(data.clone()),
        )
        .await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);

    // A grant over a different path in the same protocol does not reach the
    // role, and having *a* valid grant is not itself authority.
    let wrong_path = issue_write_grant(&fixture, "plain", "2025-01-01T00:00:30.000000Z").await;
    let reply = fixture
        .handler
        .run(
            CONTROL_TENANT,
            &bob_writes(Some(wrong_path), "2025-01-01T00:02:00.000000Z").await,
            Some(data.clone()),
        )
        .await;
    assert_eq!(
        reply.status.code, 401,
        "a grant over 'plain' must not mint 'member' keys: {}",
        reply.status.detail
    );

    // A grant that does cover the role path.
    let right_path = issue_write_grant(&fixture, "member", "2025-01-01T00:00:45.000000Z").await;
    let reply = fixture
        .handler
        .run(
            CONTROL_TENANT,
            &bob_writes(Some(right_path), "2025-01-01T00:03:00.000000Z").await,
            Some(data),
        )
        .await;
    assert_eq!(
        reply.status.code, 202,
        "a grant covering 'member' must mint its keys: {}",
        reply.status.detail
    );
}

// Covers: ENBOX-ENC-001
// A control record's data is its content, so a dataless one must be refused
// outright rather than retained as an empty shell. Retaining it would also be
// unrepairable: resubmitting the same message with its data is an exact replay
// and answers 409, leaving the record permanently describing nothing.
//
// Each case is otherwise fully admissible, so the missing data is the only
// thing that can be rejecting it.
#[tokio::test]
async fn a_dataless_control_record_is_refused_and_not_retained() {
    const RECIPIENT: &str = "did:example:bob";
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    let payload = audience_payload("member", "", &key_id, &fixture.seal_key_id);

    // Everything a delivery depends on, so only its data is missing.
    admit_audience(&fixture, &key_id, "2025-01-01T00:00:30.000000Z").await;
    grant_member_role(
        &fixture.message_store,
        RECIPIENT,
        "2025-01-01T00:00:40.000000Z",
    )
    .await;

    let cases = [
        (
            "audience",
            AUDIENCE_PATH,
            audience_tags("member", "", &key_id),
            payload,
            "2025-01-01T00:01:00.000000Z",
        ),
        (
            "delivery",
            DELIVERY_PATH,
            delivery_tags("member", "", &key_id, "roleHolder"),
            Bytes::from_static(b"sealed key material"),
            "2025-01-01T00:02:00.000000Z",
        ),
    ];

    for (label, path, tags, data, timestamp) in cases {
        let is_delivery = path == DELIVERY_PATH;
        let write = control_write(path, tags, &data, timestamp, |spec| {
            if is_delivery {
                spec.recipient = Some(RECIPIENT.to_string());
                spec.encryption = Some(delivery_envelope());
            }
        })
        .await;

        // Submitted with no data stream and no inline data.
        let reply = fixture.handler.run(CONTROL_TENANT, &write, None).await;
        assert_eq!(reply.status.code, 400, "{label}: {}", reply.status.detail);
        assert_eq!(
            reply.status.error_code.as_deref(),
            Some("EncryptionControlValidateUnexpectedRecord"),
            "{label} must be refused for its missing data, not something else: {}",
            reply.status.detail
        );

        // Nothing may have been retained, or resubmitting with data would
        // collide with a record that never carried any.
        let record_id = write["recordId"].as_str().unwrap();
        let retained = fixture
            .message_store
            .query(
                CONTROL_TENANT,
                Filters::from(filter_map([("recordId", string_filter(record_id))])),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            retained.messages.is_empty(),
            "{label}: a refused control record must leave nothing behind"
        );

        // The same message admits once its data is supplied, proving the
        // refusal did not poison the record id.
        let reply = fixture
            .handler
            .run(CONTROL_TENANT, &write, Some(data))
            .await;
        assert_eq!(
            reply.status.code, 202,
            "{label}: the same message with its data must admit: {}",
            reply.status.detail
        );
    }
}

// Covers: DWN-PROTO-002
// A nested role is addressed by the ancestor context at its parent's depth. A
// shallower context names a wider region, so truncating to whatever segments
// exist would match role holders in unrelated sibling contexts. Such a role is
// unaddressable, which is a negative answer and not a broader search.
#[tokio::test]
async fn a_context_shallower_than_the_role_matches_nothing() {
    const HOLDER: &str = "did:example:bob";
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();

    // A role holder genuinely under `x/y`.
    let role = signed_write_message(WriteSpec {
        protocol: CONTROL_PROTOCOL.to_string(),
        protocol_path: "a/b/member".to_string(),
        recipient: Some(HOLDER.to_string()),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let message: Message<Descriptor> = serde_json::from_value(role).unwrap();
    let indexes = KeyValues::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        ("method".to_string(), Value::String("Write".to_string())),
        (
            "protocol".to_string(),
            Value::String(CONTROL_PROTOCOL.to_string()),
        ),
        (
            "protocolPath".to_string(),
            Value::String("a/b/member".to_string()),
        ),
        ("recipient".to_string(), Value::String(HOLDER.to_string())),
        ("contextId".to_string(), Value::String("x/y".to_string())),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "messageTimestamp".to_string(),
            Value::String("2025-01-01T00:00:00.000000Z".to_string()),
        ),
    ]);
    message_store
        .put(CONTROL_TENANT, message, indexes)
        .await
        .unwrap();

    // The role's parent depth is 2, so `x/y` addresses it and `x` does not.
    assert!(
        role_record_exists(
            CONTROL_TENANT,
            HOLDER,
            CONTROL_PROTOCOL,
            "a/b/member",
            Some("x/y"),
            &message_store
        )
        .await
        .unwrap(),
        "the context at the role's parent depth must find the holder"
    );
    assert!(
        !role_record_exists(
            CONTROL_TENANT,
            HOLDER,
            CONTROL_PROTOCOL,
            "a/b/member",
            Some("x"),
            &message_store
        )
        .await
        .unwrap(),
        "a context shallower than the role must not widen into sibling contexts"
    );
    assert!(
        !role_record_exists(
            CONTROL_TENANT,
            HOLDER,
            CONTROL_PROTOCOL,
            "a/b/member",
            None,
            &message_store
        )
        .await
        .unwrap(),
        "an absent context cannot address a nested role"
    );
}

// Covers: DWN-PROTO-004
// `AudienceRolePathInvalid` licenses destroying a record during config repair,
// so it must mean "the configuration resolved and contradicts this record" —
// never "the configuration was missing". A missing protocol keeps its own
// repairable-dependency classification instead.
#[tokio::test]
async fn a_missing_protocol_is_not_reported_as_an_invalid_role() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    // Deliberately no protocol installed.
    let handler =
        RecordsWriteHandler::new(message_store, data_store, Some(Arc::new(test_resolver())));

    let key_id = audience_key_jwk().thumbprint().unwrap();
    let seal = role_key_jwk().thumbprint().unwrap();
    let data = audience_payload("member", "", &key_id, &seal);
    let write = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", &key_id),
        &data,
        "2025-01-01T00:01:00.000000Z",
        |_| {},
    )
    .await;

    let reply = handler.run(CONTROL_TENANT, &write, Some(data)).await;
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationProtocolNotFound"),
        "a missing protocol must stay a missing dependency: {}",
        reply.status.detail
    );
    assert!(
        !crate::errors::DwnErrorCode::try_from(reply.status.error_code.as_deref().unwrap())
            .unwrap()
            .is_control_invalidity(),
        "a missing protocol must never license destroying the record"
    );
}
