//! Who may read a control record once it is stored.

use super::*;

/// The tenant's own audience record, plus the handlers a reader needs.
async fn audience_read_fixture() -> (ControlFixture, String, String) {
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    let data = audience_payload("member", "", &key_id, &fixture.seal_key_id);
    let write = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", &key_id),
        &data,
        "2025-01-01T00:01:00.000000Z",
        |_| {},
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &write, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let record_id = write["recordId"].as_str().unwrap().to_string();
    (fixture, record_id, key_id)
}

// Covers: ENBOX-ENC-001, DWN-AUTH-001
// An audience is a directory entry: reachable by anyone who can already name it
// exactly, but never by an anonymous reader and never by sweeping for it
// without authority over the role.
#[tokio::test]
async fn an_audience_is_readable_by_exact_reference_but_not_by_sweeping() {
    let (fixture, record_id, key_id) = audience_read_fixture().await;
    let reader = RecordsReadHandler::new(
        fixture.message_store.clone(),
        TestDataStore::default(),
        None,
    );

    // Anonymous: control records are unpublished, so there is no route at all.
    let anonymous = unsigned_read_message(json!({ "recordId": record_id }));
    let reply = reader.run(CONTROL_TENANT, &anonymous, None).await;
    assert!(
        reply.status.code >= 400,
        "an unauthenticated reader must not reach a control record, got {} {}",
        reply.status.code,
        reply.status.detail
    );

    // Authenticated, naming the record exactly.
    let by_id = signed_request(
        unsigned_read_message(json!({ "recordId": record_id })),
        bob_signer(),
        None,
    )
    .await;
    let reply = reader.run(CONTROL_TENANT, &by_id, None).await;
    assert_eq!(
        reply.status.code, 200,
        "an exact recordId read must be allowed: {}",
        reply.status.detail
    );

    // Authenticated, naming the full four-field tuple.
    let by_tuple = signed_request(
        unsigned_read_message(exact_tuple_filter(Some(&key_id))),
        bob_signer(),
        None,
    )
    .await;
    let reply = reader.run(CONTROL_TENANT, &by_tuple, None).await;
    assert_eq!(
        reply.status.code, 200,
        "an exact tuple read must be allowed: {}",
        reply.status.detail
    );

    // Authenticated, but sweeping the whole control path with no authority.
    let sweep = signed_request(
        unsigned_read_message(json!({
            "protocol": CONTROL_PROTOCOL,
            "protocolPath": AUDIENCE_PATH,
        })),
        bob_signer(),
        None,
    )
    .await;
    let reply = reader.run(CONTROL_TENANT, &sweep, None).await;
    assert_eq!(
        reply.status.code, 404,
        "a broad sweep must not surface control records: {}",
        reply.status.detail
    );
}

// Covers: ENBOX-ENC-003, DWN-AUTH-005
// A delivery is addressed key material. Its parties reach it; an unrelated DID
// does not, and having *some* valid grant is not the same as having one that
// connects the reader to this recipient.
#[tokio::test]
async fn a_delivery_is_readable_only_by_its_parties_or_a_connecting_grant() {
    const RECIPIENT: &str = "did:example:bob";
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    admit_audience(&fixture, &key_id, "2025-01-01T00:01:00.000000Z").await;
    grant_member_role(
        &fixture.message_store,
        RECIPIENT,
        "2025-01-01T00:02:00.000000Z",
    )
    .await;

    let ciphertext = Bytes::from_static(b"sealed key material");
    let delivery = control_write(
        DELIVERY_PATH,
        delivery_tags("member", "", &key_id, "roleHolder"),
        &ciphertext,
        "2025-01-01T00:03:00.000000Z",
        |spec| {
            spec.recipient = Some(RECIPIENT.to_string());
            spec.encryption = Some(delivery_envelope());
        },
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &delivery, Some(ciphertext))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let record_id = delivery["recordId"].as_str().unwrap().to_string();

    let reader = RecordsReadHandler::new(
        fixture.message_store.clone(),
        TestDataStore::default(),
        None,
    );
    let read_as = |signer: crate::auth::PrivateJwkSigner| {
        let record_id = record_id.clone();
        async move {
            signed_request(
                unsigned_read_message(json!({ "recordId": record_id })),
                signer,
                None,
            )
            .await
        }
    };

    // The recipient reads its own delivery.
    let reply = reader
        .run(CONTROL_TENANT, &read_as(bob_signer()).await, None)
        .await;
    assert_eq!(
        reply.status.code, 200,
        "the recipient must read its own delivery: {}",
        reply.status.detail
    );

    // An unrelated DID does not, even naming the record exactly — an exact
    // reference opens an audience directory entry, never delivered key material.
    let reply = reader
        .run(
            CONTROL_TENANT,
            &read_as(signer_for("did:example:mallory")).await,
            None,
        )
        .await;
    assert!(
        reply.status.code >= 400,
        "an unrelated DID must not read another recipient's delivery, got {} {}",
        reply.status.code,
        reply.status.detail
    );
}

// Covers: ENBOX-ENC-001, DWN-REC-008
// Direct Read scans for the first *readable* candidate in the requested order.
// It deliberately does not apply the current-audience projection that Query,
// Count and Subscribe use, so a descending read over two audiences for the same
// role returns whichever comes first in that order — not whichever the
// projection would call current.
//
// This is the documented exception to assuming every read surface sees the same
// population. It is asserted rather than reconciled: unifying the two would be
// a contract change, not an implementation tidy-up.
#[tokio::test]
async fn direct_read_takes_the_first_readable_candidate_not_the_projected_current() {
    let fixture = control_fixture().await;
    let first_key = fixture.audience_key_id.clone();
    let second_key = other_audience_key_jwk().thumbprint().unwrap();

    // Two genuinely valid audiences for the same role, written in order.
    admit_audience(&fixture, &first_key, "2025-01-01T00:01:00.000000Z").await;
    let later_data = audience_payload_for(
        &other_audience_key_jwk(),
        "member",
        "",
        &second_key,
        &fixture.seal_key_id,
    );
    let later = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", &second_key),
        &later_data,
        "2025-01-01T00:02:00.000000Z",
        |_| {},
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &later, Some(later_data))
        .await;
    assert_eq!(
        reply.status.code, 202,
        "both audiences must be admitted, or the ordering proves nothing: {}",
        reply.status.detail
    );

    let reader = RecordsReadHandler::new(
        fixture.message_store.clone(),
        TestDataStore::default(),
        None,
    );

    // A broad read over the role's audiences, newest first. The tenant reads,
    // so authorization cannot be what decides the answer.
    let mut request = unsigned_read_message(exact_tuple_filter(None));
    request["descriptor"]["dateSort"] = json!("createdDescending");
    let descending = signed_request(request, test_signer(), None).await;

    let reply = reader.run(CONTROL_TENANT, &descending, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);

    // Whatever comes back, it came from the requested ordering rather than a
    // projection: the projection ranks oldest-first within a scope, so a
    // descending read that returned the projected winner would be evidence the
    // exception had been lost.
    let returned = reply
        .reply
        .entry
        .as_ref()
        .and_then(|entry| entry.records_write.as_ref())
        .expect("a readable candidate");
    let returned_key = crate::descriptors::records::records_write_descriptor(returned)
        .unwrap()
        .tags
        .as_ref()
        .and_then(|tags| tags.get("keyId"))
        .cloned();
    assert_eq!(
        returned_key,
        Some(Value::String(second_key.clone())),
        "descending Read must return the newest candidate, not the projected current"
    );
}

// Covers: ENBOX-ENC-001, DWN-AUTH-001
// The exact-tuple route has to work on collections, not just direct Read.
// Ordinary candidate selection narrows a non-owner to published, authored or
// received records — none of which a control record is — so without a control
// branch in the shared plan the permission could never take effect: the query
// would return nothing and the per-record check would never be consulted.
#[tokio::test]
async fn an_exact_audience_tuple_query_reaches_the_record() {
    let (fixture, _record_id, key_id) = audience_read_fixture().await;
    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);

    // An unrelated authenticated requester naming the tuple exactly.
    let exact = signed_request(
        unsigned_query_message(exact_tuple_filter(Some(&key_id))),
        bob_signer(),
        None,
    )
    .await;
    let reply = query_handler.run(CONTROL_TENANT, &exact, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(
        reply.reply.entries.as_ref().map(Vec::len),
        Some(1),
        "an exact tuple query must reach the audience it names"
    );

    // Widening the candidate set must not become a leak: the same requester
    // sweeping the control path without naming a tuple still sees nothing.
    let sweep = signed_request(
        unsigned_query_message(json!({
            "protocol": CONTROL_PROTOCOL,
            "protocolPath": AUDIENCE_PATH,
        })),
        bob_signer(),
        None,
    )
    .await;
    let reply = query_handler.run(CONTROL_TENANT, &sweep, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(
        reply.reply.entries.as_ref().map(Vec::len).unwrap_or(0),
        0,
        "a broad sweep must still surface nothing"
    );

    // And the tenant sees its own record either way.
    let as_tenant = signed_request(
        unsigned_query_message(json!({
            "protocol": CONTROL_PROTOCOL,
            "protocolPath": AUDIENCE_PATH,
        })),
        test_signer(),
        None,
    )
    .await;
    let reply = query_handler.run(CONTROL_TENANT, &as_tenant, None).await;
    assert_eq!(
        reply.reply.entries.as_ref().map(Vec::len),
        Some(1),
        "the tenant reads its own control records: {}",
        reply.status.detail
    );
}

// Covers: ENBOX-ENC-003, DWN-PROTO-004
// A subtree read grant reaches roles that subtree grants read through — but
// only while those roles are still keyed. A configuration that keeps a role and
// drops its `$keyAgreement` stops it conveying key material, and the delegate's
// reach must end with it; otherwise removing a key agreement would silently
// leave retained deliveries readable through a role that keys nothing.
#[tokio::test]
async fn a_referenced_role_must_still_be_keyed_to_convey_deliveries() {
    fn definition_with_reader(role_keyed: bool) -> Definition {
        let mut definition = control_definition();
        // `thread` grants read through the `member` role.
        definition.structure.get_mut("thread").unwrap().actions =
            vec![crate::protocols::Action::Role(
                crate::protocols::ActionRole {
                    role: "member".to_string(),
                    can: vec![crate::protocols::Can::Read],
                },
            )];
        if !role_keyed {
            definition
                .structure
                .get_mut("member")
                .unwrap()
                .key_agreement = None;
        }
        definition
    }

    for (label, role_keyed, expect_reachable) in [
        ("role still keyed", true, true),
        ("key agreement removed", false, false),
    ] {
        let definition = definition_with_reader(role_keyed);
        let scope_path = "thread";
        let role_path = "member";
        let roles = crate::handlers::records::control::visibility::delivery::read_roles_under(
            &definition,
            scope_path,
        );
        assert_eq!(
            roles.contains(role_path),
            expect_reachable,
            "{label}: a subtree delegate's reach must follow the role's key agreement"
        );
    }
}

// Covers: DWN-AUTH-001, ENBOX-ENC-003
// A delegate of the tenant reads as the delegate, not as the tenant. Its grant
// must still connect it to the recipient whose delivery it wants — otherwise
// any tenant delegate would reach every recipient's key material simply because
// the tenant is the semantic author of the grant.
#[tokio::test]
async fn a_tenant_delegate_gets_no_shortcut_to_unrelated_deliveries() {
    const RECIPIENT: &str = "did:example:bob";
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    admit_audience(&fixture, &key_id, "2025-01-01T00:01:00.000000Z").await;
    grant_member_role(
        &fixture.message_store,
        RECIPIENT,
        "2025-01-01T00:02:00.000000Z",
    )
    .await;

    let ciphertext = Bytes::from_static(b"sealed key material");
    let delivery = control_write(
        DELIVERY_PATH,
        delivery_tags("member", "", &key_id, "roleHolder"),
        &ciphertext,
        "2025-01-01T00:03:00.000000Z",
        |spec| {
            spec.recipient = Some(RECIPIENT.to_string());
            spec.encryption = Some(delivery_envelope());
        },
    )
    .await;
    assert_eq!(
        fixture
            .handler
            .run(CONTROL_TENANT, &delivery, Some(ciphertext))
            .await
            .status
            .code,
        202
    );
    let record_id = delivery["recordId"].as_str().unwrap().to_string();

    // A grant the tenant issued to Mallory. It is perfectly valid, and says
    // nothing whatsoever about Bob.
    let unrelated_grant =
        issue_write_grant(&fixture, "member", "2025-01-01T00:00:30.000000Z").await;

    let reader = RecordsReadHandler::new(
        fixture.message_store.clone(),
        TestDataStore::default(),
        None,
    );
    let read = signed_request(
        unsigned_read_message(json!({ "recordId": record_id })),
        signer_for("did:example:mallory"),
        Some(&unrelated_grant),
    )
    .await;
    let reply = reader.run(CONTROL_TENANT, &read, None).await;
    assert!(
        reply.status.code >= 400,
        "a tenant-issued grant unrelated to the recipient must not open the delivery, got {} {}",
        reply.status.code,
        reply.status.detail
    );
}

/// `control_definition()`, but with the `thread` subtree granting read through
/// the `member` role — the shape that makes a subtree grant reach `member`'s
/// deliveries.
fn definition_with_subtree_reader() -> Definition {
    let mut definition = control_definition();
    definition.structure.get_mut("thread").unwrap().actions = vec![crate::protocols::Action::Role(
        crate::protocols::ActionRole {
            role: "member".to_string(),
            can: vec![crate::protocols::Can::Read],
        },
    )];
    definition
}

// Covers: ENBOX-ENC-003, DWN-AUTH-005
// A reader handed a subtree reaches the roles that subtree reads *through* —
// the delivered key is what makes the subtree usable at all. The reach stops
// at the subtree that actually grants the read: a grant over a neighbouring
// path that reads through nothing opens nothing.
#[tokio::test]
async fn a_subtree_read_grant_reaches_the_deliveries_of_the_role_it_reads_through() {
    const READER: &str = "did:example:carol";

    let fixture = control_fixture().await;
    reconfigure(
        &fixture,
        definition_with_subtree_reader(),
        "2025-01-01T00:00:10.000000Z",
    )
    .await;
    let key_id = fixture.audience_key_id.clone();
    admit_audience(&fixture, &key_id, "2025-01-01T00:01:00.000000Z").await;

    // The delivery is addressed to the tenant, so a tenant-issued grant is what
    // connects the reader to the recipient. A grant to an *unrelated*
    // recipient's key material is the case the connection rule exists to
    // refuse, and is covered separately.
    grant_member_role(
        &fixture.message_store,
        CONTROL_TENANT,
        "2025-01-01T00:02:00.000000Z",
    )
    .await;
    let ciphertext = Bytes::from_static(b"sealed key material");
    let delivery = control_write(
        DELIVERY_PATH,
        delivery_tags("member", "", &key_id, "roleHolder"),
        &ciphertext,
        "2025-01-01T00:03:00.000000Z",
        |spec| {
            spec.recipient = Some(CONTROL_TENANT.to_string());
            spec.encryption = Some(delivery_envelope());
        },
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &delivery, Some(ciphertext))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let record_id = delivery["recordId"].as_str().unwrap().to_string();

    let reader = RecordsReadHandler::new(
        fixture.message_store.clone(),
        TestDataStore::default(),
        None,
    );
    let read_under = |grant_id: String| {
        let record_id = record_id.clone();
        async move {
            signed_request(
                unsigned_read_message(json!({ "recordId": record_id })),
                signer_for(READER),
                Some(&grant_id),
            )
            .await
        }
    };

    // `thread` grants read through `member`, so a grant over `thread` reaches
    // the `member` delivery even though `member` is declared outside it.
    let through_thread = issue_grant(
        &fixture,
        "Read",
        READER,
        "thread",
        "2025-01-01T00:04:00.000000Z",
    )
    .await;
    let reply = reader
        .run(CONTROL_TENANT, &read_under(through_thread).await, None)
        .await;
    assert_eq!(
        reply.status.code, 200,
        "a subtree grant must reach the role that subtree reads through: {}",
        reply.status.detail
    );

    // `plain` reads through nothing, so the same grantee over that subtree
    // reaches no key material at all.
    let through_plain = issue_grant(
        &fixture,
        "Read",
        READER,
        "plain",
        "2025-01-01T00:05:00.000000Z",
    )
    .await;
    let reply = reader
        .run(CONTROL_TENANT, &read_under(through_plain).await, None)
        .await;
    assert!(
        reply.status.code >= 400,
        "a subtree that reads through no role must reach no delivery, got {} {}",
        reply.status.code,
        reply.status.detail
    );
}
