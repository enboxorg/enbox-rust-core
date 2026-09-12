//! Grant invocation on Records Query, Count, Subscribe, and Delete.
//!
//! Issue #283: these descriptors carry `permissionGrantId`, but validation
//! ignored it and rejected every grant-bearing request as a signature
//! mismatch. These tests prove the wire contract: the id travels in both the
//! descriptor and the signature payload, the two must match exactly, and a
//! matching invocation authorizes like a Read grant does.

use super::*;
use crate::auth::PrivateJwkSigner;
use crate::descriptors::{
    DeleteDescriptor as RecordsDeleteDescriptor, RecordsCountDescriptor, RecordsQueryDescriptor,
    SubscribeDescriptor as RecordsSubscribeDescriptor,
};
use crate::filters::Records as CollectionFilter;

pub(crate) const TENANT: &str = "did:example:alice";
pub(crate) const GRANTEE: &str = "did:example:bob";
pub(crate) const PROTOCOL: &str = "http://example.com/notes";
pub(crate) const NOTE_PATH: &str = "note";

pub(crate) const TS_GRANT: &str = "2025-01-01T00:00:00.000000Z";
pub(crate) const TS_NOTE: &str = "2025-01-01T00:01:00.000000Z";
pub(crate) const TS_REQUEST: &str = "2025-01-01T00:10:00.000000Z";

pub(crate) fn note_filter() -> CollectionFilter {
    CollectionFilter {
        protocol: Some(PROTOCOL.to_string()),
        protocol_path: Some(NOTE_PATH.to_string()),
        ..Default::default()
    }
}

pub(crate) struct CollectionFixture {
    pub(crate) message_store: TestMessageStore,
    pub(crate) data_store: TestDataStore,
    pub(crate) note_record_id: String,
}

pub(crate) async fn collection_fixture() -> CollectionFixture {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;

    let write_handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let note_data = Bytes::from_static(b"private note");
    let note = signed_write_message(WriteSpec {
        data_cid: generate_dag_pb_cid_from_bytes(&note_data).to_string(),
        data_size: note_data.len() as u64,
        ..WriteSpec::new(TS_NOTE)
    })
    .await;
    let note_record_id = note["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .run(TENANT, &note, Some(note_data))
            .await
            .status
            .code,
        202,
        "owner note must admit"
    );
    CollectionFixture {
        message_store,
        data_store,
        note_record_id,
    }
}

/// Issues a tenant grant to Bob scoped to `method` over the notes protocol.
pub(crate) async fn issue_collection_grant(
    fixture: &CollectionFixture,
    method: &str,
    grantee: &str,
    expires: &str,
) -> String {
    let handler = RecordsWriteHandler::<_, _>::new(
        fixture.message_store.clone(),
        fixture.data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    issue_collection_grant_on(&handler, method, grantee, expires).await
}

pub(crate) async fn issue_collection_grant_on<S>(
    handler: &RecordsWriteHandler<S, TestDataStore>,
    method: &str,
    grantee: &str,
    expires: &str,
) -> String
where
    S: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    let grant_data = Bytes::from(
        serde_json::to_vec(&json!({
            "dateExpires": expires,
            "scope": {
                "interface": "Records",
                "method": method,
                "protocol": PROTOCOL,
                "protocolPath": NOTE_PATH,
            },
        }))
        .unwrap(),
    );
    let grant = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some(grantee.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String(PROTOCOL.to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new(TS_GRANT)
    })
    .await;
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run(TENANT, &grant, Some(grant_data))
            .await
            .status
            .code,
        202,
        "grant fixture must store"
    );
    grant_id
}

pub(crate) async fn revoke_grant(fixture: &CollectionFixture, grant_id: &str, timestamp: &str) {
    let handler = RecordsWriteHandler::<_, _>::new(
        fixture.message_store.clone(),
        fixture.data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    revoke_grant_on(&handler, grant_id, timestamp).await
}

pub(crate) async fn revoke_grant_on<S>(
    handler: &RecordsWriteHandler<S, TestDataStore>,
    grant_id: &str,
    timestamp: &str,
) where
    S: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    let revoke_data = Bytes::from_static(br#"{"description":"revoke"}"#);
    let revocation = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_REVOCATION_PATH.to_string(),
        parent_id: Some(grant_id.to_string()),
        parent_context_id: Some(grant_id.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String(PROTOCOL.to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&revoke_data).to_string(),
        data_size: revoke_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new(timestamp)
    })
    .await;
    assert_eq!(
        handler
            .run(TENANT, &revocation, Some(revoke_data))
            .await
            .status
            .code,
        202,
        "revocation fixture must store"
    );
}

/// Signs a typed descriptor as Bob, carrying `descriptor_grant_id` in the
/// descriptor and `payload_grant_id` in the signature payload. Passing
/// different ids builds the substitution forgery; passing the same id builds
/// the honest TS-shaped wire message.
pub(crate) async fn sign_collection_request<T: serde::Serialize>(
    descriptor: T,
    descriptor_grant_id: Option<&str>,
    payload_grant_id: Option<&str>,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    let mut descriptor_json = serde_json::to_value(&descriptor).unwrap();
    if let Some(id) = descriptor_grant_id {
        descriptor_json["permissionGrantId"] = json!(id);
    }
    let extra = match payload_grant_id {
        Some(id) => json!({ "permissionGrantId": id }),
        None => json!({}),
    };
    let signature = signature_for_descriptor(&descriptor_json, extra, signer).await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

pub(crate) async fn signed_query(
    descriptor_grant_id: Option<&str>,
    payload_grant_id: Option<&str>,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    sign_collection_request(
        RecordsQueryDescriptor {
            message_timestamp: parse_time(TS_REQUEST),
            filter: note_filter(),
            permission_grant_id: descriptor_grant_id.map(str::to_string),
            pagination: None,
            date_sort: None,
        },
        descriptor_grant_id,
        payload_grant_id,
        signer,
    )
    .await
}

pub(crate) async fn signed_count(
    descriptor_grant_id: Option<&str>,
    payload_grant_id: Option<&str>,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    sign_collection_request(
        RecordsCountDescriptor {
            message_timestamp: parse_time(TS_REQUEST),
            filter: note_filter(),
            permission_grant_id: descriptor_grant_id.map(str::to_string),
        },
        descriptor_grant_id,
        payload_grant_id,
        signer,
    )
    .await
}

pub(crate) async fn signed_subscribe(
    descriptor_grant_id: Option<&str>,
    payload_grant_id: Option<&str>,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    sign_collection_request(
        RecordsSubscribeDescriptor {
            message_timestamp: parse_time(TS_REQUEST),
            filter: note_filter(),
            permission_grant_id: descriptor_grant_id.map(str::to_string),
            date_sort: None,
            pagination: None,
            cursor: None,
        },
        descriptor_grant_id,
        payload_grant_id,
        signer,
    )
    .await
}

pub(crate) async fn signed_delete(
    record_id: &str,
    descriptor_grant_id: Option<&str>,
    payload_grant_id: Option<&str>,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    sign_collection_request(
        RecordsDeleteDescriptor {
            message_timestamp: parse_time(TS_REQUEST),
            permission_grant_id: descriptor_grant_id.map(str::to_string),
            record_id: record_id.to_string(),
            prune: false,
        },
        descriptor_grant_id,
        payload_grant_id,
        signer,
    )
    .await
}

// A descriptor/payload disagreement must reject for every collection method,
// not just Read and Write: a signed descriptor cannot be paired with a
// substituted grant.
#[tokio::test]
// Covers: DWN-AUTH-008 (pending enboxorg/knowledge#15; DWN-AUTH-003 for the grant capability itself)
async fn collection_and_delete_reject_descriptor_payload_grant_substitution() {
    const BOGUS_GRANT: &str = "bogus-grant-id";
    let fixture = collection_fixture().await;
    let grant_id =
        issue_collection_grant(&fixture, "Read", GRANTEE, "2030-01-01T00:00:00.000000Z").await;

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);
    let count_handler = RecordsCountHandler::new(fixture.message_store.clone(), None);
    let subscribe_handler = RecordsSubscribeHandler::new(fixture.message_store.clone(), None);
    let delete_handler = RecordsDeleteHandler::new(
        fixture.message_store.clone(),
        fixture.data_store.clone(),
        None,
    );

    // (label, descriptor id, payload id)
    let forgeries = [
        ("descriptor-only", Some(grant_id.as_str()), None),
        ("payload-only", None, Some(grant_id.as_str())),
        ("swapped", Some(grant_id.as_str()), Some(BOGUS_GRANT)),
    ];

    for (label, descriptor_id, payload_id) in forgeries {
        let reply = query_handler
            .run(
                TENANT,
                &signed_query(descriptor_id, payload_id, crate::testing::bob_signer()).await,
                None,
            )
            .await;
        assert_eq!(reply.status.code, 400, "query {label} must reject");
        assert!(
            reply
                .status
                .detail
                .contains("authorization signature is mismatched"),
            "query {label} must fail the exact-match check, got: {}",
            reply.status.detail
        );

        let reply = count_handler
            .run(
                TENANT,
                &signed_count(descriptor_id, payload_id, crate::testing::bob_signer()).await,
                None,
            )
            .await;
        assert_eq!(reply.status.code, 400, "count {label} must reject");
        assert!(
            reply
                .status
                .detail
                .contains("authorization signature is mismatched"),
            "count {label} must fail the exact-match check, got: {}",
            reply.status.detail
        );

        let reply = subscribe_handler
            .run(
                TENANT,
                &signed_subscribe(descriptor_id, payload_id, crate::testing::bob_signer()).await,
                None,
            )
            .await;
        assert_eq!(reply.status.code, 400, "subscribe {label} must reject");
        assert!(
            reply
                .status
                .detail
                .contains("authorization signature is mismatched"),
            "subscribe {label} must fail the exact-match check, got: {}",
            reply.status.detail
        );

        let reply = delete_handler
            .run(
                TENANT,
                &signed_delete(
                    &fixture.note_record_id,
                    descriptor_id,
                    payload_id,
                    crate::testing::bob_signer(),
                )
                .await,
                None,
            )
            .await;
        assert_eq!(reply.status.code, 400, "delete {label} must reject");
        assert!(
            reply
                .status
                .detail
                .contains("authorization signature is mismatched"),
            "delete {label} must fail the exact-match check, got: {}",
            reply.status.detail
        );
    }
}

// A grant-authorized Query returns the private record a stranger could not
// otherwise see, and Count counts that same projected population.
#[tokio::test]
// Covers: DWN-AUTH-003, DWN-REC-008
async fn grant_authorized_query_and_count_see_private_records() {
    let fixture = collection_fixture().await;
    // A Records Read grant covers collection reads (Query/Count/Subscribe).
    let read_grant =
        issue_collection_grant(&fixture, "Read", GRANTEE, "2030-01-01T00:00:00.000000Z").await;

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);
    let count_handler = RecordsCountHandler::new(fixture.message_store.clone(), None);

    // The wire message carries the id in both the descriptor (schema-visible)
    // and the signature payload (signature-covered), exactly like TS emits it.
    let request = signed_query(
        Some(&read_grant),
        Some(&read_grant),
        crate::testing::bob_signer(),
    )
    .await;
    assert_eq!(
        request["descriptor"]["permissionGrantId"].as_str(),
        Some(read_grant.as_str()),
        "descriptor must carry the invocation for schema validation"
    );
    let reply = query_handler.run(TENANT, &request, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    let entries = reply.reply.entries.as_ref().unwrap();
    assert_eq!(entries.len(), 1, "grant must reveal the private note");
    let entry = serde_json::to_value(&entries[0]).unwrap();
    assert_eq!(
        entry["descriptor"]["protocolPath"].as_str(),
        Some(NOTE_PATH)
    );

    let reply = query_handler
        .run(
            TENANT,
            &signed_query(None, None, crate::testing::bob_signer()).await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert!(
        reply.reply.entries.as_ref().unwrap().is_empty(),
        "the same query without a grant must reveal nothing"
    );

    let reply = count_handler
        .run(
            TENANT,
            &signed_count(
                Some(&read_grant),
                Some(&read_grant),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(
        reply.reply.count,
        Some(1),
        "count must count the grant-projected population"
    );

    let reply = count_handler
        .run(
            TENANT,
            &signed_count(None, None, crate::testing::bob_signer()).await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(
        reply.reply.count,
        Some(0),
        "the same count without a grant must count nothing"
    );
}

// A grant-authorized Subscribe opens with the private record in its snapshot.
#[tokio::test]
// Covers: DWN-AUTH-003, DWN-AUTH-005
async fn grant_authorized_subscribe_snapshot_sees_private_records() {
    let fixture = collection_fixture().await;
    // A Records Read grant covers collection reads (Query/Count/Subscribe).
    let grant_id =
        issue_collection_grant(&fixture, "Read", GRANTEE, "2030-01-01T00:00:00.000000Z").await;

    let handler = RecordsSubscribeHandler::new(fixture.message_store.clone(), None);
    let reply = handler
        .run(
            TENANT,
            &signed_subscribe(
                Some(&grant_id),
                Some(&grant_id),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    let entries = reply.reply.entries.as_ref().unwrap();
    assert_eq!(entries.len(), 1, "grant must reveal the private note");
}

// A grant-authorized Delete removes a record the grantee could not otherwise
// touch; without the grant the delete stays unauthorized.
#[tokio::test]
// Covers: DWN-AUTH-003
async fn grant_authorized_delete_removes_record() {
    let fixture = collection_fixture().await;
    let grant_id =
        issue_collection_grant(&fixture, "Delete", GRANTEE, "2030-01-01T00:00:00.000000Z").await;

    let delete_handler = RecordsDeleteHandler::new(
        fixture.message_store.clone(),
        fixture.data_store.clone(),
        None,
    );
    let reply = delete_handler
        .run(
            TENANT,
            &signed_delete(
                &fixture.note_record_id,
                None,
                None,
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(
        reply.status.code, 401,
        "delete without a grant must stay unauthorized"
    );

    // The tenant sees its own private note, so its disappearance proves the
    // tombstone applied rather than the filter hiding it.
    async fn owner_sees_note(
        query_handler: &RecordsQueryHandler<TestMessageStore>,
        note_record_id: &str,
    ) -> bool {
        let reply = query_handler
            .run(
                TENANT,
                &signed_query(None, None, crate::testing::test_signer()).await,
                None,
            )
            .await;
        assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
        reply.reply.entries.as_ref().unwrap().iter().any(|entry| {
            serde_json::to_value(entry).unwrap()["recordId"].as_str() == Some(note_record_id)
        })
    }

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);
    assert!(
        owner_sees_note(&query_handler, &fixture.note_record_id).await,
        "owner must see the private note before Delete"
    );

    let reply = delete_handler
        .run(
            TENANT,
            &signed_delete(
                &fixture.note_record_id,
                Some(&grant_id),
                Some(&grant_id),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    assert!(
        !owner_sees_note(&query_handler, &fixture.note_record_id).await,
        "deleted record must leave the owner's visible population"
    );
}

// The grant must name this grantee, this method, and this protocol target.
#[tokio::test]
// Covers: DWN-AUTH-003
async fn grant_for_wrong_grantee_method_or_scope_is_rejected() {
    let fixture = collection_fixture().await;
    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);

    let carol_grant = issue_collection_grant(
        &fixture,
        "Read",
        "did:example:carol",
        "2030-01-01T00:00:00.000000Z",
    )
    .await;
    let reply = query_handler
        .run(
            TENANT,
            &signed_query(
                Some(&carol_grant),
                Some(&carol_grant),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 401, "carol's grant must not serve bob");
    assert!(
        reply
            .status
            .detail
            .contains("grant is not authorized for author"),
        "wrong grantee must name the cause, got: {}",
        reply.status.detail
    );

    let write_grant =
        issue_collection_grant(&fixture, "Write", GRANTEE, "2030-01-01T00:00:00.000000Z").await;
    let reply = query_handler
        .run(
            TENANT,
            &signed_query(
                Some(&write_grant),
                Some(&write_grant),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert!(
        reply.status.code >= 400,
        "a write grant must not authorize a query"
    );
    assert!(
        reply
            .status
            .detail
            .contains("outside the scope of the grant ID"),
        "method mismatch must name the cause, got: {}",
        reply.status.detail
    );

    let other_data = Bytes::from_static(br#"{"dateExpires":"2030-01-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Read","protocol":"http://example.com/other","protocolPath":"note"}}"#);
    let write_handler = RecordsWriteHandler::<_, _>::new(
        fixture.message_store.clone(),
        fixture.data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let other_grant = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some(GRANTEE.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/other".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&other_data).to_string(),
        data_size: other_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new(TS_GRANT)
    })
    .await;
    let other_grant_id = other_grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .run(TENANT, &other_grant, Some(other_data))
            .await
            .status
            .code,
        202
    );
    let reply = query_handler
        .run(
            TENANT,
            &signed_query(
                Some(&other_grant_id),
                Some(&other_grant_id),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 401, "out-of-scope grant must not serve");
    assert!(
        reply.status.detail.contains("grant is outside of scope"),
        "scope mismatch must name the cause, got: {}",
        reply.status.detail
    );
}

// Expiry and revocation end collection visibility for new requests.
#[tokio::test]
// Covers: DWN-AUTH-004
async fn expired_and_revoked_grants_stop_collection_reads() {
    let fixture = collection_fixture().await;
    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);

    let expired_grant =
        issue_collection_grant(&fixture, "Read", GRANTEE, "2025-01-01T00:05:00.000000Z").await;
    let reply = query_handler
        .run(
            TENANT,
            &signed_query(
                Some(&expired_grant),
                Some(&expired_grant),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert!(
        reply.status.code >= 400,
        "expired grant must not authorize, got {}",
        reply.status.code
    );
    assert!(
        reply.status.detail.contains("grant is expired"),
        "expiry must name the cause, got: {}",
        reply.status.detail
    );

    let grant_id =
        issue_collection_grant(&fixture, "Read", GRANTEE, "2030-01-01T00:00:00.000000Z").await;
    let reply = query_handler
        .run(
            TENANT,
            &signed_query(
                Some(&grant_id),
                Some(&grant_id),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);

    revoke_grant(&fixture, &grant_id, "2025-01-01T00:04:00.000000Z").await;
    let reply = query_handler
        .run(
            TENANT,
            &signed_query(
                Some(&grant_id),
                Some(&grant_id),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert!(
        reply.status.code >= 400,
        "revoked grant must not authorize, got {}",
        reply.status.code
    );
    assert!(
        reply.status.detail.contains("grant is revoked"),
        "revocation must name the cause, got: {}",
        reply.status.detail
    );
}

// The delivery recheck runs against a context admitted from a signed wire
// message — not a hand-built one — and a later revocation terminates it.
#[tokio::test]
// Covers: DWN-AUTH-005
async fn wire_grant_context_fails_delivery_after_revocation() {
    let fixture = collection_fixture().await;
    let grant_id =
        issue_collection_grant(&fixture, "Read", GRANTEE, "2030-01-01T00:00:00.000000Z").await;

    let request = signed_subscribe(
        Some(&grant_id),
        Some(&grant_id),
        crate::testing::bob_signer(),
    )
    .await;
    let message: Message<Descriptor> =
        serde_json::from_value(request).expect("subscribe request must deserialize");
    let resolver = test_resolver();
    let auth_ctx = permissions::validate_authorization_signature(&message, Some(&resolver), true)
        .await
        .expect("wire grant invocation must validate")
        .expect("subscribe requires authorization");
    assert_eq!(
        auth_ctx.permission_grant_id(),
        Some(grant_id.as_str()),
        "wire context must carry the invoked grant"
    );

    let filter = note_filter();
    let auth = DeliveryAuthorization {
        message,
        filter,
        auth_ctx,
        grant_valid_at_open: true,
        role_invoked: false,
        request_timestamp: TS_REQUEST.to_string(),
        control_only: false,
    };
    authorize_records_delivery(TENANT, &auth, &fixture.message_store)
        .await
        .expect("live grant must authorize delivery");

    revoke_grant(&fixture, &grant_id, "2025-01-01T00:04:00.000000Z").await;
    let error = authorize_records_delivery(TENANT, &auth, &fixture.message_store)
        .await
        .expect_err("revoked grant must fail delivery");
    assert_eq!(
        error.code,
        SubscriptionErrorCode::RecordsDeliveryAuthorizationFailed
    );
}
