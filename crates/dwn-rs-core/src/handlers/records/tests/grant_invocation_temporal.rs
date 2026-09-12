//! Temporal, negative, and builder grant-invocation cases: not-yet-active
//! grants, missing grants, historical Delete replay after revocation,
//! post-revocation Count behavior, context-boundary scope, public
//! `Message::create` builder round-trips carrying grant ids, malformed
//! descriptor schema negatives, and live-stream termination on revocation.

use super::grant_invocation::{
    collection_fixture, issue_collection_grant, issue_collection_grant_on, note_filter,
    revoke_grant, revoke_grant_on, signed_count, signed_delete, signed_query, signed_subscribe,
    GRANTEE, TENANT, TS_REQUEST,
};
use super::*;
use crate::descriptors::records::{
    CountParameters, DeleteParameters, QueryParameters, SubscribeParameters,
};
use crate::descriptors::{
    DeleteDescriptor as RecordsDeleteDescriptor, RecordsCountDescriptor, RecordsQueryDescriptor,
    SubscribeDescriptor as RecordsSubscribeDescriptor,
};

// A grant that activates after the signed request time must not authorize it,
// and a grant id that resolves to nothing must fail closed.
#[tokio::test]
// Covers: DWN-AUTH-004
async fn not_yet_active_and_missing_grants_rejected() {
    let fixture = collection_fixture().await;
    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);

    // The grant's activation follows its own signed time: a grant written in
    // February cannot authorize a request signed in January.
    let activating_grant_data = Bytes::from(
        serde_json::to_vec(&json!({
            "dateExpires": "2030-01-01T00:00:00.000000Z",
            "scope": {
                "interface": "Records",
                "method": "Read",
                "protocol": "http://example.com/notes",
                "protocolPath": "note",
            },
        }))
        .unwrap(),
    );
    let write_handler = RecordsWriteHandler::<_, _>::new(
        fixture.message_store.clone(),
        fixture.data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let activating = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some(GRANTEE.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&activating_grant_data).to_string(),
        data_size: activating_grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-02-01T00:00:00.000000Z")
    })
    .await;
    let activating_id = activating["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .run(TENANT, &activating, Some(activating_grant_data))
            .await
            .status
            .code,
        202
    );
    // The request is signed 2025-01-01, before the grant activates in February.
    let reply = query_handler
        .run(
            TENANT,
            &signed_query(
                Some(&activating_id),
                Some(&activating_id),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert!(
        reply.status.code >= 400,
        "not-yet-active grant must not authorize, got {}",
        reply.status.code
    );
    assert!(
        reply.status.detail.contains("grant is not active"),
        "activation must name the cause, got: {}",
        reply.status.detail
    );

    let reply = query_handler
        .run(
            TENANT,
            &signed_query(
                Some("missing-grant-id"),
                Some("missing-grant-id"),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert!(
        reply.status.code >= 400,
        "missing grant must fail closed, got {}",
        reply.status.code
    );
    assert!(
        reply
            .status
            .detail
            .contains("could not find permission grant"),
        "missing grant must name the cause, got: {}",
        reply.status.detail
    );
}

// Replaying a historically valid granted Delete after the grant is revoked
// returns the exact duplicate without fresh authorization: the settled
// tombstone is classified before mutable grant state is consulted, so the
// later revocation neither reauthorizes nor disturbs it.
#[tokio::test]
// Covers: DWN-AUTH-004, DWN-REC-003
async fn historical_granted_delete_replay_after_revocation() {
    let fixture = collection_fixture().await;
    let grant_id =
        issue_collection_grant(&fixture, "Delete", GRANTEE, "2030-01-01T00:00:00.000000Z").await;

    let delete_handler = RecordsDeleteHandler::new(
        fixture.message_store.clone(),
        fixture.data_store.clone(),
        None,
    );
    let delete = signed_delete(
        &fixture.note_record_id,
        Some(&grant_id),
        Some(&grant_id),
        crate::testing::bob_signer(),
    )
    .await;
    let reply = delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // Revocation lands after the Delete's signed time, so the original
    // admission stays valid and only the replay classification can answer.
    revoke_grant(&fixture, &grant_id, "2025-01-01T00:15:00.000000Z").await;
    let reply = delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(
        reply.status.code, 409,
        "exact replay must stay idempotent after revocation, got {} {}",
        reply.status.code, reply.status.detail
    );

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);
    let reply = query_handler
        .run(
            TENANT,
            &signed_query(None, None, crate::testing::test_signer()).await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert!(
        !reply.reply.entries.as_ref().unwrap().iter().any(|entry| {
            serde_json::to_value(entry).unwrap()["recordId"].as_str()
                == Some(fixture.note_record_id.as_str())
        }),
        "replayed delete must not resurrect the record"
    );
}

// Revocation drains both the entries and the count of new requests.
#[tokio::test]
// Covers: DWN-AUTH-004, DWN-REC-008
async fn revoked_grant_drains_count() {
    let fixture = collection_fixture().await;
    let grant_id =
        issue_collection_grant(&fixture, "Read", GRANTEE, "2030-01-01T00:00:00.000000Z").await;

    let count_handler = RecordsCountHandler::new(fixture.message_store.clone(), None);
    let reply = count_handler
        .run(
            TENANT,
            &signed_count(
                Some(&grant_id),
                Some(&grant_id),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(reply.reply.count, Some(1));

    revoke_grant(&fixture, &grant_id, "2025-01-01T00:04:00.000000Z").await;
    let reply = count_handler
        .run(
            TENANT,
            &signed_count(
                Some(&grant_id),
                Some(&grant_id),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    // A presented but invalid credential errors; presenting none would
    // instead yield the public-only population.
    assert_eq!(
        reply.status.code, 401,
        "revoked grant must not authorize, got {} {}",
        reply.status.code, reply.status.detail
    );
    assert!(
        reply.status.detail.contains("grant is revoked"),
        "revocation must name the cause, got: {}",
        reply.status.detail
    );
}

// A grant scoped to one context does not cover a contextless filter over the
// same protocol path: context is a boundary, not a hint.
#[tokio::test]
// Covers: DWN-AUTH-003
async fn context_scoped_grant_rejects_contextless_filter() {
    let fixture = collection_fixture().await;
    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);

    let scoped_data = Bytes::from(
        serde_json::to_vec(&json!({
            "dateExpires": "2030-01-01T00:00:00.000000Z",
            "scope": {
                "interface": "Records",
                "method": "Read",
                "protocol": "http://example.com/notes",
                "contextId": "some-context",
            },
        }))
        .unwrap(),
    );
    let write_handler = RecordsWriteHandler::<_, _>::new(
        fixture.message_store.clone(),
        fixture.data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let scoped = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some(GRANTEE.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&scoped_data).to_string(),
        data_size: scoped_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let scoped_id = scoped["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .run(TENANT, &scoped, Some(scoped_data))
            .await
            .status
            .code,
        202
    );

    let reply = query_handler
        .run(
            TENANT,
            &signed_query(
                Some(&scoped_id),
                Some(&scoped_id),
                crate::testing::bob_signer(),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(
        reply.status.code, 401,
        "context-scoped grant must not cover a contextless filter"
    );
    assert!(
        reply.status.detail.contains("grant is outside of scope"),
        "context boundary must name the cause, got: {}",
        reply.status.detail
    );
}

/// Rewraps a typed builder's flat authorization fields into the nested wire
/// envelope handlers admit.
///
/// Typed non-Write messages serialize `Authorization` flat (`signature` at
/// top level) while the DWN wire shape nests it under `authorization`;
/// admission looks up the nested key, so the flat shape reads as unsigned.
/// The rewrap keeps these tests about builder threading (descriptor id plus
/// signed payload id, which is the #283 contract) rather than the envelope
/// asymmetry, which needs its own contract decision as a follow-up.
fn wire_envelope<D>(built: &Message<D>) -> serde_json::Value
where
    D: MessageDescriptor + serde::Serialize,
{
    let built = serde_json::to_value(built).unwrap();
    let mut authorization = serde_json::Map::new();
    for (key, value) in built.as_object().unwrap() {
        if key != "descriptor" {
            authorization.insert(key.clone(), value.clone());
        }
    }
    json!({
        "descriptor": built["descriptor"],
        "authorization": authorization,
    })
}

// The public typed builders thread a grant id into both the descriptor and
// the signed payload for every collection method and Delete.
#[tokio::test]
// Covers: DWN-AUTH-008
async fn typed_builders_carry_grant_invocation() {
    let fixture = collection_fixture().await;
    let read_grant =
        issue_collection_grant(&fixture, "Read", GRANTEE, "2030-01-01T00:00:00.000000Z").await;
    let delete_grant =
        issue_collection_grant(&fixture, "Delete", GRANTEE, "2030-01-01T00:00:00.000000Z").await;

    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);
    let built: Message<RecordsQueryDescriptor> = Message::create(
        QueryParameters {
            message_timestamp: Some(parse_time(TS_REQUEST)),
            filter: Some(note_filter()),
            permission_grant_id: Some(read_grant.clone()),
            ..Default::default()
        },
        Some(crate::testing::bob_signer()),
    )
    .await
    .expect("query builder must carry the grant");
    let request = wire_envelope(&built);
    assert_eq!(
        request["descriptor"]["permissionGrantId"].as_str(),
        Some(read_grant.as_str())
    );
    let reply = query_handler.run(TENANT, &request, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(reply.reply.entries.as_ref().unwrap().len(), 1);

    let count_handler = RecordsCountHandler::new(fixture.message_store.clone(), None);
    let built: Message<RecordsCountDescriptor> = Message::create(
        CountParameters {
            message_timestamp: Some(parse_time(TS_REQUEST)),
            filter: note_filter(),
            permission_grant_id: Some(read_grant.clone()),
            ..Default::default()
        },
        Some(crate::testing::bob_signer()),
    )
    .await
    .expect("count builder must carry the grant");
    let reply = count_handler
        .run(TENANT, &wire_envelope(&built), None)
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(reply.reply.count, Some(1));

    let subscribe_handler = RecordsSubscribeHandler::new(fixture.message_store.clone(), None);
    let built: Message<RecordsSubscribeDescriptor> = Message::create(
        SubscribeParameters {
            message_timestamp: Some(parse_time(TS_REQUEST)),
            filters: note_filter(),
            permission_grant_id: Some(read_grant.clone()),
            ..Default::default()
        },
        Some(crate::testing::bob_signer()),
    )
    .await
    .expect("subscribe builder must carry the grant");
    let reply = subscribe_handler
        .run(TENANT, &wire_envelope(&built), None)
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(reply.reply.entries.as_ref().unwrap().len(), 1);

    let delete_handler = RecordsDeleteHandler::new(
        fixture.message_store.clone(),
        fixture.data_store.clone(),
        None,
    );
    let built: Message<RecordsDeleteDescriptor> = Message::create(
        DeleteParameters {
            record_id: fixture.note_record_id.clone(),
            message_timestamp: Some(parse_time(TS_REQUEST)),
            permission_grant_id: Some(delete_grant.clone()),
            ..Default::default()
        },
        Some(crate::testing::bob_signer()),
    )
    .await
    .expect("delete builder must carry the grant");
    let request = wire_envelope(&built);
    assert_eq!(
        request["descriptor"]["permissionGrantId"].as_str(),
        Some(delete_grant.as_str())
    );
    let reply = delete_handler.run(TENANT, &request, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// A live subscription opened by grant delivers matching events, then
// terminates with the defined error once the grant is revoked.
#[tokio::test]
// Covers: DWN-AUTH-005
async fn live_subscription_terminates_when_grant_revoked() {
    let wake_bus = InProcessWakeBus::new();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    message_store.open().await.unwrap();
    let mut data_store = TestDataStore::default();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;

    let write_handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let grant_id = issue_collection_grant_on(
        &write_handler,
        "Read",
        GRANTEE,
        "2030-01-01T00:00:00.000000Z",
    )
    .await;

    let event_log = DurableEventLog::new(message_store.clone(), wake_bus, None, None);
    let subscribe_handler = RecordsEventLogSubscribeHandler::new(
        message_store.clone(),
        event_log,
        Some(Arc::new(test_resolver())),
    );
    let delivered = Arc::new(std::sync::RwLock::new(Vec::new()));
    let result = subscribe_handler
        .handle_subscribe(
            TENANT,
            &signed_subscribe(
                Some(&grant_id),
                Some(&grant_id),
                crate::testing::bob_signer(),
            )
            .await,
            {
                let delivered = delivered.clone();
                Box::new(move |message| delivered.write().unwrap().push(message))
            },
        )
        .await;
    assert_eq!(
        result.reply.status.code, 200,
        "{}",
        result.reply.status.detail
    );
    assert!(result.subscription.is_some(), "stream must stay open");

    async fn admit_note(
        handler: &RecordsWriteHandler<MemoryMessageStore, TestDataStore>,
        body: &'static str,
        timestamp: &str,
    ) {
        let data = Bytes::from_static(body.as_bytes());
        let note = signed_write_message(WriteSpec {
            data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
            data_size: data.len() as u64,
            ..WriteSpec::new(timestamp)
        })
        .await;
        assert_eq!(
            handler.run(TENANT, &note, Some(data)).await.status.code,
            202
        );
    }
    admit_note(&write_handler, "live one", "2025-01-01T00:11:00.000000Z").await;

    async fn await_messages(
        delivered: &Arc<std::sync::RwLock<Vec<SubscriptionMessage>>>,
        count: usize,
    ) -> Vec<SubscriptionMessage> {
        for _ in 0..500 {
            {
                let guard = delivered.read().unwrap();
                if guard.len() >= count {
                    return guard.clone();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        delivered.read().unwrap().clone()
    }
    let messages = await_messages(&delivered, 1).await;
    assert!(
        matches!(messages.first(), Some(SubscriptionMessage::Event { .. })),
        "live grant-visible write must deliver, got {messages:?}"
    );

    revoke_grant_on(&write_handler, &grant_id, "2025-06-01T00:00:00.000000Z").await;
    admit_note(&write_handler, "live two", "2025-01-01T00:12:00.000000Z").await;
    let messages = await_messages(&delivered, 2).await;
    assert!(
        messages.len() >= 2,
        "revocation must terminate the stream, got {messages:?}"
    );
    assert!(
        matches!(
            messages.get(1),
            Some(SubscriptionMessage::Error { error, .. })
                if error.code == SubscriptionErrorCode::RecordsDeliveryAuthorizationFailed
        ),
        "termination must carry the defined error, got {messages:?}"
    );
}

// Malformed invocations fail schema validation, not grant evaluation.
#[tokio::test]
async fn malformed_grant_invocation_fails_schema() {
    let fixture = collection_fixture().await;
    let query_handler = RecordsQueryHandler::new(fixture.message_store.clone(), None);

    let mut descriptor = serde_json::to_value(RecordsQueryDescriptor {
        message_timestamp: parse_time(TS_REQUEST),
        filter: note_filter(),
        permission_grant_id: None,
        pagination: None,
        date_sort: None,
    })
    .unwrap();
    descriptor["permissionGrantId"] = json!(123);
    let signature = signature_for_descriptor(
        &descriptor,
        json!({ "permissionGrantId": "grant-1" }),
        crate::testing::bob_signer(),
    )
    .await;
    let reply = query_handler
        .run(
            TENANT,
            &json!({ "descriptor": descriptor, "authorization": { "signature": signature } }),
            None,
        )
        .await;
    assert_eq!(
        reply.status.code, 400,
        "non-string grant id must fail schema validation"
    );

    let mut descriptor = serde_json::to_value(RecordsQueryDescriptor {
        message_timestamp: parse_time(TS_REQUEST),
        filter: note_filter(),
        permission_grant_id: Some("grant-1".to_string()),
        pagination: None,
        date_sort: None,
    })
    .unwrap();
    descriptor["unknownProperty"] = json!(true);
    let signature = signature_for_descriptor(
        &descriptor,
        json!({ "permissionGrantId": "grant-1" }),
        crate::testing::bob_signer(),
    )
    .await;
    let reply = query_handler
        .run(
            TENANT,
            &json!({ "descriptor": descriptor, "authorization": { "signature": signature } }),
            None,
        )
        .await;
    assert_eq!(
        reply.status.code, 400,
        "unknown descriptor properties must fail schema validation"
    );
}
