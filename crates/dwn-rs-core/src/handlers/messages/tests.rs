use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use futures_util::stream;
use serde_json::json;
use ssi_jwk::Algorithm;

use crate::auth::{ed25519_jwk, Jws, PrivateJwkSigner, StaticPublicKeyResolver, JWK};
use crate::cid::{
    generate_cid_from_json, generate_dag_pb_cid_from_bytes, generate_message_cid_from_json,
};
use crate::descriptors::{
    MessagesSubscribeDescriptor, MessagesSyncDescriptor, RecordsWriteDescriptor,
};
use crate::dwn::{Handler, MethodHandlerRequest};
use crate::errors::{DataStoreError, MessageStoreError};
use crate::handlers::messages::subscribe::MessagesSubscribeHandler;
use crate::handlers::messages::sync::MessagesSyncHandler;
use crate::interfaces::messages::descriptors::messages::SyncAction;
use crate::stores::durable_event_log::DurableEventLog;
use crate::stores::memory::MemoryMessageStore;
use crate::stores::replication_feed_reader::{build_token, GLOBAL_DOMAIN};
use crate::stores::state_index::MemoryStateIndex;
use crate::stores::wake::InProcessWakeBus;
use crate::stores::{
    DataStore, DataStoreGetResult, DataStorePutResult, EventLog, EventLogReadOptions, KeyValues,
    MessageQueryResult, MessageStore, ReplicationFeedReader, StateIndex, SubscriptionMessage,
};
use crate::{message_filters, permissions, Descriptor, MapValue, Message, ProgressToken, Value};

#[tokio::test]
async fn messages_sync_diff_returns_remote_messages_and_inline_data() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore;
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();

    let (cid, stored_message) = records_write_with_inline_data();
    message_store
        .insert("did:example:alice", &cid, stored_message.clone())
        .await;
    state_index
        .insert(
            "did:example:alice",
            &cid,
            MapValue::from([(
                "protocol".to_string(),
                Value::String("http://example.com/notes".to_string()),
            )]),
        )
        .await
        .unwrap();

    let handler = MessagesSyncHandler::new(
        message_store,
        data_store,
        state_index,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_sync_message(SyncSpec {
        action: SyncAction::Diff,
        protocol: Some("http://example.com/notes".to_string()),
        depth: Some(1),
        hashes: Some(BTreeMap::new()),
        signer: test_signer(),
        permission_grant_ids: None,
        ..SyncSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;

    let reply = handler
        .run(MethodHandlerRequest::new(
            "did:example:alice",
            &request,
            None,
        ))
        .await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    let only_remote = reply.reply.only_remote.as_ref().unwrap();
    assert_eq!(only_remote.len(), 1);
    assert_eq!(only_remote[0].message_cid.as_deref(), Some(cid.as_str()));
    assert_eq!(only_remote[0].encoded_data.as_deref(), Some("aGVsbG8"));
    assert!(
        serde_json::to_value(only_remote[0].message.as_ref().unwrap())
            .unwrap()
            .get("encodedData")
            .is_none()
    );
    assert!(reply.reply.only_local.as_ref().unwrap().is_empty());
}

#[tokio::test]
async fn messages_sync_is_not_authorized_by_messages_read_grant() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore;
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();

    let grant = permission_grant_message("grant-sync-1", Some("http://example.com/notes")).await;
    message_store
        .insert("did:example:alice", "grant-sync-1", grant)
        .await;
    let handler = MessagesSyncHandler::new(
        message_store,
        data_store,
        state_index,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_sync_message(SyncSpec {
        action: SyncAction::Root,
        protocol: Some("http://example.com/notes".to_string()),
        signer: bob_signer(),
        permission_grant_ids: Some(vec!["grant-sync-1".to_string()]),
        ..SyncSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;

    let reply = handler
        .run(MethodHandlerRequest::new(
            "did:example:alice",
            &request,
            None,
        ))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert!(reply
        .status
        .detail
        .contains("authorization signature is mismatched"));
}

#[tokio::test]
async fn messages_sync_rejection_does_not_depend_on_protocol_scope() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore;
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();

    let grant = permission_grant_message("grant-sync-2", Some("http://example.com/notes")).await;
    message_store
        .insert("did:example:alice", "grant-sync-2", grant)
        .await;
    let handler = MessagesSyncHandler::new(
        message_store,
        data_store,
        state_index,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_sync_message(SyncSpec {
        action: SyncAction::Root,
        signer: bob_signer(),
        permission_grant_ids: Some(vec!["grant-sync-2".to_string()]),
        ..SyncSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;

    let reply = handler
        .run(MethodHandlerRequest::new(
            "did:example:alice",
            &request,
            None,
        ))
        .await;
    assert_eq!(reply.status.code, 400);
    assert!(reply
        .status
        .detail
        .contains("authorization signature is mismatched"));
}

#[tokio::test]
async fn messages_subscribe_replays_from_cursor_and_sends_eose() {
    const TENANT: &str = "did:example:alice";

    let wake_bus = InProcessWakeBus::new();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    message_store.open().await.unwrap();

    let (_, stored_message) = records_write_with_inline_data();
    let first_message = retimestamped(&stored_message, "2025-01-01T00:01:00.000000Z");
    let second_message = retimestamped(&stored_message, "2025-01-01T00:02:00.000000Z");
    let second_cid =
        generate_message_cid_from_json(&serde_json::to_value(&second_message).unwrap())
            .unwrap()
            .to_string();
    for message in [&first_message, &second_message] {
        let indexes = records_feed_indexes("http://example.com/notes");
        message_store
            .put(TENANT, message.clone(), indexes)
            .await
            .unwrap();
    }

    let event_log = DurableEventLog::new(message_store.clone(), wake_bus, None, None);

    let read = EventLog::read(
        &event_log,
        TENANT,
        Some(EventLogReadOptions {
            limit: Some(1),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(read.events.len(), 1);
    let first = read
        .cursor
        .expect("scan cursor after the first committed entry");

    let delivered = Arc::new(RwLock::new(Vec::new()));
    let delivered_for_listener = delivered.clone();
    let handler = MessagesSubscribeHandler::new(
        message_store.clone(),
        event_log,
        None::<MemoryMessageStore>,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_subscribe_message(SubscribeSpec {
        filters: vec![message_filters::Messages {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        }],
        cursor: Some(first),
        ..SubscribeSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;

    let message = serde_json::from_value(request.clone()).unwrap();
    let result = handler
        .handle_subscribe(
            "did:example:alice",
            &message,
            Box::new(move |message| delivered_for_listener.write().unwrap().push(message)),
        )
        .await;
    assert_eq!(
        result.reply.status.code, 200,
        "{}",
        result.reply.status.detail
    );
    let reply_body = serde_json::to_value(&result.reply.reply).unwrap();
    assert_eq!(
        reply_body["subscriptionId"],
        result.subscription.as_ref().unwrap().id
    );
    let delivered = delivered.read().unwrap();
    assert_eq!(delivered.len(), 2);
    match &delivered[0] {
        SubscriptionMessage::Event { cursor, .. } => {
            assert_eq!(cursor.position, "2");
            assert_eq!(cursor.message_cid.as_deref(), Some(second_cid.as_str()));
        }
        other => panic!("expected event, got {other:?}"),
    }
    match &delivered[1] {
        SubscriptionMessage::Eose { cursor } => {
            assert_eq!(cursor.position, "2");
            assert_eq!(cursor.message_cid.as_deref(), Some(second_cid.as_str()));
        }
        other => panic!("expected eose, got {other:?}"),
    }
}

#[tokio::test]
async fn messages_subscribe_maps_progress_gap_to_410() {
    const TENANT: &str = "did:example:alice";

    let wake_bus = InProcessWakeBus::new();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    message_store.open().await.unwrap();

    let (_, stored_message) = records_write_with_inline_data();
    let indexes = records_feed_indexes("http://example.com/notes");
    message_store
        .put(TENANT, stored_message, indexes)
        .await
        .unwrap();

    // A token from a superseded feed epoch can never resume; the reader must
    // surface it as a structured progress gap.
    let stale_cursor = build_token(TENANT, "00000000-superseded-epoch", 1, None);

    let event_log = DurableEventLog::new(message_store.clone(), wake_bus, None, None);
    let handler = MessagesSubscribeHandler::new(
        message_store,
        event_log,
        None::<MemoryMessageStore>,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_subscribe_message(SubscribeSpec {
        filters: vec![message_filters::Messages {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        }],
        cursor: Some(stale_cursor),
        ..SubscribeSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;

    let message = serde_json::from_value(request.clone()).unwrap();
    let result = handler
        .handle_subscribe("did:example:alice", &message, Box::new(|_| {}))
        .await;
    assert_eq!(result.reply.status.code, 410);
    let reply_body = serde_json::to_value(&result.reply.reply).unwrap();
    assert_eq!(reply_body["error"]["code"], "ProgressGap");
    assert_eq!(reply_body["error"]["reason"], "epoch_mismatch");
    assert!(result.subscription.is_none());
}

#[tokio::test]
async fn messages_subscribe_stops_replay_when_grant_has_expired_at_delivery() {
    const TENANT: &str = "did:example:alice";
    const PROTOCOL: &str = "http://example.com/notes";

    let mut authorization_store = TestMessageStore::default();
    authorization_store.open().await.unwrap();
    let grant = permission_grant_message("grant-expired-at-delivery", Some(PROTOCOL)).await;
    authorization_store
        .insert(TENANT, "grant-expired-at-delivery", grant)
        .await;

    let wake_bus = InProcessWakeBus::new();
    let mut feed_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    feed_store.open().await.unwrap();
    let event_log = DurableEventLog::new(feed_store.clone(), wake_bus, None, None);

    let delivered = Arc::new(RwLock::new(Vec::new()));
    let delivered_for_listener = delivered.clone();
    let handler = MessagesSubscribeHandler::new(
        authorization_store,
        event_log,
        None::<MemoryMessageStore>,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_subscribe_message(SubscribeSpec {
        filters: vec![message_filters::Messages {
            protocol: Some(PROTOCOL.to_string()),
            ..Default::default()
        }],
        permission_grant_ids: Some(vec!["grant-expired-at-delivery".to_string()]),
        signer: bob_signer(),
        ..SubscribeSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;

    let message = serde_json::from_value(request).unwrap();
    let result = handler
        .handle_subscribe(
            TENANT,
            &message,
            Box::new(move |message| delivered_for_listener.write().unwrap().push(message)),
        )
        .await;

    assert_eq!(result.reply.status.code, 200);

    let (_, stored_message) = records_write_with_inline_data();
    feed_store
        .put(TENANT, stored_message, records_feed_indexes(PROTOCOL))
        .await
        .unwrap();
    for _ in 0..20 {
        if !delivered.read().unwrap().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }

    let delivered = delivered.read().unwrap();
    assert_eq!(delivered.len(), 1);
    let SubscriptionMessage::Error { error, .. } = &delivered[0] else {
        panic!("delivery authorization failure expected");
    };
    assert_eq!(
        error.code,
        crate::stores::SubscriptionErrorCode::DeliveryAuthorizationFailed
    );
}

#[tokio::test]
async fn messages_subscribe_role_reply_identifies_the_resolved_role_record() {
    use crate::handlers::messages::authorization::tests::{exact_filter, role_store, ROLE, TENANT};

    let (message_store, _) = role_store().await;
    let handler = MessagesSubscribeHandler::new(
        message_store.clone(),
        (),
        Some(message_store),
        Some(Arc::new(test_resolver())),
    );
    let request = signed_subscribe_message(SubscribeSpec {
        filters: vec![exact_filter("thread/message")],
        protocol_role: Some(ROLE.to_string()),
        ..SubscribeSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;
    let message = serde_json::from_value(request).unwrap();

    let result = handler
        .handle_subscribe(TENANT, &message, Box::new(|_| {}))
        .await;

    assert_eq!(
        result.reply.status.code, 200,
        "{}",
        result.reply.status.detail
    );
    assert_eq!(
        result.reply.reply.role_record_id.as_deref(),
        Some("role-record-1")
    );
    assert!(result.reply.reply.head.is_none());
    assert!(result.reply.reply.fingerprint.is_none());
}

#[tokio::test]
async fn messages_subscribe_attaches_post_installation_head_and_fingerprint() {
    const TENANT: &str = "did:example:alice";

    let mut message_store = MemoryMessageStore::default();
    message_store.open().await.unwrap();
    let (_, stored_message) = records_write_with_inline_data();
    message_store
        .put(
            TENANT,
            stored_message,
            records_feed_indexes("http://example.com/notes"),
        )
        .await
        .unwrap();
    let expected_fingerprint = message_store
        .fingerprint(TENANT, &[GLOBAL_DOMAIN.to_string()])
        .await
        .unwrap()
        .hex();

    let handler = MessagesSubscribeHandler::new(
        message_store.clone(),
        (),
        Some(message_store),
        Some(Arc::new(test_resolver())),
    );
    let request = signed_subscribe_message(SubscribeSpec::new("2025-01-01T00:10:00.000000Z")).await;
    let message = serde_json::from_value(request).unwrap();

    let result = handler
        .handle_subscribe(TENANT, &message, Box::new(|_| {}))
        .await;

    assert_eq!(result.reply.status.code, 200);
    assert_eq!(result.reply.reply.head.as_ref().unwrap().position, "1");
    assert_eq!(
        result.reply.reply.fingerprint.as_deref(),
        Some(expected_fingerprint.as_str())
    );

    let request = signed_subscribe_message(SubscribeSpec {
        filters: vec![message_filters::Messages {
            protocol: Some("http://example.com/notes".to_string()),
            method: Some("Write".to_string()),
            ..Default::default()
        }],
        ..SubscribeSpec::new("2025-01-01T00:11:00.000000Z")
    })
    .await;
    let message = serde_json::from_value(request).unwrap();
    let result = handler
        .handle_subscribe(TENANT, &message, Box::new(|_| {}))
        .await;
    assert_eq!(result.reply.reply.head.as_ref().unwrap().position, "1");
    assert!(result.reply.reply.fingerprint.is_none());
}

#[tokio::test]
async fn messages_subscribe_empty_feed_uses_position_zero_snapshot() {
    const TENANT: &str = "did:example:alice";
    let mut message_store = MemoryMessageStore::default();
    message_store.open().await.unwrap();
    let handler = MessagesSubscribeHandler::new(
        message_store.clone(),
        (),
        Some(message_store),
        Some(Arc::new(test_resolver())),
    );
    let request = signed_subscribe_message(SubscribeSpec::new("2025-01-01T00:10:00.000000Z")).await;
    let message = serde_json::from_value(request).unwrap();

    let result = handler
        .handle_subscribe(TENANT, &message, Box::new(|_| {}))
        .await;

    assert_eq!(result.reply.reply.head.as_ref().unwrap().position, "0");
    let zero_fingerprint = "0".repeat(64);
    assert_eq!(
        result.reply.reply.fingerprint.as_deref(),
        Some(zero_fingerprint.as_str())
    );
}

#[tokio::test]
async fn messages_subscribe_rejects_filter_outside_grant_protocol_path_scope() {
    let mut message_store = TestMessageStore::default();
    let event_log = feed_backed_event_log();
    message_store.open().await.unwrap();

    let grant = permission_grant_message_with_scope(
        "grant-subscribe-path",
        json!({
            "interface": "Messages",
            "method": "Read",
            "protocol": "http://example.com/notes",
            "protocolPath": "note",
        }),
    )
    .await;
    message_store
        .insert("did:example:alice", "grant-subscribe-path", grant)
        .await;

    let handler = MessagesSubscribeHandler::new(
        message_store,
        event_log,
        None::<MemoryMessageStore>,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_subscribe_message(SubscribeSpec {
        filters: vec![message_filters::Messages {
            protocol: Some("http://example.com/notes".to_string()),
            protocol_path_prefix: Some("comment".to_string()),
            ..Default::default()
        }],
        permission_grant_ids: Some(vec!["grant-subscribe-path".to_string()]),
        signer: bob_signer(),
        ..SubscribeSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;

    let message = serde_json::from_value(request.clone()).unwrap();
    let result = handler
        .handle_subscribe("did:example:alice", &message, Box::new(|_| {}))
        .await;
    assert_eq!(
        result.reply.status.code, 401,
        "{}",
        result.reply.status.detail
    );
    assert!(result
        .reply
        .status
        .detail
        .contains("grant is outside of scope"));
}

#[tokio::test]
async fn messages_subscribe_allows_filters_covered_by_different_grants() {
    let mut message_store = TestMessageStore::default();
    let event_log = feed_backed_event_log();
    message_store.open().await.unwrap();

    for (grant_id, protocol) in [
        ("grant-notes", "http://example.com/notes"),
        ("grant-chat", "http://example.com/chat"),
    ] {
        let grant = permission_grant_message(grant_id, Some(protocol)).await;
        message_store
            .insert("did:example:alice", grant_id, grant)
            .await;
    }

    let handler = MessagesSubscribeHandler::new(
        message_store,
        event_log,
        None::<MemoryMessageStore>,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_subscribe_message(SubscribeSpec {
        filters: vec![
            message_filters::Messages {
                protocol: Some("http://example.com/notes".to_string()),
                ..Default::default()
            },
            message_filters::Messages {
                protocol: Some("http://example.com/chat".to_string()),
                ..Default::default()
            },
        ],
        permission_grant_ids: Some(vec!["grant-chat".to_string(), "grant-notes".to_string()]),
        signer: bob_signer(),
        ..SubscribeSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;

    let message = serde_json::from_value(request.clone()).unwrap();
    let result = handler
        .handle_subscribe("did:example:alice", &message, Box::new(|_| {}))
        .await;
    assert_eq!(
        result.reply.status.code, 200,
        "{}",
        result.reply.status.detail
    );
}

fn records_write_with_inline_data() -> (String, Message<Descriptor>) {
    let data = Bytes::from_static(b"hello");
    let descriptor = RecordsWriteDescriptor {
        protocol: "http://example.com/notes".to_string(),
        protocol_path: "note".to_string(),
        recipient: None,
        schema: None,
        tags: None,
        parent_id: None,
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        date_created: parse_time("2025-01-01T00:00:00.000000Z"),
        message_timestamp: parse_time("2025-01-01T00:00:00.000000Z"),
        published: None,
        date_published: None,
        data_format: "text/plain".to_string(),
        permission_grant_id: None,
        squash: None,
    };
    let wire_message = json!({
        "descriptor": descriptor,
        "recordId": "record-1",
        "contextId": "record-1"
    });
    let cid = generate_cid_from_json(&wire_message).unwrap().to_string();
    let stored_message = json!({
        "descriptor": wire_message["descriptor"].clone(),
        "recordId": "record-1",
        "contextId": "record-1",
        "encodedData": URL_SAFE_NO_PAD.encode(data),
    });
    (cid, serde_json::from_value(stored_message).unwrap())
}

/// Indexes matching what real `RecordsWrite` handling commits, so feed-backed
/// subscription filters can match seeded messages.
fn records_feed_indexes(protocol: &str) -> KeyValues {
    KeyValues::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        ("method".to_string(), Value::String("Write".to_string())),
        ("protocol".to_string(), Value::String(protocol.to_string())),
    ])
}

fn retimestamped(message: &Message<Descriptor>, timestamp: &str) -> Message<Descriptor> {
    let mut value = serde_json::to_value(message).unwrap();
    value["descriptor"]["messageTimestamp"] = serde_json::json!(timestamp);
    serde_json::from_value(value).unwrap()
}

/// A durable event log over an empty feed, for tests that need a handler
/// wired to a log without seeding any events.
fn feed_backed_event_log() -> DurableEventLog<MemoryMessageStore, InProcessWakeBus> {
    let wake_bus = InProcessWakeBus::new();
    let message_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    DurableEventLog::new(message_store, wake_bus, None, None)
}

async fn permission_grant_message(grant_id: &str, protocol: Option<&str>) -> Message<Descriptor> {
    let scope = match protocol {
        Some(protocol) => json!({
            "interface": "Messages",
            "method": "Read",
            "protocol": protocol,
        }),
        None => json!({
            "interface": "Messages",
            "method": "Read",
        }),
    };
    permission_grant_message_with_scope(grant_id, scope).await
}

async fn permission_grant_message_with_scope(
    grant_id: &str,
    scope: serde_json::Value,
) -> Message<Descriptor> {
    let data = serde_json::to_vec(&json!({
        "dateExpires": "2025-02-01T00:00:00.000000Z",
        "scope": scope.clone(),
    }))
    .unwrap();
    let descriptor = RecordsWriteDescriptor {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some("did:example:bob".to_string()),
        schema: None,
        tags: scope
            .get("protocol")
            .and_then(serde_json::Value::as_str)
            .map(|protocol| {
                MapValue::from([("protocol".to_string(), Value::String(protocol.to_string()))])
            }),
        parent_id: None,
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        date_created: parse_time("2025-01-01T00:00:00.000000Z"),
        message_timestamp: parse_time("2025-01-01T00:00:00.000000Z"),
        published: None,
        date_published: None,
        data_format: "application/json".to_string(),
        permission_grant_id: None,
        squash: None,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let payload = json!({
        "recordId": grant_id,
        "contextId": grant_id,
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
    });
    let signature = Jws::create(
        serde_json::to_vec(&payload).unwrap().as_slice(),
        &[test_signer()],
    )
    .await
    .unwrap();
    serde_json::from_value(json!({
        "descriptor": descriptor_json,
        "recordId": grant_id,
        "contextId": grant_id,
        "authorization": { "signature": signature },
        "encodedData": URL_SAFE_NO_PAD.encode(data),
    }))
    .unwrap()
}

#[derive(Clone)]
struct SubscribeSpec {
    timestamp: String,
    filters: Vec<message_filters::Messages>,
    permission_grant_ids: Option<Vec<String>>,
    protocol_role: Option<String>,
    cursor: Option<ProgressToken>,
    signer: PrivateJwkSigner,
}

impl SubscribeSpec {
    fn new(timestamp: &str) -> Self {
        Self {
            timestamp: timestamp.to_string(),
            filters: Vec::new(),
            permission_grant_ids: None,
            protocol_role: None,
            cursor: None,
            signer: test_signer(),
        }
    }
}

async fn signed_subscribe_message(spec: SubscribeSpec) -> serde_json::Value {
    let descriptor = MessagesSubscribeDescriptor {
        message_timestamp: parse_time(&spec.timestamp),
        filters: spec.filters,
        permission_grant_ids: spec.permission_grant_ids.clone(),
        cursor: spec.cursor,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let mut payload = serde_json::Map::from_iter([(
        "descriptorCid".to_string(),
        serde_json::Value::String(
            generate_cid_from_json(&descriptor_json)
                .unwrap()
                .to_string(),
        ),
    )]);
    if let Some(permission_grant_ids) = spec.permission_grant_ids {
        payload.insert(
            "permissionGrantIds".to_string(),
            serde_json::to_value(permission_grant_ids).unwrap(),
        );
    }
    if let Some(protocol_role) = spec.protocol_role {
        payload.insert(
            "protocolRole".to_string(),
            serde_json::Value::String(protocol_role),
        );
    }
    let signature = Jws::create(
        serde_json::to_vec(&serde_json::Value::Object(payload))
            .unwrap()
            .as_slice(),
        &[spec.signer],
    )
    .await
    .unwrap();
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature },
    })
}

#[derive(Clone)]
struct SyncSpec {
    timestamp: String,
    action: SyncAction,
    protocol: Option<String>,
    prefix: Option<String>,
    permission_grant_ids: Option<Vec<String>>,
    hashes: Option<BTreeMap<String, String>>,
    depth: Option<u16>,
    signer: PrivateJwkSigner,
}

impl SyncSpec {
    fn new(timestamp: &str) -> Self {
        Self {
            timestamp: timestamp.to_string(),
            action: SyncAction::Root,
            protocol: None,
            prefix: None,
            permission_grant_ids: None,
            hashes: None,
            depth: None,
            signer: test_signer(),
        }
    }
}

async fn signed_sync_message(spec: SyncSpec) -> serde_json::Value {
    let descriptor = MessagesSyncDescriptor {
        message_timestamp: parse_time(&spec.timestamp),
        action: spec.action,
        protocol: spec.protocol,
        prefix: spec.prefix,
        permission_grant_ids: spec.permission_grant_ids.clone(),
        hashes: spec.hashes,
        depth: spec.depth,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let mut payload = serde_json::Map::from_iter([(
        "descriptorCid".to_string(),
        serde_json::Value::String(
            generate_cid_from_json(&descriptor_json)
                .unwrap()
                .to_string(),
        ),
    )]);
    if let Some(permission_grant_ids) = spec.permission_grant_ids {
        payload.insert(
            "permissionGrantIds".to_string(),
            serde_json::to_value(permission_grant_ids).unwrap(),
        );
    }
    let signature = Jws::create(
        serde_json::to_vec(&serde_json::Value::Object(payload))
            .unwrap()
            .as_slice(),
        &[spec.signer],
    )
    .await
    .unwrap();
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature },
    })
}

fn parse_time(value: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

fn test_signer() -> PrivateJwkSigner {
    signer_for("did:example:alice")
}

fn bob_signer() -> PrivateJwkSigner {
    signer_for("did:example:bob")
}

fn signer_for(did: &str) -> PrivateJwkSigner {
    let key_id = format!("{did}#key1");
    PrivateJwkSigner::new(
        &key_id,
        Algorithm::EdDSA,
        ed25519_jwk(
            "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"),
            Some(&key_id),
        )
        .unwrap(),
    )
}

fn test_resolver() -> StaticPublicKeyResolver {
    StaticPublicKeyResolver::new(BTreeMap::from([
        (
            "did:example:alice#key1".to_string(),
            test_public_jwk("did:example:alice#key1"),
        ),
        (
            "did:example:bob#key1".to_string(),
            test_public_jwk("did:example:bob#key1"),
        ),
    ]))
}

fn test_public_jwk(key_id: &str) -> JWK {
    ed25519_jwk(
        "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        None,
        Some(key_id),
    )
    .unwrap()
}

#[derive(Clone, Default)]
struct TestMessageStore {
    rows: Arc<RwLock<TestMessageRows>>,
}

type TestMessageRows = BTreeMap<(String, String), Message<Descriptor>>;

impl TestMessageStore {
    async fn insert(&self, tenant: &str, cid: &str, message: Message<Descriptor>) {
        self.rows
            .write()
            .unwrap()
            .insert((tenant.to_string(), cid.to_string()), message);
    }
}

impl MessageStore for TestMessageStore {
    async fn open(&mut self) -> Result<(), MessageStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    async fn put<D: crate::descriptors::MessageDescriptor + Send>(
        &self,
        tenant: &str,
        message: Message<D>,
        _indexes: MapValue,
    ) -> Result<(), MessageStoreError> {
        let value = serde_json::to_value(&message)?;
        let cid = generate_cid_from_json(&value)
            .map_err(test_message_store_error)?
            .to_string();
        let message: Message<Descriptor> = serde_json::from_value(value)?;
        self.insert(tenant, &cid, message).await;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        cid: &str,
    ) -> Result<Option<Message<Descriptor>>, MessageStoreError> {
        Ok(self
            .rows
            .read()
            .unwrap()
            .get(&(tenant.to_string(), cid.to_string()))
            .cloned())
    }

    async fn query(
        &self,
        tenant: &str,
        filters: crate::filters::Filters,
        _sort: Option<crate::MessageSort>,
        _pagination: Option<crate::Pagination>,
    ) -> Result<MessageQueryResult, MessageStoreError> {
        let record_id = filters.into_iter().find_map(|filter| {
            filter
                .get(&crate::filters::FilterKey::Index("recordId".to_string()))
                .and_then(|filter| match filter {
                    crate::filters::Filter::Equal(Value::String(value)) => Some(value.clone()),
                    _ => None,
                })
        });
        let messages = self
            .rows
            .read()
            .unwrap()
            .iter()
            .filter(|((row_tenant, cid), _)| {
                row_tenant == tenant && Some(cid.as_str()) == record_id.as_deref()
            })
            .map(|(_, message)| message.clone())
            .collect();
        Ok(MessageQueryResult {
            messages,
            cursor: None,
        })
    }

    async fn count(
        &self,
        _tenant: &str,
        _filters: crate::filters::Filters,
        _sort: Option<crate::MessageSort>,
    ) -> Result<u64, MessageStoreError> {
        Ok(0)
    }

    async fn delete(&self, _tenant: &str, _cid: &str) -> Result<(), MessageStoreError> {
        Ok(())
    }

    async fn clear(&self) -> Result<(), MessageStoreError> {
        self.rows.write().unwrap().clear();
        Ok(())
    }
}

#[derive(Clone, Default)]
struct TestDataStore;

impl DataStore for TestDataStore {
    async fn open(&mut self) -> Result<(), DataStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    async fn put<T: futures_util::Stream<Item = Bytes> + Send + Unpin>(
        &self,
        _tenant: &str,
        _record_id: &str,
        _data_cid: &str,
        _data_stream: T,
    ) -> Result<DataStorePutResult, DataStoreError> {
        Ok(DataStorePutResult { data_size: 0 })
    }

    async fn get(
        &self,
        _tenant: &str,
        _record_id: &str,
        _data_cid: &str,
    ) -> Result<Option<DataStoreGetResult>, DataStoreError> {
        Ok(Some(DataStoreGetResult {
            data_size: 0,
            data_stream: Box::pin(stream::iter(Vec::<Result<Bytes, std::io::Error>>::new())),
        }))
    }

    async fn delete(
        &self,
        _tenant: &str,
        _record_id: &str,
        _data_cid: &str,
    ) -> Result<(), DataStoreError> {
        Ok(())
    }

    async fn clear(&self) -> Result<(), DataStoreError> {
        Ok(())
    }
}

fn test_message_store_error(err: impl std::fmt::Display) -> MessageStoreError {
    MessageStoreError::StoreError(crate::errors::StoreError::InternalException(
        err.to_string(),
    ))
}
