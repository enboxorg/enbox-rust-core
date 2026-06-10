use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use futures_util::stream;
use serde_json::json;

use crate::auth::{Jws, JwsPrivateJwk, JwsPublicJwk, PrivateJwkSigner, StaticPublicKeyResolver};
use crate::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
use crate::descriptors::{
    MessagesSubscribeDescriptor, MessagesSyncDescriptor, RecordsWriteDescriptor,
};
use crate::errors::{DataStoreError, MessageStoreError};
use crate::events::MessageEvent;
use crate::interfaces::messages::descriptors::messages::SyncAction;
use crate::local::MemoryEventLog;
use crate::state_index::MemoryStateIndex;
use crate::stores::{
    DataStore, DataStoreGetResult, DataStorePutResult, EventLog, MessageQueryResult, MessageStore,
    StateIndex, SubscriptionMessage,
};
use crate::{MapValue, Value};

use super::common::*;
use super::*;

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

    let handler = MessagesSyncHandler::with_public_key_resolver(
        message_store,
        data_store,
        state_index,
        test_resolver(),
    );
    let request = signed_sync_message(SyncSpec {
        action: SyncAction::Diff,
        protocol: Some("http://example.com/notes".to_string()),
        depth: Some(0),
        hashes: Some(BTreeMap::new()),
        signer: test_signer(),
        permission_grant_id: None,
        ..SyncSpec::new("2025-01-01T00:10:00.000000Z")
    });

    let reply = handler.handle_sync("did:example:alice", &request).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    let only_remote = reply.body["onlyRemote"].as_array().unwrap();
    assert_eq!(only_remote.len(), 1);
    assert_eq!(only_remote[0]["messageCid"], cid);
    assert_eq!(only_remote[0]["encodedData"], "aGVsbG8");
    assert!(only_remote[0]["message"].get("encodedData").is_none());
    assert!(reply.body["onlyLocal"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn messages_sync_accepts_messages_read_grant_for_protocol_scope() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore;
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();

    let grant = permission_grant_message("grant-sync-1", Some("http://example.com/notes"));
    message_store
        .insert("did:example:alice", "grant-sync-1", grant)
        .await;
    let handler = MessagesSyncHandler::with_public_key_resolver(
        message_store,
        data_store,
        state_index,
        test_resolver(),
    );
    let request = signed_sync_message(SyncSpec {
        action: SyncAction::Root,
        protocol: Some("http://example.com/notes".to_string()),
        signer: bob_signer(),
        permission_grant_id: Some("grant-sync-1".to_string()),
        ..SyncSpec::new("2025-01-01T00:10:00.000000Z")
    });

    let reply = handler.handle_sync("did:example:alice", &request).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert!(reply.body["root"].as_str().is_some());
}

#[tokio::test]
async fn messages_sync_rejects_protocol_scoped_grant_for_unscoped_sync() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore;
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();

    let grant = permission_grant_message("grant-sync-2", Some("http://example.com/notes"));
    message_store
        .insert("did:example:alice", "grant-sync-2", grant)
        .await;
    let handler = MessagesSyncHandler::with_public_key_resolver(
        message_store,
        data_store,
        state_index,
        test_resolver(),
    );
    let request = signed_sync_message(SyncSpec {
        action: SyncAction::Root,
        signer: bob_signer(),
        permission_grant_id: Some("grant-sync-2".to_string()),
        ..SyncSpec::new("2025-01-01T00:10:00.000000Z")
    });

    let reply = handler.handle_sync("did:example:alice", &request).await;
    assert_eq!(reply.status.code, 401);
    assert!(reply
        .status
        .detail
        .contains("MessagesGrantAuthorizationMismatchedProtocol"));
}

#[tokio::test]
async fn messages_subscribe_replays_from_cursor_and_sends_eose() {
    let message_store = TestMessageStore::default();
    let mut event_log = MemoryEventLog::default();
    event_log.open().await.unwrap();
    let (_, stored_message) = records_write_with_inline_data();
    let first = event_log
        .emit(
            "did:example:alice",
            MessageEvent {
                message: stored_message.clone(),
                initial_write: None,
            },
            event_indexes("http://example.com/notes"),
            "first-cid",
        )
        .await
        .unwrap()
        .unwrap();
    event_log
        .emit(
            "did:example:alice",
            MessageEvent {
                message: stored_message,
                initial_write: None,
            },
            event_indexes("http://example.com/notes"),
            "second-cid",
        )
        .await
        .unwrap();

    let delivered = Arc::new(RwLock::new(Vec::new()));
    let delivered_for_listener = delivered.clone();
    let handler = MessagesSubscribeHandler::with_public_key_resolver(
        message_store,
        event_log,
        test_resolver(),
    );
    let request = signed_subscribe_message(SubscribeSpec {
        filters: vec![MessagesFilter {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        }],
        cursor: Some(first),
        ..SubscribeSpec::new("2025-01-01T00:10:00.000000Z")
    });

    let result = handler
        .handle_subscribe(
            "did:example:alice",
            &request,
            Box::new(move |message| delivered_for_listener.write().unwrap().push(message)),
        )
        .await;
    assert_eq!(
        result.reply.status.code, 200,
        "{}",
        result.reply.status.detail
    );
    assert_eq!(
        result.reply.body["subscriptionId"],
        result.subscription.as_ref().unwrap().id
    );
    let delivered = delivered.read().unwrap();
    assert_eq!(delivered.len(), 2);
    match &delivered[0] {
        SubscriptionMessage::Event { cursor, .. } => {
            assert_eq!(cursor.position, "2");
            assert_eq!(cursor.message_cid, "second-cid");
        }
        other => panic!("expected event, got {other:?}"),
    }
    match &delivered[1] {
        SubscriptionMessage::Eose { cursor } => {
            assert_eq!(cursor.position, "2");
            assert_eq!(cursor.message_cid, "second-cid");
        }
        other => panic!("expected eose, got {other:?}"),
    }
}

#[tokio::test]
async fn messages_subscribe_maps_progress_gap_to_410() {
    let message_store = TestMessageStore::default();
    let mut event_log = MemoryEventLog::new(1);
    event_log.open().await.unwrap();
    let (_, stored_message) = records_write_with_inline_data();
    let mut old_cursor = event_log
        .emit(
            "did:example:alice",
            MessageEvent {
                message: stored_message.clone(),
                initial_write: None,
            },
            event_indexes("http://example.com/notes"),
            "first-cid",
        )
        .await
        .unwrap()
        .unwrap();
    old_cursor.position = "0".to_string();
    event_log
        .emit(
            "did:example:alice",
            MessageEvent {
                message: stored_message,
                initial_write: None,
            },
            event_indexes("http://example.com/notes"),
            "second-cid",
        )
        .await
        .unwrap();

    let handler = MessagesSubscribeHandler::with_public_key_resolver(
        message_store,
        event_log,
        test_resolver(),
    );
    let request = signed_subscribe_message(SubscribeSpec {
        filters: vec![MessagesFilter {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        }],
        cursor: Some(old_cursor),
        ..SubscribeSpec::new("2025-01-01T00:10:00.000000Z")
    });

    let result = handler
        .handle_subscribe("did:example:alice", &request, Box::new(|_| {}))
        .await;
    assert_eq!(result.reply.status.code, 410);
    assert_eq!(result.reply.body["error"]["code"], "ProgressGap");
    assert_eq!(result.reply.body["error"]["reason"], "token_too_old");
    assert!(result.subscription.is_none());
}

fn records_write_with_inline_data() -> (String, Message<Descriptor>) {
    let data = Bytes::from_static(b"hello");
    let descriptor = RecordsWriteDescriptor {
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
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

fn event_indexes(protocol: &str) -> MapValue {
    MapValue::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        ("method".to_string(), Value::String("Write".to_string())),
        ("protocol".to_string(), Value::String(protocol.to_string())),
    ])
}

fn permission_grant_message(grant_id: &str, protocol: Option<&str>) -> Message<Descriptor> {
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
    let data = serde_json::to_vec(&json!({
        "dateExpires": "2025-02-01T00:00:00.000000Z",
        "scope": scope,
    }))
    .unwrap();
    let descriptor = RecordsWriteDescriptor {
        protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
        protocol_path: Some(permissions::PERMISSIONS_GRANT_PATH.to_string()),
        recipient: Some("did:example:bob".to_string()),
        schema: None,
        tags: protocol.map(|protocol| {
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
    let signature = Jws::create_general(
        serde_json::to_vec(&payload).unwrap().as_slice(),
        &[test_signer()],
    )
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
    filters: Vec<MessagesFilter>,
    permission_grant_id: Option<String>,
    cursor: Option<crate::stores::ProgressToken>,
    signer: PrivateJwkSigner,
}

impl SubscribeSpec {
    fn new(timestamp: &str) -> Self {
        Self {
            timestamp: timestamp.to_string(),
            filters: Vec::new(),
            permission_grant_id: None,
            cursor: None,
            signer: test_signer(),
        }
    }
}

fn signed_subscribe_message(spec: SubscribeSpec) -> JsonValue {
    let descriptor = MessagesSubscribeDescriptor {
        message_timestamp: parse_time(&spec.timestamp),
        filters: spec.filters,
        permission_grant_id: spec.permission_grant_id.clone(),
        cursor: spec.cursor,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let mut payload = serde_json::Map::from_iter([(
        "descriptorCid".to_string(),
        JsonValue::String(
            generate_cid_from_json(&descriptor_json)
                .unwrap()
                .to_string(),
        ),
    )]);
    if let Some(permission_grant_id) = spec.permission_grant_id {
        payload.insert(
            "permissionGrantId".to_string(),
            JsonValue::String(permission_grant_id),
        );
    }
    let signature = Jws::create_general(
        serde_json::to_vec(&JsonValue::Object(payload))
            .unwrap()
            .as_slice(),
        &[spec.signer],
    )
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
    permission_grant_id: Option<String>,
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
            permission_grant_id: None,
            hashes: None,
            depth: None,
            signer: test_signer(),
        }
    }
}

fn signed_sync_message(spec: SyncSpec) -> JsonValue {
    let descriptor = MessagesSyncDescriptor {
        message_timestamp: parse_time(&spec.timestamp),
        action: spec.action,
        protocol: spec.protocol,
        prefix: spec.prefix,
        permission_grant_id: spec.permission_grant_id.clone(),
        hashes: spec.hashes,
        depth: spec.depth,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let mut payload = serde_json::Map::from_iter([(
        "descriptorCid".to_string(),
        JsonValue::String(
            generate_cid_from_json(&descriptor_json)
                .unwrap()
                .to_string(),
        ),
    )]);
    if let Some(permission_grant_id) = spec.permission_grant_id {
        payload.insert(
            "permissionGrantId".to_string(),
            JsonValue::String(permission_grant_id),
        );
    }
    let signature = Jws::create_general(
        serde_json::to_vec(&JsonValue::Object(payload))
            .unwrap()
            .as_slice(),
        &[spec.signer],
    )
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
        "EdDSA",
        JwsPrivateJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            d: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string(),
            x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
            y: None,
            kid: Some(key_id.clone()),
            alg: Some("EdDSA".to_string()),
        },
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

fn test_public_jwk(key_id: &str) -> JwsPublicJwk {
    JwsPublicJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
        y: None,
        kid: Some(key_id.to_string()),
        alg: Some("EdDSA".to_string()),
    }
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
