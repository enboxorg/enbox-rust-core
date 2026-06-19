use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use serde_json::json;

use crate::auth::{Jws, JwsPrivateJwk, JwsPublicJwk, PrivateJwkSigner, StaticPublicKeyResolver};
use crate::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
use crate::descriptors::{
    ConfigureDescriptor, DeleteDescriptor, Protocols as ProtocolsDescriptor, Records,
    RecordsWriteDescriptor, SubscribeDescriptor,
};
use crate::errors::{DataStoreError, MessageStoreError, StoreError};
use crate::events::MessageEvent;
use crate::fields::WriteFields;
use crate::filters::Records as RecordsFilter;
use crate::interfaces::messages::protocols::{ActionWho, Type};
use crate::stores::memory::MemoryEventLog;
use crate::protocols::{Action, Can, Definition, RuleSet, Who};
use crate::stores::state_index::MemoryStateIndex;
use crate::stores::{
    DataStore, DataStoreGetResult, DataStorePutResult, EventLog, KeyValues, MessageQueryResult,
    MessageStore, StateIndex, SubscriptionMessage,
};
use crate::{
    permissions, Fields, Filter, FilterKey, Filters, MapValue, Message, MessageSort, Pagination,
    RangeFilter, SortDirection,
};
use crate::{Descriptor, Value};

use super::common::*;
use super::*;

#[tokio::test]
async fn records_write_read_query_and_count_published_inline_data() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();

    let write_handler = RecordsWriteHandler::<_, _, _, ()>::with_public_key_resolver(
        message_store.clone(),
        data_store.clone(),
        state_index,
        test_resolver(),
    );
    let read_handler = RecordsReadHandler::new(message_store.clone(), data_store.clone());
    let query_handler = RecordsQueryHandler::new(message_store.clone());
    let count_handler = RecordsCountHandler::new(message_store.clone());

    let data = Bytes::from_static(b"hello world");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let write = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    });
    let record_id = write["recordId"].as_str().unwrap().to_string();

    let reply = write_handler
        .handle_write("did:example:alice", &write, Some(data.clone()))
        .await;
    assert_eq!(reply.status.code, 202);

    let query = unsigned_query_message(json!({ "published": true }));
    let reply = query_handler
        .handle_query("did:example:alice", &query)
        .await;
    assert_eq!(reply.status.code, 200);
    let entries = reply.body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["encodedData"].as_str(),
        Some(URL_SAFE_NO_PAD.encode(&data).as_str())
    );

    let count = unsigned_count_message(json!({ "published": true }));
    let reply = count_handler
        .handle_count("did:example:alice", &count)
        .await;
    assert_eq!(reply.status.code, 200);
    assert_eq!(reply.body["count"], json!(1));

    let read = unsigned_read_message(json!({ "recordId": record_id }));
    let reply = read_handler.handle_read("did:example:alice", &read).await;
    assert_eq!(reply.status.code, 200);
    assert_eq!(
        reply.body["entry"]["encodedData"].as_str(),
        Some(URL_SAFE_NO_PAD.encode(&data).as_str())
    );
}

#[tokio::test]
async fn records_write_update_without_data_copies_previous_inline_data_and_keeps_initial() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let handler = RecordsWriteHandler::<_, _, _, ()>::with_public_key_resolver(
        message_store.clone(),
        data_store,
        state_index,
        test_resolver(),
    );

    let data = Bytes::from_static(b"version one");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let initial = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    });
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    let context_id = initial["contextId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .handle_write("did:example:alice", &initial, Some(data.clone()))
            .await
            .status
            .code,
        202
    );

    let update = signed_write_message(WriteSpec {
        record_id: Some(record_id.clone()),
        context_id: Some(context_id),
        data_cid,
        data_size: data.len() as u64,
        date_created: "2025-01-01T00:00:00.000000Z".to_string(),
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    });
    let reply = handler
        .handle_write("did:example:alice", &update, None)
        .await;
    assert_eq!(reply.status.code, 202);

    let stored = fetch_record_messages("did:example:alice", &record_id, &message_store)
        .await
        .unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(
        stored
            .iter()
            .filter(|message| write_fields(message)
                .ok()
                .and_then(|fields| fields.encoded_data.as_ref())
                .is_some())
            .count(),
        1
    );
}

#[tokio::test]
async fn records_write_rejects_older_conflicting_write() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let handler = RecordsWriteHandler::<_, _, _, ()>::with_public_key_resolver(
        message_store.clone(),
        data_store,
        state_index,
        test_resolver(),
    );

    let data = Bytes::from_static(b"newest");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let initial = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:10:00.000000Z")
    });
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    let context_id = initial["contextId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .handle_write("did:example:alice", &initial, Some(data.clone()))
            .await
            .status
            .code,
        202
    );

    let older = signed_write_message(WriteSpec {
        record_id: Some(record_id),
        context_id: Some(context_id),
        data_cid,
        data_size: data.len() as u64,
        date_created: "2025-01-01T00:10:00.000000Z".to_string(),
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:09:00.000000Z")
    });
    let reply = handler
        .handle_write("did:example:alice", &older, Some(data))
        .await;
    assert_eq!(reply.status.code, 409);
}

#[tokio::test]
async fn records_read_returns_gone_when_external_data_is_missing() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let handler = RecordsWriteHandler::<_, _, _, ()>::with_public_key_resolver(
        message_store.clone(),
        data_store.clone(),
        state_index,
        test_resolver(),
    );
    let read_handler = RecordsReadHandler::new(message_store.clone(), data_store.clone());

    let data = Bytes::from(vec![7u8; (MAX_ENCODED_DATA_SIZE + 1) as usize]);
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let write = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    });
    let record_id = write["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .handle_write("did:example:alice", &write, Some(data))
            .await
            .status
            .code,
        202
    );
    data_store
        .delete("did:example:alice", &record_id, &data_cid)
        .await
        .unwrap();

    let reply = read_handler
        .handle_read(
            "did:example:alice",
            &unsigned_read_message(json!({ "recordId": record_id })),
        )
        .await;
    assert_eq!(reply.status.code, 410);
}

#[tokio::test]
async fn records_delete_prune_purges_descendant_records() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let write_handler = RecordsWriteHandler::<_, _, _, ()>::with_public_key_resolver(
        message_store.clone(),
        data_store.clone(),
        state_index.clone(),
        test_resolver(),
    );
    let delete_handler = RecordsDeleteHandler::with_public_key_resolver(
        message_store.clone(),
        data_store.clone(),
        state_index,
        test_resolver(),
    );

    let data = Bytes::from_static(b"parent");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let parent = signed_write_message(WriteSpec {
        data_cid,
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    });
    let parent_record_id = parent["recordId"].as_str().unwrap().to_string();
    let parent_context_id = parent["contextId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .handle_write("did:example:alice", &parent, Some(data))
            .await
            .status
            .code,
        202
    );

    let child_data = Bytes::from_static(b"child");
    let child_data_cid = generate_dag_pb_cid_from_bytes(&child_data).to_string();
    let child = signed_write_message(WriteSpec {
        parent_id: Some(parent_record_id.clone()),
        parent_context_id: Some(parent_context_id),
        data_cid: child_data_cid,
        data_size: child_data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    });
    let child_record_id = child["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .handle_write("did:example:alice", &child, Some(child_data))
            .await
            .status
            .code,
        202
    );

    let delete = signed_delete_message(&parent_record_id, true, "2025-01-01T00:02:00.000000Z");
    let reply = delete_handler
        .handle_delete("did:example:alice", &delete)
        .await;
    assert_eq!(reply.status.code, 202);

    let child_messages =
        fetch_record_messages("did:example:alice", &child_record_id, &message_store)
            .await
            .unwrap();
    assert!(child_messages.is_empty());
}

#[tokio::test]
async fn records_write_squash_purges_older_sibling_records_and_sets_backstop() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();
    put_squash_protocol("did:example:alice", &message_store).await;
    let handler = RecordsWriteHandler::<_, _, _, ()>::with_public_key_resolver(
        message_store.clone(),
        data_store.clone(),
        state_index,
        test_resolver(),
    );

    let old_data = Bytes::from_static(b"old note");
    let old = signed_write_message(WriteSpec {
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&old_data).to_string(),
        data_size: old_data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    });
    let old_record_id = old["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .handle_write("did:example:alice", &old, Some(old_data))
            .await
            .status
            .code,
        202
    );

    let squash_data = Bytes::from_static(b"snapshot");
    let squash = signed_write_message(WriteSpec {
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&squash_data).to_string(),
        data_size: squash_data.len() as u64,
        published: Some(true),
        squash: Some(true),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    });
    assert_eq!(
        handler
            .handle_write("did:example:alice", &squash, Some(squash_data))
            .await
            .status
            .code,
        202
    );
    assert!(
        fetch_record_messages("did:example:alice", &old_record_id, &message_store)
            .await
            .unwrap()
            .is_empty()
    );

    let late_old_data = Bytes::from_static(b"late old");
    let late_old = signed_write_message(WriteSpec {
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&late_old_data).to_string(),
        data_size: late_old_data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:30.000000Z")
    });
    let reply = handler
        .handle_write("did:example:alice", &late_old, Some(late_old_data))
        .await;
    assert_eq!(reply.status.code, 409);
}

#[tokio::test]
async fn records_write_accepts_permission_grant_id_and_enforces_publication_condition() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;

    let handler = RecordsWriteHandler::<_, _, _, ()>::with_public_key_resolver(
        message_store.clone(),
        data_store,
        state_index,
        test_resolver(),
    );

    let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"},"conditions":{"publication":"Required"}}"#);
    let grant = signed_write_message(WriteSpec {
        protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
        protocol_path: Some(permissions::PERMISSIONS_GRANT_PATH.to_string()),
        recipient: Some("did:example:bob".to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    });
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .handle_write("did:example:alice", &grant, Some(grant_data.clone()))
            .await
            .status
            .code,
        202
    );
    let unpublished_data = Bytes::from_static(b"unpublished note");
    let unpublished = signed_write_message(WriteSpec {
        author: "did:example:bob".to_string(),
        signer: bob_signer(),
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&unpublished_data).to_string(),
        data_size: unpublished_data.len() as u64,
        permission_grant_id: Some(grant_id.clone()),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    });
    let reply = handler
        .handle_write("did:example:alice", &unpublished, Some(unpublished_data))
        .await;
    assert_eq!(reply.status.code, 401);
    assert!(reply
        .status
        .detail
        .contains("RecordsGrantAuthorizationConditionPublicationRequired"));

    let published_data = Bytes::from_static(b"published note");
    let published = signed_write_message(WriteSpec {
        author: "did:example:bob".to_string(),
        signer: bob_signer(),
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&published_data).to_string(),
        data_size: published_data.len() as u64,
        published: Some(true),
        permission_grant_id: Some(grant_id),
        ..WriteSpec::new("2025-01-01T00:02:00.000000Z")
    });
    let reply = handler
        .handle_write("did:example:alice", &published, Some(published_data))
        .await;
    assert_eq!(reply.status.code, 202);
}

#[tokio::test]
async fn records_write_accepts_embedded_author_delegated_grant() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;

    let handler = RecordsWriteHandler::<_, _, _, ()>::with_public_key_resolver(
        message_store.clone(),
        data_store,
        state_index,
        test_resolver(),
    );

    let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"},"delegated":true}"#);
    let grant = signed_write_message(WriteSpec {
        protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
        protocol_path: Some(permissions::PERMISSIONS_GRANT_PATH.to_string()),
        recipient: Some("did:example:bob".to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    });
    assert_eq!(
        handler
            .handle_write("did:example:alice", &grant, Some(grant_data.clone()))
            .await
            .status
            .code,
        202
    );
    let mut delegated_grant = grant.clone();
    delegated_grant["encodedData"] = serde_json::Value::String(URL_SAFE_NO_PAD.encode(&grant_data));

    let note_data = Bytes::from_static(b"delegated note");
    let note = signed_write_message(WriteSpec {
        author: "did:example:alice".to_string(),
        signer: bob_signer(),
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&note_data).to_string(),
        data_size: note_data.len() as u64,
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    });
    let note = with_author_delegated_grant(note, &delegated_grant, bob_signer());
    let reply = handler
        .handle_write("did:example:alice", &note, Some(note_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

#[tokio::test]
async fn permissions_revocation_cleans_grant_authorized_messages() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    state_index.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;

    let handler = RecordsWriteHandler::<_, _, _, ()>::with_public_key_resolver(
        message_store.clone(),
        data_store.clone(),
        state_index,
        test_resolver(),
    );

    let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"}}"#);
    let grant = signed_write_message(WriteSpec {
        protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
        protocol_path: Some(permissions::PERMISSIONS_GRANT_PATH.to_string()),
        recipient: Some("did:example:bob".to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    });
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .handle_write("did:example:alice", &grant, Some(grant_data))
            .await
            .status
            .code,
        202
    );

    let note_data = Bytes::from_static(b"revoked note");
    let note = signed_write_message(WriteSpec {
        author: "did:example:bob".to_string(),
        signer: bob_signer(),
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&note_data).to_string(),
        data_size: note_data.len() as u64,
        permission_grant_id: Some(grant_id.clone()),
        ..WriteSpec::new("2025-01-01T00:05:00.000000Z")
    });
    let note_record_id = note["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .handle_write("did:example:alice", &note, Some(note_data))
            .await
            .status
            .code,
        202
    );

    let revoke_data = Bytes::from_static(br#"{"description":"revoke"}"#);
    let revocation = signed_write_message(WriteSpec {
        protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
        protocol_path: Some(permissions::PERMISSIONS_REVOCATION_PATH.to_string()),
        parent_id: Some(grant_id.clone()),
        parent_context_id: Some(grant_id.clone()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&revoke_data).to_string(),
        data_size: revoke_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:04:00.000000Z")
    });
    assert_eq!(
        handler
            .handle_write("did:example:alice", &revocation, Some(revoke_data))
            .await
            .status
            .code,
        202
    );

    assert!(
        fetch_record_messages("did:example:alice", &note_record_id, &message_store)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn records_event_log_subscribe_replays_from_cursor_and_sends_eose() {
    let mut message_store = TestMessageStore::default();
    let mut event_log = MemoryEventLog::default();
    message_store.open().await.unwrap();
    event_log.open().await.unwrap();

    let note = stored_note_message("2025-01-01T00:01:00.000000Z");
    let first = event_log
        .emit(
            "did:example:alice",
            MessageEvent {
                message: note.clone(),
                initial_write: None,
            },
            record_event_indexes("http://example.com/notes", "Write"),
            "first-cid",
        )
        .await
        .unwrap()
        .unwrap();
    event_log
        .emit(
            "did:example:alice",
            MessageEvent {
                message: note,
                initial_write: None,
            },
            record_event_indexes("http://example.com/notes", "Write"),
            "second-cid",
        )
        .await
        .unwrap();

    let delivered = Arc::new(RwLock::new(Vec::new()));
    let delivered_for_listener = delivered.clone();
    let handler = RecordsEventLogSubscribeHandler::with_public_key_resolver(
        message_store,
        event_log,
        test_resolver(),
    );
    let request = signed_records_subscribe_message(
        RecordsFilter {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        },
        Some(first),
        "2025-01-01T00:10:00.000000Z",
    );

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
    assert!(!result.reply.body.contains_key("entries"));
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
async fn records_event_log_subscribe_maps_progress_gap_to_410() {
    let message_store = TestMessageStore::default();
    let mut event_log = MemoryEventLog::new(1);
    event_log.open().await.unwrap();

    let note = stored_note_message("2025-01-01T00:01:00.000000Z");
    let mut old_cursor = event_log
        .emit(
            "did:example:alice",
            MessageEvent {
                message: note.clone(),
                initial_write: None,
            },
            record_event_indexes("http://example.com/notes", "Write"),
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
                message: note,
                initial_write: None,
            },
            record_event_indexes("http://example.com/notes", "Write"),
            "second-cid",
        )
        .await
        .unwrap();

    let handler = RecordsEventLogSubscribeHandler::with_public_key_resolver(
        message_store,
        event_log,
        test_resolver(),
    );
    let request = signed_records_subscribe_message(
        RecordsFilter {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        },
        Some(old_cursor),
        "2025-01-01T00:10:00.000000Z",
    );

    let result = handler
        .handle_subscribe("did:example:alice", &request, Box::new(|_| {}))
        .await;
    assert_eq!(result.reply.status.code, 410);
    assert_eq!(result.reply.body["error"]["code"], "ProgressGap");
    assert_eq!(result.reply.body["error"]["reason"], "token_too_old");
    assert!(result.subscription.is_none());
}

#[tokio::test]
async fn records_event_log_subscribe_without_cursor_returns_snapshot_and_live_subscription() {
    let mut message_store = TestMessageStore::default();
    let mut event_log = MemoryEventLog::default();
    message_store.open().await.unwrap();
    event_log.open().await.unwrap();

    let note = stored_note_message("2025-01-01T00:01:00.000000Z");
    let indexes = records_write_indexes(&note, "did:example:alice", true).unwrap();
    message_store
        .put("did:example:alice", note.clone(), indexes)
        .await
        .unwrap();

    let delivered = Arc::new(RwLock::new(Vec::new()));
    let delivered_for_listener = delivered.clone();
    let handler = RecordsEventLogSubscribeHandler::with_public_key_resolver(
        message_store,
        event_log.clone(),
        test_resolver(),
    );
    let request = signed_records_subscribe_message(
        RecordsFilter {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        },
        None,
        "2025-01-01T00:10:00.000000Z",
    );

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
    assert_eq!(result.reply.body["entries"].as_array().unwrap().len(), 1);
    assert!(result.subscription.is_some());

    event_log
        .emit(
            "did:example:alice",
            MessageEvent {
                message: note,
                initial_write: None,
            },
            record_event_indexes("http://example.com/notes", "Write"),
            "live-cid",
        )
        .await
        .unwrap();
    let delivered = delivered.read().unwrap();
    assert_eq!(delivered.len(), 1);
    assert!(matches!(delivered[0], SubscriptionMessage::Event { .. }));
}

#[test]
fn generic_records_descriptor_deserializes_by_method() {
    let count = json!({
        "interface": "Records",
        "method": "Count",
        "messageTimestamp": "2025-01-01T00:00:00.000000Z",
        "filter": { "published": true }
    });
    let descriptor: Descriptor = serde_json::from_value(count).unwrap();
    assert!(matches!(
        descriptor,
        Descriptor::Records(records) if matches!(records.as_ref(), Records::Count(_))
    ));

    let query = json!({
        "interface": "Records",
        "method": "Query",
        "messageTimestamp": "2025-01-01T00:00:00.000000Z",
        "filter": { "published": true }
    });
    let descriptor: Descriptor = serde_json::from_value(query).unwrap();
    assert!(matches!(
        descriptor,
        Descriptor::Records(records) if matches!(records.as_ref(), Records::Query(_))
    ));
}

#[derive(Clone)]
struct WriteSpec {
    author: String,
    signer: PrivateJwkSigner,
    timestamp: String,
    date_created: String,
    record_id: Option<String>,
    context_id: Option<String>,
    parent_id: Option<String>,
    parent_context_id: Option<String>,
    protocol: Option<String>,
    protocol_path: Option<String>,
    recipient: Option<String>,
    tags: Option<MapValue>,
    data_cid: String,
    data_size: u64,
    data_format: String,
    published: Option<bool>,
    permission_grant_id: Option<String>,
    squash: Option<bool>,
}

impl WriteSpec {
    fn new(timestamp: &str) -> Self {
        Self {
            author: "did:example:alice".to_string(),
            signer: test_signer(),
            timestamp: timestamp.to_string(),
            date_created: timestamp.to_string(),
            record_id: None,
            context_id: None,
            parent_id: None,
            parent_context_id: None,
            protocol: None,
            protocol_path: None,
            recipient: None,
            tags: None,
            data_cid: generate_dag_pb_cid_from_bytes([]).to_string(),
            data_size: 0,
            data_format: "text/plain".to_string(),
            published: None,
            permission_grant_id: None,
            squash: None,
        }
    }
}

fn signed_write_message(spec: WriteSpec) -> serde_json::Value {
    let descriptor = RecordsWriteDescriptor {
        protocol: spec.protocol,
        protocol_path: spec.protocol_path,
        recipient: spec.recipient,
        schema: None,
        tags: spec.tags,
        parent_id: spec.parent_id.clone(),
        data_cid: spec.data_cid,
        data_size: spec.data_size,
        date_created: parse_time(&spec.date_created),
        message_timestamp: parse_time(&spec.timestamp),
        published: spec.published,
        date_published: spec.published.map(|_| parse_time(&spec.timestamp)),
        data_format: spec.data_format,
        permission_grant_id: spec.permission_grant_id.clone(),
        squash: spec.squash,
    };
    let record_id = spec
        .record_id
        .clone()
        .unwrap_or_else(|| entry_id(&spec.author, &descriptor).unwrap());
    let context_id = spec.context_id.unwrap_or_else(|| {
        spec.parent_context_id
            .filter(|context| !context.is_empty())
            .map(|parent| format!("{parent}/{record_id}"))
            .unwrap_or_else(|| record_id.clone())
    });
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature_payload =
        payload_with_permission_grant(&record_id, &context_id, spec.permission_grant_id.as_deref());
    let signature = signature_for_descriptor(&descriptor_json, signature_payload, spec.signer);
    json!({
        "descriptor": descriptor_json,
        "recordId": record_id,
        "contextId": context_id,
        "authorization": { "signature": signature }
    })
}

fn with_author_delegated_grant(
    mut message: serde_json::Value,
    grant: &serde_json::Value,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    let grant_message: Message<Descriptor> = serde_json::from_value(grant.clone()).unwrap();
    let grant_cid = message_cid(&grant_message).unwrap();
    let descriptor_json = message["descriptor"].clone();
    let signature = signature_for_descriptor(
        &descriptor_json,
        json!({
            "recordId": message["recordId"].as_str().unwrap(),
            "contextId": message["contextId"].as_str().unwrap(),
            "delegatedGrantId": grant_cid,
        }),
        signer,
    );
    message["authorization"] = json!({
        "signature": signature,
        "authorDelegatedGrant": grant,
    });
    message
}

fn signed_delete_message(record_id: &str, prune: bool, timestamp: &str) -> serde_json::Value {
    let descriptor = DeleteDescriptor {
        message_timestamp: parse_time(timestamp),
        record_id: record_id.to_string(),
        prune,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(&descriptor_json, json!({}), test_signer());
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

fn stored_note_message(timestamp: &str) -> Message<Descriptor> {
    serde_json::from_value(signed_write_message(WriteSpec {
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        ..WriteSpec::new(timestamp)
    }))
    .unwrap()
}

fn record_event_indexes(protocol: &str, method: &str) -> KeyValues {
    KeyValues::from([
        (
            "interface".to_string(),
            Value::String(RECORDS_INTERFACE.to_string()),
        ),
        ("method".to_string(), Value::String(method.to_string())),
        ("protocol".to_string(), Value::String(protocol.to_string())),
    ])
}

fn signed_records_subscribe_message(
    filter: RecordsFilter,
    cursor: Option<crate::stores::ProgressToken>,
    timestamp: &str,
) -> serde_json::Value {
    let descriptor = SubscribeDescriptor {
        message_timestamp: parse_time(timestamp),
        filter,
        date_sort: None,
        pagination: None,
        cursor,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(&descriptor_json, json!({}), test_signer());
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

fn unsigned_query_message(filter: serde_json::Value) -> serde_json::Value {
    json!({
        "descriptor": {
            "interface": "Records",
            "method": "Query",
            "messageTimestamp": "2025-01-01T00:10:00.000000Z",
            "filter": filter
        }
    })
}

fn unsigned_count_message(filter: serde_json::Value) -> serde_json::Value {
    json!({
        "descriptor": {
            "interface": "Records",
            "method": "Count",
            "messageTimestamp": "2025-01-01T00:10:00.000000Z",
            "filter": filter
        }
    })
}

fn unsigned_read_message(filter: serde_json::Value) -> serde_json::Value {
    json!({
        "descriptor": {
            "interface": "Records",
            "method": "Read",
            "messageTimestamp": "2025-01-01T00:10:00.000000Z",
            "filter": filter
        }
    })
}

async fn put_squash_protocol(tenant: &str, message_store: &TestMessageStore) {
    let definition = Definition {
        protocol: "http://example.com/notes".to_string(),
        published: true,
        uses: None,
        types: BTreeMap::from([(
            "note".to_string(),
            Type {
                schema: None,
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([(
            "note".to_string(),
            RuleSet {
                squash: Some(true),
                actions: vec![Action::Who(ActionWho {
                    who: Who::Anyone,
                    of: None,
                    can: vec![Can::Create, Can::Read, Can::Squash],
                })],
                ..Default::default()
            },
        )]),
    };
    let descriptor = ConfigureDescriptor {
        message_timestamp: parse_time("2024-12-31T00:00:00.000000Z"),
        definition,
        permission_grant_id: None,
    };
    let message = Message {
        descriptor: Descriptor::Protocols(Box::new(ProtocolsDescriptor::Configure(descriptor))),
        fields: Fields::Write(WriteFields::default()),
    };
    let indexes = BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Protocols".to_string()),
        ),
        ("method".to_string(), Value::String("Configure".to_string())),
        (
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        ),
        ("published".to_string(), Value::Bool(true)),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "messageTimestamp".to_string(),
            Value::String("2024-12-31T00:00:00.000000Z".to_string()),
        ),
    ]);
    message_store.put(tenant, message, indexes).await.unwrap();
}

async fn put_notes_protocol_without_actions(tenant: &str, message_store: &TestMessageStore) {
    let definition = Definition {
        protocol: "http://example.com/notes".to_string(),
        published: false,
        uses: None,
        types: BTreeMap::from([(
            "note".to_string(),
            Type {
                schema: None,
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([("note".to_string(), RuleSet::default())]),
    };
    let descriptor = ConfigureDescriptor {
        message_timestamp: parse_time("2024-12-31T00:00:00.000000Z"),
        definition,
        permission_grant_id: None,
    };
    let message = Message {
        descriptor: Descriptor::Protocols(Box::new(ProtocolsDescriptor::Configure(descriptor))),
        fields: Fields::Write(WriteFields::default()),
    };
    let indexes = BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Protocols".to_string()),
        ),
        ("method".to_string(), Value::String("Configure".to_string())),
        (
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        ),
        ("published".to_string(), Value::Bool(false)),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "messageTimestamp".to_string(),
            Value::String("2024-12-31T00:00:00.000000Z".to_string()),
        ),
    ]);
    message_store.put(tenant, message, indexes).await.unwrap();
}

fn signature_for_descriptor(
    descriptor: &serde_json::Value,
    extra_payload: serde_json::Value,
    signer: PrivateJwkSigner,
) -> Jws {
    let mut payload = extra_payload.as_object().cloned().unwrap_or_default();
    payload.insert(
        "descriptorCid".to_string(),
        serde_json::Value::String(generate_cid_from_json(descriptor).unwrap().to_string()),
    );
    Jws::create_general(
        serde_json::to_vec(&serde_json::Value::Object(payload))
            .unwrap()
            .as_slice(),
        &[signer],
    )
    .unwrap()
}

fn payload_with_permission_grant(
    record_id: &str,
    context_id: &str,
    permission_grant_id: Option<&str>,
) -> serde_json::Value {
    let mut payload = serde_json::Map::from_iter([
        (
            "recordId".to_string(),
            serde_json::Value::String(record_id.to_string()),
        ),
        (
            "contextId".to_string(),
            serde_json::Value::String(context_id.to_string()),
        ),
    ]);
    if let Some(permission_grant_id) = permission_grant_id {
        payload.insert(
            "permissionGrantId".to_string(),
            serde_json::Value::String(permission_grant_id.to_string()),
        );
    }
    serde_json::Value::Object(payload)
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
    rows: Arc<RwLock<Vec<TestMessageRow>>>,
}

#[derive(Clone)]
struct TestMessageRow {
    tenant: String,
    cid: String,
    message: Message<Descriptor>,
    indexes: KeyValues,
}

impl MessageStore for TestMessageStore {
    async fn open(&mut self) -> Result<(), MessageStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    fn put<D: crate::descriptors::MessageDescriptor + Send>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        async move {
            let value = serde_json::to_value(&message)?;
            let message: Message<Descriptor> = serde_json::from_value(value)?;
            let cid = message_cid(&message).map_err(test_store_error)?;
            rows.write()
                .unwrap()
                .retain(|row| row.tenant != tenant || row.cid != cid);
            rows.write().unwrap().push(TestMessageRow {
                tenant,
                cid,
                message,
                indexes,
            });
            Ok(())
        }
    }

    fn get(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<Option<Message<Descriptor>>, MessageStoreError>> + Send {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        let cid = cid.to_string();
        async move {
            Ok(rows
                .read()
                .unwrap()
                .iter()
                .find(|row| row.tenant == tenant && row.cid == cid)
                .map(|row| row.message.clone()))
        }
    }

    fn query(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
        pagination: Option<Pagination>,
    ) -> impl Future<Output = Result<MessageQueryResult, MessageStoreError>> + Send {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        async move {
            let mut rows = rows
                .read()
                .unwrap()
                .iter()
                .filter(|row| {
                    row.tenant == tenant && matches_filters(&row.indexes, filters.clone())
                })
                .cloned()
                .collect::<Vec<_>>();
            if let Some(sort) = sort {
                let (property, direction) = match sort {
                    MessageSort::DateCreated(direction) => ("dateCreated", direction),
                    MessageSort::DatePublished(direction) => ("datePublished", direction),
                    MessageSort::Timestamp(direction) => ("messageTimestamp", direction),
                };
                rows.sort_by(|left, right| {
                    let order = value_string(left.indexes.get(property))
                        .cmp(&value_string(right.indexes.get(property)))
                        .then_with(|| left.cid.cmp(&right.cid));
                    match direction {
                        SortDirection::Ascending => order,
                        SortDirection::Descending => order.reverse(),
                    }
                });
            }
            if let Some(limit) = pagination.and_then(|pagination| pagination.limit) {
                rows.truncate(limit as usize);
            }
            Ok(MessageQueryResult {
                messages: rows.into_iter().map(|row| row.message).collect(),
                cursor: None,
            })
        }
    }

    async fn count(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
    ) -> Result<u64, MessageStoreError> {
        Ok(self
            .query(tenant, filters, sort, None)
            .await?
            .messages
            .len() as u64)
    }

    fn delete(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        let cid = cid.to_string();
        async move {
            rows.write()
                .unwrap()
                .retain(|row| row.tenant != tenant || row.cid != cid);
            Ok(())
        }
    }

    fn clear(&self) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
        let rows = self.rows.clone();
        async move {
            rows.write().unwrap().clear();
            Ok(())
        }
    }
}

type TestDataKey = (String, String, String);
type TestDataValues = Arc<RwLock<BTreeMap<TestDataKey, Bytes>>>;

#[derive(Clone, Default)]
struct TestDataStore {
    values: TestDataValues,
}

impl DataStore for TestDataStore {
    async fn open(&mut self) -> Result<(), DataStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    fn put<T: Stream<Item = Bytes> + Send + Unpin>(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
        mut data_stream: T,
    ) -> impl Future<Output = Result<DataStorePutResult, DataStoreError>> + Send {
        let values = self.values.clone();
        let key = (
            tenant.to_string(),
            record_id.to_string(),
            data_cid.to_string(),
        );
        async move {
            let mut bytes = Vec::new();
            while let Some(chunk) = data_stream.next().await {
                bytes.extend_from_slice(&chunk);
            }
            let bytes = Bytes::from(bytes);
            let data_size = bytes.len();
            values.write().unwrap().insert(key, bytes);
            Ok(DataStorePutResult { data_size })
        }
    }

    fn get(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> impl Future<Output = Result<Option<DataStoreGetResult>, DataStoreError>> + Send {
        let values = self.values.clone();
        let key = (
            tenant.to_string(),
            record_id.to_string(),
            data_cid.to_string(),
        );
        async move {
            Ok(values.read().unwrap().get(&key).cloned().map(|bytes| {
                let data_size = bytes.len();
                DataStoreGetResult {
                    data_size,
                    data_stream: Box::pin(stream::iter(vec![Ok(bytes)])),
                }
            }))
        }
    }

    fn delete(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> impl Future<Output = Result<(), DataStoreError>> + Send {
        let values = self.values.clone();
        let key = (
            tenant.to_string(),
            record_id.to_string(),
            data_cid.to_string(),
        );
        async move {
            values.write().unwrap().remove(&key);
            Ok(())
        }
    }

    fn clear(&self) -> impl Future<Output = Result<(), DataStoreError>> + Send {
        let values = self.values.clone();
        async move {
            values.write().unwrap().clear();
            Ok(())
        }
    }
}

fn matches_filters(indexes: &KeyValues, filters: Filters) -> bool {
    let mut has_filter_set = false;
    for filter_set in filters {
        has_filter_set = true;
        if filter_set.into_iter().all(|(key, filter)| match key {
            FilterKey::Index(index) => indexes
                .get(&index)
                .is_some_and(|value| matches_filter(value, &filter)),
            FilterKey::Tag(_) => false,
        }) {
            return true;
        }
    }
    !has_filter_set
}

fn matches_filter(value: &Value, filter: &Filter<Value>) -> bool {
    match filter {
        Filter::Equal(expected) => value == expected,
        Filter::OneOf(values) => values.iter().any(|expected| value == expected),
        Filter::Prefix(prefix) => {
            value_string(Some(value)).starts_with(&value_string(Some(prefix)))
        }
        Filter::Range(RangeFilter::Numeric(lower, upper))
        | Filter::Range(RangeFilter::Criterion(lower, upper)) => {
            matches_lower_bound(value, lower) && matches_upper_bound(value, upper)
        }
    }
}

fn matches_lower_bound(value: &Value, bound: &Bound<Value>) -> bool {
    match bound {
        Bound::Included(bound) => value_string(Some(value)) >= value_string(Some(bound)),
        Bound::Excluded(bound) => value_string(Some(value)) > value_string(Some(bound)),
        Bound::Unbounded => true,
    }
}

fn matches_upper_bound(value: &Value, bound: &Bound<Value>) -> bool {
    match bound {
        Bound::Included(bound) => value_string(Some(value)) <= value_string(Some(bound)),
        Bound::Excluded(bound) => value_string(Some(value)) < value_string(Some(bound)),
        Bound::Unbounded => true,
    }
}

fn value_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

fn test_store_error(error: String) -> MessageStoreError {
    MessageStoreError::StoreError(StoreError::InternalException(error))
}
