//! Backend-neutral MessageStore + DataStore conformance battery (issue #169).
//!
//! Same assertions on every backend so the durable path cannot drift from
//! the reference path. Backends run the suites with an async factory; the
//! harness opens each fresh store. Memory runs here, SQLite in
//! `dwn-rs-stores` (core has no in-memory `DataStore`, so the data battery
//! has no in-core runner).
//!
//! Feed ordering/progress, crash recovery, and concurrency live in
//! `replication_feed_conformance`, `concurrent_conformance`, and the live
//! suite; this file covers retained-message and content-addressed-data
//! behavior only.

use std::{collections::BTreeMap, future::Future};

use bytes::Bytes;
use futures_util::{stream, TryStreamExt};

use super::{DataStore, KeyValues, MessageStore};
use crate::cid::generate_dag_pb_cid_from_bytes;
use crate::descriptors::{Records, RecordsWriteDescriptor};
use crate::fields::{MessageFields, WriteFields};
use crate::filters::{Filter, FilterKey, Filters};
use crate::{Descriptor, Fields, Message, MessageSort, Pagination, SortDirection, Value};

/// Runs the message battery against stores returned by `factory`.
///
/// The factory is invoked once per scenario; the harness opens the store.
pub async fn run_message_stores<S, F, Fut>(factory: F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    put_get_roundtrip(&factory).await;
    filters_sorts_counts_and_paginates(&factory).await;
    delete_removes(&factory).await;
    duplicate_put_updates_without_duplicating(&factory).await;
    clear_empties(&factory).await;
}

/// Runs the data battery against stores returned by `factory`.
pub async fn run_data_stores<S, F, Fut>(factory: F)
where
    S: DataStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    put_get_delete_with_sharing(&factory).await;
    missing_and_clear(&factory).await;
}

async fn new_message_store<S, F, Fut>(factory: &F) -> S
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = factory().await;
    store.open().await.expect("conformance store must open");
    store
}

async fn new_data_store<S, F, Fut>(factory: &F) -> S
where
    S: DataStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = factory().await;
    store.open().await.expect("conformance store must open");
    store
}

const TENANT: &str = "did:example:alice";
const OTHER_TENANT: &str = "did:example:bob";

fn message(timestamp: &str, protocol: &str, encoded_data: Option<&str>) -> Message<Descriptor> {
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let descriptor =
        Descriptor::Records(Box::new(Records::Write(Box::new(RecordsWriteDescriptor {
            protocol: protocol.to_string(),
            protocol_path: "note".to_string(),
            recipient: None,
            schema: None,
            tags: None,
            parent_id: None,
            data_cid: "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e".to_string(),
            data_size: 11,
            date_created: timestamp,
            message_timestamp: timestamp,
            published: None,
            date_published: None,
            data_format: "text/plain".to_string(),
            permission_grant_id: None,
            squash: None,
        }))));
    let fields = Fields::Write(WriteFields {
        record_id: Some(format!("record-{timestamp}")),
        encoded_data: encoded_data.map(ToString::to_string),
        ..Default::default()
    });

    Message { descriptor, fields }
}

fn indexes(message: &Message<Descriptor>) -> KeyValues {
    let mut indexes = BTreeMap::new();
    indexes.insert(
        "messageTimestamp".to_string(),
        Value::String(
            serde_json::to_value(&message.descriptor).unwrap()["messageTimestamp"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
    );
    indexes.insert(
        "interface".to_string(),
        Value::String("Records".to_string()),
    );
    indexes.insert("method".to_string(), Value::String("Write".to_string()));
    if let Some(protocol) = serde_json::to_value(&message.descriptor).unwrap()["protocol"].as_str()
    {
        indexes.insert("protocol".to_string(), Value::String(protocol.to_string()));
    }
    indexes
}

fn message_cid(message: &Message<Descriptor>) -> String {
    let mut canonical = message.clone();
    canonical.fields.encoded_data();
    canonical.cid().unwrap().to_string()
}

fn protocol_filter(protocol: &str) -> Filters {
    Filters::from([[(
        FilterKey::Index("protocol".to_string()),
        Filter::Equal(Value::String(protocol.to_string())),
    )]])
}

async fn put_get_roundtrip<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = new_message_store(factory).await;
    let msg = message(
        "2025-01-01T00:00:00.000000Z",
        "https://example.com/protocol/notes",
        Some("aGVsbG8"),
    );
    let cid = message_cid(&msg);

    store.put(TENANT, msg.clone(), indexes(&msg)).await.unwrap();
    assert_eq!(store.get(TENANT, &cid).await.unwrap(), Some(msg));

    // Missing CID and other-tenant isolation.
    assert_eq!(store.get(TENANT, "bafkreibogus").await.unwrap(), None);
    assert_eq!(store.get(OTHER_TENANT, &cid).await.unwrap(), None);
    store.close().await;
}

async fn filters_sorts_counts_and_paginates<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = new_message_store(factory).await;
    let first = message(
        "2025-01-01T00:00:00.000000Z",
        "https://example.com/protocol/notes",
        None,
    );
    let second = message(
        "2025-01-01T00:00:01.000000Z",
        "https://example.com/protocol/notes",
        None,
    );
    let third = message(
        "2025-01-01T00:00:02.000000Z",
        "https://example.com/protocol/tasks",
        None,
    );
    for msg in [&first, &second, &third] {
        store.put(TENANT, msg.clone(), indexes(msg)).await.unwrap();
    }

    let filters = protocol_filter("https://example.com/protocol/notes");
    assert_eq!(store.count(TENANT, filters.clone(), None).await.unwrap(), 2);

    let page1 = store
        .query(
            TENANT,
            filters.clone(),
            Some(MessageSort::Timestamp(SortDirection::Descending)),
            Some(Pagination::with_limit(1)),
        )
        .await
        .unwrap();
    assert_eq!(page1.messages, vec![second.clone()]);
    assert!(page1.cursor.is_some());

    let page2 = store
        .query(
            TENANT,
            filters,
            Some(MessageSort::Timestamp(SortDirection::Descending)),
            Some(Pagination::new(page1.cursor, Some(1))),
        )
        .await
        .unwrap();
    assert_eq!(page2.messages, vec![first]);
    assert!(page2.cursor.is_none());

    // Ascending order returns the same population reversed.
    let all = store
        .query(
            TENANT,
            protocol_filter("https://example.com/protocol/notes"),
            Some(MessageSort::Timestamp(SortDirection::Ascending)),
            None,
        )
        .await
        .unwrap();
    assert_eq!(all.messages.len(), 2);
    store.close().await;
}

async fn delete_removes<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = new_message_store(factory).await;
    let msg = message(
        "2025-01-01T00:00:00.000000Z",
        "https://example.com/protocol/notes",
        None,
    );
    let cid = message_cid(&msg);
    store.put(TENANT, msg.clone(), indexes(&msg)).await.unwrap();

    store.delete(TENANT, &cid).await.unwrap();
    assert_eq!(store.get(TENANT, &cid).await.unwrap(), None);
    assert_eq!(
        store
            .count(
                TENANT,
                protocol_filter("https://example.com/protocol/notes"),
                None
            )
            .await
            .unwrap(),
        0
    );

    // Deleting again is idempotent.
    store.delete(TENANT, &cid).await.unwrap();
    store.close().await;
}

// Covers: DWN-REC-003 (duplicate delivery is idempotent).
async fn duplicate_put_updates_without_duplicating<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = new_message_store(factory).await;
    let msg = message(
        "2025-01-01T00:00:00.000000Z",
        "https://example.com/protocol/notes",
        None,
    );
    let cid = message_cid(&msg);
    store.put(TENANT, msg.clone(), indexes(&msg)).await.unwrap();

    let mut updated_indexes = indexes(&msg);
    updated_indexes.insert(
        "recipient".to_string(),
        Value::Array(vec![Value::String(OTHER_TENANT.to_string())]),
    );
    store
        .put(TENANT, msg.clone(), updated_indexes)
        .await
        .unwrap();

    let filters = protocol_filter("https://example.com/protocol/notes");
    assert_eq!(store.count(TENANT, filters.clone(), None).await.unwrap(), 1);
    let result = store.query(TENANT, filters, None, None).await.unwrap();
    assert_eq!(result.messages.len(), 1);
    assert_eq!(store.get(TENANT, &cid).await.unwrap(), Some(msg));
    store.close().await;
}

async fn clear_empties<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = new_message_store(factory).await;
    for ts in ["2025-01-01T00:00:00.000000Z", "2025-01-01T00:00:01.000000Z"] {
        let msg = message(ts, "https://example.com/protocol/notes", None);
        store.put(TENANT, msg.clone(), indexes(&msg)).await.unwrap();
    }

    store.clear().await.unwrap();

    let filters = protocol_filter("https://example.com/protocol/notes");
    assert_eq!(store.count(TENANT, filters.clone(), None).await.unwrap(), 0);
    let result = store.query(TENANT, filters, None, None).await.unwrap();
    assert!(result.messages.is_empty());
    store.close().await;
}

async fn read_data(
    store: &impl DataStore,
    tenant: &str,
    record_id: &str,
    data_cid: &str,
) -> Option<Vec<u8>> {
    let stored = store.get(tenant, record_id, data_cid).await.unwrap()?;
    Some(
        stored
            .data_stream
            .try_fold(Vec::new(), |mut read, chunk| async move {
                read.extend_from_slice(&chunk);
                Ok(read)
            })
            .await
            .unwrap(),
    )
}

async fn put_get_delete_with_sharing<S, F, Fut>(factory: &F)
where
    S: DataStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = new_data_store(factory).await;
    let bytes = Bytes::from_static(b"hello battery data");
    let data_cid = generate_dag_pb_cid_from_bytes(&bytes).to_string();

    let put = DataStore::put(
        &store,
        TENANT,
        "record-1",
        &data_cid,
        stream::iter(vec![bytes.clone()]),
    )
    .await
    .unwrap();
    assert_eq!(put.data_size, bytes.len());

    // Duplicate put of the same ref ignores the stream but reports the size.
    let duplicate = DataStore::put(
        &store,
        TENANT,
        "record-1",
        &data_cid,
        stream::iter(vec![Bytes::from_static(b"ignored duplicate stream")]),
    )
    .await
    .unwrap();
    assert_eq!(duplicate.data_size, bytes.len());

    // Second record shares the same content-addressed block.
    let shared = DataStore::put(
        &store,
        TENANT,
        "record-2",
        &data_cid,
        stream::iter(vec![Bytes::from_static(b"ignored shared stream")]),
    )
    .await
    .unwrap();
    assert_eq!(shared.data_size, bytes.len());

    // Deleting one ref keeps the shared block readable via the other.
    DataStore::delete(&store, TENANT, "record-1", &data_cid)
        .await
        .unwrap();
    assert_eq!(
        read_data(&store, TENANT, "record-2", &data_cid).await,
        Some(bytes.to_vec())
    );

    DataStore::delete(&store, TENANT, "record-2", &data_cid)
        .await
        .unwrap();
    assert_eq!(read_data(&store, TENANT, "record-2", &data_cid).await, None);
    store.close().await;
}

async fn missing_and_clear<S, F, Fut>(factory: &F)
where
    S: DataStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut store = new_data_store(factory).await;
    assert_eq!(
        read_data(&store, TENANT, "nope", "bafkreibogus").await,
        None
    );

    let bytes = Bytes::from_static(b"clear me");
    let data_cid = generate_dag_pb_cid_from_bytes(&bytes).to_string();
    DataStore::put(
        &store,
        TENANT,
        "record-9",
        &data_cid,
        stream::iter(vec![bytes.clone()]),
    )
    .await
    .unwrap();

    store.clear().await.unwrap();
    assert_eq!(read_data(&store, TENANT, "record-9", &data_cid).await, None);
    store.close().await;
}

#[tokio::test]
async fn memory_message_store_conforms_to_store_contract() {
    run_message_stores(|| async { super::memory::MemoryMessageStore::default() }).await;
}
