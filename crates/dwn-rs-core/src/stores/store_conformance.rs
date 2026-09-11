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
    let store = new_message_store(factory).await;
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
}

async fn filters_sorts_counts_and_paginates<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_message_store(factory).await;
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
    assert_eq!(
        store
            .count(TENANT, filters.clone(), None, None)
            .await
            .unwrap(),
        2
    );

    let page1 = store
        .query(
            TENANT,
            filters.clone(),
            Some(MessageSort::Timestamp(SortDirection::Descending)),
            Some(Pagination::with_limit(1)),
            None,
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
            None,
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
            None,
        )
        .await
        .unwrap();
    assert_eq!(all.messages.len(), 2);
}

async fn delete_removes<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_message_store(factory).await;
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
                None,
                None,
            )
            .await
            .unwrap(),
        0
    );

    // Deleting again is idempotent.
    store.delete(TENANT, &cid).await.unwrap();
}

// Covers: DWN-REC-003 (duplicate delivery is idempotent).
async fn duplicate_put_updates_without_duplicating<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_message_store(factory).await;
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
    assert_eq!(
        store
            .count(TENANT, filters.clone(), None, None)
            .await
            .unwrap(),
        1
    );
    let result = store
        .query(TENANT, filters, None, None, None)
        .await
        .unwrap();
    assert_eq!(result.messages.len(), 1);
    assert_eq!(store.get(TENANT, &cid).await.unwrap(), Some(msg));
}

async fn clear_empties<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_message_store(factory).await;
    for ts in ["2025-01-01T00:00:00.000000Z", "2025-01-01T00:00:01.000000Z"] {
        let msg = message(ts, "https://example.com/protocol/notes", None);
        store.put(TENANT, msg.clone(), indexes(&msg)).await.unwrap();
    }

    store.clear().await.unwrap();

    let filters = protocol_filter("https://example.com/protocol/notes");
    assert_eq!(
        store
            .count(TENANT, filters.clone(), None, None)
            .await
            .unwrap(),
        0
    );
    let result = store
        .query(TENANT, filters, None, None, None)
        .await
        .unwrap();
    assert!(result.messages.is_empty());
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
    let store = new_data_store(factory).await;
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
}

async fn missing_and_clear<S, F, Fut>(factory: &F)
where
    S: DataStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_data_store(factory).await;
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
}

#[tokio::test]
async fn memory_message_store_conforms_to_store_contract() {
    run_message_stores(|| async { super::memory::MemoryMessageStore::default() }).await;
}

#[tokio::test]
async fn memory_message_store_conforms_to_record_limit() {
    run_record_limit_stores(|| async { super::memory::MemoryMessageStore::default() }).await;
}

#[tokio::test]
async fn memory_message_store_orders_ties_by_cid() {
    run_sort_tie_break_stores(|| async { super::memory::MemoryMessageStore::default() }).await;
}

#[tokio::test]
async fn memory_message_store_excludes_rows_missing_the_sort_property() {
    run_sort_property_stores(|| async { super::memory::MemoryMessageStore::default() }).await;
}

// ---- record-limit occupancy battery ----
//
// Same assertions on every backend: deterministic winners independent of
// insertion order, per-group partitioning, pagination and counting over the
// admitted set, and fail-closed reads. SQLite runs in `dwn-rs-stores`.

const LIMIT_PROTOCOL: &str = "https://example.com/protocol/threads";
const LIMIT_ROOT_PATH: &str = "thread";
const LIMIT_NESTED_PATH: &str = "thread/message";

fn limit_day(day: u32) -> String {
    format!("2025-01-{day:02}T00:00:00.000000Z")
}

/// Shared with the record-limit reopen test in `dwn-rs-stores`.
pub struct LimitRow {
    record_id: String,
    parent_id: Option<String>,
    context_id: Option<String>,
    date_created: String,
    protocol_path: String,
    latest: bool,
    tombstone: bool,
}

/// Shared with the record-limit reopen test in `dwn-rs-stores`.
pub fn limit_row(
    record_id: &str,
    parent_id: Option<&str>,
    context_id: Option<&str>,
    day: u32,
    protocol_path: &str,
) -> LimitRow {
    LimitRow {
        record_id: record_id.to_string(),
        parent_id: parent_id.map(str::to_string),
        context_id: context_id.map(str::to_string),
        date_created: limit_day(day),
        protocol_path: protocol_path.to_string(),
        latest: true,
        tombstone: false,
    }
}

/// Shared with the record-limit reopen test in `dwn-rs-stores`.
pub fn limit_message(row: &LimitRow) -> Message<Descriptor> {
    let timestamp = chrono::DateTime::parse_from_rfc3339(&row.date_created)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let descriptor =
        Descriptor::Records(Box::new(Records::Write(Box::new(RecordsWriteDescriptor {
            protocol: LIMIT_PROTOCOL.to_string(),
            protocol_path: row.protocol_path.clone(),
            recipient: None,
            schema: None,
            tags: None,
            parent_id: row.parent_id.clone(),
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
        record_id: Some(row.record_id.clone()),
        context_id: row.context_id.clone(),
        ..Default::default()
    });

    Message { descriptor, fields }
}

/// Shared with the record-limit reopen test in `dwn-rs-stores`.
pub fn limit_indexes(row: &LimitRow) -> KeyValues {
    let mut indexes = BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        (
            "method".to_string(),
            Value::String(if row.tombstone { "Delete" } else { "Write" }.to_string()),
        ),
        ("isLatestBaseState".to_string(), Value::Bool(row.latest)),
        (
            "protocol".to_string(),
            Value::String(LIMIT_PROTOCOL.to_string()),
        ),
        (
            "protocolPath".to_string(),
            Value::String(row.protocol_path.clone()),
        ),
        ("recordId".to_string(), Value::String(row.record_id.clone())),
        (
            "dateCreated".to_string(),
            Value::String(row.date_created.clone()),
        ),
        (
            "messageTimestamp".to_string(),
            Value::String(row.date_created.clone()),
        ),
    ]);
    if let Some(parent_id) = row.parent_id.as_deref() {
        indexes.insert("parentId".to_string(), Value::String(parent_id.to_string()));
    }
    if let Some(context_id) = row.context_id.as_deref() {
        indexes.insert(
            "contextId".to_string(),
            Value::String(context_id.to_string()),
        );
    }
    indexes
}

/// Shared with the record-limit reopen test in `dwn-rs-stores`.
pub fn write_record_ids(messages: &[Message<Descriptor>]) -> Vec<String> {
    messages
        .iter()
        .map(|message| match &message.fields {
            Fields::Write(fields) => fields
                .record_id
                .clone()
                .expect("seed rows carry record IDs"),
            _ => panic!("seed rows are records writes"),
        })
        .collect()
}

/// Shared with the record-limit reopen test in `dwn-rs-stores`.
pub fn limit_policy(
    protocol_path: &str,
    max: u64,
    context_id: Option<&str>,
    parent_id: Option<Vec<String>>,
) -> super::RecordLimitOccupancy {
    super::RecordLimitOccupancy {
        protocol: LIMIT_PROTOCOL.to_string(),
        protocol_path: protocol_path.to_string(),
        context_id: context_id.map(str::to_string),
        parent_id,
        max,
    }
}

/// Shared with the record-limit reopen test in `dwn-rs-stores`.
pub fn latest_writes_filter() -> Filters {
    Filters::from(BTreeMap::from([
        (
            FilterKey::Index("interface".to_string()),
            Filter::Equal(Value::String("Records".to_string())),
        ),
        (
            FilterKey::Index("method".to_string()),
            Filter::Equal(Value::String("Write".to_string())),
        ),
        (
            FilterKey::Index("isLatestBaseState".to_string()),
            Filter::Equal(Value::Bool(true)),
        ),
    ]))
}

fn created_sort() -> Option<MessageSort> {
    Some(MessageSort::DateCreated(SortDirection::Ascending))
}

async fn seed_limit_store<S, F, Fut>(factory: &F, rows: &[LimitRow]) -> S
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_message_store(factory).await;
    for row in rows {
        store
            .put(TENANT, limit_message(row), limit_indexes(row))
            .await
            .unwrap();
    }
    store
}

/// Runs the record-limit battery against stores returned by `factory`.
pub async fn run_record_limit_stores<S, F, Fut>(factory: F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    root_admits_oldest_max(&factory).await;
    ties_break_by_record_id(&factory).await;
    nested_groups_partition(&factory).await;
    subtree_policy_fences_candidates(&factory).await;
    non_live_state_excluded(&factory).await;
    occupancy_applies_before_caller_filters(&factory).await;
    invalid_max_and_corrupt_candidates_fail(&factory).await;
    absent_policy_returns_unprojected(&factory).await;
}

/// Runs the sort-property battery: a record whose indexes lack the property a
/// query sorts by is excluded from that query's results.
///
/// Upstream drops such items rather than ordering them among the rest
/// (`index-level.ts` skips any item whose `sortProperty` is undefined), so a
/// backend that returns them answers a differently-populated query than another
/// backend would — the divergence `DWN-REC-001` exists to prevent.
///
/// The realistic case is publication sorting: an unpublished record carries no
/// `datePublished` index, so sorting by it must not surface records that were
/// never published.
pub async fn run_sort_property_stores<S, F, Fut>(factory: F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    rows_missing_the_sort_property_are_excluded(&factory).await;
}

/// Runs the sort tie-break battery: equal primary keys order by CID in the
/// requested direction on every backend, with cursors chaining without
/// duplicates or skips.
pub async fn run_sort_tie_break_stores<S, F, Fut>(factory: F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    equal_timestamps_order_by_cid(&factory).await;
}

// Covers: DWN-REC-001
async fn rows_missing_the_sort_property_are_excluded<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let store = new_message_store(factory).await;

    // Two rows alike but for one index: only `published` carries a
    // `datePublished`, exactly as an unpublished record would not.
    for (record_id, published) in [("sort-published", true), ("sort-unpublished", false)] {
        let row = limit_row(record_id, None, None, 1, LIMIT_ROOT_PATH);
        let mut indexes = limit_indexes(&row);
        if published {
            indexes.insert(
                "datePublished".to_string(),
                Value::String(limit_day(1).to_string()),
            );
        }
        store
            .put(TENANT, limit_message(&row), indexes)
            .await
            .unwrap();
    }

    for direction in [SortDirection::Ascending, SortDirection::Descending] {
        let found = store
            .query(
                TENANT,
                latest_writes_filter(),
                Some(MessageSort::DatePublished(direction)),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            write_record_ids(&found.messages),
            vec!["sort-published".to_string()],
            "sorting by datePublished ({direction:?}) must exclude the row without one, \
             not order it among the rest"
        );
    }

    // The excluded row is present and reachable — it is the *sort* that
    // excludes it, not the filter or the seeding.
    let unsorted = store
        .query(TENANT, latest_writes_filter(), None, None, None)
        .await
        .unwrap();
    assert_eq!(
        unsorted.messages.len(),
        2,
        "both rows must be stored, or the exclusion above proves nothing"
    );
}

// Covers: DWN-REC-004
async fn root_admits_oldest_max<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let policy = limit_policy(LIMIT_ROOT_PATH, 2, None, None);
    for order in [[1, 2, 3, 4], [4, 3, 2, 1], [3, 1, 4, 2]] {
        let rows: Vec<LimitRow> = order
            .into_iter()
            .map(|day| limit_row(&format!("root-{day}"), None, None, day, LIMIT_ROOT_PATH))
            .collect();
        let store = seed_limit_store(factory, &rows).await;
        let found = store
            .query(
                TENANT,
                latest_writes_filter(),
                created_sort(),
                None,
                Some(policy.clone()),
            )
            .await
            .unwrap();
        assert_eq!(
            write_record_ids(&found.messages),
            vec!["root-1".to_string(), "root-2".to_string()],
            "insertion order {order:?} must not change the winners"
        );
        assert_eq!(
            store
                .count(
                    TENANT,
                    latest_writes_filter(),
                    created_sort(),
                    Some(policy.clone())
                )
                .await
                .unwrap(),
            2,
            "count must equal the admitted population"
        );
    }
}

// Covers: DWN-REC-004
async fn ties_break_by_record_id<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let policy = limit_policy(LIMIT_ROOT_PATH, 2, None, None);
    for order in [["tie-a", "tie-b", "tie-c"], ["tie-c", "tie-b", "tie-a"]] {
        let rows: Vec<LimitRow> = order
            .into_iter()
            .map(|record_id| limit_row(record_id, None, None, 1, LIMIT_ROOT_PATH))
            .collect();
        let store = seed_limit_store(factory, &rows).await;
        let found = store
            .query(
                TENANT,
                latest_writes_filter(),
                created_sort(),
                None,
                Some(policy.clone()),
            )
            .await
            .unwrap();
        let mut winners = write_record_ids(&found.messages);
        winners.sort();
        assert_eq!(
            winners,
            vec!["tie-a".to_string(), "tie-b".to_string()],
            "equal creation times rank by record ID in insertion order {order:?}"
        );
    }
}

// Covers: DWN-REC-004
async fn nested_groups_partition<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let rows: Vec<LimitRow> = ["pa", "pb"]
        .into_iter()
        .flat_map(|parent| {
            [1, 2, 3].map(|day| {
                limit_row(
                    &format!("{parent}-{day}"),
                    Some(parent),
                    None,
                    day,
                    LIMIT_NESTED_PATH,
                )
            })
        })
        .collect();
    let store = seed_limit_store(factory, &rows).await;

    let wide = limit_policy(LIMIT_NESTED_PATH, 2, None, None);
    let found = store
        .query(
            TENANT,
            latest_writes_filter(),
            created_sort(),
            None,
            Some(wide.clone()),
        )
        .await
        .unwrap();
    let mut winners = write_record_ids(&found.messages);
    winners.sort();
    assert_eq!(
        winners,
        vec![
            "pa-1".to_string(),
            "pa-2".to_string(),
            "pb-1".to_string(),
            "pb-2".to_string()
        ],
        "each direct-parent group keeps its own max"
    );
    assert_eq!(
        store
            .count(TENANT, latest_writes_filter(), created_sort(), Some(wide))
            .await
            .unwrap(),
        4
    );

    let scoped = limit_policy(LIMIT_NESTED_PATH, 2, None, Some(vec!["pa".to_string()]));
    let found = store
        .query(
            TENANT,
            latest_writes_filter(),
            created_sort(),
            None,
            Some(scoped.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        write_record_ids(&found.messages),
        vec!["pa-1".to_string(), "pa-2".to_string()]
    );
    assert_eq!(
        store
            .count(TENANT, latest_writes_filter(), created_sort(), Some(scoped))
            .await
            .unwrap(),
        2
    );

    let empty = limit_policy(LIMIT_NESTED_PATH, 2, None, Some(Vec::new()));
    let found = store
        .query(
            TENANT,
            latest_writes_filter(),
            created_sort(),
            None,
            Some(empty.clone()),
        )
        .await
        .unwrap();
    assert!(found.messages.is_empty());
    assert_eq!(
        store
            .count(TENANT, latest_writes_filter(), created_sort(), Some(empty))
            .await
            .unwrap(),
        0
    );
}

// Covers: DWN-REC-004
async fn subtree_policy_fences_candidates<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let rows = [
        limit_row("in-a1", None, Some("ctx-a/1"), 1, LIMIT_ROOT_PATH),
        limit_row("in-a2", None, Some("ctx-a/2"), 2, LIMIT_ROOT_PATH),
        limit_row("out-b1", None, Some("ctx-b/1"), 1, LIMIT_ROOT_PATH),
    ];
    let store = seed_limit_store(factory, &rows).await;
    let policy = limit_policy(LIMIT_ROOT_PATH, 1, Some("ctx-a"), None);
    let found = store
        .query(
            TENANT,
            latest_writes_filter(),
            created_sort(),
            None,
            Some(policy.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        write_record_ids(&found.messages),
        vec!["in-a1".to_string()],
        "candidates outside the policy subtree consume no slots"
    );
    assert_eq!(
        store
            .count(TENANT, latest_writes_filter(), created_sort(), Some(policy))
            .await
            .unwrap(),
        1
    );
}

// Covers: DWN-REC-005
async fn non_live_state_excluded<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let mut rows: Vec<LimitRow> = [1, 2, 3]
        .into_iter()
        .map(|day| limit_row(&format!("live-{day}"), None, None, day, LIMIT_ROOT_PATH))
        .collect();
    let mut stale = limit_row("stale-0", None, None, 1, LIMIT_ROOT_PATH);
    stale.date_created = "2024-12-01T00:00:00.000000Z".to_string();
    stale.latest = false;
    rows.push(stale);
    let mut tombstone = limit_row("gone-9", None, None, 1, LIMIT_ROOT_PATH);
    tombstone.date_created = "2024-01-01T00:00:00.000000Z".to_string();
    tombstone.tombstone = true;
    rows.push(tombstone);

    let store = seed_limit_store(factory, &rows).await;
    let policy = limit_policy(LIMIT_ROOT_PATH, 2, None, None);
    let found = store
        .query(
            TENANT,
            latest_writes_filter(),
            created_sort(),
            None,
            Some(policy.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        write_record_ids(&found.messages),
        vec!["live-1".to_string(), "live-2".to_string()],
        "superseded writes and tombstones never occupy slots"
    );
    assert_eq!(
        store
            .count(TENANT, latest_writes_filter(), created_sort(), Some(policy))
            .await
            .unwrap(),
        2
    );
}

// Covers: DWN-REC-004, DWN-REC-005
async fn occupancy_applies_before_caller_filters<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let rows: Vec<LimitRow> = [1, 2, 3, 4, 5]
        .into_iter()
        .map(|day| limit_row(&format!("w{day}"), None, None, day, LIMIT_ROOT_PATH))
        .collect();
    let store = seed_limit_store(factory, &rows).await;
    let policy = limit_policy(LIMIT_ROOT_PATH, 3, None, None);
    // w4 and w5 match the caller filter but lost their slots: occupancy wins.
    let mut caller = latest_writes_filter();
    for set in caller.set.iter_mut() {
        set.insert(
            FilterKey::Index("recordId".to_string()),
            Filter::OneOf(
                ["w2", "w3", "w4", "w5"]
                    .into_iter()
                    .map(|record_id| Value::String(record_id.to_string()))
                    .collect(),
            ),
        );
    }

    let count = store
        .count(TENANT, caller.clone(), created_sort(), Some(policy.clone()))
        .await
        .unwrap();
    assert_eq!(
        count, 2,
        "non-occupants matching the filter are not counted"
    );

    let mut cursor = None;
    let mut pages = Vec::new();
    loop {
        let page = store
            .query(
                TENANT,
                caller.clone(),
                created_sort(),
                Some(Pagination::new(cursor, Some(1))),
                Some(policy.clone()),
            )
            .await
            .unwrap();
        pages.extend(write_record_ids(&page.messages));
        cursor = page.cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(pages, vec!["w2".to_string(), "w3".to_string()]);
}

// Covers: DWN-REC-004
async fn invalid_max_and_corrupt_candidates_fail<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let rows: Vec<LimitRow> = [1, 2]
        .into_iter()
        .map(|day| limit_row(&format!("r{day}"), None, None, day, LIMIT_ROOT_PATH))
        .collect();
    let store = seed_limit_store(factory, &rows).await;

    let zero_max = limit_policy(LIMIT_ROOT_PATH, 0, None, None);
    assert!(
        store
            .query(
                TENANT,
                latest_writes_filter(),
                created_sort(),
                None,
                Some(zero_max.clone())
            )
            .await
            .is_err(),
        "max == 0 must fail rather than widen"
    );
    assert!(store
        .count(
            TENANT,
            latest_writes_filter(),
            created_sort(),
            Some(zero_max)
        )
        .await
        .is_err());

    let forged_message = limit_message(&limit_row("r9", None, None, 1, LIMIT_ROOT_PATH));
    let mut forged_indexes = limit_indexes(&limit_row("r9", None, None, 1, LIMIT_ROOT_PATH));
    forged_indexes.insert("dateCreated".to_string(), Value::Number(42));
    let forged = new_message_store(factory).await;
    forged
        .put(TENANT, forged_message, forged_indexes)
        .await
        .unwrap();
    assert!(
        forged
            .query(
                TENANT,
                latest_writes_filter(),
                created_sort(),
                None,
                Some(limit_policy(LIMIT_ROOT_PATH, 2, None, None)),
            )
            .await
            .is_err(),
        "corrupt rank components must fail rather than widen"
    );
}

async fn absent_policy_returns_unprojected<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    let rows: Vec<LimitRow> = [1, 2, 3]
        .into_iter()
        .map(|day| limit_row(&format!("r{day}"), None, None, day, LIMIT_ROOT_PATH))
        .collect();
    let store = seed_limit_store(factory, &rows).await;
    let found = store
        .query(TENANT, latest_writes_filter(), created_sort(), None, None)
        .await
        .unwrap();
    assert_eq!(found.messages.len(), 3);
    assert_eq!(
        store
            .count(TENANT, latest_writes_filter(), created_sort(), None)
            .await
            .unwrap(),
        3
    );
}

// Covers: DWN-REC-004
async fn equal_timestamps_order_by_cid<S, F, Fut>(factory: &F)
where
    S: MessageStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    // Two seed orders: a backend returning insertion order instead of CID
    // order can match at most one of them, so agreement on both proves the
    // tie-break rather than coinciding with it.
    for seed_order in [["tie-a", "tie-b", "tie-c"], ["tie-c", "tie-b", "tie-a"]] {
        let rows: Vec<LimitRow> = seed_order
            .into_iter()
            .map(|record_id| limit_row(record_id, None, None, 1, LIMIT_ROOT_PATH))
            .collect();
        let store = seed_limit_store(factory, &rows).await;

        let mut expected: Vec<(String, String)> = rows
            .iter()
            .map(|row| {
                let message = limit_message(row);
                let cid = message
                    .cid()
                    .expect("seed message must have a CID")
                    .to_string();
                (cid, row.record_id.clone())
            })
            .collect();
        expected.sort();

        for direction in [SortDirection::Ascending, SortDirection::Descending] {
            let sort = Some(MessageSort::DateCreated(direction));
            let mut ordered = expected.clone();
            if direction == SortDirection::Descending {
                ordered.reverse();
            }
            let found = store
                .query(TENANT, latest_writes_filter(), sort, None, None)
                .await
                .unwrap();
            assert_eq!(
                write_record_ids(&found.messages),
                ordered
                    .iter()
                    .map(|(_, record_id)| record_id.clone())
                    .collect::<Vec<_>>(),
                "equal timestamps order by CID in {direction:?} on every backend"
            );

            // Page size 1 across the tie: every page chains, nothing duplicates
            // or skips, and the concatenated pages equal the full order.
            let mut cursor = None;
            let mut paged = Vec::new();
            loop {
                let page = store
                    .query(
                        TENANT,
                        latest_writes_filter(),
                        sort,
                        Some(Pagination::new(cursor, Some(1))),
                        None,
                    )
                    .await
                    .unwrap();
                paged.extend(write_record_ids(&page.messages));
                cursor = page.cursor;
                if cursor.is_none() {
                    break;
                }
            }
            assert_eq!(
                paged,
                ordered
                    .iter()
                    .map(|(_, record_id)| record_id.clone())
                    .collect::<Vec<_>>(),
                "paged traversal matches full order in {direction:?}"
            );
        }
    }
}
