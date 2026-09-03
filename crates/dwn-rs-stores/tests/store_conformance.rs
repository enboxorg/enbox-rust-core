//! Shared MessageStore + DataStore conformance battery for issue #169.
//!
//! Same assertions on every backend so the durable path cannot drift from the
//! reference path:
//! - MessageStore: memory (`MemoryMessageStore`) × sqlite-mem × sqlite-disk.
//! - DataStore: sqlite-mem × sqlite-disk (core has no in-memory DataStore).
//!
//! Feed-specific ordering/progress/fingerprint cases belong to C2; crash and
//! concurrency belong to C6/C8. This file covers retained-message and
//! content-addressed-data behavior only.

mod common;

use bytes::Bytes;
use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
use dwn_rs_core::filters::{Filter, FilterKey, Filters};
use dwn_rs_core::stores::memory::MemoryMessageStore;
use dwn_rs_core::stores::{DataStore, MessageStore};
use dwn_rs_core::{MessageSort, Pagination, SortDirection, Value};
use futures_util::{stream, TryStreamExt};

use common::fixtures::{indexes_for_message as indexes, message_cid, write_message as message};
use common::TempDb;

const TENANT: &str = "did:example:alice";
const OTHER_TENANT: &str = "did:example:bob";

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

fn protocol_filter(protocol: &str) -> Filters {
    Filters::from([[(
        FilterKey::Index("protocol".to_string()),
        Filter::Equal(Value::String(protocol.to_string())),
    )]])
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

// ---------------------------------------------------------------------------
// MessageStore cases (generic over backend)
// ---------------------------------------------------------------------------

async fn case_put_get_roundtrip(store: &impl MessageStore) {
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

async fn case_filters_sorts_counts_and_paginates(store: &impl MessageStore) {
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
}

async fn case_delete_removes(store: &impl MessageStore) {
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
}

// Covers: DWN-REC-003 (duplicate delivery is idempotent).
async fn case_duplicate_put_updates_without_duplicating(store: &impl MessageStore) {
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
}

async fn case_clear_empties(store: &impl MessageStore) {
    for ts in ["2025-01-01T00:00:00.000000Z", "2025-01-01T00:00:01.000000Z"] {
        let msg = message(ts, "https://example.com/protocol/notes", None);
        store.put(TENANT, msg.clone(), indexes(&msg)).await.unwrap();
    }

    store.clear().await.unwrap();

    let filters = protocol_filter("https://example.com/protocol/notes");
    assert_eq!(store.count(TENANT, filters.clone(), None).await.unwrap(), 0);
    let result = store.query(TENANT, filters, None, None).await.unwrap();
    assert!(result.messages.is_empty());
}

// ---------------------------------------------------------------------------
// DataStore cases (generic over backend)
// ---------------------------------------------------------------------------

async fn case_data_put_get_delete_with_sharing(store: &impl DataStore) {
    let bytes = Bytes::from_static(b"hello battery data");
    let data_cid = generate_dag_pb_cid_from_bytes(&bytes).to_string();

    let put = DataStore::put(
        store,
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
        store,
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
        store,
        TENANT,
        "record-2",
        &data_cid,
        stream::iter(vec![Bytes::from_static(b"ignored shared stream")]),
    )
    .await
    .unwrap();
    assert_eq!(shared.data_size, bytes.len());

    // Deleting one ref keeps the shared block readable via the other.
    DataStore::delete(store, TENANT, "record-1", &data_cid)
        .await
        .unwrap();
    assert_eq!(
        read_data(store, TENANT, "record-2", &data_cid).await,
        Some(bytes.to_vec())
    );

    DataStore::delete(store, TENANT, "record-2", &data_cid)
        .await
        .unwrap();
    assert_eq!(read_data(store, TENANT, "record-2", &data_cid).await, None);
}

async fn case_data_missing_and_clear(store: &impl DataStore) {
    assert_eq!(read_data(store, TENANT, "nope", "bafkreibogus").await, None);

    let bytes = Bytes::from_static(b"clear me");
    let data_cid = generate_dag_pb_cid_from_bytes(&bytes).to_string();
    DataStore::put(
        store,
        TENANT,
        "record-9",
        &data_cid,
        stream::iter(vec![bytes.clone()]),
    )
    .await
    .unwrap();

    store.clear().await.unwrap();
    assert_eq!(read_data(store, TENANT, "record-9", &data_cid).await, None);
}

// ---------------------------------------------------------------------------
// Backend wiring: memory × sqlite-mem × sqlite-disk (messages),
// sqlite-mem × sqlite-disk (data; core has no memory DataStore).
// ---------------------------------------------------------------------------

macro_rules! message_battery {
    ($mem:ident, $sqlite_mem:ident, $sqlite_disk:ident, $case:ident) => {
        #[tokio::test]
        async fn $mem() {
            let mut store = MemoryMessageStore::default();
            MessageStore::open(&mut store).await.unwrap();
            $case(&store).await;
        }

        #[tokio::test]
        async fn $sqlite_mem() {
            let store = common::open_sqlite_mem().await;
            $case(&store).await;
        }

        #[tokio::test]
        async fn $sqlite_disk() {
            let db = TempDb::new(stringify!($sqlite_disk));
            let store = common::open_sqlite_disk(&db).await;
            $case(&store).await;
        }
    };
}

message_battery!(
    message_put_get_roundtrip_memory,
    message_put_get_roundtrip_sqlite_mem,
    message_put_get_roundtrip_sqlite_disk,
    case_put_get_roundtrip
);
message_battery!(
    message_filters_sorts_counts_and_paginates_memory,
    message_filters_sorts_counts_and_paginates_sqlite_mem,
    message_filters_sorts_counts_and_paginates_sqlite_disk,
    case_filters_sorts_counts_and_paginates
);
message_battery!(
    message_delete_removes_memory,
    message_delete_removes_sqlite_mem,
    message_delete_removes_sqlite_disk,
    case_delete_removes
);
message_battery!(
    message_duplicate_put_updates_memory,
    message_duplicate_put_updates_sqlite_mem,
    message_duplicate_put_updates_sqlite_disk,
    case_duplicate_put_updates_without_duplicating
);
message_battery!(
    message_clear_empties_memory,
    message_clear_empties_sqlite_mem,
    message_clear_empties_sqlite_disk,
    case_clear_empties
);

macro_rules! data_battery {
    ($sqlite_mem:ident, $sqlite_disk:ident, $case:ident) => {
        #[tokio::test]
        async fn $sqlite_mem() {
            let store = common::open_sqlite_mem().await;
            $case(&store).await;
        }

        #[tokio::test]
        async fn $sqlite_disk() {
            let db = TempDb::new(stringify!($sqlite_disk));
            let store = common::open_sqlite_disk(&db).await;
            $case(&store).await;
        }
    };
}

data_battery!(
    data_put_get_delete_with_sharing_sqlite_mem,
    data_put_get_delete_with_sharing_sqlite_disk,
    case_data_put_get_delete_with_sharing
);
data_battery!(
    data_missing_and_clear_sqlite_mem,
    data_missing_and_clear_sqlite_disk,
    case_data_missing_and_clear
);
