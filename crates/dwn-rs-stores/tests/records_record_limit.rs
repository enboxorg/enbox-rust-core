//! Record-limit reopen parity: a file-backed SQLite store returns the
//! identical occupant population after close and reopen.
//!
//! Seeding scaffolding is shared with the record-limit conformance battery.
//!
//! Covers: DWN-REC-004, DWN-REC-005

use dwn_rs_core::stores::store_conformance::{
    latest_writes_filter, limit_indexes, limit_message, limit_policy, limit_row, write_record_ids,
};
use dwn_rs_core::stores::MessageStore;

use dwn_rs_stores::SqliteStore;

mod common;

const TENANT: &str = "did:example:alice";

fn record_limit() -> dwn_rs_core::stores::RecordLimitOccupancy {
    limit_policy("thread", 2, None, None)
}

async fn query_occupants(store: &SqliteStore) -> (Vec<String>, u64) {
    let found = store
        .query(
            TENANT,
            latest_writes_filter(),
            None,
            None,
            Some(record_limit()),
        )
        .await
        .expect("occupant query must succeed");
    let mut ids = write_record_ids(&found.messages);
    ids.sort();
    let count = store
        .count(TENANT, latest_writes_filter(), None, Some(record_limit()))
        .await
        .expect("occupant count must succeed");
    (ids, count)
}

#[tokio::test]
async fn record_limit_population_survives_close_and_reopen() {
    let dir = tempfile::tempdir().expect("reopen tempdir");
    let path = dir.path().join("record-limit.sqlite");

    let expected = {
        let mut store = SqliteStore::new(&path, common::noop_waker());
        MessageStore::open(&mut store).await.unwrap();
        for (record_id, day) in [("r1", 1), ("r2", 2), ("r3", 3), ("r4", 4)] {
            let row = limit_row(record_id, None, None, day, "thread");
            store
                .put(TENANT, limit_message(&row), limit_indexes(&row))
                .await
                .unwrap();
        }
        let (ids, count) = query_occupants(&store).await;
        assert_eq!(ids.len(), 2, "only max occupants are visible");
        assert_eq!(count, 2);
        ids
    };

    let mut reopened = SqliteStore::new(&path, common::noop_waker());
    MessageStore::open(&mut reopened).await.unwrap();
    let (actual, count) = query_occupants(&reopened).await;
    assert_eq!(count, 2);
    assert_eq!(actual, expected, "reopen preserves the occupant population");
}
