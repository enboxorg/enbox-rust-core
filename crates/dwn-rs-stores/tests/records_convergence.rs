//! Dwn-level convergence battery for issue #169 (C6b commit 3).
//!
//! Same signed RecordsWrite/Delete inputs through identical
//! `SqliteNativeDwn` code on sqlite-mem vs sqlite-disk, in different arrival
//! orders and across a mid-sequence drop+reopen of the disk node. Converged
//! contract: equal RecordsQuery populations, equal RecordsRead bodies,
//! equal status codes, equal global fingerprints.
//!
//! Signed builders come from `dwn_rs_core::testing` (test-utils feature).
//!
//! Covers: DWN-REC-004, ENBOX-REC-001, DWN-REC-006, DWN-AUTH-006.

mod common;

use bytes::Bytes;
use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
use dwn_rs_core::stores::ReplicationFeedReader;
use dwn_rs_core::testing::{
    put_notes_protocol_without_actions, signed_delete_message, signed_write_message, test_resolver,
    unsigned_query_message, unsigned_read_message, WriteSpec,
};
use dwn_rs_core::Reply;
use serde_json::{json, Value as JsonValue};

use common::TempDb;
use dwn_rs_stores::SqliteNativeDwn;

const TENANT: &str = "did:example:alice";
const T1: &str = "2025-01-01T00:00:00.000000Z";
const T2: &str = "2025-01-01T00:00:01.000000Z";
const T3: &str = "2025-01-01T00:00:02.000000Z";

#[derive(Clone)]
enum Op {
    Write { value: JsonValue, data: Bytes },
    Delete { value: JsonValue },
}

/// Built once per test: v1 write, v2 update of the same record, and a delete
/// newer than both so delete-wins is deterministic.
struct Scenario {
    ops: Vec<Op>,
    record_id: String,
}

async fn scenario() -> Scenario {
    let payload_v1 = Bytes::from_static(b"convergence version one");
    let payload_v2 = Bytes::from_static(b"convergence version two");
    let v1 = signed_write_message(WriteSpec {
        data_cid: generate_dag_pb_cid_from_bytes(&payload_v1).to_string(),
        data_size: payload_v1.len() as u64,
        published: Some(true),
        timestamp: T1.to_string(),
        date_created: T1.to_string(),
        ..WriteSpec::new(T1)
    })
    .await;
    let record_id = v1["recordId"].as_str().expect("recordId").to_string();
    // NB: date_created is immutable: the update keeps the initial's value and
    // only advances message_timestamp.
    let v2 = signed_write_message(WriteSpec {
        record_id: Some(record_id.clone()),
        data_cid: generate_dag_pb_cid_from_bytes(&payload_v2).to_string(),
        data_size: payload_v2.len() as u64,
        published: Some(true),
        timestamp: T2.to_string(),
        date_created: T1.to_string(),
        ..WriteSpec::new(T2)
    })
    .await;
    let delete = signed_delete_message(&record_id, false, T3).await;
    Scenario {
        ops: vec![
            Op::Write {
                value: v1,
                data: payload_v1,
            },
            Op::Write {
                value: v2,
                data: payload_v2,
            },
            Op::Delete { value: delete },
        ],
        record_id,
    }
}

struct Nodes {
    mem: SqliteNativeDwn,
    // `Option` so a mid-sequence restart can drop the old node (releasing its
    // SQLite connections) *before* opening the fresh handle on the same file.
    // Holding two live connection sets on one file piles onto the
    // process-global Unix VFS lock.
    disk: Option<SqliteNativeDwn>,
    _db: TempDb,
}

async fn fresh_nodes() -> Nodes {
    let db = TempDb::new("records-convergence");
    let mem = SqliteNativeDwn::open_in_memory(test_resolver())
        .await
        .expect("open mem node");
    let disk = SqliteNativeDwn::open_at(db.path(), test_resolver())
        .await
        .expect("open disk node");
    for node in [&mem, &disk] {
        put_notes_protocol_without_actions(TENANT, node.store()).await;
    }
    Nodes {
        mem,
        disk: Some(disk),
        _db: db,
    }
}

async fn apply(node: &SqliteNativeDwn, op: &Op) -> i32 {
    match op {
        Op::Write { value, data } => {
            node.process_message_with_data(TENANT, value.clone(), Some(data.clone()))
                .await
                .status
                .code
        }
        Op::Delete { value } => {
            node.dwn()
                .process_message(TENANT, value.clone())
                .await
                .status
                .code
        }
    }
}

#[derive(Debug, PartialEq)]
struct VisibleState {
    query_status: i32,
    query_entries: Vec<JsonValue>,
    read_status: i32,
    read_entry: JsonValue,
    fingerprint: String,
    head: String,
}

impl VisibleState {
    /// Cross-order convergence key. `head` is excluded: rejected messages
    /// consume no feed positions, so orders admitting different sets
    /// legitimately differ in head while visible state and fingerprints
    /// converge (cursors are source-local, DWN-SYNC-004).
    fn convergence_key(&self) -> (i32, Vec<JsonValue>, i32, JsonValue, String) {
        (
            self.query_status,
            self.query_entries.clone(),
            self.read_status,
            self.read_entry.clone(),
            self.fingerprint.clone(),
        )
    }
}

async fn visible_state(node: &SqliteNativeDwn, record_id: &str) -> VisibleState {
    let query = node
        .dwn()
        .process_message(TENANT, unsigned_query_message(json!({ "published": true })))
        .await;
    let Reply::RecordsQuery(query_reply) = query.reply else {
        panic!("expected RecordsQuery reply, got {:?}", query.status);
    };
    let read = node
        .dwn()
        .process_message(
            TENANT,
            unsigned_read_message(json!({ "recordId": record_id })),
        )
        .await;
    let Reply::RecordsRead(read_reply) = read.reply else {
        panic!("expected RecordsRead reply, got {:?}", read.status);
    };
    let (_, latest) = node
        .store()
        .log_bounds(TENANT)
        .await
        .expect("bounds")
        .expect("non-empty feed");
    VisibleState {
        query_status: query.status.code,
        query_entries: query_reply
            .entries
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| serde_json::to_value(entry).unwrap())
                    .collect()
            })
            .unwrap_or_default(),
        read_status: read.status.code,
        read_entry: serde_json::to_value(&read_reply.entry).unwrap(),
        fingerprint: node
            .store()
            .fingerprint(TENANT, &["".to_string()])
            .await
            .expect("fingerprint")
            .to_string(),
        head: latest.position,
    }
}

/// Feed ops in `order` on both nodes; restarts the disk node after
/// `restart_disk_after` ops when set. Returns per-node status codes.
async fn run_order(
    nodes: &mut Nodes,
    ops: &[Op],
    order: &[usize],
    restart_disk_after: Option<usize>,
) -> (Vec<i32>, Vec<i32>) {
    let mut mem_statuses = Vec::new();
    for index in order {
        mem_statuses.push(apply(&nodes.mem, &ops[*index]).await);
    }
    let mut disk_statuses = Vec::new();
    for (applied, index) in order.iter().enumerate() {
        if restart_disk_after == Some(applied) {
            // Drop the old node (connections close) *before* reopening the same
            // file, so the two connection sets never overlap.
            let path = nodes._db.path().to_path_buf();
            drop(nodes.disk.take());
            nodes.disk = Some(
                SqliteNativeDwn::open_at(&path, test_resolver())
                    .await
                    .expect("reopen disk node"),
            );
        }
        disk_statuses.push(apply(nodes.disk.as_ref().expect("disk node"), &ops[*index]).await);
    }
    (mem_statuses, disk_statuses)
}

async fn states(nodes: &Nodes, record_id: &str) -> (VisibleState, VisibleState) {
    (
        visible_state(&nodes.mem, record_id).await,
        visible_state(nodes.disk.as_ref().expect("disk node"), record_id).await,
    )
}

// Covers: ENBOX-REC-001 (terminal delete dominates regardless of order).
//
// A delete arriving before any write is an error, not a tombstone (there is
// nothing to delete against), so both orders below create the record first:
// the delete still wins whether the competing update lands before or after
// it, and the stale loser is rejected without reviving the record.
#[tokio::test]
async fn delete_wins_in_both_arrival_orders() {
    // Serialize file-backed tests process-wide.
    let _disk = common::disk_test_guard().await;
    let scenario = scenario().await;
    let mut observed = Vec::new();
    // Write, update, delete vs write, delete, stale-update-rejected.
    for (order, expected) in [
        (vec![0, 1, 2], vec![202, 202, 202]),
        (vec![0, 2, 1], vec![202, 202, 409]),
    ] {
        let mut nodes = fresh_nodes().await;
        let (mem_statuses, disk_statuses) =
            run_order(&mut nodes, &scenario.ops, &order, None).await;
        assert_eq!(mem_statuses, expected);
        assert_eq!(disk_statuses, expected);
        let (mem_state, disk_state) = states(&nodes, &scenario.record_id).await;
        assert_eq!(mem_state, disk_state);
        // Tombstone: reads miss, queries are empty.
        assert_eq!(mem_state.read_status, 404);
        assert!(mem_state.query_entries.is_empty());
        observed.push(mem_state.convergence_key());
    }
    assert_eq!(observed[0], observed[1]);
}

// Covers: DWN-REC-004 (same valid set, any order, same state).
//
// Note on scope: an update arriving before its initial is rejected as a
// missing dependency (400) and is not retried at this layer, so reversed
// orders admit different sets and legitimately diverge; dependency retry is
// the sync layer's job (#188, DWN-SYNC-003). What must converge is replay of
// the same admitted set below: the newest write stays latest, and an
// identical replay is rejected as conflicting (409) without changing state
// (DWN-REC-003 idempotence of logical state, not of status codes).
#[tokio::test]
async fn newest_write_wins_and_identical_replay_rejected() {
    // Serialize file-backed tests process-wide.
    let _disk = common::disk_test_guard().await;
    let scenario = scenario().await;
    let ops = vec![
        scenario.ops[0].clone(),
        scenario.ops[1].clone(),
        scenario.ops[1].clone(),
    ];
    let mut nodes = fresh_nodes().await;
    let (mem_statuses, disk_statuses) = run_order(&mut nodes, &ops, &[0, 1, 2], None).await;
    assert_eq!(mem_statuses, vec![202, 202, 409]);
    assert_eq!(disk_statuses, mem_statuses);
    let (mem_state, disk_state) = states(&nodes, &scenario.record_id).await;
    assert_eq!(mem_state, disk_state);
    assert_eq!(mem_state.read_status, 200);
    assert_eq!(mem_state.query_entries.len(), 1);
}

#[tokio::test]
async fn stale_write_rejected_identically() {
    // Serialize file-backed tests process-wide.
    let _disk = common::disk_test_guard().await;
    let scenario = scenario().await;
    // Initial, update, then the stale initial again: rejected, state newest.
    let ops = vec![
        scenario.ops[0].clone(),
        scenario.ops[1].clone(),
        scenario.ops[0].clone(),
    ];
    let mut nodes = fresh_nodes().await;
    let (mem_statuses, disk_statuses) = run_order(&mut nodes, &ops, &[0, 1, 2], None).await;
    assert_eq!(mem_statuses, vec![202, 202, 409]);
    assert_eq!(disk_statuses, mem_statuses);
    let (mem_state, disk_state) = states(&nodes, &scenario.record_id).await;
    assert_eq!(mem_state, disk_state);
    assert_eq!(mem_state.read_status, 200);
}

#[tokio::test]
async fn duplicate_replay_converges() {
    // Serialize file-backed tests process-wide.
    let _disk = common::disk_test_guard().await;
    let scenario = scenario().await;
    let ops = vec![scenario.ops[0].clone(), scenario.ops[0].clone()];
    let mut nodes = fresh_nodes().await;
    let (mem_statuses, disk_statuses) = run_order(&mut nodes, &ops, &[0, 1], None).await;
    assert_eq!(mem_statuses, disk_statuses);
    let (mem_state, disk_state) = states(&nodes, &scenario.record_id).await;
    assert_eq!(mem_state, disk_state);
    assert_eq!(mem_state.query_entries.len(), 1);
}

#[tokio::test]
async fn restart_mid_sequence_converges_with_uninterrupted_run() {
    // Serialize file-backed tests process-wide.
    let _disk = common::disk_test_guard().await;
    let scenario = scenario().await;
    let order = vec![0, 1, 2];
    let mut nodes = fresh_nodes().await;
    let (mem_statuses, disk_statuses) = run_order(&mut nodes, &scenario.ops, &order, Some(1)).await;
    assert_eq!(mem_statuses, disk_statuses);
    let (mem_state, disk_state) = states(&nodes, &scenario.record_id).await;
    assert_eq!(mem_state, disk_state);
    assert_eq!(mem_state.read_status, 404);
}
