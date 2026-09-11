//! File-backed recovery for encryption-control purges.
//!
//! A purge is several store mutations with no single point of no return, so a
//! crash partway through must be finishable rather than silent. These tests
//! interrupt one at each boundary that matters, reopen the database with fresh
//! handles, and drive recovery through `ResumableTaskManager` — the same entry
//! point a node uses at open, not a private helper standing in for it.
//!
//! Covers: DWN-REC-006

mod common;

use std::collections::BTreeMap;

use bytes::Bytes;
use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
use dwn_rs_core::stores::{DataStore, MessageStore, ResumableTaskStore};
use dwn_rs_core::tasks::controller::{ResumableControlPurgeData, StorageController};
use dwn_rs_core::tasks::manager::{ResumableTask, ResumableTaskManager, ResumableTaskName};
use dwn_rs_core::{Descriptor, Filters, Message, Value};
use futures_util::{stream, TryStreamExt};
use serde_json::json;

use common::TempDb;
use dwn_rs_stores::{SqliteResumableTaskStore, SqliteStore};

const TENANT: &str = "did:example:alice";
const RECORD_ID: &str = "audience-record";
const PROTOCOL: &str = "https://example.com/protocol/threads";

/// Tasks are handed out under a lease, so recovery only reclaims work whose
/// lease has expired — a restarting node must not seize a purge another node is
/// still running. A crashed process's lease has lapsed by the time anyone
/// restarts; registering with a zero timeout models that without sleeping.
const LAPSED_LEASE: u64 = 0;

fn purge_task(data_cids: Vec<String>) -> ResumableTask {
    ResumableTask {
        name: ResumableTaskName::ControlPurge,
        data: serde_json::to_value(ResumableControlPurgeData {
            tenant: TENANT.to_string(),
            record_id: RECORD_ID.to_string(),
            data_cids,
        })
        .expect("purge task must serialize"),
    }
}

fn manager(
    store: &SqliteStore,
    tasks: &SqliteResumableTaskStore,
) -> ResumableTaskManager<SqliteStore, SqliteStore, SqliteResumableTaskStore> {
    ResumableTaskManager::new(
        tasks.clone(),
        StorageController::new(store.clone(), store.clone()),
    )
}

fn audience_message(data_cid: &str, data_size: usize) -> Message<Descriptor> {
    serde_json::from_value(json!({
        "descriptor": {
            "interface": "Records",
            "method": "Write",
            "protocol": PROTOCOL,
            "protocolPath": "$encryption/audience",
            "dataCid": data_cid,
            "dataSize": data_size,
            "dataFormat": "application/json",
            "dateCreated": "2025-01-01T00:00:00.000000Z",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z"
        },
        "recordId": RECORD_ID
    }))
    .expect("audience fixture must deserialize")
}

fn indexes(data_cid: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        ("method".to_string(), Value::String("Write".to_string())),
        ("recordId".to_string(), Value::String(RECORD_ID.to_string())),
        ("protocol".to_string(), Value::String(PROTOCOL.to_string())),
        (
            "protocolPath".to_string(),
            Value::String("$encryption/audience".to_string()),
        ),
        ("dataCid".to_string(), Value::String(data_cid.to_string())),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "messageTimestamp".to_string(),
            Value::String("2025-01-01T00:00:00.000000Z".to_string()),
        ),
        (
            "dateCreated".to_string(),
            Value::String("2025-01-01T00:00:00.000000Z".to_string()),
        ),
    ])
}

/// Seeds one control record with its data, and returns its data CID.
async fn seed(store: &SqliteStore, payload: &Bytes) -> String {
    let data_cid = generate_dag_pb_cid_from_bytes(payload).to_string();
    MessageStore::put(
        store,
        TENANT,
        audience_message(&data_cid, payload.len()),
        indexes(&data_cid),
    )
    .await
    .expect("seed message");
    DataStore::put(
        store,
        TENANT,
        RECORD_ID,
        &data_cid,
        stream::iter(vec![payload.clone()]),
    )
    .await
    .expect("seed data");
    data_cid
}

async fn retained(store: &SqliteStore) -> usize {
    MessageStore::query(store, TENANT, Filters::default(), None, None, None)
        .await
        .expect("query")
        .messages
        .len()
}

async fn data_present(store: &SqliteStore, data_cid: &str) -> bool {
    match DataStore::get(store, TENANT, RECORD_ID, data_cid).await {
        Ok(Some(result)) => result
            .data_stream
            .try_fold(0usize, |seen, chunk| async move { Ok(seen + chunk.len()) })
            .await
            .is_ok(),
        _ => false,
    }
}

/// Opens the file with fresh handles, as a restarting node would.
async fn reopen(db: &TempDb) -> (SqliteStore, SqliteResumableTaskStore) {
    let mut store = SqliteStore::new(db.path(), common::noop_waker());
    MessageStore::open(&mut store).await.expect("reopen store");
    let mut tasks = SqliteResumableTaskStore::new(&store);
    ResumableTaskStore::open(&mut tasks)
        .await
        .expect("reopen task store");
    (store, tasks)
}

#[tokio::test]
async fn a_completed_purge_removes_the_record_and_discharges_its_task() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("control-purge-complete");
    let payload = Bytes::from_static(b"audience payload");

    let (store, tasks) = reopen(&db).await;
    let data_cid = seed(&store, &payload).await;
    assert_eq!(retained(&store).await, 1);

    manager(&store, &tasks)
        .run(purge_task(vec![data_cid.clone()]))
        .await
        .expect("purge must succeed");

    assert_eq!(retained(&store).await, 0, "the record's messages are gone");
    assert!(
        !data_present(&store, &data_cid).await,
        "the record's data is gone"
    );

    // Nothing outstanding: a later recovery pass has no work to redo.
    let (reopened, reopened_tasks) = reopen(&db).await;
    manager(&reopened, &reopened_tasks)
        .resume_tasks_and_wait_for_completion()
        .await
        .expect("recovery must succeed");
    assert_eq!(
        retained(&reopened).await,
        0,
        "a discharged purge leaves no work behind"
    );
}

#[tokio::test]
async fn a_purge_interrupted_before_any_removal_is_finished_after_reopen() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("control-purge-interrupted-early");
    let payload = Bytes::from_static(b"audience payload");

    let data_cid = {
        let (store, tasks) = reopen(&db).await;
        let data_cid = seed(&store, &payload).await;

        // The intent is registered and the process dies before touching the
        // record — the window a purge must not be lost in.
        tasks
            .register(purge_task(vec![data_cid.clone()]), LAPSED_LEASE)
            .await
            .expect("register intent");
        assert_eq!(retained(&store).await, 1, "nothing removed yet");
        data_cid
    };

    let (store, tasks) = reopen(&db).await;
    manager(&store, &tasks)
        .resume_tasks_and_wait_for_completion()
        .await
        .expect("recovery must succeed");
    assert_eq!(retained(&store).await, 0);
    assert!(!data_present(&store, &data_cid).await);
}

#[tokio::test]
async fn a_purge_interrupted_after_messages_but_before_data_is_reclaimed() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("control-purge-interrupted-late");
    let payload = Bytes::from_static(b"audience payload");

    let data_cid = {
        let (store, tasks) = reopen(&db).await;
        let data_cid = seed(&store, &payload).await;
        tasks
            .register(purge_task(vec![data_cid.clone()]), LAPSED_LEASE)
            .await
            .expect("register intent");

        // Messages removed, data not yet: the ordering ADR 0004 requires, and
        // the state a crash here leaves behind.
        let message = audience_message(&data_cid, payload.len());
        let cid = message.cid().expect("cid").to_string();
        MessageStore::delete(&store, TENANT, &cid)
            .await
            .expect("remove message");
        assert_eq!(retained(&store).await, 0);
        assert!(
            data_present(&store, &data_cid).await,
            "data outlives its messages until cleanup runs"
        );
        data_cid
    };

    let (store, tasks) = reopen(&db).await;
    manager(&store, &tasks)
        .resume_tasks_and_wait_for_completion()
        .await
        .expect("recovery must succeed");
    assert!(
        !data_present(&store, &data_cid).await,
        "orphaned data must be reclaimed rather than left behind"
    );
}

#[tokio::test]
async fn repeated_recovery_is_safe() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("control-purge-repeat");
    let payload = Bytes::from_static(b"audience payload");

    {
        let (store, tasks) = reopen(&db).await;
        let data_cid = seed(&store, &payload).await;
        tasks
            .register(purge_task(vec![data_cid.clone()]), LAPSED_LEASE)
            .await
            .expect("register intent");
    }

    let (store, tasks) = reopen(&db).await;
    let manager = manager(&store, &tasks);
    manager
        .resume_tasks_and_wait_for_completion()
        .await
        .unwrap();
    // A second pass finds nothing outstanding and must not fail on what is
    // already gone.
    manager
        .resume_tasks_and_wait_for_completion()
        .await
        .expect("a repeated pass must be safe");
    assert_eq!(retained(&store).await, 0);
}
