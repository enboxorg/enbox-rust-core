//! File-backed recovery for encryption-control repair.
//!
//! Accepting a configuration creates an obligation to re-examine the control
//! records it governs. That obligation has to survive the crash that could
//! happen immediately after the configuration commits — otherwise an accepted
//! history is left permanently contradicted by records nothing remembers to
//! check. These tests interrupt a repair at each boundary that matters, reopen
//! the database with fresh handles, and drive recovery through
//! `ResumableTaskManager` — the same entry point a node uses at open, not a
//! private helper standing in for it.
//!
//! The obligation names the protocol, not its victims. A resumed repair re-asks
//! which records the configuration contradicts rather than replaying a list,
//! which is what makes repeated repair safe and a partial pass finishable.
//!
//! Covers: DWN-PROTO-004, DWN-REC-006

use std::collections::BTreeMap;

use bytes::Bytes;
use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
use dwn_rs_core::protocols::Definition;
use dwn_rs_core::stores::{DataStore, MessageStore, ResumableTaskStore};
use dwn_rs_core::tasks::controller::{
    ResumableControlPurgeData, ResumableControlRepairData, StorageController,
};
use dwn_rs_core::tasks::manager::{ResumableTask, ResumableTaskManager, ResumableTaskName};
use dwn_rs_core::testing::{put_protocol_definition, signed_write_message, WriteSpec};
use dwn_rs_core::{Descriptor, Filter, FilterKey, Filters, MapValue, Message, Value};
use futures_util::{stream, TryStreamExt};
use serde_json::json;

use crate::common::TempDb;
use dwn_rs_stores::{SqliteResumableTaskStore, SqliteStore};

const TENANT: &str = "did:example:alice";
const PROTOCOL: &str = "https://example.com/protocol/threads";
/// Two audiences under the role the configuration demotes, and one under a
/// role it keeps, so the scan has something it must leave alone.
const SEEDED: [(&str, &str); 3] = [("first", "member"), ("second", "member"), ("kept", "keyed")];

/// Tasks are handed out under a lease, so recovery only reclaims work whose
/// lease has expired — a restarting node must not seize a repair another node
/// is still running. A crashed process's lease has lapsed by the time anyone
/// restarts; registering with a zero timeout models that without sleeping.
const LAPSED_LEASE: u64 = 0;

fn repair_task() -> ResumableTask {
    ResumableTask {
        name: ResumableTaskName::ControlRepair,
        data: serde_json::to_value(ResumableControlRepairData {
            tenant: TENANT.to_string(),
            protocol: PROTOCOL.to_string(),
        })
        .expect("repair task must serialize"),
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

/// A configuration in which `member` is an ordinary record type rather than a
/// keyed role, and `keyed` is a role that carries key agreement.
///
/// Every audience under `member` is therefore contradicted by the configuration
/// itself — the invalidity that licenses removal — while one under `keyed` is
/// not.
fn configuration() -> Definition {
    serde_json::from_value(json!({
        "protocol": PROTOCOL,
        "published": true,
        "types": { "member": {}, "keyed": {} },
        "structure": {
            "member": {},
            "keyed": {
                "$role": true,
                "$keyAgreement": {
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": "Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI"
                    }
                }
            }
        }
    }))
    .expect("configuration fixture must deserialize")
}

/// Builds a real signed audience write, so the stored record has the entry id
/// the engine derives rather than one a fixture invented.
///
/// That matters here: repair only examines *initial writes*, and whether a
/// stored message is one is decided by re-deriving its id from its own
/// descriptor and author. A hand-written record id makes every record look
/// like an update, and the scan would correctly skip all of them.
async fn audience_write(label: &str, role_path: &str, payload: &Bytes) -> serde_json::Value {
    let data_cid = generate_dag_pb_cid_from_bytes(payload).to_string();
    signed_write_message(WriteSpec {
        author: TENANT.to_string(),
        protocol: PROTOCOL.to_string(),
        protocol_path: "$encryption/audience".to_string(),
        tags: Some(MapValue::from([
            ("protocol".to_string(), Value::String(PROTOCOL.to_string())),
            ("rolePath".to_string(), Value::String(role_path.to_string())),
            ("contextId".to_string(), Value::String(String::new())),
            ("keyId".to_string(), Value::String(format!("key-{label}"))),
        ])),
        data_cid: data_cid.clone(),
        data_size: payload.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    })
    .await
}

fn audience_indexes(record_id: &str, role_path: &str, data_cid: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        ("method".to_string(), Value::String("Write".to_string())),
        ("recordId".to_string(), Value::String(record_id.to_string())),
        ("protocol".to_string(), Value::String(PROTOCOL.to_string())),
        (
            "protocolPath".to_string(),
            Value::String("$encryption/audience".to_string()),
        ),
        ("dataCid".to_string(), Value::String(data_cid.to_string())),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "tag.rolePath".to_string(),
            Value::String(role_path.to_string()),
        ),
        (
            "messageTimestamp".to_string(),
            Value::String("2025-01-01T00:01:00.000000Z".to_string()),
        ),
        (
            "dateCreated".to_string(),
            Value::String("2025-01-01T00:01:00.000000Z".to_string()),
        ),
    ])
}

/// What the fixture stored, so tests can name a record without knowing its id.
struct Seeded {
    record_id: String,
    data_cid: String,
    message: Message<Descriptor>,
}

/// Seeds the configuration plus two contradicted audiences and one sound one.
async fn seed(store: &SqliteStore, payload: &Bytes) -> BTreeMap<&'static str, Seeded> {
    put_protocol_definition(
        TENANT,
        store,
        configuration(),
        "2025-01-01T00:00:00.000000Z",
    )
    .await;

    let mut seeded = BTreeMap::new();
    for (label, role_path) in SEEDED {
        let write = audience_write(label, role_path, payload).await;
        let record_id = write["recordId"]
            .as_str()
            .expect("signed write carries a record id")
            .to_string();
        let message: Message<Descriptor> =
            serde_json::from_value(write).expect("audience write must deserialize");
        let data_cid = generate_dag_pb_cid_from_bytes(payload).to_string();
        MessageStore::put(
            store,
            TENANT,
            message.clone(),
            audience_indexes(&record_id, role_path, &data_cid),
        )
        .await
        .expect("seed message");
        DataStore::put(
            store,
            TENANT,
            &record_id,
            &data_cid,
            stream::iter(vec![payload.clone()]),
        )
        .await
        .expect("seed data");
        seeded.insert(
            label,
            Seeded {
                record_id,
                data_cid,
                message,
            },
        );
    }
    seeded
}

/// Which of the seeded audiences still have retained messages, by label.
///
/// Probed one record id at a time rather than read off the returned messages:
/// a record id lives in a message's fields, and the accessor for it is crate
/// private to `dwn-rs-core`.
async fn retained(
    store: &SqliteStore,
    seeded: &BTreeMap<&'static str, Seeded>,
) -> Vec<&'static str> {
    let mut found = Vec::new();
    for (label, record) in seeded {
        let filters = Filters::from(BTreeMap::from([(
            FilterKey::Index("recordId".to_string()),
            Filter::Equal(Value::String(record.record_id.clone())),
        )]));
        let count = MessageStore::query(store, TENANT, filters, None, None, None)
            .await
            .expect("query")
            .messages
            .len();
        if count > 0 {
            found.push(*label);
        }
    }
    found
}

async fn data_present(store: &SqliteStore, record: &Seeded) -> bool {
    match DataStore::get(store, TENANT, &record.record_id, &record.data_cid).await {
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
    let mut store = SqliteStore::new(db.path(), crate::common::noop_waker());
    MessageStore::open(&mut store).await.expect("reopen store");
    let mut tasks = SqliteResumableTaskStore::new(&store);
    ResumableTaskStore::open(&mut tasks)
        .await
        .expect("reopen task store");
    (store, tasks)
}

#[tokio::test]
async fn a_completed_repair_removes_only_what_the_configuration_contradicts() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("control-repair-complete");
    let payload = Bytes::from_static(b"audience payload");

    let (store, tasks) = reopen(&db).await;
    let seeded = seed(&store, &payload).await;

    manager(&store, &tasks)
        .run(repair_task())
        .await
        .expect("repair must succeed");

    assert_eq!(
        retained(&store, &seeded).await,
        vec!["kept"],
        "both contradicted audiences go; the sound one stays"
    );
    for label in ["first", "second"] {
        assert!(
            !data_present(&store, &seeded[label]).await,
            "{label}'s data must go with its messages"
        );
    }
    assert!(
        data_present(&store, &seeded["kept"]).await,
        "a record the configuration does not contradict keeps its data"
    );

    // Nothing outstanding: a later recovery pass has no work to redo.
    let (reopened, reopened_tasks) = reopen(&db).await;
    manager(&reopened, &reopened_tasks)
        .resume_tasks_and_wait_for_completion()
        .await
        .expect("recovery must succeed");
    assert_eq!(
        retained(&reopened, &seeded).await,
        vec!["kept"],
        "a discharged repair leaves no work behind"
    );
}

#[tokio::test]
async fn a_repair_enlisted_but_never_started_is_finished_after_reopen() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("control-repair-never-started");
    let payload = Bytes::from_static(b"audience payload");

    let seeded = {
        let (store, tasks) = reopen(&db).await;
        let seeded = seed(&store, &payload).await;

        // The obligation is recorded and the process dies before examining
        // anything. This is the window the obligation exists for: the
        // configuration is durable and nothing has looked at a single record.
        tasks
            .register(repair_task(), LAPSED_LEASE)
            .await
            .expect("enlist obligation");
        assert_eq!(
            retained(&store, &seeded).await,
            vec!["first", "kept", "second"],
            "nothing examined yet"
        );
        seeded
    };

    let (store, tasks) = reopen(&db).await;
    manager(&store, &tasks)
        .resume_tasks_and_wait_for_completion()
        .await
        .expect("recovery must succeed");
    assert_eq!(
        retained(&store, &seeded).await,
        vec!["kept"],
        "a repair nobody started must still happen"
    );
    assert!(!data_present(&store, &seeded["first"]).await);
    assert!(!data_present(&store, &seeded["second"]).await);
}

#[tokio::test]
async fn a_repair_interrupted_between_two_invalid_records_finishes_the_rest() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("control-repair-midway");
    let payload = Bytes::from_static(b"audience payload");

    let seeded = {
        let (store, tasks) = reopen(&db).await;
        let seeded = seed(&store, &payload).await;
        tasks
            .register(repair_task(), LAPSED_LEASE)
            .await
            .expect("enlist obligation");

        // The first record's removal completed; the process died before the
        // second was reached. A resumed repair must judge what is left rather
        // than conclude it already ran.
        let first = &seeded["first"];
        let cid = first.message.cid().expect("cid").to_string();
        MessageStore::delete(&store, TENANT, &cid)
            .await
            .expect("remove first record");
        DataStore::delete(&store, TENANT, &first.record_id, &first.data_cid)
            .await
            .expect("remove first data");
        assert_eq!(
            retained(&store, &seeded).await,
            vec!["kept", "second"],
            "one down, one still contradicted"
        );
        seeded
    };

    let (store, tasks) = reopen(&db).await;
    manager(&store, &tasks)
        .resume_tasks_and_wait_for_completion()
        .await
        .expect("recovery must succeed");
    assert_eq!(
        retained(&store, &seeded).await,
        vec!["kept"],
        "the record the interrupted pass never reached must still go"
    );
    assert!(!data_present(&store, &seeded["second"]).await);
}

#[tokio::test]
async fn repeated_recovery_is_safe() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("control-repair-repeat");
    let payload = Bytes::from_static(b"audience payload");

    let seeded = {
        let (store, tasks) = reopen(&db).await;
        let seeded = seed(&store, &payload).await;
        tasks
            .register(repair_task(), LAPSED_LEASE)
            .await
            .expect("enlist obligation");
        seeded
    };

    let (store, tasks) = reopen(&db).await;
    let manager = manager(&store, &tasks);
    manager
        .resume_tasks_and_wait_for_completion()
        .await
        .unwrap();
    // A second pass re-asks the same question of what is left, and must not
    // fail on what is already gone.
    manager
        .resume_tasks_and_wait_for_completion()
        .await
        .expect("a repeated pass must be safe");
    assert_eq!(retained(&store, &seeded).await, vec!["kept"]);
}

#[tokio::test]
async fn cleanup_intent_outlives_the_messages_that_described_it() {
    // Serialize file-backed tests process-wide.
    let db = TempDb::new("control-repair-cleanup-intent");
    let payload = Bytes::from_static(b"audience payload");

    let seeded = {
        let (store, tasks) = reopen(&db).await;
        let seeded = seed(&store, &payload).await;
        let first = &seeded["first"];

        // The state a crash between the two halves of a removal leaves: the
        // record's messages are gone, so no scan can ever rediscover which
        // data belonged to it, and its data is still on disk. Only the intent
        // enlisted before the removal began can finish this.
        tasks
            .register(
                ResumableTask {
                    name: ResumableTaskName::ControlPurge,
                    data: serde_json::to_value(ResumableControlPurgeData {
                        tenant: TENANT.to_string(),
                        record_id: first.record_id.clone(),
                        data_cids: vec![first.data_cid.clone()],
                    })
                    .expect("purge intent must serialize"),
                },
                LAPSED_LEASE,
            )
            .await
            .expect("enlist cleanup intent");
        let cid = first.message.cid().expect("cid").to_string();
        MessageStore::delete(&store, TENANT, &cid)
            .await
            .expect("remove first record");
        assert!(
            data_present(&store, first).await,
            "data outlives its messages until cleanup runs"
        );
        seeded
    };

    let (store, tasks) = reopen(&db).await;
    manager(&store, &tasks)
        .resume_tasks_and_wait_for_completion()
        .await
        .expect("recovery must succeed");
    assert!(
        !data_present(&store, &seeded["first"]).await,
        "orphaned data must be reclaimed through the intent that outlived its record"
    );
}
