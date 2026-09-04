//! Persistence tests for SQLite auxiliary stores.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::TempDb;

use dwn_rs_core::events::MessageEvent;
use dwn_rs_core::stores::wake::WakePublishHandler;
use dwn_rs_core::stores::{EventLog, ResumableTaskStore, StateIndex};
use dwn_rs_core::{Descriptor, Message, Value};
use serde::{Deserialize, Serialize};
use serde_json::json;

use dwn_rs_stores::{SqliteEventLog, SqliteResumableTaskStore, SqliteStateIndex, SqliteStore};

const TENANT: &str = "did:example:alice";

#[tokio::test]
async fn sqlite_state_index_survives_reopen() {
    // Serialize file-backed tests process-wide.
    let _disk = common::disk_test_guard().await;
    let db = TempDb::new("state-index");
    let path = db.path();
    let indexes = BTreeMap::from([(
        "messageTimestamp".to_string(),
        Value::String("2025-01-01T00:00:00.000000Z".to_string()),
    )]);

    {
        let store = SqliteStore::new(path, WakePublishHandler::new(Arc::new(())));
        let mut state_index = SqliteStateIndex::new(&store);
        state_index.open().await.unwrap();
        state_index
            .insert(TENANT, "bafyreihash", indexes.clone())
            .await
            .unwrap();
        let root_before = state_index.get_root(TENANT).await.unwrap();
        state_index.close().await;
        drop(store);

        // Fresh handle on the same file: root must survive a real reopen.
        let fresh = SqliteStore::new(path, WakePublishHandler::new(Arc::new(())));
        let mut reopened = SqliteStateIndex::new(&fresh);
        reopened.open().await.unwrap();
        let root_after = reopened.get_root(TENANT).await.unwrap();
        assert_eq!(root_before, root_after);
    }
}

#[tokio::test]
async fn sqlite_event_log_survives_reopen() {
    // Serialize file-backed tests process-wide.
    let _disk = common::disk_test_guard().await;
    let db = TempDb::new("event-log");
    let path = db.path();
    let indexes = BTreeMap::from([(
        "messageTimestamp".to_string(),
        Value::String("2025-01-01T00:00:00.000000Z".to_string()),
    )]);
    let message: Message<Descriptor> = serde_json::from_value(json!({
        "descriptor": {
            "interface": "Messages",
            "method": "Query",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z"
        },
        "authorization": { "signature": {} }
    }))
    .unwrap();
    let event = MessageEvent {
        message,
        initial_write: None,
    };

    {
        let store = SqliteStore::new(path, WakePublishHandler::new(Arc::new(())));
        let mut event_log = SqliteEventLog::new(&store);
        event_log.open().await.unwrap();
        let token = event_log
            .emit(TENANT, event.clone(), indexes.clone(), "bafyreihash")
            .await
            .unwrap()
            .expect("progress token");
        event_log.close().await;
        drop(store);

        let fresh = SqliteStore::new(path, WakePublishHandler::new(Arc::new(())));
        let mut reopened = SqliteEventLog::new(&fresh);
        reopened.open().await.unwrap();
        let read = reopened.read(TENANT, None).await.unwrap();
        assert_eq!(read.events.len(), 1);
        assert_eq!(read.events[0].message_cid.as_deref(), Some("bafyreihash"));
        assert!(read.cursor.is_some());
        assert_eq!(read.cursor.unwrap().epoch, token.epoch);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SampleTask {
    action: String,
}

#[tokio::test]
async fn sqlite_resumable_task_store_survives_reopen() {
    // Serialize file-backed tests process-wide.
    let _disk = common::disk_test_guard().await;
    let db = TempDb::new("resumable-tasks");
    let path = db.path();
    let task = SampleTask {
        action: "delete".to_string(),
    };

    {
        let store = SqliteStore::new(path, WakePublishHandler::new(Arc::new(())));
        let mut task_store = SqliteResumableTaskStore::new(&store);
        task_store.open().await.unwrap();
        let managed = task_store.register(task.clone(), 120).await.unwrap();
        task_store.close().await;
        drop(store);

        let fresh = SqliteStore::new(path, WakePublishHandler::new(Arc::new(())));
        let mut reopened = SqliteResumableTaskStore::new(&fresh);
        reopened.open().await.unwrap();
        let loaded = reopened.read::<SampleTask>(&managed.id).await.unwrap();
        assert_eq!(loaded.expect("task").task, task);
    }
}
