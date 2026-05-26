//! Progress token replay, gap detection, and EOSE semantics on [`SqliteEventLog`].

use std::sync::{Arc, Mutex};

use dwn_rs_core::errors::EventLogError;
use dwn_rs_core::events::MessageEvent;
use dwn_rs_core::stores::{
    EventLog, EventLogReadOptions, EventLogSubscribeOptions, EventLogTrimBound, ProgressGapReason,
    SubscriptionMessage,
};
use dwn_rs_core::{Descriptor, Message, Value};
use serde_json::json;

use dwn_rs_stores::{SqliteEventLog, SqliteStore};

const TENANT: &str = "did:example:alice";

#[tokio::test]
async fn sqlite_event_log_subscribe_replays_from_cursor_and_emits_eose() {
    let store = SqliteStore::in_memory();
    let mut event_log = SqliteEventLog::new(&store);
    event_log.open().await.unwrap();

    let (event, indexes) = sample_event();
    let first = emit(&event_log, "cid-1", &event, &indexes).await;
    emit(&event_log, "cid-2", &event, &indexes).await;

    let delivered = Arc::new(Mutex::new(Vec::new()));
    let delivered_listener = delivered.clone();
    let subscription = event_log
        .subscribe(
            TENANT,
            "sub-1",
            Box::new(move |message| delivered_listener.lock().unwrap().push(message)),
            Some(EventLogSubscribeOptions {
                cursor: Some(first),
                filters: None,
            }),
        )
        .await
        .unwrap();

    let messages = delivered.lock().unwrap().clone();
    assert_eq!(messages.len(), 2);
    match &messages[0] {
        SubscriptionMessage::Event { cursor, .. } => {
            assert_eq!(cursor.position, "2");
            assert_eq!(cursor.message_cid, "cid-2");
        }
        other => panic!("expected event, got {other:?}"),
    }
    match &messages[1] {
        SubscriptionMessage::Eose { cursor } => {
            assert_eq!(cursor.position, "2");
            assert_eq!(cursor.message_cid, "cid-2");
        }
        other => panic!("expected eose, got {other:?}"),
    }

    (subscription.close)().await.unwrap();
}

#[tokio::test]
async fn sqlite_event_log_read_returns_progress_gap_after_trim() {
    let store = SqliteStore::in_memory();
    let mut event_log = SqliteEventLog::new(&store);
    event_log.open().await.unwrap();

    let (event, indexes) = sample_event();
    let first = emit(&event_log, "cid-1", &event, &indexes).await;
    emit(&event_log, "cid-2", &event, &indexes).await;
    emit(&event_log, "cid-3", &event, &indexes).await;
    let fourth = emit(&event_log, "cid-4", &event, &indexes).await;

    event_log
        .trim(TENANT, EventLogTrimBound::Sequence(3))
        .await
        .unwrap();

    let gap = event_log
        .read(
            TENANT,
            Some(EventLogReadOptions {
                cursor: Some(first),
                limit: None,
                filters: None,
            }),
        )
        .await
        .unwrap_err();
    let EventLogError::ProgressGap(gap) = gap else {
        panic!("expected progress gap");
    };
    assert_eq!(gap.reason, ProgressGapReason::TokenTooOld);
    assert_eq!(gap.oldest_available.message_cid, "cid-3");
    assert_eq!(gap.latest_available, fourth);

    event_log
        .trim(TENANT, EventLogTrimBound::Sequence(5))
        .await
        .unwrap();
    assert!(event_log.get_replay_bounds(TENANT).await.unwrap().is_none());
}

#[tokio::test]
async fn sqlite_event_log_replay_bounds_survive_reopen() {
    let path = std::env::temp_dir().join(format!(
        "dwn-rs-event-log-progress-{}-{}.sqlite",
        std::process::id(),
        ulid::Ulid::new()
    ));
    let (event, indexes) = sample_event();

    {
        let store = SqliteStore::new(&path);
        let mut event_log = SqliteEventLog::new(&store);
        event_log.open().await.unwrap();
        emit(&event_log, "cid-1", &event, &indexes).await;
        emit(&event_log, "cid-2", &event, &indexes).await;
        event_log.close().await;
    }

    {
        let store = SqliteStore::new(&path);
        let mut event_log = SqliteEventLog::new(&store);
        event_log.open().await.unwrap();
        let bounds = event_log
            .get_replay_bounds(TENANT)
            .await
            .unwrap()
            .expect("replay bounds");
        assert_eq!(bounds.oldest.message_cid, "cid-1");
        assert_eq!(bounds.latest.message_cid, "cid-2");

        let read = event_log
            .read(
                TENANT,
                Some(EventLogReadOptions {
                    cursor: Some(bounds.oldest.clone()),
                    limit: Some(1),
                    filters: None,
                }),
            )
            .await
            .unwrap();
        assert_eq!(read.events.len(), 1);
        assert_eq!(read.events[0].message_cid.as_deref(), Some("cid-2"));
    }

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn sqlite_event_log_read_from_empty_store_returns_no_events() {
    let store = SqliteStore::in_memory();
    let mut event_log = SqliteEventLog::new(&store);
    event_log.open().await.unwrap();

    let read = event_log.read(TENANT, None).await.unwrap();
    assert!(read.events.is_empty());
    assert!(read.cursor.is_none());
}

fn sample_event() -> (
    MessageEvent<Descriptor>,
    std::collections::BTreeMap<String, Value>,
) {
    let message: Message<Descriptor> = serde_json::from_value(json!({
        "descriptor": {
            "interface": "Messages",
            "method": "Query",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z"
        },
        "authorization": { "signature": {} }
    }))
    .unwrap();
    let indexes = std::collections::BTreeMap::from([(
        "messageTimestamp".to_string(),
        Value::String("2025-01-01T00:00:00.000000Z".to_string()),
    )]);
    (
        MessageEvent {
            message,
            initial_write: None,
        },
        indexes,
    )
}

async fn emit(
    event_log: &SqliteEventLog,
    message_cid: &str,
    event: &MessageEvent<Descriptor>,
    indexes: &std::collections::BTreeMap<String, Value>,
) -> dwn_rs_core::stores::ProgressToken {
    event_log
        .emit(TENANT, event.clone(), indexes.clone(), message_cid)
        .await
        .unwrap()
        .expect("progress token")
}
