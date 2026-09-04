use dwn_rs_core::errors::StoreError;

pub mod conn;
mod data_migrations;
pub mod data_store;
pub mod event_log;
pub mod message_store;
mod migrations;
mod query;
pub mod replication_feed_reader;
pub mod resumable_task_store;
pub mod secrets_store;
pub mod state_index;
pub mod store;
mod sync_ledger;

pub use self::conn::SqliteConnection;
#[doc(hidden)]
#[deprecated(note = "Use DurableEventLog instead")]
pub use self::event_log::SqliteEventLog;
pub use self::resumable_task_store::SqliteResumableTaskStore;
pub use self::secrets_store::SqliteSecretStore;
pub use self::state_index::SqliteStateIndex;
pub(crate) use self::store::sqlite_store_error;
pub use self::store::SqliteStore;
pub use self::sync_ledger::SqliteSyncLedger;

pub(crate) fn json_store_error(error: serde_json::Error) -> StoreError {
    StoreError::InternalException(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use dwn_rs_core::stores::replication_feed_reader::{cid_contribution, xor_in_place};
    use dwn_rs_core::stores::wake::{Wake, WakeError, WakePublishHandler, WakePublisher};
    use futures_util::{stream, TryStreamExt};

    use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
    use dwn_rs_core::descriptors::{Records, RecordsWriteDescriptor};
    use dwn_rs_core::fields::WriteFields;
    use dwn_rs_core::filters::{Filter, FilterKey, Filters};
    use dwn_rs_core::stores::{
        DataStore, KeyValues, LatestStateMutation, LatestStateTransition, MessageStore,
    };
    use dwn_rs_core::{Descriptor, Fields, Message, MessageSort, Pagination, SortDirection, Value};
    use rusqlite::OptionalExtension;

    use super::*;
    use crate::sqlite::conn::disk_test_guard;

    const TENANT: &str = "did:example:alice";

    #[derive(Default)]
    struct RecordingPublisher {
        wakes: Mutex<Vec<(String, u64, bool)>>,
        database_path: Option<PathBuf>,
    }

    impl WakePublisher for RecordingPublisher {
        fn publish(&self, wake: Wake) -> Result<(), dwn_rs_core::stores::wake::WakeError> {
            let committed = self.database_path.as_ref().is_none_or(|path| {
                rusqlite::Connection::open(path)
                    .and_then(|connection| {
                        connection.query_row(
                            "SELECT EXISTS(SELECT 1 FROM feed_entries \
                             WHERE tenant = ?1 AND position = ?2)",
                            rusqlite::params![&wake.tenant, wake.position as i64],
                            |row| row.get::<_, bool>(0),
                        )
                    })
                    .unwrap_or(false)
            });
            self.wakes
                .lock()
                .unwrap()
                .push((wake.tenant, wake.position, committed));
            Ok(())
        }
    }

    struct RejectingPublisher;

    impl WakePublisher for RejectingPublisher {
        fn publish(&self, _wake: Wake) -> Result<(), dwn_rs_core::stores::wake::WakeError> {
            Err(dwn_rs_core::stores::wake::WakeError::PublishError(
                "injected failure".to_string(),
            ))
        }
    }

    fn message_cid(message: &Message<Descriptor>) -> String {
        message.cid().unwrap().to_string()
    }

    fn non_feed_message(timestamp: &str) -> Message<Descriptor> {
        serde_json::from_value(serde_json::json!({
            "descriptor": {
                "interface": "Messages",
                "method": "Query",
                "messageTimestamp": timestamp,
            },
            "authorization": { "signature": {} },
        }))
        .unwrap()
    }

    async fn feed_rows(store: &SqliteStore) -> Vec<(i64, String, String)> {
        store
            .connection()
            .await
            .unwrap()
            .with_reader(|connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT position, message_cid, indexes_json FROM feed_entries \
                         WHERE tenant = ?1 ORDER BY position",
                    )
                    .map_err(sqlite_store_error)?;
                let rows = statement
                    .query_map([TENANT], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                    .map_err(sqlite_store_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_store_error)?;
                Ok(rows)
            })
            .await
            .unwrap()
    }

    async fn feed_head(store: &SqliteStore) -> Option<i64> {
        store
            .connection()
            .await
            .unwrap()
            .with_reader(|connection| {
                connection
                    .query_row(
                        "SELECT head FROM feed_heads WHERE tenant = ?1",
                        [TENANT],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sqlite_store_error)
            })
            .await
            .unwrap()
    }

    async fn global_fingerprint(store: &SqliteStore) -> Option<Vec<u8>> {
        store
            .connection()
            .await
            .unwrap()
            .with_reader(|connection| {
                connection
                    .query_row(
                        "SELECT value FROM feed_fingerprints WHERE tenant = ?1 AND domain = ''",
                        [TENANT],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sqlite_store_error)
            })
            .await
            .unwrap()
    }

    async fn feed_epoch(store: &SqliteStore) -> String {
        store
            .connection()
            .await
            .unwrap()
            .with_reader(|connection| {
                connection
                    .query_row("SELECT epoch FROM feed_metadata WHERE id = 1", [], |row| {
                        row.get(0)
                    })
                    .map_err(sqlite_store_error)
            })
            .await
            .unwrap()
    }

    fn test_memory_uri() -> String {
        format!(
            "file:dwn-feed-test-{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        )
    }

    #[tokio::test]
    async fn message_store_roundtrips_inline_data_without_changing_message_cid() {
        let mut store = SqliteStore::in_memory(None);
        MessageStore::open(&mut store).await.unwrap();
        let message = message(
            "2025-01-01T00:00:00.000000Z",
            "https://example.com/protocol/notes",
            Some("aGVsbG8"),
        );
        let cid = message.cid().unwrap().to_string();

        MessageStore::put(
            &store,
            "did:example:alice",
            message.clone(),
            indexes(&message),
        )
        .await
        .unwrap();

        assert_eq!(
            MessageStore::get(&store, "did:example:alice", &cid)
                .await
                .unwrap()
                .unwrap(),
            message
        );
    }

    #[tokio::test]
    async fn message_store_persists_across_reopen() {
        // Serialize file-backed tests process-wide.
        let _disk = disk_test_guard().await;
        let path = temp_db_path("message-store");
        let _ = std::fs::remove_file(&path);
        let message = message(
            "2025-01-01T00:00:00.000000Z",
            "https://example.com/protocols/notes",
            None,
        );
        let cid = message.cid().unwrap().to_string();

        {
            let mut store = SqliteStore::new(&path, WakePublishHandler::new(Arc::new(())));
            MessageStore::open(&mut store).await.unwrap();
            MessageStore::put(
                &store,
                "did:example:alice",
                message.clone(),
                indexes(&message),
            )
            .await
            .unwrap();
            MessageStore::close(&mut store).await;
            // Drop the old handle before reopening: holding two live connection
            // sets on one file piles onto the process-global Unix VFS lock.
            drop(store);
        }

        let mut reopened = SqliteStore::new(&path, WakePublishHandler::new(Arc::new(())));
        MessageStore::open(&mut reopened).await.unwrap();
        assert_eq!(
            MessageStore::get(&reopened, "did:example:alice", &cid)
                .await
                .unwrap(),
            Some(message)
        );
        MessageStore::close(&mut reopened).await;
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn message_store_filters_sorts_counts_and_paginates() {
        let mut store = SqliteStore::in_memory(None);
        MessageStore::open(&mut store).await.unwrap();
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

        for message in [&first, &second, &third] {
            MessageStore::put(
                &store,
                "did:example:alice",
                message.clone(),
                indexes(message),
            )
            .await
            .unwrap();
        }
        let mut third_indexes = indexes(&third);
        third_indexes.insert(
            "recipient".to_string(),
            Value::Array(vec![
                Value::String("did:example:bob".to_string()),
                Value::String("did:example:carol".to_string()),
            ]),
        );
        MessageStore::put(&store, "did:example:alice", third.clone(), third_indexes)
            .await
            .unwrap();
        let published = message(
            "2025-01-01T00:00:03.000000Z",
            "https://example.com/protocol/published",
            None,
        );
        let mut published_indexes = indexes(&published);
        published_indexes.insert(
            "datePublished".to_string(),
            Value::String("2025-01-01T00:00:03.000000Z".to_string()),
        );
        MessageStore::put(
            &store,
            "did:example:alice",
            published.clone(),
            published_indexes,
        )
        .await
        .unwrap();

        let filters = Filters::from([[(
            FilterKey::Index("protocol".to_string()),
            Filter::Equal(Value::String(
                "https://example.com/protocol/notes".to_string(),
            )),
        )]]);
        assert_eq!(
            store
                .count("did:example:alice", filters.clone(), None)
                .await
                .unwrap(),
            2
        );

        let result = store
            .query(
                "did:example:alice",
                filters.clone(),
                Some(MessageSort::Timestamp(SortDirection::Descending)),
                Some(Pagination::with_limit(1)),
            )
            .await
            .unwrap();
        assert_eq!(result.messages, vec![second.clone()]);
        assert!(result.cursor.is_some());

        let result = store
            .query(
                "did:example:alice",
                filters,
                Some(MessageSort::Timestamp(SortDirection::Descending)),
                Some(Pagination::new(result.cursor, Some(1))),
            )
            .await
            .unwrap();
        assert_eq!(result.messages, vec![first]);
        assert!(result.cursor.is_none());

        let result = store
            .query(
                "did:example:alice",
                Filters::from([[(
                    FilterKey::Index("recipient".to_string()),
                    Filter::Equal(Value::String("did:example:bob".to_string())),
                )]]),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.messages, vec![third]);

        let result = store
            .query(
                "did:example:alice",
                Filters::default(),
                Some(MessageSort::DatePublished(SortDirection::Ascending)),
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.messages, vec![published]);

        let result = store
            .query(
                "did:example:alice",
                Filters::default(),
                Some(MessageSort::Timestamp(SortDirection::Ascending)),
                Some(Pagination::with_limit(0)),
            )
            .await
            .unwrap();
        assert!(result.messages.is_empty());
        assert!(result.cursor.is_none());
    }

    #[tokio::test]
    async fn durable_feed_assigns_monotonic_positions_and_updates_existing_cids() {
        let publisher = Arc::new(RecordingPublisher::default());
        let mut store = SqliteStore::new(
            test_memory_uri(),
            WakePublishHandler::new(publisher.clone()),
        );
        MessageStore::open(&mut store).await.unwrap();

        let first = message("2025-01-01T00:00:00Z", "https://example.com/notes", None);
        let second = message("2025-01-01T00:00:01Z", "https://example.com/notes", None);
        let incomplete = message("2025-01-01T00:00:02Z", "https://example.com/notes", None);
        let complete = message(
            "2025-01-01T00:00:02Z",
            "https://example.com/notes",
            Some("dGVzdA=="),
        );
        let cids = [&first, &second, &incomplete]
            .map(message_cid)
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(message_cid(&complete), cids[2]);

        MessageStore::put(&store, TENANT, first.clone(), indexes(&first))
            .await
            .unwrap();
        MessageStore::put(&store, TENANT, second.clone(), indexes(&second))
            .await
            .unwrap();

        let mut updated_indexes = indexes(&second);
        updated_indexes.insert("marker".to_string(), Value::String("updated".to_string()));
        MessageStore::put(&store, TENANT, second, updated_indexes)
            .await
            .unwrap();
        MessageStore::put(&store, TENANT, incomplete.clone(), indexes(&incomplete))
            .await
            .unwrap();
        MessageStore::put(&store, TENANT, complete.clone(), indexes(&complete))
            .await
            .unwrap();

        let rows = feed_rows(&store).await;
        assert_eq!(rows.iter().map(|row| row.0).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(
            rows.iter().map(|row| row.1.as_str()).collect::<Vec<_>>(),
            cids
        );
        assert!(rows[1].2.contains("updated"));
        assert_eq!(feed_head(&store).await, Some(3));
        assert_eq!(
            MessageStore::get(&store, TENANT, &cids[2]).await.unwrap(),
            Some(complete)
        );

        let mut expected = cid_contribution(&cids[0]);
        xor_in_place(&mut expected, &cid_contribution(&cids[1]));
        xor_in_place(&mut expected, &cid_contribution(&cids[2]));
        assert_eq!(
            global_fingerprint(&store).await.unwrap(),
            expected.as_slice()
        );

        let wakes = publisher.wakes.lock().unwrap();
        assert_eq!(
            wakes
                .iter()
                .map(|(_, position, _)| *position)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
    }

    #[tokio::test]
    async fn durable_feed_deletes_leave_holes_and_preserve_the_head() {
        let publisher = Arc::new(RecordingPublisher::default());
        let mut store = SqliteStore::new(
            test_memory_uri(),
            WakePublishHandler::new(publisher.clone()),
        );
        MessageStore::open(&mut store).await.unwrap();
        let messages = [
            message("2025-01-01T00:00:00Z", "https://example.com/notes", None),
            message("2025-01-01T00:00:01Z", "https://example.com/notes", None),
            message("2025-01-01T00:00:02Z", "https://example.com/notes", None),
        ];
        let cids = messages.iter().map(message_cid).collect::<Vec<_>>();
        for message in messages {
            MessageStore::put(&store, TENANT, message.clone(), indexes(&message))
                .await
                .unwrap();
        }

        MessageStore::delete(&store, TENANT, &cids[1])
            .await
            .unwrap();
        MessageStore::delete(&store, TENANT, &cids[2])
            .await
            .unwrap();

        assert_eq!(
            feed_rows(&store)
                .await
                .into_iter()
                .map(|row| row.0)
                .collect::<Vec<_>>(),
            [1]
        );
        assert_eq!(feed_head(&store).await, Some(3));
        assert_eq!(
            global_fingerprint(&store).await.unwrap(),
            cid_contribution(&cids[0]).as_slice()
        );
        assert_eq!(publisher.wakes.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn durable_feed_clear_replaces_epoch_and_restarts_positions_without_waking() {
        let publisher = Arc::new(RecordingPublisher::default());
        let mut store = SqliteStore::new(
            test_memory_uri(),
            WakePublishHandler::new(publisher.clone()),
        );
        MessageStore::open(&mut store).await.unwrap();
        let before = message("2025-01-01T00:00:00Z", "https://example.com/notes", None);
        MessageStore::put(&store, TENANT, before.clone(), indexes(&before))
            .await
            .unwrap();
        let old_epoch = feed_epoch(&store).await;

        MessageStore::clear(&store).await.unwrap();

        assert_ne!(feed_epoch(&store).await, old_epoch);
        assert!(feed_rows(&store).await.is_empty());
        assert_eq!(feed_head(&store).await, None);
        assert_eq!(global_fingerprint(&store).await, None);
        assert_eq!(publisher.wakes.lock().unwrap().len(), 1);

        let after = message("2025-01-01T00:00:01Z", "https://example.com/notes", None);
        MessageStore::put(&store, TENANT, after.clone(), indexes(&after))
            .await
            .unwrap();
        assert_eq!(feed_rows(&store).await[0].0, 1);
        assert_eq!(publisher.wakes.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn durable_feed_rolls_back_all_sql_state_and_does_not_wake() {
        let publisher = Arc::new(RecordingPublisher::default());
        let mut store = SqliteStore::new(
            test_memory_uri(),
            WakePublishHandler::new(publisher.clone()),
        );
        MessageStore::open(&mut store).await.unwrap();
        store
            .connection()
            .await
            .unwrap()
            .with_writer(|connection| {
                connection
                    .execute_batch(
                        "CREATE TRIGGER reject_fingerprint BEFORE INSERT ON feed_fingerprints \
                         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
                    )
                    .map_err(sqlite_store_error)
            })
            .await
            .unwrap();
        let rejected = message("2025-01-01T00:00:00Z", "https://example.com/notes", None);
        let rejected_cid = message_cid(&rejected);

        assert!(
            MessageStore::put(&store, TENANT, rejected, KeyValues::new())
                .await
                .is_err()
        );

        assert!(feed_rows(&store).await.is_empty());
        assert_eq!(feed_head(&store).await, None);
        assert_eq!(global_fingerprint(&store).await, None);
        assert!(MessageStore::get(&store, TENANT, &rejected_cid)
            .await
            .unwrap()
            .is_none());
        assert!(publisher.wakes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn non_feed_put_only_stores_the_message_and_does_not_wake() {
        let publisher = Arc::new(RecordingPublisher::default());
        let mut store = SqliteStore::new(
            test_memory_uri(),
            WakePublishHandler::new(publisher.clone()),
        );
        MessageStore::open(&mut store).await.unwrap();
        let message = non_feed_message("2025-01-01T00:00:00Z");
        let cid = message_cid(&message);

        MessageStore::put(&store, TENANT, message.clone(), KeyValues::new())
            .await
            .unwrap();

        assert_eq!(
            MessageStore::get(&store, TENANT, &cid).await.unwrap(),
            Some(message)
        );
        assert!(feed_rows(&store).await.is_empty());
        assert_eq!(feed_head(&store).await, None);
        assert_eq!(global_fingerprint(&store).await, None);
        assert!(publisher.wakes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn wake_publication_failure_does_not_fail_or_roll_back_put() {
        let mut store = SqliteStore::new(
            test_memory_uri(),
            WakePublishHandler::new(Arc::new(RejectingPublisher)),
        );
        MessageStore::open(&mut store).await.unwrap();
        let message = message("2025-01-01T00:00:00Z", "https://example.com/notes", None);
        let cid = message_cid(&message);

        MessageStore::put(&store, TENANT, message.clone(), indexes(&message))
            .await
            .expect("publisher failure must not fail put");

        assert_eq!(feed_head(&store).await, Some(1));
        assert_eq!(
            MessageStore::get(&store, TENANT, &cid).await.unwrap(),
            Some(message)
        );
    }

    #[tokio::test]
    async fn feed_wakes_publish_only_after_the_full_transaction_is_visible() {
        // Serialize file-backed tests process-wide.
        let _disk = disk_test_guard().await;
        struct CommitVisibilityPublisher {
            database_path: PathBuf,
            /// CIDs in expected commit order; each wake must observe the row of
            /// the next expected commit from a separate connection.
            expected: Mutex<Vec<String>>,
            observed: Mutex<Vec<(u64, String)>>,
        }

        impl WakePublisher for CommitVisibilityPublisher {
            fn publish(&self, wake: Wake) -> Result<(), WakeError> {
                let connection = rusqlite::Connection::open(&self.database_path)
                    .map_err(|error| WakeError::PublishError(error.to_string()))?;
                let (message_cid, indexes_json): (String, String) = connection
                    .query_row(
                        "SELECT message_cid, indexes_json FROM feed_entries \
                         WHERE tenant = ?1 AND position = ?2",
                        rusqlite::params![wake.tenant, wake.position as i64],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|error| WakeError::PublishError(error.to_string()))?;

                let mut expected = self.expected.lock().unwrap();
                let want = expected
                    .first()
                    .ok_or_else(|| {
                        WakeError::PublishError("wake published without a pending commit".into())
                    })?
                    .clone();
                if message_cid != want {
                    return Err(WakeError::PublishError(format!(
                        "wake at position {} carries {message_cid}, expected {want}",
                        wake.position
                    )));
                }
                if indexes_json.is_empty() {
                    return Err(WakeError::PublishError(
                        "committed feed row is missing its indexes".into(),
                    ));
                }
                expected.remove(0);
                self.observed
                    .lock()
                    .unwrap()
                    .push((wake.position, message_cid));
                Ok(())
            }
        }

        let path = temp_db_path("feed-wake-commit-visibility");
        let first = message("2025-01-01T00:00:00Z", "https://example.com/notes", None);
        let second = message("2025-01-01T00:00:01Z", "https://example.com/tasks", None);
        let publisher = Arc::new(CommitVisibilityPublisher {
            database_path: path.clone(),
            expected: Mutex::new([&first, &second].map(message_cid).to_vec()),
            observed: Mutex::new(Vec::new()),
        });

        let mut store = SqliteStore::new(&path, WakePublishHandler::new(publisher.clone()));
        MessageStore::open(&mut store).await.unwrap();
        MessageStore::put(&store, TENANT, first.clone(), indexes(&first))
            .await
            .unwrap();
        MessageStore::put(&store, TENANT, second.clone(), indexes(&second))
            .await
            .unwrap();

        let (positions, cids) = {
            let observed = publisher.observed.lock().unwrap();
            (
                observed
                    .iter()
                    .map(|(position, _)| *position)
                    .collect::<Vec<_>>(),
                observed
                    .iter()
                    .map(|(_, cid)| cid.clone())
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(positions, [1, 2]);
        assert_eq!(
            cids.iter().map(String::as_str).collect::<Vec<_>>(),
            [&message_cid(&first), &message_cid(&second)]
        );
        MessageStore::close(&mut store).await;
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn durable_feed_state_survives_reopen_and_wakes_only_after_commit() {
        // Serialize file-backed tests process-wide.
        let _disk = disk_test_guard().await;
        let path = temp_db_path("durable-feed-reopen");
        let publisher = Arc::new(RecordingPublisher {
            wakes: Mutex::new(Vec::new()),
            database_path: Some(path.clone()),
        });
        let first = message("2025-01-01T00:00:00Z", "https://example.com/notes", None);
        let second = message("2025-01-01T00:00:01Z", "https://example.com/tasks", None);
        let cids = [&first, &second].map(message_cid);
        let mut expected = cid_contribution(&cids[0]);
        xor_in_place(&mut expected, &cid_contribution(&cids[1]));

        let mut store = SqliteStore::new(&path, WakePublishHandler::new(publisher.clone()));
        MessageStore::open(&mut store).await.unwrap();
        MessageStore::put(&store, TENANT, first.clone(), indexes(&first))
            .await
            .unwrap();
        MessageStore::put(&store, TENANT, second.clone(), indexes(&second))
            .await
            .unwrap();
        let epoch = feed_epoch(&store).await;
        MessageStore::close(&mut store).await;
        // Drop the old handle before reopening.
        drop(store);

        let mut reopened = SqliteStore::new(&path, WakePublishHandler::default());
        MessageStore::open(&mut reopened).await.unwrap();
        assert_eq!(feed_epoch(&reopened).await, epoch);
        assert_eq!(feed_head(&reopened).await, Some(2));
        assert_eq!(
            feed_rows(&reopened)
                .await
                .into_iter()
                .map(|row| row.1)
                .collect::<Vec<_>>(),
            cids
        );
        assert_eq!(
            global_fingerprint(&reopened).await.unwrap(),
            expected.as_slice()
        );
        assert_eq!(
            MessageStore::get(&reopened, TENANT, &cids[1])
                .await
                .unwrap(),
            Some(second)
        );
        assert!(publisher
            .wakes
            .lock()
            .unwrap()
            .iter()
            .all(|(_, _, committed)| *committed));
        MessageStore::close(&mut reopened).await;
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn atomic_latest_state_transition_survives_reopen() {
        // Covers: DWN-REC-006
        // Serialize file-backed tests process-wide.
        let _disk = disk_test_guard().await;
        let path = temp_db_path("latest-state-transition-reopen");
        let first = message("2025-01-01T00:00:00Z", "https://example.com/notes", None);
        let displaced = message("2025-01-01T00:00:01Z", "https://example.com/notes", None);
        let winner = message("2025-01-01T00:00:02Z", "https://example.com/notes", None);
        let first_cid = message_cid(&first);
        let displaced_cid = message_cid(&displaced);
        let winner_cid = message_cid(&winner);

        let mut store = SqliteStore::new(&path, WakePublishHandler::default());
        MessageStore::open(&mut store).await.unwrap();
        MessageStore::put(&store, TENANT, first.clone(), indexes(&first))
            .await
            .unwrap();
        MessageStore::put(&store, TENANT, displaced, indexes(&winner))
            .await
            .unwrap();

        let mut retained_indexes = indexes(&first);
        retained_indexes.insert("isLatestBaseState".to_string(), Value::Bool(false));
        let result = MessageStore::commit_latest_state(
            &store,
            TENANT,
            LatestStateTransition {
                put: LatestStateMutation {
                    message: winner.clone(),
                    indexes: indexes(&winner),
                },
                retains: vec![LatestStateMutation {
                    message: first,
                    indexes: retained_indexes,
                }],
                deletes: vec![displaced_cid.clone()],
            },
        )
        .await
        .unwrap();
        assert_eq!(
            result
                .position
                .as_ref()
                .map(|token| token.position.as_str()),
            Some("3")
        );
        let epoch = feed_epoch(&store).await;
        MessageStore::close(&mut store).await;
        // Drop the old handle before reopening.
        drop(store);

        let mut reopened = SqliteStore::new(&path, WakePublishHandler::default());
        MessageStore::open(&mut reopened).await.unwrap();
        assert_eq!(feed_epoch(&reopened).await, epoch);
        assert_eq!(feed_head(&reopened).await, Some(3));
        assert_eq!(
            feed_rows(&reopened)
                .await
                .into_iter()
                .map(|(position, cid, _)| (position, cid))
                .collect::<Vec<_>>(),
            [(1, first_cid), (3, winner_cid.clone())]
        );
        assert!(MessageStore::get(&reopened, TENANT, &displaced_cid)
            .await
            .unwrap()
            .is_none());
        assert!(MessageStore::get(&reopened, TENANT, &winner_cid)
            .await
            .unwrap()
            .is_some());
        MessageStore::close(&mut reopened).await;
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn data_store_shares_content_addressed_blocks_and_refs() {
        let mut store = SqliteStore::in_memory(None);
        DataStore::open(&mut store).await.unwrap();
        let bytes = Bytes::from_static(b"hello sqlite data");
        let data_cid = generate_dag_pb_cid_from_bytes(&bytes).to_string();

        let put = DataStore::put(
            &store,
            "did:example:alice",
            "record-1",
            &data_cid,
            stream::iter(vec![bytes.clone()]),
        )
        .await
        .unwrap();
        assert_eq!(put.data_size, bytes.len());

        let duplicate = DataStore::put(
            &store,
            "did:example:alice",
            "record-1",
            &data_cid,
            stream::iter(vec![Bytes::from_static(b"ignored duplicate stream")]),
        )
        .await
        .unwrap();
        assert_eq!(duplicate.data_size, bytes.len());

        let shared = DataStore::put(
            &store,
            "did:example:alice",
            "record-2",
            &data_cid,
            stream::iter(vec![Bytes::from_static(b"ignored shared stream")]),
        )
        .await
        .unwrap();
        assert_eq!(shared.data_size, bytes.len());

        DataStore::delete(&store, "did:example:alice", "record-1", &data_cid)
            .await
            .unwrap();
        let stored = DataStore::get(&store, "did:example:alice", "record-2", &data_cid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.data_size, bytes.len());
        let read = stored
            .data_stream
            .try_fold(Vec::new(), |mut read, chunk| async move {
                read.extend_from_slice(&chunk);
                Ok(read)
            })
            .await
            .unwrap();
        assert_eq!(read, bytes.to_vec());

        DataStore::delete(&store, "did:example:alice", "record-2", &data_cid)
            .await
            .unwrap();
        assert!(
            DataStore::get(&store, "did:example:alice", "record-2", &data_cid)
                .await
                .unwrap()
                .is_none()
        );
    }

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
        if let Some(protocol) =
            serde_json::to_value(&message.descriptor).unwrap()["protocol"].as_str()
        {
            indexes.insert("protocol".to_string(), Value::String(protocol.to_string()));
        }
        indexes
    }

    fn temp_db_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dwn-rs-{name}-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ))
    }
}
