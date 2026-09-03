use dwn_rs_core::{
    cid::generate_message_cid_from_json,
    errors::{EventLogError, MessageReplicationError, StoreError},
    fields::MessageFields,
    matches_filters,
    matching::has_valid_subtree_filters,
    stores::{
        replication_feed_reader::{
            build_token, derive_stream_id, normalize_scopes, parse_feed_position,
            validate_feed_cursor, xor_in_place, FeedCursorState, Fingerprint, ReplicationBounds,
        },
        EventLogEntry, EventLogReadOptions, EventLogReadResult, KeyValues, ReplicationFeedReader,
    },
    Descriptor, FilterError, Message, MessageEvent, ProgressToken, Value,
};
use rusqlite::{OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::{
    message_store::{get_single_feed_fingerprint, select_feed_entry_by_position},
    sqlite_store_error, SqliteStore,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct FeedEntry {
    pub(crate) tenant: String,
    pub(crate) position: i64,
    pub(crate) message_cid: String,
    #[serde(
        rename = "indexes_json",
        deserialize_with = "deserialize_keyvalues_json"
    )]
    pub(crate) indexes: KeyValues,
    #[serde(
        rename = "fingerprint_scopes_json",
        deserialize_with = "deserialize_json_string_to_array"
    )]
    pub(crate) fingerprint_scopes: Vec<String>,
}

fn deserialize_json_string_to_array<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    serde_json::from_str(&s).map_err(serde::de::Error::custom)
}

fn deserialize_keyvalues_json<'de, D>(deserializer: D) -> Result<KeyValues, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    serde_json::from_str(&s).map_err(serde::de::Error::custom)
}

impl ReplicationFeedReader for SqliteStore {
    async fn log_read(
        &self,
        tenant: &str,
        options: EventLogReadOptions,
    ) -> Result<EventLogReadResult, dwn_rs_core::errors::EventLogError> {
        if let Some(filters) = &options.filters {
            if !has_valid_subtree_filters(filters) {
                return Err(EventLogError::FilterError(FilterError::UnparseableFilter(
                    "invalid subtree filter".to_string(),
                )));
            }
        };

        let position = if let Some(cursor) = &options.cursor {
            parse_feed_position(&cursor.position)?
        } else {
            0
        };

        let tenant = tenant.to_owned();
        let (events, progress_token, drained) = self
            .connection()
            .await?
            .with_writer(move |conn| {
                let tx = conn.transaction().map_err(sqlite_store_error)?;
                let epoch = Self::epoch_tx(&tx)?;
                let mut events = Vec::new();

                let head = get_head(&tx, &tenant)?.unwrap_or(0) as u64;

                let cursor_entry = if let Some(cursor) = &options.cursor {
                    let bounds = log_bounds(&tx, &tenant, &epoch)?;
                    let entry = select_feed_entry_by_position(&tx, &tenant, position as i64)?;

                    (head, entry, Some(cursor.clone()), Some(bounds))
                } else {
                    (head, None, None, None)
                };

                if let (head, entry, Some(ref cursor), Some(bounds)) = cursor_entry {
                    let message_cid_at_position =
                        entry.as_ref().map(|entry| entry.message_cid.as_str());
                    let zero = build_token(&tenant, &cursor.epoch, 0, None);
                    let zero_bounds = (zero.clone(), zero.clone());
                    if let Err(err) = validate_feed_cursor(
                        cursor,
                        FeedCursorState {
                            expected_stream_id: derive_stream_id(&tenant).as_str(),
                            expected_epoch: &epoch,
                            head,
                            oldest_replayable: 0,
                            message_cid_at_position,
                            bounds: match bounds {
                                Some(ref bounds) => Some(bounds),
                                None => Some(&zero_bounds),
                            },
                        },
                    ) {
                        return Ok(Err(err));
                    };
                };

                let (head, _, ref cursor, _) = cursor_entry;
                if head == 0 {
                    return Ok(Ok((
                        events,
                        Some(rebuild_cursor(&tenant, &epoch, cursor.clone())),
                        true,
                    )));
                }

                let start_position = cursor
                    .as_ref()
                    .and_then(|cursor| parse_feed_position(&cursor.position).ok())
                    .unwrap_or(0);

                let max_events = options.limit.unwrap_or(u64::MAX);
                if max_events == 0 {
                    return Ok(Ok((
                        events,
                        Some(rebuild_cursor(&tenant, &epoch, cursor.clone())),
                        start_position >= head,
                    )));
                }

                if start_position == head {
                    return Ok(Ok((
                        events,
                        Some(build_token(&tenant, &epoch, start_position, None)),
                        true,
                    )));
                }

                if start_position > head {
                    return Ok(Ok((events, cursor.clone(), true)));
                }

                let mut entries = fetch_feed_entries(&tx, &tenant, start_position, head)?;

                let mut last_scanned = start_position;
                let mut limit_reached = false;
                for (entry, message_json, msg_cid) in &mut entries {
                    last_scanned = entry.position as u64;

                    if !matches_filters(&entry.indexes, options.filters.as_ref()) {
                        continue;
                    }

                    let (message_json, msg_cid) = match (message_json, msg_cid) {
                        (Some(json), Some(cid)) => (json, cid),
                        (None, None) | (Some(_), None) | (None, Some(_)) => {
                            return Err(StoreError::ReplicationError(
                                MessageReplicationError::MissingMessage {
                                    message_cid: entry.message_cid.clone(),
                                },
                            ))
                        }
                    };

                    let message_value: serde_json::Value = serde_json::from_str(message_json)
                        .map_err(|err| StoreError::InternalException(err.to_string()))?;

                    let computed_cid = generate_message_cid_from_json(&message_value)
                        .map_err(|err| StoreError::InternalException(err.to_string()))?
                        .to_string();

                    let mut msg: Message<Descriptor> = serde_json::from_value(message_value)
                        .map_err(|err| StoreError::InternalException(err.to_string()))?;

                    let encoded_data = match msg.fields.encoded_data() {
                        Some(Value::String(data)) => Ok(Some(data.clone())),
                        Some(Value::Null) | None => Ok(None),
                        Some(_) => Err(StoreError::ReplicationError(
                            MessageReplicationError::InvalidEncodedData,
                        )),
                    }?;

                    if entry.message_cid != *msg_cid {
                        return Err(StoreError::ReplicationError(
                            MessageReplicationError::CidsMismatch {
                                expected: entry.message_cid.clone(),
                                actual: msg_cid.clone(),
                            },
                        ));
                    }

                    if computed_cid != entry.message_cid {
                        return Err(StoreError::ReplicationError(
                            MessageReplicationError::CidsMismatch {
                                expected: entry.message_cid.clone(),
                                actual: computed_cid,
                            },
                        ));
                    }

                    events.push(EventLogEntry {
                        seq: entry.position.to_string(),
                        event: MessageEvent {
                            message: msg.clone(),
                            initial_write: None,
                        },
                        indexes: entry.indexes.clone(),
                        message_cid: Some(entry.message_cid.clone()),
                        encoded_data,
                    });

                    if events.len() as u64 >= max_events {
                        limit_reached = true;
                        break;
                    }
                }

                if !limit_reached {
                    last_scanned = head;
                }

                Ok(Ok((
                    events.clone(),
                    Some(build_token(
                        &tenant,
                        &epoch,
                        last_scanned,
                        if last_scanned
                            == events
                                .last()
                                .map_or(0, |entry| parse_feed_position(&entry.seq).unwrap_or(0))
                        {
                            events.last().and_then(|entry| entry.message_cid.as_deref())
                        } else {
                            None
                        },
                    )),
                    last_scanned >= head,
                )))
            })
            .await
            .map_err(EventLogError::StoreError)??;

        Ok(EventLogReadResult {
            events: events.clone(),
            cursor: progress_token,
            drained,
        })
    }

    async fn log_bounds(&self, tenant: &str) -> Result<Option<ReplicationBounds>, EventLogError> {
        let tenant = tenant.to_owned();

        self.connection()
            .await?
            .with_writer(move |conn| {
                let tx = conn.transaction().map_err(sqlite_store_error)?;
                let epoch = Self::epoch_tx(&tx)?;
                log_bounds(&tx, &tenant, &epoch)
            })
            .await
            .map_err(EventLogError::StoreError)
    }

    async fn fingerprint(
        &self,
        tenant: &str,
        scopes: &[String],
    ) -> Result<Fingerprint, EventLogError> {
        let normal_scopes = normalize_scopes(scopes);
        let tenant = tenant.to_owned();

        let fingerprint = self
            .connection()
            .await?
            .with_writer(move |conn| {
                let tx = conn.transaction().map_err(sqlite_store_error)?;
                let mut fingerprint = Fingerprint::default();
                for scope in &normal_scopes {
                    let scope_fp = get_single_feed_fingerprint(&tx, &tenant, scope)?;
                    if let Some(ref fp) = scope_fp {
                        xor_in_place(&mut fingerprint, fp);
                    }
                }

                Ok(fingerprint)
            })
            .await?;

        Ok(fingerprint)
    }

    async fn epoch(&self) -> Result<String, EventLogError> {
        self.connection()
            .await?
            .with_writer(|conn| {
                let tx = conn.transaction().map_err(sqlite_store_error)?;
                Self::epoch_tx(&tx)
            })
            .await
            .map_err(EventLogError::StoreError)
    }
}

fn get_head(conn: &Transaction, tenant: &str) -> Result<Option<i64>, StoreError> {
    let head = conn
        .query_row(
            "SELECT head FROM feed_heads WHERE tenant = ?1",
            [tenant],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_store_error)?;

    Ok(head)
}

fn latest_feed_entry_cid(
    conn: &rusqlite::Connection,
    tenant: &str,
) -> Result<Option<String>, StoreError> {
    let latest_cid = conn
        .query_row(
            "
            SELECT message_cid
            FROM feed_entries
            JOIN feed_heads ON 
                feed_entries.tenant = feed_heads.tenant 
                AND feed_entries.position = feed_heads.head
            WHERE feed_entries.tenant = ?1
            ORDER BY position DESC LIMIT 1",
            [tenant],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_store_error)?;

    Ok(latest_cid)
}

fn log_bounds(
    conn: &Transaction,
    tenant: &str,
    epoch: &str,
) -> Result<Option<ReplicationBounds>, StoreError> {
    let head = get_head(conn, tenant)?.unwrap_or(0) as u64;
    if head == 0 {
        return Ok(None);
    };

    let oldest = build_token(tenant, epoch, 0, None);
    let latest = latest_feed_entry_cid(conn, tenant)?
        .map(|cid| build_token(tenant, epoch, head, Some(&cid)))
        .unwrap_or(build_token(tenant, epoch, head, None));

    Ok(Some((oldest, latest)))
}

fn rebuild_cursor(tenant: &str, epoch: &str, current: Option<ProgressToken>) -> ProgressToken {
    current.unwrap_or(build_token(tenant, epoch, 0, None))
}

// This type represents a row of feed entries fetched from the database, where each entry
// consists of a FeedEntry, an optional Message (as JSON to be parsed), and an optional message CID.
type FeedEntryRow = Vec<(FeedEntry, Option<String>, Option<String>)>;

fn fetch_feed_entries(
    tx: &Transaction<'_>,
    tenant: &str,
    start_position: u64,
    head: u64,
) -> Result<FeedEntryRow, StoreError> {
    tx.prepare(
        "
            SELECT
                f.tenant as feed_tenant,
                f.position as feed_position,
                f.message_cid as feed_message_cid,
                f.indexes_json as feed_indexes_json,
                f.fingerprint_scopes_json as feed_fingerprint_scopes_json,
                m.message_json as message_json,
                m.message_cid as message_cid
            FROM feed_entries AS f
            LEFT JOIN messages AS m
                ON m.tenant = f.tenant
            AND m.message_cid = f.message_cid
            WHERE f.tenant = ?1
                AND f.position > ?2
                AND f.position <= ?3
            ORDER BY f.position ASC",
    )
    .map_err(sqlite_store_error)?
    .query_and_then(
        [tenant, &start_position.to_string(), &head.to_string()],
        |row| {
            Ok((
                FeedEntry {
                    tenant: row.get("feed_tenant")?,
                    position: row.get("feed_position")?,
                    message_cid: row.get("feed_message_cid")?,
                    indexes: serde_json::from_str::<KeyValues>(
                        &row.get::<_, String>("feed_indexes_json")?,
                    )
                    .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?,
                    fingerprint_scopes: serde_json::from_str::<Vec<String>>(
                        &row.get::<_, String>("feed_fingerprint_scopes_json")?,
                    )
                    .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?,
                },
                row.get::<_, Option<String>>("message_json")?,
                row.get("message_cid")?,
            ))
        },
    )
    .map_err(sqlite_store_error)?
    .collect::<Result<FeedEntryRow, rusqlite::Error>>()
    .map_err(sqlite_store_error)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use dwn_rs_core::descriptors::{DeleteDescriptor, Records};
    use dwn_rs_core::errors::{EventLogError, MessageReplicationError, StoreError};
    use dwn_rs_core::filters::{Filter, FilterKey, Filters};
    use dwn_rs_core::stores::replication_feed_conformance;
    use dwn_rs_core::stores::wake::WakePublishHandler;
    use dwn_rs_core::stores::{EventLogReadOptions, KeyValues, MessageStore};
    use dwn_rs_core::{Descriptor, Fields, Message, Value};

    use super::*;

    const TENANT: &str = "did:example:alice";

    fn delete_message(record_id: &str, timestamp: &str) -> Message<Descriptor> {
        Message {
            descriptor: Descriptor::Records(Box::new(Records::Delete(Box::new(
                DeleteDescriptor {
                    message_timestamp: timestamp.parse().expect("valid timestamp"),
                    record_id: record_id.to_string(),
                    prune: false,
                },
            )))),
            fields: Fields::Authorization(Default::default()),
        }
    }

    fn indexes(marker: &str) -> KeyValues {
        BTreeMap::from([("marker".to_string(), Value::String(marker.to_string()))])
    }

    fn marker_filter(marker: &str) -> Filters {
        Filters::from(BTreeMap::from([(
            FilterKey::Index("marker".to_string()),
            Filter::Equal(Value::String(marker.to_string())),
        )]))
    }

    async fn opened_memory_store() -> SqliteStore {
        let mut store = SqliteStore::in_memory(None);
        MessageStore::open(&mut store).await.expect("open store");
        store
    }

    #[tokio::test]
    async fn sqlite_conforms_to_replication_feed_contract() {
        use std::sync::atomic::{AtomicU64, Ordering};

        replication_feed_conformance::run(|| async { SqliteStore::in_memory(None) }).await;

        // The production path is file-backed: run the same suite on disk with
        // a fresh file per scenario.
        let dir = tempfile::tempdir().expect("battery tempdir");
        let seq = AtomicU64::new(0);
        replication_feed_conformance::run(|| async {
            let n = seq.fetch_add(1, Ordering::Relaxed);
            SqliteStore::new(
                dir.path().join(format!("feed-{n}.sqlite")),
                WakePublishHandler::new(Arc::new(())),
            )
        })
        .await;
    }

    #[tokio::test]
    async fn filtered_out_corrupt_message_is_not_hydrated() {
        let store = opened_memory_store().await;
        let skipped = delete_message("skipped", "2025-01-01T00:00:00Z");
        let matched = delete_message("matched", "2025-01-01T00:00:01Z");

        MessageStore::put(&store, TENANT, skipped, indexes("skipped"))
            .await
            .expect("put skipped message");
        MessageStore::put(&store, TENANT, matched, indexes("matched"))
            .await
            .expect("put matched message");

        let tenant = TENANT.to_string();
        store
            .connection()
            .await
            .expect("connection")
            .with_writer(move |connection| {
                connection
                    .execute(
                        "UPDATE messages SET message_json = '{' \
                         WHERE tenant = ?1 AND message_cid = (\
                             SELECT message_cid FROM feed_entries \
                             WHERE tenant = ?1 AND position = 1\
                         )",
                        [tenant],
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .expect("corrupt filtered-out message");

        let page = store
            .log_read(
                TENANT,
                EventLogReadOptions {
                    filters: Some(marker_filter("matched")),
                    ..Default::default()
                },
            )
            .await
            .expect("filtered read");

        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].seq, "2");
        assert!(page.drained);
        assert_eq!(page.cursor.expect("cursor").position, "2");
    }

    #[tokio::test]
    async fn matching_feed_entry_without_message_is_corruption() {
        let store = opened_memory_store().await;
        let message = delete_message("missing", "2025-01-01T00:00:00Z");
        MessageStore::put(&store, TENANT, message, indexes("missing"))
            .await
            .expect("put message");

        let tenant = TENANT.to_string();
        store
            .connection()
            .await
            .expect("connection")
            .with_writer(move |connection| {
                connection
                    .execute("DELETE FROM messages WHERE tenant = ?1", [tenant])
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .expect("remove message row");

        let error = store
            .log_read(TENANT, EventLogReadOptions::default())
            .await
            .expect_err("orphaned feed entry must fail");

        assert!(matches!(
            error,
            EventLogError::StoreError(StoreError::ReplicationError(
                MessageReplicationError::MissingMessage { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn malformed_feed_metadata_is_corruption() {
        for column in ["indexes_json", "fingerprint_scopes_json"] {
            let store = opened_memory_store().await;
            MessageStore::put(
                &store,
                TENANT,
                delete_message("corrupt", "2025-01-01T00:00:00Z"),
                indexes("corrupt"),
            )
            .await
            .expect("put message");

            let statement = format!("UPDATE feed_entries SET {column} = '{{' WHERE tenant = ?1");
            let tenant = TENANT.to_string();
            store
                .connection()
                .await
                .expect("connection")
                .with_writer(move |connection| {
                    connection
                        .execute(&statement, [tenant])
                        .map_err(sqlite_store_error)?;
                    Ok(())
                })
                .await
                .expect("corrupt feed metadata");

            assert!(matches!(
                store.log_read(TENANT, EventLogReadOptions::default()).await,
                Err(EventLogError::StoreError(_))
            ));
        }
    }

    #[tokio::test]
    async fn message_json_with_wrong_cid_is_corruption() {
        let store = opened_memory_store().await;
        MessageStore::put(
            &store,
            TENANT,
            delete_message("original", "2025-01-01T00:00:00Z"),
            indexes("original"),
        )
        .await
        .expect("put message");

        let replacement =
            serde_json::to_string(&delete_message("replacement", "2025-01-01T00:00:01Z"))
                .expect("serialize replacement");
        let tenant = TENANT.to_string();
        store
            .connection()
            .await
            .expect("connection")
            .with_writer(move |connection| {
                connection
                    .execute(
                        "UPDATE messages SET message_json = ?1 WHERE tenant = ?2",
                        rusqlite::params![replacement, tenant],
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .expect("replace message JSON");

        assert!(matches!(
            store.log_read(TENANT, EventLogReadOptions::default()).await,
            Err(EventLogError::StoreError(StoreError::ReplicationError(
                MessageReplicationError::CidsMismatch { .. }
            )))
        ));
    }

    #[tokio::test]
    async fn invalid_fingerprint_bytes_are_corruption() {
        let store = opened_memory_store().await;
        MessageStore::put(
            &store,
            TENANT,
            delete_message("fingerprint", "2025-01-01T00:00:00Z"),
            indexes("fingerprint"),
        )
        .await
        .expect("put message");

        let tenant = TENANT.to_string();
        store
            .connection()
            .await
            .expect("connection")
            .with_writer(move |connection| {
                connection
                    .execute_batch("PRAGMA ignore_check_constraints = ON")
                    .map_err(sqlite_store_error)?;
                connection
                    .execute(
                        "UPDATE feed_fingerprints SET value = x'00' WHERE tenant = ?1",
                        [tenant],
                    )
                    .map_err(sqlite_store_error)?;
                connection
                    .execute_batch("PRAGMA ignore_check_constraints = OFF")
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .expect("corrupt fingerprint");

        assert!(matches!(
            store.fingerprint(TENANT, &[String::new()]).await,
            Err(EventLogError::StoreError(_))
        ));
    }

    #[tokio::test]
    async fn reopened_store_preserves_feed_positions_bounds_and_epoch() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("replication-feed.sqlite3");
        let publisher = WakePublishHandler::new(Arc::new(()));
        let mut store = SqliteStore::new(&path, publisher.clone());
        MessageStore::open(&mut store).await.expect("open store");

        for (record_id, timestamp) in [
            ("one", "2025-01-01T00:00:00Z"),
            ("two", "2025-01-01T00:00:01Z"),
        ] {
            MessageStore::put(
                &store,
                TENANT,
                delete_message(record_id, timestamp),
                indexes(record_id),
            )
            .await
            .expect("put message");
        }

        let epoch = store.epoch().await.expect("epoch");
        let bounds = store.log_bounds(TENANT).await.expect("bounds");
        MessageStore::close(&mut store).await;

        let mut reopened = SqliteStore::new(&path, publisher);
        MessageStore::open(&mut reopened)
            .await
            .expect("reopen store");
        let page = reopened
            .log_read(TENANT, EventLogReadOptions::default())
            .await
            .expect("read reopened feed");

        assert_eq!(reopened.epoch().await.expect("reopened epoch"), epoch);
        assert_eq!(
            reopened.log_bounds(TENANT).await.expect("reopened bounds"),
            bounds
        );
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.seq.as_str())
                .collect::<Vec<_>>(),
            ["1", "2"]
        );
        assert_eq!(page.cursor.expect("cursor").position, "2");
        assert!(page.drained);
    }
}
