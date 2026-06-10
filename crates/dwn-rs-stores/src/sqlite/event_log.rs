//! Durable SQLite backends for [`StateIndex`], [`EventLog`], and
//! [`ResumableTaskStore`].

use std::collections::BTreeMap;
use std::future::Future;

use rusqlite::{params, OptionalExtension};

use dwn_rs_core::errors::{EventLogError, StoreError};
use dwn_rs_core::events::MessageEvent;
use dwn_rs_core::local::MemoryEventLog;
use dwn_rs_core::stores::{
    EventLog, EventLogReadOptions, EventLogReadResult, EventLogReplayBounds,
    EventLogSubscribeOptions, EventLogTrimBound, EventSubscription, KeyValues, ProgressToken,
    ResumableTaskStore, StateIndex, SubscriptionListener,
};
use dwn_rs_core::{Descriptor, Value};

use crate::sqlite::{json_store_error, sqlite_store_error, SqliteStore};

/// SQLite-backed [`EventLog`] with in-memory subscriptions and durable events.
#[derive(Clone)]
pub struct SqliteEventLog {
    inner: MemoryEventLog,
    store: SqliteStore,
}

impl Default for SqliteEventLog {
    fn default() -> Self {
        Self::new(&SqliteStore::in_memory())
    }
}

impl SqliteEventLog {
    pub fn new(store: &SqliteStore) -> Self {
        Self {
            inner: MemoryEventLog::default(),
            store: store.clone(),
        }
    }

    async fn load_epoch(&self) -> Result<String, StoreError> {
        self.store
            .connection()
            .await?
            .with_reader(|connection| {
                let epoch = connection
                    .query_row("SELECT epoch FROM event_log_meta WHERE id = 1", [], |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()
                    .map_err(sqlite_store_error)?;
                Ok(epoch.unwrap_or_else(|| ulid::Ulid::new().to_string()))
            })
            .await
    }

    async fn persist_epoch(&self, epoch: &str) -> Result<(), StoreError> {
        let epoch = epoch.to_string();

        self.store
            .connection()
            .await?
            .with_writer(move |connection| {
                connection
                    .execute(
                        "INSERT OR REPLACE INTO event_log_meta (id, epoch) VALUES (1, ?1)",
                        params![epoch],
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
    }

    async fn load_events(&self) -> Result<(), StoreError> {
        // The reader closure must be `Send + 'static`, so it can't borrow local
        // mutables — build both maps inside and return them, then restore into
        // `inner` after the await.
        let (tenant_seqs, mut events_by_tenant) = self
            .store
            .connection()
            .await?
            .with_reader(|connection| {
                let mut tenant_seqs = BTreeMap::<String, u64>::new();
                let mut events_by_tenant = BTreeMap::<
                    String,
                    Vec<(u64, MessageEvent<Descriptor>, KeyValues, String)>,
                >::new();

                let mut seq_statement = connection
                    .prepare("SELECT tenant, next_seq FROM event_log_tenant_seq")
                    .map_err(sqlite_store_error)?;
                let seq_rows = seq_statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
                    })
                    .map_err(sqlite_store_error)?;
                for row in seq_rows {
                    let (tenant, next_seq) = row.map_err(sqlite_store_error)?;
                    tenant_seqs.insert(tenant, next_seq as u64);
                }

                let mut statement = connection
                    .prepare(
                        "SELECT tenant, seq, event_json, indexes_json, message_cid \
                     FROM event_log_events ORDER BY tenant, seq",
                    )
                    .map_err(sqlite_store_error)?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)? as u64,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    })
                    .map_err(sqlite_store_error)?;

                for row in rows {
                    let (tenant, seq, event_json, indexes_json, message_cid) =
                        row.map_err(sqlite_store_error)?;
                    let event: MessageEvent<Descriptor> =
                        serde_json::from_str(&event_json).map_err(json_store_error)?;
                    let indexes: KeyValues =
                        serde_json::from_str(&indexes_json).map_err(json_store_error)?;
                    events_by_tenant.entry(tenant).or_default().push((
                        seq as u64,
                        event,
                        indexes,
                        message_cid,
                    ));
                }

                Ok((tenant_seqs, events_by_tenant))
            })
            .await?;

        for (tenant, next_seq) in tenant_seqs {
            let events = events_by_tenant.remove(&tenant).unwrap_or_default();
            self.inner
                .restore_tenant(&tenant, next_seq, events)
                .map_err(|err| StoreError::InternalException(err.to_string()))?;
        }

        for (tenant, events) in events_by_tenant {
            let next_seq = events.last().map(|(seq, _, _, _)| *seq).unwrap_or(0);
            self.inner
                .restore_tenant(&tenant, next_seq, events)
                .map_err(|err| StoreError::InternalException(err.to_string()))?;
        }

        Ok(())
    }

    async fn persist_emit(
        &self,
        tenant: &str,
        seq: u64,
        event: &MessageEvent<Descriptor>,
        indexes: &KeyValues,
        message_cid: &str,
    ) -> Result<(), StoreError> {
        let event_json = serde_json::to_string(event).map_err(json_store_error)?;
        let indexes_json = serde_json::to_string(indexes).map_err(json_store_error)?;

        let tenant = tenant.to_string();
        let message_cid = message_cid.to_string();

        self.store
            .connection()
            .await?
            .with_writer(move |connection| {
                connection
                    .execute(
                        "INSERT OR REPLACE INTO event_log_events \
                     (tenant, seq, event_json, indexes_json, message_cid) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![tenant, seq as i64, event_json, indexes_json, message_cid],
                    )
                    .map_err(sqlite_store_error)?;
                connection
                    .execute(
                        "INSERT OR REPLACE INTO event_log_tenant_seq (tenant, next_seq) \
                     VALUES (?1, ?2)",
                        params![tenant, seq as i64],
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
    }

    async fn persist_trim(
        &self,
        tenant: &str,
        older_than: &EventLogTrimBound,
    ) -> Result<(), StoreError> {
        let tenant = tenant.to_string();
        let older_than = older_than.clone();

        self.store
            .connection()
            .await?
            .with_writer(move |connection| {
                let tx = connection.transaction().map_err(sqlite_store_error)?;
                match older_than {
                    EventLogTrimBound::Sequence(sequence) => {
                        tx.execute(
                            "DELETE FROM event_log_events WHERE tenant = ?1 AND seq < ?2",
                            params![tenant, sequence as i64],
                        )
                        .map_err(sqlite_store_error)?;
                    }
                    EventLogTrimBound::Timestamp(timestamp) => {
                        let mut statement = tx
                            .prepare(
                                "SELECT seq, indexes_json FROM event_log_events WHERE tenant = ?1",
                            )
                            .map_err(sqlite_store_error)?;
                        let rows = statement
                            .query_map(params![tenant], |row| {
                                Ok((row.get::<_, i64>(0)? as u64, row.get::<_, String>(1)?))
                            })
                            .map_err(sqlite_store_error)?;
                        for row in rows {
                            let (seq, indexes_json) = row.map_err(sqlite_store_error)?;
                            let indexes: KeyValues =
                                serde_json::from_str(&indexes_json).map_err(json_store_error)?;
                            let keep = indexes
                                .get("messageTimestamp")
                                .and_then(|value| match value {
                                    Value::String(message_timestamp) => {
                                        Some(message_timestamp.as_str())
                                    }
                                    _ => None,
                                })
                                .is_none_or(|message_timestamp| {
                                    message_timestamp >= timestamp.as_str()
                                });
                            if !keep {
                                tx.execute(
                                    "DELETE FROM event_log_events WHERE tenant = ?1 AND seq = ?2",
                                    params![tenant, seq as i64],
                                )
                                .map_err(sqlite_store_error)?;
                            }
                        }
                    }
                }
                tx.commit().map_err(sqlite_store_error)?;

                Ok(())
            })
            .await
    }
}

impl EventLog for SqliteEventLog {
    async fn open(&mut self) -> Result<(), EventLogError> {
        let epoch = self.load_epoch().await.map_err(EventLogError::from)?;
        self.inner = MemoryEventLog::with_epoch(epoch.clone());
        self.inner.open().await?;
        self.load_events().await.map_err(EventLogError::from)?;
        self.persist_epoch(&epoch)
            .await
            .map_err(EventLogError::from)?;
        Ok(())
    }

    async fn close(&mut self) -> () {
        self.inner.close().await;
    }

    async fn emit(
        &self,
        tenant: &str,
        event: MessageEvent<Descriptor>,
        indexes: KeyValues,
        message_cid: &str,
    ) -> Result<Option<ProgressToken>, EventLogError> {
        let tenant = tenant.to_string();
        let message_cid = message_cid.to_string();
        let token = self
            .inner
            .emit(&tenant, event.clone(), indexes.clone(), &message_cid)
            .await?;
        if let Some(token) = &token {
            let seq = token.position.parse::<u64>().map_err(|_| {
                EventLogError::StoreError(StoreError::InternalException(
                    "invalid event log sequence".to_string(),
                ))
            })?;
            self.persist_emit(&tenant, seq, &event, &indexes, &message_cid)
                .await
                .map_err(EventLogError::from)?;
        }
        Ok(token)
    }

    async fn read(
        &self,
        tenant: &str,
        options: Option<EventLogReadOptions>,
    ) -> Result<EventLogReadResult, EventLogError> {
        self.inner.read(tenant, options).await
    }

    async fn subscribe(
        &self,
        tenant: &str,
        id: &str,
        listener: SubscriptionListener,
        options: Option<EventLogSubscribeOptions>,
    ) -> Result<EventSubscription, EventLogError> {
        self.inner.subscribe(tenant, id, listener, options).await
    }

    async fn get_replay_bounds(
        &self,
        tenant: &str,
    ) -> Result<Option<EventLogReplayBounds>, EventLogError> {
        self.inner.get_replay_bounds(tenant).await
    }

    async fn trim(&self, tenant: &str, older_than: EventLogTrimBound) -> Result<(), EventLogError> {
        let tenant = tenant.to_string();
        self.inner.trim(&tenant, older_than.clone()).await?;
        self.persist_trim(&tenant, &older_than)
            .await
            .map_err(EventLogError::from)
    }
}
