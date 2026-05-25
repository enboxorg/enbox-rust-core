//! Durable SQLite backends for [`StateIndex`], [`EventLog`], and
//! [`ResumableTaskStore`].

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;

use rusqlite::{params, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value as JsonValue;

use dwn_rs_core::errors::{EventLogError, ResumableTaskStoreError, StoreError};
use dwn_rs_core::events::MessageEvent;
use dwn_rs_core::local::{MemoryEventLog, MemoryResumableTaskStore};
use dwn_rs_core::state_index::MemoryStateIndex;
use dwn_rs_core::stores::{
    EventLog, EventLogReadOptions, EventLogReadResult, EventLogReplayBounds,
    EventLogSubscribeOptions, EventLogTrimBound, EventSubscription, KeyValues,
    ManagedResumableTask, ProgressToken, ResumableTaskStore, StateHash, StateIndex,
    SubscriptionListener,
};
use dwn_rs_core::{Descriptor, Value};

use crate::sqlite::{json_store_error, sqlite_store_error, SqliteConnection, SqliteStore};

/// SQLite-backed [`StateIndex`] that persists sparse-merkle-tree entries.
#[derive(Debug, Clone)]
pub struct SqliteStateIndex {
    inner: MemoryStateIndex,
    connection: SqliteConnection,
}

impl Default for SqliteStateIndex {
    fn default() -> Self {
        Self::new(&SqliteStore::in_memory())
    }
}

impl SqliteStateIndex {
    pub fn new(store: &SqliteStore) -> Self {
        Self {
            inner: MemoryStateIndex::default(),
            connection: store.shared_connection(),
        }
    }

    fn load_entries(&self) -> Result<Vec<(String, String, KeyValues)>, StoreError> {
        self.connection.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT tenant, message_cid, indexes_json \
                     FROM state_index_entries",
                )
                .map_err(sqlite_store_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(sqlite_store_error)?;

            let mut entries = Vec::new();
            for row in rows {
                let (tenant, message_cid, indexes_json) = row.map_err(sqlite_store_error)?;
                let indexes: KeyValues =
                    serde_json::from_str(&indexes_json).map_err(json_store_error)?;
                entries.push((tenant, message_cid, indexes));
            }
            Ok(entries)
        })
    }

    fn persist_insert(
        &self,
        tenant: &str,
        message_cid: &str,
        indexes: &KeyValues,
    ) -> Result<(), StoreError> {
        let protocol = match indexes.get("protocol") {
            Some(Value::String(protocol)) => Some(protocol.clone()),
            _ => None,
        };
        let indexes_json = serde_json::to_string(indexes).map_err(json_store_error)?;
        self.connection.with_connection(|connection| {
            connection
                .execute(
                    "INSERT OR REPLACE INTO state_index_entries \
                     (tenant, message_cid, protocol, indexes_json) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![tenant, message_cid, protocol, indexes_json],
                )
                .map_err(sqlite_store_error)?;
            Ok(())
        })
    }

    fn persist_delete(&self, tenant: &str, message_cids: &[String]) -> Result<(), StoreError> {
        self.connection.with_connection(|connection| {
            for message_cid in message_cids {
                connection
                    .execute(
                        "DELETE FROM state_index_entries \
                         WHERE tenant = ?1 AND message_cid = ?2",
                        params![tenant, message_cid],
                    )
                    .map_err(sqlite_store_error)?;
            }
            Ok(())
        })
    }

    fn persist_clear(&self) -> Result<(), StoreError> {
        self.connection.with_connection(|connection| {
            connection
                .execute("DELETE FROM state_index_entries", [])
                .map_err(sqlite_store_error)?;
            Ok(())
        })
    }
}

impl StateIndex for SqliteStateIndex {
    async fn open(&mut self) -> Result<(), StoreError> {
        self.connection.open()?;
        self.inner.clear().await?;
        for (tenant, message_cid, indexes) in self.load_entries()? {
            self.inner.insert(&tenant, &message_cid, indexes).await?;
        }
        Ok(())
    }

    async fn close(&mut self) {
        self.connection.close();
    }

    fn clear(&self) -> impl Future<Output = Result<(), StoreError>> + Send {
        let inner = self.inner.clone();
        let store = self.clone();
        async move {
            inner.clear().await?;
            store.persist_clear()
        }
    }

    fn insert(
        &self,
        tenant: &str,
        message_cid: &str,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let inner = self.inner.clone();
        let store = self.clone();
        let tenant = tenant.to_string();
        let message_cid = message_cid.to_string();
        async move {
            inner.insert(&tenant, &message_cid, indexes.clone()).await?;
            store.persist_insert(&tenant, &message_cid, &indexes)
        }
    }

    fn delete(
        &self,
        tenant: &str,
        message_cids: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let inner = self.inner.clone();
        let store = self.clone();
        let tenant = tenant.to_string();
        let message_cids = message_cids.to_vec();
        async move {
            inner.delete(&tenant, &message_cids).await?;
            store.persist_delete(&tenant, &message_cids)
        }
    }

    fn get_root(&self, tenant: &str) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        self.inner.get_root(tenant)
    }

    fn get_protocol_root(
        &self,
        tenant: &str,
        protocol: &str,
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        self.inner.get_protocol_root(tenant, protocol)
    }

    fn get_subtree_hash(
        &self,
        tenant: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        self.inner.get_subtree_hash(tenant, prefix)
    }

    fn get_protocol_subtree_hash(
        &self,
        tenant: &str,
        protocol: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        self.inner
            .get_protocol_subtree_hash(tenant, protocol, prefix)
    }

    fn get_leaves(
        &self,
        tenant: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send {
        self.inner.get_leaves(tenant, prefix)
    }

    fn get_protocol_leaves(
        &self,
        tenant: &str,
        protocol: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send {
        self.inner.get_protocol_leaves(tenant, protocol, prefix)
    }
}

/// SQLite-backed [`EventLog`] with in-memory subscriptions and durable events.
#[derive(Clone)]
pub struct SqliteEventLog {
    inner: MemoryEventLog,
    connection: SqliteConnection,
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
            connection: store.shared_connection(),
        }
    }

    fn load_epoch(&self) -> Result<String, StoreError> {
        self.connection.with_connection(|connection| {
            let epoch = connection
                .query_row("SELECT epoch FROM event_log_meta WHERE id = 1", [], |row| {
                    row.get::<_, String>(0)
                })
                .optional()
                .map_err(sqlite_store_error)?;
            Ok(epoch.unwrap_or_else(|| ulid::Ulid::new().to_string()))
        })
    }

    fn persist_epoch(&self, epoch: &str) -> Result<(), StoreError> {
        self.connection.with_connection(|connection| {
            connection
                .execute(
                    "INSERT OR REPLACE INTO event_log_meta (id, epoch) VALUES (1, ?1)",
                    params![epoch],
                )
                .map_err(sqlite_store_error)?;
            Ok(())
        })
    }

    fn load_events(&self) -> Result<(), StoreError> {
        let mut tenant_seqs = BTreeMap::<String, u64>::new();
        let mut events_by_tenant =
            BTreeMap::<String, Vec<(u64, MessageEvent<Descriptor>, KeyValues, String)>>::new();

        self.connection.with_connection(|connection| {
            let mut seq_statement = connection
                .prepare("SELECT tenant, next_seq FROM event_log_tenant_seq")
                .map_err(sqlite_store_error)?;
            let seq_rows = seq_statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
                })
                .map_err(sqlite_store_error)?;
            for row in seq_rows {
                let (tenant, next_seq) = row.map_err(sqlite_store_error)?;
                tenant_seqs.insert(tenant, next_seq);
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
                        row.get::<_, u64>(1)?,
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
                    seq,
                    event,
                    indexes,
                    message_cid,
                ));
            }
            Ok(())
        })?;

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

    fn persist_emit(
        &self,
        tenant: &str,
        seq: u64,
        event: &MessageEvent<Descriptor>,
        indexes: &KeyValues,
        message_cid: &str,
    ) -> Result<(), StoreError> {
        let event_json = serde_json::to_string(event).map_err(json_store_error)?;
        let indexes_json = serde_json::to_string(indexes).map_err(json_store_error)?;
        self.connection.with_connection(|connection| {
            connection
                .execute(
                    "INSERT OR REPLACE INTO event_log_events \
                     (tenant, seq, event_json, indexes_json, message_cid) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![tenant, seq, event_json, indexes_json, message_cid],
                )
                .map_err(sqlite_store_error)?;
            connection
                .execute(
                    "INSERT OR REPLACE INTO event_log_tenant_seq (tenant, next_seq) \
                     VALUES (?1, ?2)",
                    params![tenant, seq],
                )
                .map_err(sqlite_store_error)?;
            Ok(())
        })
    }

    fn persist_trim(&self, tenant: &str, older_than: &EventLogTrimBound) -> Result<(), StoreError> {
        self.connection
            .with_connection(|connection| match older_than {
                EventLogTrimBound::Sequence(sequence) => {
                    connection
                        .execute(
                            "DELETE FROM event_log_events WHERE tenant = ?1 AND seq < ?2",
                            params![tenant, *sequence],
                        )
                        .map_err(sqlite_store_error)?;
                    Ok(())
                }
                EventLogTrimBound::Timestamp(timestamp) => {
                    let mut statement = connection
                        .prepare("SELECT seq, indexes_json FROM event_log_events WHERE tenant = ?1")
                        .map_err(sqlite_store_error)?;
                    let rows = statement
                        .query_map(params![tenant], |row| {
                            Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
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
                            connection
                                .execute(
                                    "DELETE FROM event_log_events WHERE tenant = ?1 AND seq = ?2",
                                    params![tenant, seq],
                                )
                                .map_err(sqlite_store_error)?;
                        }
                    }
                    Ok(())
                }
            })
    }
}

impl EventLog for SqliteEventLog {
    async fn open(&mut self) -> Result<(), EventLogError> {
        self.connection.open().map_err(EventLogError::from)?;
        let epoch = self.load_epoch().map_err(EventLogError::from)?;
        self.inner = MemoryEventLog::with_epoch(epoch.clone());
        self.inner.open().await?;
        self.load_events().map_err(EventLogError::from)?;
        self.persist_epoch(&epoch).map_err(EventLogError::from)?;
        Ok(())
    }

    fn close(&mut self) -> impl Future<Output = ()> + Send {
        let mut store = self.clone();
        async move {
            store.inner.close().await;
            store.connection.close();
        }
    }

    fn emit(
        &self,
        tenant: &str,
        event: MessageEvent<Descriptor>,
        indexes: KeyValues,
        message_cid: &str,
    ) -> impl Future<Output = Result<Option<ProgressToken>, EventLogError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        let message_cid = message_cid.to_string();
        async move {
            let token = store
                .inner
                .emit(&tenant, event.clone(), indexes.clone(), &message_cid)
                .await?;
            if let Some(token) = &token {
                let seq = token.position.parse::<u64>().map_err(|_| {
                    EventLogError::StoreError(StoreError::InternalException(
                        "invalid event log sequence".to_string(),
                    ))
                })?;
                store
                    .persist_emit(&tenant, seq, &event, &indexes, &message_cid)
                    .map_err(EventLogError::from)?;
            }
            Ok(token)
        }
    }

    fn read(
        &self,
        tenant: &str,
        options: Option<EventLogReadOptions>,
    ) -> impl Future<Output = Result<EventLogReadResult, EventLogError>> + Send {
        self.inner.read(tenant, options)
    }

    fn subscribe(
        &self,
        tenant: &str,
        id: &str,
        listener: SubscriptionListener,
        options: Option<EventLogSubscribeOptions>,
    ) -> impl Future<Output = Result<EventSubscription, EventLogError>> + Send {
        self.inner.subscribe(tenant, id, listener, options)
    }

    fn get_replay_bounds(
        &self,
        tenant: &str,
    ) -> impl Future<Output = Result<Option<EventLogReplayBounds>, EventLogError>> + Send {
        self.inner.get_replay_bounds(tenant)
    }

    fn trim(
        &self,
        tenant: &str,
        older_than: EventLogTrimBound,
    ) -> impl Future<Output = Result<(), EventLogError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        async move {
            store.inner.trim(&tenant, older_than.clone()).await?;
            store
                .persist_trim(&tenant, &older_than)
                .map_err(EventLogError::from)
        }
    }
}

/// SQLite-backed [`ResumableTaskStore`].
#[derive(Debug, Clone)]
pub struct SqliteResumableTaskStore {
    inner: MemoryResumableTaskStore,
    connection: SqliteConnection,
}

impl Default for SqliteResumableTaskStore {
    fn default() -> Self {
        Self::new(&SqliteStore::in_memory())
    }
}

impl SqliteResumableTaskStore {
    pub fn new(store: &SqliteStore) -> Self {
        Self {
            inner: MemoryResumableTaskStore::default(),
            connection: store.shared_connection(),
        }
    }

    fn load(&self) -> Result<(), ResumableTaskStoreError> {
        self.connection
            .with_connection(|connection| {
                let mut statement = connection
                    .prepare("SELECT id, task_json, timeout_ms, retry_count FROM resumable_tasks")
                    .map_err(sqlite_store_error)?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, u64>(2)?,
                            row.get::<_, u64>(3)?,
                        ))
                    })
                    .map_err(sqlite_store_error)?;

                for row in rows {
                    let (id, task_json, timeout, retry_count) = row.map_err(sqlite_store_error)?;
                    let task: JsonValue =
                        serde_json::from_str(&task_json).map_err(json_store_error)?;
                    self.inner
                        .restore(id, task, timeout, retry_count)
                        .map_err(|err| {
                            StoreError::InternalException(format!(
                                "failed to restore resumable task: {err}"
                            ))
                        })?;
                }
                Ok(())
            })
            .map_err(ResumableTaskStoreError::from)
    }

    fn persist_task(
        &self,
        id: &str,
        task: &JsonValue,
        timeout: u64,
        retry_count: u64,
    ) -> Result<(), ResumableTaskStoreError> {
        let task_json = serde_json::to_string(task).map_err(json_store_error)?;
        self.connection
            .with_connection(|connection| {
                connection
                    .execute(
                        "INSERT OR REPLACE INTO resumable_tasks \
                         (id, task_json, timeout_ms, retry_count) \
                         VALUES (?1, ?2, ?3, ?4)",
                        params![id, task_json, timeout, retry_count],
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .map_err(ResumableTaskStoreError::from)
    }

    fn delete_task(&self, task_id: &str) -> Result<(), ResumableTaskStoreError> {
        self.connection
            .with_connection(|connection| {
                connection
                    .execute(
                        "DELETE FROM resumable_tasks WHERE id = ?1",
                        params![task_id],
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .map_err(ResumableTaskStoreError::from)
    }

    fn clear_tasks(&self) -> Result<(), ResumableTaskStoreError> {
        self.connection
            .with_connection(|connection| {
                connection
                    .execute("DELETE FROM resumable_tasks", [])
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .map_err(ResumableTaskStoreError::from)
    }
}

impl ResumableTaskStore for SqliteResumableTaskStore {
    async fn open(&mut self) -> Result<(), ResumableTaskStoreError> {
        self.connection
            .open()
            .map_err(ResumableTaskStoreError::from)?;
        self.load()
    }

    async fn close(&mut self) {
        self.connection.close();
    }

    fn register<T: Serialize + Send + Sync + DeserializeOwned + Debug + 'static>(
        &self,
        task: T,
        timeout_in_seconds: u64,
    ) -> impl Future<Output = Result<ManagedResumableTask<T>, ResumableTaskStoreError>> + Send {
        let store = self.clone();
        async move {
            let managed = store.inner.register(task, timeout_in_seconds).await?;
            store.persist_task(
                &managed.id,
                &serde_json::to_value(&managed.task).map_err(json_store_error)?,
                managed.timeout,
                managed.retry_count,
            )?;
            Ok(managed)
        }
    }

    fn grab<T: Serialize + Send + Sync + DeserializeOwned + Debug + Unpin>(
        &self,
        count: u64,
    ) -> impl Future<Output = Result<Vec<ManagedResumableTask<T>>, ResumableTaskStoreError>> + Send
    {
        let store = self.clone();
        async move {
            let grabbed = store.inner.grab::<T>(count).await?;
            for task in &grabbed {
                store.persist_task(
                    &task.id,
                    &serde_json::to_value(&task.task).map_err(json_store_error)?,
                    task.timeout,
                    task.retry_count,
                )?;
            }
            Ok(grabbed)
        }
    }

    fn read<T: Serialize + Send + Sync + DeserializeOwned + Debug>(
        &self,
        task_id: &str,
    ) -> impl Future<Output = Result<Option<ManagedResumableTask<T>>, ResumableTaskStoreError>> + Send
    {
        self.inner.read(task_id)
    }

    fn extend(
        &self,
        task_id: &str,
        timeout_in_seconds: u64,
    ) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send {
        let store = self.clone();
        let task_id = task_id.to_string();
        async move {
            store.inner.extend(&task_id, timeout_in_seconds).await?;
            if let Some(task) = store.inner.read::<JsonValue>(&task_id).await? {
                store.persist_task(
                    &task.id,
                    &serde_json::to_value(&task.task).map_err(json_store_error)?,
                    task.timeout,
                    task.retry_count,
                )?;
            }
            Ok(())
        }
    }

    fn delete(
        &self,
        task_id: &str,
    ) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send {
        let store = self.clone();
        let task_id = task_id.to_string();
        async move {
            store.inner.delete(&task_id).await?;
            store.delete_task(&task_id)
        }
    }

    fn clear(&self) -> impl Future<Output = Result<(), ResumableTaskStoreError>> + Send {
        let store = self.clone();
        async move {
            store.inner.clear().await?;
            store.clear_tasks()
        }
    }
}
