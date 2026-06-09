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
use dwn_rs_core::stores::{
    EventLog, EventLogReadOptions, EventLogReadResult, EventLogReplayBounds,
    EventLogSubscribeOptions, EventLogTrimBound, EventSubscription, KeyValues,
    ManagedResumableTask, ProgressToken, ResumableTaskStore, StateHash, StateIndex,
    SubscriptionListener,
};
use dwn_rs_core::{Descriptor, Value};

use crate::sqlite::{json_store_error, sqlite_store_error, SqliteConnection, SqliteStore};

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
