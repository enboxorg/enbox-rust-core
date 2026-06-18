//! Durable SQLite backends for [`StateIndex`], [`EventLog`], and
//! [`ResumableTaskStore`].

use std::fmt::Debug;

use rusqlite::params;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value as JsonValue;

use dwn_rs_core::errors::{ResumableTaskStoreError, StoreError};
use dwn_rs_core::local::MemoryResumableTaskStore;
use dwn_rs_core::stores::{ManagedResumableTask, ResumableTaskStore};

use crate::sqlite::{json_store_error, sqlite_store_error, SqliteStore};

/// SQLite-backed [`ResumableTaskStore`].
#[derive(Debug, Clone)]
pub struct SqliteResumableTaskStore {
    inner: MemoryResumableTaskStore,
    store: SqliteStore,
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
            store: store.clone(),
        }
    }

    async fn load(&self) -> Result<(), ResumableTaskStoreError> {
        let inner = self.inner.clone();

        self.store
            .connection()
            .await?
            .with_reader(move |connection| {
                let mut statement = connection
                    .prepare("SELECT id, task_json, timeout_ms, retry_count FROM resumable_tasks")
                    .map_err(sqlite_store_error)?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)? as u64,
                            row.get::<_, i64>(3)? as u64,
                        ))
                    })
                    .map_err(sqlite_store_error)?;

                for row in rows {
                    let (id, task_json, timeout, retry_count) = row.map_err(sqlite_store_error)?;
                    let task: JsonValue =
                        serde_json::from_str(&task_json).map_err(json_store_error)?;
                    inner
                        .restore(id, task, timeout, retry_count)
                        .map_err(|err| {
                            StoreError::InternalException(format!(
                                "failed to restore resumable task: {err}"
                            ))
                        })?;
                }
                Ok(())
            })
            .await
            .map_err(ResumableTaskStoreError::from)
    }

    async fn persist_task(
        &self,
        id: &str,
        task: &JsonValue,
        timeout: u64,
        retry_count: u64,
    ) -> Result<(), ResumableTaskStoreError> {
        let task_json = serde_json::to_string(task).map_err(json_store_error)?;
        let id = id.to_string();

        self.store
            .connection()
            .await?
            .with_writer(move |connection| {
                connection
                    .execute(
                        "INSERT OR REPLACE INTO resumable_tasks \
                         (id, task_json, timeout_ms, retry_count) \
                         VALUES (?1, ?2, ?3, ?4)",
                        params![id, task_json, timeout as i64, retry_count as i64],
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .map_err(ResumableTaskStoreError::from)
    }

    async fn delete_task(&self, task_id: &str) -> Result<(), ResumableTaskStoreError> {
        let task_id = task_id.to_string();

        self.store
            .connection()
            .await?
            .with_writer(move |connection| {
                connection
                    .execute(
                        "DELETE FROM resumable_tasks WHERE id = ?1",
                        params![task_id],
                    )
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .map_err(ResumableTaskStoreError::from)
    }

    async fn clear_tasks(&self) -> Result<(), ResumableTaskStoreError> {
        self.store
            .connection()
            .await?
            .with_writer(|connection| {
                connection
                    .execute("DELETE FROM resumable_tasks", [])
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .map_err(ResumableTaskStoreError::from)
    }
}

impl ResumableTaskStore for SqliteResumableTaskStore {
    async fn open(&mut self) -> Result<(), ResumableTaskStoreError> {
        self.load().await
    }

    async fn close(&mut self) {
        self.inner.close().await;
    }

    async fn register<T: Serialize + Send + Sync + DeserializeOwned + Debug + 'static>(
        &self,
        task: T,
        timeout_in_seconds: u64,
    ) -> Result<ManagedResumableTask<T>, ResumableTaskStoreError> {
        let managed = self.inner.register(task, timeout_in_seconds).await?;
        self.persist_task(
            &managed.id,
            &serde_json::to_value(&managed.task).map_err(json_store_error)?,
            managed.timeout,
            managed.retry_count,
        )
        .await?;
        Ok(managed)
    }

    async fn grab<T: Serialize + Send + Sync + DeserializeOwned + Debug + Unpin>(
        &self,
        count: u64,
    ) -> Result<Vec<ManagedResumableTask<T>>, ResumableTaskStoreError> {
        let grabbed = self.inner.grab::<T>(count).await?;
        for task in &grabbed {
            self.persist_task(
                &task.id,
                &serde_json::to_value(&task.task).map_err(json_store_error)?,
                task.timeout,
                task.retry_count,
            )
            .await?;
        }
        Ok(grabbed)
    }

    async fn read<T: Serialize + Send + Sync + DeserializeOwned + Debug>(
        &self,
        task_id: &str,
    ) -> Result<Option<ManagedResumableTask<T>>, ResumableTaskStoreError> {
        self.inner.read(task_id).await
    }

    async fn extend(
        &self,
        task_id: &str,
        timeout_in_seconds: u64,
    ) -> Result<(), ResumableTaskStoreError> {
        let task_id = task_id.to_string();
        self.inner.extend(&task_id, timeout_in_seconds).await?;
        if let Some(task) = self.inner.read::<JsonValue>(&task_id).await? {
            self.persist_task(
                &task.id,
                &serde_json::to_value(&task.task).map_err(json_store_error)?,
                task.timeout,
                task.retry_count,
            )
            .await?;
        }
        Ok(())
    }

    async fn delete(&self, task_id: &str) -> Result<(), ResumableTaskStoreError> {
        self.inner.delete(task_id).await?;
        self.delete_task(task_id).await
    }

    async fn clear(&self) -> Result<(), ResumableTaskStoreError> {
        self.inner.clear().await?;
        self.clear_tasks().await
    }
}
