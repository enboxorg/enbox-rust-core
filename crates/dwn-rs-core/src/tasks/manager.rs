//! Resumable background task orchestration for long-running store mutations.
//!
//! Mirrors TypeScript `ResumableTaskManager` from `@enbox/dwn-sdk-js`.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::errors::ResumableTaskStoreError;
use crate::stores::{ManagedResumableTask, ResumableTaskStore};
use crate::tasks::controller::{
    ResumableRecordsDeleteData, ResumableRecordsSquashData, StorageController,
};

pub const TIMEOUT_EXTENSION_FREQUENCY_SECONDS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ResumableTaskName {
    RecordsDelete,
    RecordsSquash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumableTask {
    pub name: ResumableTaskName,
    pub data: JsonValue,
}

#[derive(Clone)]
pub struct ResumableTaskManager<MessageStore, DataStore, StateIndex, TaskStore> {
    task_store: TaskStore,
    storage_controller: StorageController<MessageStore, DataStore, StateIndex>,
    batch_size: u64,
}

impl<MessageStore, DataStore, StateIndex, TaskStore>
    ResumableTaskManager<MessageStore, DataStore, StateIndex, TaskStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
    TaskStore: ResumableTaskStore + Clone + Send + Sync + 'static,
{
    pub fn new(
        task_store: TaskStore,
        storage_controller: StorageController<MessageStore, DataStore, StateIndex>,
    ) -> Self {
        Self {
            task_store,
            storage_controller,
            batch_size: 100,
        }
    }

    pub async fn run(&self, task: ResumableTask) -> Result<(), ResumableTaskStoreError> {
        let timeout_in_seconds = TIMEOUT_EXTENSION_FREQUENCY_SECONDS * 2;
        let managed = self.task_store.register(task, timeout_in_seconds).await?;
        self.run_with_automatic_timeout_extension(managed).await
    }

    pub async fn resume_tasks_and_wait_for_completion(
        &self,
    ) -> Result<(), ResumableTaskStoreError> {
        loop {
            let tasks = self
                .task_store
                .grab::<ResumableTask>(self.batch_size)
                .await?;
            if tasks.is_empty() {
                break;
            }
            self.retry_tasks_until_completion(tasks).await?;
        }
        Ok(())
    }

    async fn retry_tasks_until_completion(
        &self,
        mut tasks: Vec<ManagedResumableTask<ResumableTask>>,
    ) -> Result<(), ResumableTaskStoreError> {
        while !tasks.is_empty() {
            let batch = tasks;
            tasks = Vec::new();
            for managed in batch {
                if let Err(error) = self
                    .run_with_automatic_timeout_extension(managed.clone())
                    .await
                {
                    tracing::error!(?error, task = ?managed, "resumable task failed");
                    tasks.push(managed);
                }
            }
        }
        Ok(())
    }

    async fn run_with_automatic_timeout_extension(
        &self,
        managed: ManagedResumableTask<ResumableTask>,
    ) -> Result<(), ResumableTaskStoreError> {
        let timeout_in_seconds = TIMEOUT_EXTENSION_FREQUENCY_SECONDS * 2;
        let task_store = self.task_store.clone();
        let task_id = managed.id.clone();
        let extension = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(TIMEOUT_EXTENSION_FREQUENCY_SECONDS));
            loop {
                interval.tick().await;
                let _ = task_store.extend(&task_id, timeout_in_seconds).await;
            }
        });
        let abort_handle = extension.abort_handle();

        let result = self.dispatch_task(&managed.task).await;
        abort_handle.abort();
        let _ = extension.await;

        result?;
        self.task_store.delete(&managed.id).await
    }

    async fn dispatch_task(&self, task: &ResumableTask) -> Result<(), ResumableTaskStoreError> {
        match task.name {
            ResumableTaskName::RecordsDelete => {
                let data: ResumableRecordsDeleteData = serde_json::from_value(task.data.clone())
                    .map_err(|err| {
                        ResumableTaskStoreError::StoreError(
                            crate::errors::StoreError::InternalException(err.to_string()),
                        )
                    })?;
                self.storage_controller
                    .perform_records_delete(data)
                    .await
                    .map_err(|detail| {
                        ResumableTaskStoreError::StoreError(
                            crate::errors::StoreError::InternalException(detail),
                        )
                    })
            }
            ResumableTaskName::RecordsSquash => {
                let data: ResumableRecordsSquashData = serde_json::from_value(task.data.clone())
                    .map_err(|err| {
                        ResumableTaskStoreError::StoreError(
                            crate::errors::StoreError::InternalException(err.to_string()),
                        )
                    })?;
                self.storage_controller
                    .perform_records_squash(data)
                    .await
                    .map_err(|detail| {
                        ResumableTaskStoreError::StoreError(
                            crate::errors::StoreError::InternalException(detail),
                        )
                    })
            }
        }
    }
}
