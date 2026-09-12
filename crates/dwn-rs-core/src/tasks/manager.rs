//! Resumable background task orchestration for long-running store mutations.
//!
//! Mirrors TypeScript `ResumableTaskManager` from `@enbox/dwn-sdk-js`.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::errors::{ResumableTaskStoreError, StoreError};
use crate::stores::{ManagedResumableTask, ResumableTaskStore};
use crate::tasks::controller::{
    ResumableControlPurgeData, ResumableControlRepairData, ResumableRecordsDeleteData,
    ResumableRecordsSquashData, StorageController,
};

pub const TIMEOUT_EXTENSION_FREQUENCY_SECONDS: u64 = 30;

/// Every failure a task can report reaches the store layer as one kind.
fn internal(detail: impl ToString) -> ResumableTaskStoreError {
    ResumableTaskStoreError::StoreError(StoreError::InternalException(detail.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ResumableTaskName {
    RecordsDelete,
    RecordsSquash,
    /// Re-examine one protocol's control records. Names the protocol, not its
    /// victims, so a resumed scan re-asks the question rather than replaying a
    /// list it may no longer be able to reproduce.
    ControlRepair,
    /// Remove one control record the scan condemned. Enlisted by the scan
    /// before the removal starts, because deleting a record's messages
    /// destroys the only account of which data belonged to it.
    ControlPurge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumableTask {
    pub name: ResumableTaskName,
    pub data: JsonValue,
}

#[derive(Clone)]
pub struct ResumableTaskManager<MessageStore, DataStore, TaskStore> {
    task_store: TaskStore,
    storage_controller: StorageController<MessageStore, DataStore>,
    batch_size: u64,
}

impl<MessageStore, DataStore, TaskStore> ResumableTaskManager<MessageStore, DataStore, TaskStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    TaskStore: ResumableTaskStore + Clone + Send + Sync + 'static,
{
    pub fn new(
        task_store: TaskStore,
        storage_controller: StorageController<MessageStore, DataStore>,
    ) -> Self {
        Self {
            task_store,
            storage_controller,
            batch_size: 100,
        }
    }

    pub async fn run(&self, task: ResumableTask) -> Result<(), ResumableTaskStoreError> {
        let managed = self.enlist(task).await?;
        self.fulfil(managed).await
    }

    /// Records the obligation to run `task` without running it yet.
    ///
    /// Splitting registration from execution is what lets a caller make the
    /// obligation durable *before* the state change it answers for. Registering
    /// afterwards leaves a window in which the change has landed and nothing
    /// remembers that it needs answering; registering first leaves only the
    /// harmless converse, a recorded obligation for a change that never
    /// happened, which resumes, finds nothing to do and retires.
    pub async fn enlist(
        &self,
        task: ResumableTask,
    ) -> Result<ManagedResumableTask<ResumableTask>, ResumableTaskStoreError> {
        let timeout_in_seconds = TIMEOUT_EXTENSION_FREQUENCY_SECONDS * 2;
        self.task_store.register(task, timeout_in_seconds).await
    }

    /// Runs an enlisted task, retiring it only once it succeeds.
    pub async fn fulfil(
        &self,
        managed: ManagedResumableTask<ResumableTask>,
    ) -> Result<(), ResumableTaskStoreError> {
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

    /// Attempts each grabbed task once, reporting the first failure.
    ///
    /// One attempt per pass, not retries until success. A task that cannot
    /// succeed yet — a repair whose store is unreachable, a purge against a
    /// data store that is down — would otherwise be retried in a tight loop
    /// forever, burning a core and never letting the node finish opening. A
    /// failed task is left enlisted rather than deleted, so the obligation is
    /// still there for the next pass or another node under a fresh lease.
    /// Losing the work is the thing that must not happen; finishing it *now*
    /// was never the promise.
    async fn retry_tasks_until_completion(
        &self,
        tasks: Vec<ManagedResumableTask<ResumableTask>>,
    ) -> Result<(), ResumableTaskStoreError> {
        let mut first_failure = None;
        for managed in tasks {
            if let Err(error) = self
                .run_with_automatic_timeout_extension(managed.clone())
                .await
            {
                tracing::error!(?error, task = ?managed, "resumable task failed");
                first_failure = first_failure.or(Some(error));
            }
        }
        match first_failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
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

    /// Runs one protocol's repair: judge, then remove each condemned record
    /// under its own durable intent.
    ///
    /// The child intent is what makes an interrupted removal recoverable. The
    /// scan cannot rediscover a half-finished one — it derives its victims from
    /// retained messages, and the first step of a removal is to delete those —
    /// so the data CIDs are enlisted before the removal starts and outlive it.
    /// Enlisting happens here rather than in the storage controller because
    /// this is the layer holding the task store.
    ///
    /// The scan's own obligation is discharged only once every child has
    /// finished, so a failure anywhere leaves the whole repair to be re-run.
    async fn repair_controls(
        &self,
        data: ResumableControlRepairData,
    ) -> Result<(), ResumableTaskStoreError> {
        for purge in self
            .storage_controller
            .control_records_to_purge(&data)
            .await
            .map_err(internal)?
        {
            // Enlisted, performed, retired — deliberately not routed back
            // through `run`, which would nest one task's execution inside
            // another's and recurse this future into itself.
            let managed = self
                .enlist(ResumableTask {
                    name: ResumableTaskName::ControlPurge,
                    data: serde_json::to_value(&purge).map_err(internal)?,
                })
                .await?;
            self.storage_controller
                .perform_control_purge(purge)
                .await
                .map_err(internal)?;
            self.task_store.delete(&managed.id).await?;
        }
        Ok(())
    }

    async fn dispatch_task(&self, task: &ResumableTask) -> Result<(), ResumableTaskStoreError> {
        match task.name {
            ResumableTaskName::RecordsDelete => {
                let data: ResumableRecordsDeleteData =
                    serde_json::from_value(task.data.clone()).map_err(internal)?;
                self.storage_controller
                    .perform_records_delete(data)
                    .await
                    .map_err(internal)
            }
            ResumableTaskName::ControlRepair => {
                let data: ResumableControlRepairData =
                    serde_json::from_value(task.data.clone()).map_err(internal)?;
                self.repair_controls(data).await
            }
            ResumableTaskName::ControlPurge => {
                let data: ResumableControlPurgeData =
                    serde_json::from_value(task.data.clone()).map_err(internal)?;
                self.storage_controller
                    .perform_control_purge(data)
                    .await
                    .map_err(internal)
            }
            ResumableTaskName::RecordsSquash => {
                let data: ResumableRecordsSquashData =
                    serde_json::from_value(task.data.clone()).map_err(internal)?;
                self.storage_controller
                    .perform_records_squash(data)
                    .await
                    .map_err(internal)
            }
        }
    }
}
