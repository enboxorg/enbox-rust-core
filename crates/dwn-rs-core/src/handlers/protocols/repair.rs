//! Re-examining stored control records when a configuration changes.
//!
//! Accepting a configuration can change what an already-stored record means.
//! A role may have been removed, or a historical configuration learned late may
//! reveal that a record sealed to the wrong key was never admissible. Records
//! that the configuration now contradicts are removed; everything else stays.
//!
//! The bias is deliberate and one-directional. A record wrongly kept can be
//! removed later, once whatever made it undecidable is resolved. A record
//! wrongly destroyed is custody material nobody can reconstruct — so anything
//! this pass cannot determine is kept, and only a contradiction the
//! configuration itself owns licenses removal.
//!
//! Scoped to control records. Repairing ordinary application records against
//! configuration changes is separate work.

use std::future::Future;
use std::pin::Pin;

use crate::stores::ManagedResumableTask;
use crate::tasks::controller::ResumableControlRepairData;
use crate::tasks::manager::{ResumableTask, ResumableTaskManager, ResumableTaskName};

use super::configure::{ControlRepairer, EnlistedRepair};

/// Repairs control records through the resumable task machinery, so a removal
/// interrupted partway is finished rather than lost.
#[derive(Clone)]
pub struct TaskControlRepairer<MessageStore, DataStore, TaskStore> {
    task_manager: ResumableTaskManager<MessageStore, DataStore, TaskStore>,
}

impl<MessageStore, DataStore, TaskStore> TaskControlRepairer<MessageStore, DataStore, TaskStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    TaskStore: crate::stores::ResumableTaskStore + Clone + Send + Sync + 'static,
{
    pub fn new(task_manager: ResumableTaskManager<MessageStore, DataStore, TaskStore>) -> Self {
        Self { task_manager }
    }

    async fn enlist_protocol_repair(
        &self,
        tenant: &str,
        protocol: &str,
    ) -> Result<ManagedResumableTask<ResumableTask>, String> {
        self.task_manager
            .enlist(ResumableTask {
                name: ResumableTaskName::ControlRepair,
                data: serde_json::to_value(ResumableControlRepairData {
                    tenant: tenant.to_string(),
                    protocol: protocol.to_string(),
                })
                .map_err(|error| error.to_string())?,
            })
            .await
            .map_err(|error| error.to_string())
    }
}

impl<MessageStore, DataStore, TaskStore> ControlRepairer
    for TaskControlRepairer<MessageStore, DataStore, TaskStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    TaskStore: crate::stores::ResumableTaskStore + Clone + Send + Sync + 'static,
{
    fn enlist<'a>(
        &'a self,
        tenant: &'a str,
        protocol: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<EnlistedRepair, String>> + Send + 'a>> {
        Box::pin(async move {
            self.enlist_protocol_repair(tenant, protocol)
                .await
                .map(EnlistedRepair)
        })
    }

    fn fulfil<'a>(
        &'a self,
        enlisted: EnlistedRepair,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.task_manager
                .fulfil(enlisted.0)
                .await
                .map_err(|error| error.to_string())
        })
    }
}
