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
//! The capability belongs to the resumable task manager rather than to a
//! wrapper around it: a repair obligation *is* a task, and the manager is what
//! makes tasks durable.
//!
//! Scoped to control records. Repairing ordinary application records against
//! configuration changes is separate work.

use std::future::Future;
use std::pin::Pin;

use crate::tasks::controller::ResumableControlRepairData;
use crate::tasks::manager::{ResumableTask, ResumableTaskManager, ResumableTaskName};

use super::configure::{ControlRepairer, EnlistedRepair};

impl<MessageStore, DataStore, TaskStore> ControlRepairer
    for ResumableTaskManager<MessageStore, DataStore, TaskStore>
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
            let task = ResumableTask {
                name: ResumableTaskName::ControlRepair,
                data: serde_json::to_value(ResumableControlRepairData {
                    tenant: tenant.to_string(),
                    protocol: protocol.to_string(),
                })
                .map_err(|error| error.to_string())?,
            };
            ResumableTaskManager::enlist(self, task)
                .await
                .map(EnlistedRepair)
                .map_err(|error| error.to_string())
        })
    }

    fn fulfil<'a>(
        &'a self,
        enlisted: EnlistedRepair,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            ResumableTaskManager::fulfil(self, enlisted.0)
                .await
                .map_err(|error| error.to_string())
        })
    }
}
