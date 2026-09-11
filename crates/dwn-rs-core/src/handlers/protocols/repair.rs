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

use crate::descriptors::messages::record_id;
use crate::descriptors::records::{is_initial_write, records_write_descriptor};
use crate::encryption::control::ControlKind;
use crate::filters::Filters;
use crate::handlers::records::common::{filter_map, string_filter};
use crate::handlers::records::control::{control_config_validity, ControlConfigValidity};
use crate::permissions::message_author;
use crate::tasks::controller::ResumableControlPurgeData;
use crate::tasks::manager::{ResumableTask, ResumableTaskManager, ResumableTaskName};
use crate::{Descriptor, Message};

use super::configure::ControlRepairer;

/// Repairs control records through the resumable task machinery, so a removal
/// interrupted partway is finished rather than lost.
#[derive(Clone)]
pub struct TaskControlRepairer<MessageStore, DataStore, TaskStore> {
    message_store: MessageStore,
    task_manager: ResumableTaskManager<MessageStore, DataStore, TaskStore>,
}

impl<MessageStore, DataStore, TaskStore> TaskControlRepairer<MessageStore, DataStore, TaskStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    TaskStore: crate::stores::ResumableTaskStore + Clone + Send + Sync + 'static,
{
    pub fn new(
        message_store: MessageStore,
        task_manager: ResumableTaskManager<MessageStore, DataStore, TaskStore>,
    ) -> Self {
        Self {
            message_store,
            task_manager,
        }
    }

    async fn repair_protocol(&self, tenant: &str, protocol: &str) -> Result<(), String> {
        for control in self.stored_control_initial_writes(tenant, protocol).await? {
            if control_config_validity(tenant, &control, &self.message_store).await
                != ControlConfigValidity::Invalid
            {
                continue;
            }
            let Some(record_id) = record_id(&control) else {
                continue;
            };

            // Read before the purge starts: removing the messages destroys the
            // only record of which data belonged here.
            let data_cids = vec![records_write_descriptor(&control)
                .map_err(|error| error.to_string())?
                .data_cid
                .clone()];

            self.task_manager
                .run(ResumableTask {
                    name: ResumableTaskName::ControlPurge,
                    data: serde_json::to_value(ResumableControlPurgeData {
                        tenant: tenant.to_string(),
                        record_id,
                        data_cids,
                    })
                    .map_err(|error| error.to_string())?,
                })
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// The control records this protocol holds, one entry per record.
    ///
    /// Only initial writes are examined. A control record is immutable, so its
    /// initial write is the whole record, and judging each retained message
    /// separately would ask the same question repeatedly of the same record.
    async fn stored_control_initial_writes(
        &self,
        tenant: &str,
        protocol: &str,
    ) -> Result<Vec<Message<Descriptor>>, String> {
        let mut found = Vec::new();
        for path in [
            ControlKind::Audience.protocol_path(),
            ControlKind::Delivery.protocol_path(),
        ] {
            let filter = filter_map([
                (
                    "interface",
                    string_filter(super::super::records::RECORDS_INTERFACE),
                ),
                ("method", string_filter(super::super::records::WRITE_METHOD)),
                ("protocol", string_filter(protocol)),
                ("protocolPath", string_filter(path)),
            ]);
            let result = self
                .message_store
                .query(tenant, Filters::from(filter), None, None, None)
                .await
                .map_err(|error| error.to_string())?;
            for message in result.messages {
                let author = message_author(&message).unwrap_or_default();
                if is_initial_write(&message, &author).unwrap_or(false) {
                    found.push(message);
                }
            }
        }
        Ok(found)
    }
}

impl<MessageStore, DataStore, TaskStore> ControlRepairer
    for TaskControlRepairer<MessageStore, DataStore, TaskStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    TaskStore: crate::stores::ResumableTaskStore + Clone + Send + Sync + 'static,
{
    fn repair<'a>(
        &'a self,
        tenant: &'a str,
        protocol: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(self.repair_protocol(tenant, protocol))
    }
}
