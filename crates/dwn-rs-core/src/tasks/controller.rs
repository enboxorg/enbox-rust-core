//! Storage orchestration for resumable tasks.
//!
//! Mirrors TypeScript `StorageController` from `@enbox/dwn-sdk-js`.
//!
//! Every long-running store mutation a task can resume lives here as a method
//! rather than a free function reached through a forwarding layer: the
//! controller already owns the two stores each one needs, so holding them as
//! parameters bought nothing, and grouping them makes the set of resumable
//! storage operations something you can read in one place.

use serde::{Deserialize, Serialize};

use crate::descriptors::records::records_write_descriptor;
use crate::handlers::records::common::{
    delete_from_data_store_if_needed, extract_author, fetch_record_messages, find_initial_write,
    newest_message, purge_record_descendants, records_delete_descriptor,
};
use crate::handlers::records::delete::{perform_records_delete, RecordsDeleteExecution};
use crate::handlers::records::state::{plan_records_transition, RecordsTransitionPlan};
use crate::handlers::records::write::perform_records_squash;
use crate::{Descriptor, Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumableRecordsDeleteData {
    pub tenant: String,
    pub message: Message<Descriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumableRecordsSquashData {
    pub tenant: String,
    pub message: Message<Descriptor>,
}

#[derive(Clone)]
pub struct StorageController<MessageStore, DataStore> {
    message_store: MessageStore,
    data_store: DataStore,
}

impl<MessageStore, DataStore> StorageController<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    pub fn new(message_store: MessageStore, data_store: DataStore) -> Self {
        Self {
            message_store,
            data_store,
        }
    }

    /// Finishes a delete that was registered but may not have completed.
    ///
    /// Re-plans against what is actually retained rather than trusting the
    /// state the task was written in: by the time a resume runs, the delete may
    /// have been superseded, already applied, or had its record change beneath
    /// it, and each of those means the work is done rather than owed.
    pub async fn perform_records_delete(
        &self,
        data: ResumableRecordsDeleteData,
    ) -> Result<(), String> {
        let message_store = &self.message_store;
        let data_store = &self.data_store;
        let tenant = data.tenant.as_str();
        let message = &data.message;

        let descriptor = records_delete_descriptor(message)?;
        let existing_messages =
            fetch_record_messages(tenant, &descriptor.record_id, message_store).await?;
        let Some(newest_existing) = newest_message(&existing_messages) else {
            return Ok(());
        };
        let plan = plan_records_transition(message, &existing_messages)?;
        if matches!(plan, RecordsTransitionPlan::Superseded { .. }) {
            return Ok(());
        }
        if matches!(plan, RecordsTransitionPlan::Duplicate { .. }) {
            if descriptor.prune {
                purge_record_descendants(tenant, &descriptor.record_id, message_store, data_store)
                    .await?;
            }
            for existing in &existing_messages {
                if records_write_descriptor(existing).is_ok() {
                    delete_from_data_store_if_needed(tenant, existing, message, data_store).await?;
                }
            }
            return Ok(());
        }
        let initial_write = find_initial_write(
            &existing_messages,
            extract_author(&newest_existing)
                .as_deref()
                .unwrap_or_default(),
        )
        .or_else(|| {
            existing_messages
                .iter()
                .find(|message| records_write_descriptor(message).is_ok())
                .cloned()
        })
        .ok_or_else(|| "RecordsDeleteAuthorizationFailed: initial write not found".to_string())?;
        perform_records_delete(
            message_store,
            data_store,
            tenant,
            RecordsDeleteExecution {
                message,
                existing_messages: &existing_messages,
                initial_write: &initial_write,
                plan: &plan,
            },
        )
        .await
    }

    pub async fn perform_records_squash(
        &self,
        data: ResumableRecordsSquashData,
    ) -> Result<(), String> {
        perform_records_squash(
            &self.message_store,
            &self.data_store,
            &data.tenant,
            &data.message,
        )
        .await
    }
}
