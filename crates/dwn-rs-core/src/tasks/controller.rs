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
    message_cid, newest_message, purge_record_descendants, records_delete_descriptor,
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

/// A control record whose removal has been decided but may not yet have
/// finished.
///
/// Names the record rather than its messages, because the store is the
/// authority on what is still retained: a resume removes what is actually
/// there, not what was there when the task was written.
///
/// Data is the exception and is captured before the task is registered. Which
/// data belonged to a record is only knowable from its messages, and removing
/// those is precisely what this task does — so a resume arriving after message
/// removal would have nothing left to tell it what to reclaim, and the bytes
/// would be orphaned for good.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumableControlPurgeData {
    pub tenant: String,
    pub record_id: String,
    pub data_cids: Vec<String>,
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

    /// Removes every retained message of a control record, then its data.
    ///
    /// Runs as a resumable task rather than inline because a purge is several
    /// store mutations with no single point of no return: the task records the
    /// intent before the first removal and is discharged only after the last,
    /// so a crash between them is finished on the next resume rather than lost.
    /// Every step is idempotent, so replaying a partly-finished purge completes
    /// it instead of failing on what is already gone.
    ///
    /// Ordering follows ADR 0004 — messages first, data second. Failing after
    /// the messages are gone orphans bytes nothing references, which a later
    /// pass reclaims from the task; the reverse would leave a live message
    /// whose data had already been destroyed, which nothing can undo.
    ///
    /// Deciding *which* records deserve this belongs to configuration repair.
    /// Nothing here judges a record.
    pub async fn perform_control_purge(
        &self,
        data: ResumableControlPurgeData,
    ) -> Result<(), String> {
        let tenant = data.tenant.as_str();
        for message in fetch_record_messages(tenant, &data.record_id, &self.message_store).await? {
            let cid = message_cid(&message)?;
            self.message_store
                .delete(tenant, &cid)
                .await
                .map_err(|err| err.to_string())?;
        }

        for data_cid in &data.data_cids {
            self.data_store
                .delete(tenant, &data.record_id, data_cid)
                .await
                .map_err(|err| err.to_string())?;
        }
        Ok(())
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
