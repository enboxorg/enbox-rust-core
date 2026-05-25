//! Storage orchestration for resumable RecordsDelete and RecordsSquash tasks.
//!
//! Mirrors TypeScript `StorageController` from `@enbox/dwn-sdk-js`.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::handlers::records::{resume_records_delete_from_task, resume_records_squash_from_task};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumableRecordsDeleteData {
    pub tenant: String,
    pub message: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumableRecordsSquashData {
    pub tenant: String,
    pub message: JsonValue,
}

#[derive(Clone)]
pub struct StorageController<MessageStore, DataStore, StateIndex> {
    message_store: MessageStore,
    data_store: DataStore,
    state_index: StateIndex,
}

impl<MessageStore, DataStore, StateIndex> StorageController<MessageStore, DataStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    pub fn new(
        message_store: MessageStore,
        data_store: DataStore,
        state_index: StateIndex,
    ) -> Self {
        Self {
            message_store,
            data_store,
            state_index,
        }
    }

    pub async fn perform_records_delete(
        &self,
        data: ResumableRecordsDeleteData,
    ) -> Result<(), String> {
        resume_records_delete_from_task(
            &self.message_store,
            &self.data_store,
            &self.state_index,
            &data.tenant,
            &data.message,
        )
        .await
    }

    pub async fn perform_records_squash(
        &self,
        data: ResumableRecordsSquashData,
    ) -> Result<(), String> {
        resume_records_squash_from_task(
            &self.message_store,
            &self.data_store,
            &self.state_index,
            &data.tenant,
            &data.message,
        )
        .await
    }
}
