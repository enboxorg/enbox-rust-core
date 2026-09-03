//! Storage orchestration for resumable RecordsDelete and RecordsSquash tasks.
//!
//! Mirrors TypeScript `StorageController` from `@enbox/dwn-sdk-js`.

use serde::{Deserialize, Serialize};

use crate::{
    handlers::records::{resume_records_delete_from_task, resume_records_squash_from_task},
    Descriptor, Message,
};

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

    pub async fn perform_records_delete(
        &self,
        data: ResumableRecordsDeleteData,
    ) -> Result<(), String> {
        resume_records_delete_from_task(
            &self.message_store,
            &self.data_store,
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
            &data.tenant,
            &data.message,
        )
        .await
    }
}
