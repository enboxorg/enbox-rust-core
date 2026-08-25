use std::{future::Future, pin::Pin, sync::Arc};

use crate::{
    descriptors::{
        messages::record_id, records::is_initial_write, Records, RecordsWriteDescriptor,
    },
    errors::{EventLogError, StoreError},
    permissions,
    stores::MessageStore,
    Descriptor, Filter, FilterKey, Filters, Message, Pagination, Value,
};

pub type InitialWriteFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<Option<Message<RecordsWriteDescriptor>>, EventLogError>>
            + Send
            + 'a,
    >,
>;

pub trait InitialWriteResolver: Send + Sync {
    fn resolve_initial_write<'a>(
        &'a self,
        tenant: &'a str,
        event: &'a Message<Descriptor>,
    ) -> InitialWriteFuture<'a>;
}

pub struct MessageStoreInitialWriteResolver<M> {
    store: Arc<M>,
}

impl<M> MessageStoreInitialWriteResolver<M>
where
    M: MessageStore + Send + Sync + 'static,
{
    pub fn new(store: Arc<M>) -> Self {
        Self { store }
    }
}

impl<M> InitialWriteResolver for MessageStoreInitialWriteResolver<M>
where
    M: MessageStore + Send + Sync + 'static,
{
    fn resolve_initial_write<'a>(
        &'a self,
        tenant: &'a str,
        event: &'a Message<Descriptor>,
    ) -> InitialWriteFuture<'a> {
        let store = self.store.clone();
        Box::pin(async move {
            let record_id = match &event.descriptor {
                Descriptor::Records(records) => match records.as_ref() {
                    Records::Write(_) => {
                        let author = permissions::message_author(event).ok_or_else(|| {
                            EventLogError::StoreError(StoreError::InternalException(
                                "RecordsWrite message missing author".to_string(),
                            ))
                        })?;

                        let initial_write = is_initial_write(event, &author).map_err(|e| {
                            EventLogError::StoreError(StoreError::InternalException(format!(
                                "Failed to determine if RecordsWrite is initial write: {e}"
                            )))
                        })?;
                        if initial_write {
                            return Ok(None);
                        }

                        record_id(event).ok_or_else(|| {
                            EventLogError::StoreError(StoreError::InternalException(
                                "RecordsWrite message missing recordId".to_string(),
                            ))
                        })?
                    }
                    Records::Delete(delete) => delete.record_id.clone(),
                    _ => return Ok(None),
                },
                _ => return Ok(None),
            };

            let filters = Filters::from([[(
                FilterKey::Index("entryId".to_string()),
                Filter::Equal(Value::String(record_id)),
            )]]);

            let result = store
                .query(tenant, filters, None, Some(Pagination::with_limit(1)))
                .await
                .map_err(|e| {
                    EventLogError::StoreError(StoreError::InternalException(format!(
                        "Failed to query for initial write: {e}"
                    )))
                })?;

            let Some(initial_write) = result.messages.into_iter().next() else {
                return Ok(None);
            };

            let initial_write: Message<RecordsWriteDescriptor> =
                initial_write.try_into().map_err(|e| {
                    EventLogError::StoreError(StoreError::InternalException(format!(
                        "Failed to convert message to RecordsWrite: {e}"
                    )))
                })?;

            Ok(Some(initial_write))
        })
    }
}
