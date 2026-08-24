use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::TryStreamExt;
use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::descriptors::records::is_initial_write;
use crate::descriptors::{
    messages::record_id,
    records::{records_write_descriptor, write_fields},
    ReadDescriptor,
};
use crate::dwn::{Handler, HandlerContext};
use crate::filters::{FilterKey, Filters};
use crate::handlers::records::common::{
    authorize_records_read, bool_filter, date_sort_to_message_sort, extract_author,
    fetch_initial_write_message, fetch_newest_write, message_record_id, records_delete_descriptor,
    records_filter_to_filter_map, set_encoded_data, store_error_reply, string_filter,
};
use crate::permissions::{self};
use crate::replies::records::{Read, ReadEntry};
use crate::Response;
use crate::{replies, Pagination};

use super::RECORDS_INTERFACE;

#[derive(Clone)]
pub struct RecordsReadHandler<MessageStore, DataStore> {
    message_store: MessageStore,
    data_store: DataStore,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MessageStore, DataStore> Handler for RecordsReadHandler<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    type Reply = Read;
    type Descriptor = ReadDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = Response<Self::Reply>> + Send {
        async move {
            let HandlerContext {
                tenant,
                message,
                descriptor,
                ..
            } = ctx;

            let signature = match permissions::validate_authorization_signature(
                &message,
                self.did_resolver.as_deref(),
                false,
            )
            .await
            {
                Ok(signature) => signature,
                Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                    return Response::bad_request(detail.to_string())
                }
                Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                    return Response::unauthorized(detail.to_string())
                }
                Err(error) => return Response::bad_request(error.to_string()),
            };
            let mut filter =
                records_filter_to_filter_map(&descriptor.filter, descriptor.date_sort.as_ref());
            filter.insert(
                FilterKey::Index("interface".to_string()),
                string_filter(RECORDS_INTERFACE),
            );
            filter.insert(
                FilterKey::Index("isLatestBaseState".to_string()),
                bool_filter(true),
            );
            let result = match self
                .message_store
                .query(
                    tenant,
                    Filters::from(filter),
                    Some(date_sort_to_message_sort(
                        descriptor.date_sort.as_ref(),
                        true,
                    )),
                    Some(Pagination::with_limit(1)),
                )
                .await
            {
                Ok(result) => result,
                Err(err) => return store_error_reply(err.to_string()),
            };
            let Some(mut matched_message) = result.messages.into_iter().next() else {
                return Response::not_found();
            };

            if records_delete_descriptor(&matched_message).is_ok() {
                let record_id = message_record_id(&matched_message).unwrap_or_default();
                let initial_write = match fetch_initial_write_message(
                    tenant,
                    &record_id,
                    &self.message_store,
                )
                .await
                {
                    Ok(Some(message)) => message,
                    Ok(None) => return Response::bad_request(
                        "RecordsReadInitialWriteNotFound: initial write for deleted record not found".to_string(),
                    ),
                    Err(detail) => return store_error_reply(detail),
                };
                let newest_write = fetch_newest_write(tenant, &record_id, &self.message_store)
                    .await
                    .unwrap_or_else(|_| initial_write.clone());
                if let Err(detail) = authorize_records_read(
                    tenant,
                    &message,
                    signature.as_ref(),
                    &newest_write,
                    &self.message_store,
                )
                .await
                {
                    return Response::unauthorized(detail);
                }
                return Response::new(
                    replies::Status {
                        code: 404,
                        detail: "Not Found".to_string(),
                    },
                    Read {
                        entry: Some(ReadEntry {
                            records_delete: Some(matched_message.clone()),
                            initial_write: Some(initial_write),
                            records_write: None,
                            encoded_data: None,
                        }),
                    },
                );
            }

            if let Err(detail) = authorize_records_read(
                tenant,
                &message,
                signature.as_ref(),
                &matched_message,
                &self.message_store,
            )
            .await
            {
                return Response::unauthorized(detail);
            }

            let mut entry = ReadEntry::default();
            if let Some(encoded_data) = write_fields(&matched_message)
                .ok()
                .and_then(|fields| fields.encoded_data.clone())
            {
                entry.encoded_data = Some(encoded_data.clone());
            } else {
                let Some(record_id) = record_id(&matched_message) else {
                    return Response::bad_request(
                        "RecordsReadMissingRecordId: recordId is required".to_string(),
                    );
                };
                let data_cid = match records_write_descriptor(&matched_message) {
                    Ok(descriptor) => descriptor.data_cid.clone(),
                    Err(detail) => return Response::bad_request(detail.to_string()),
                };
                let data = match self.data_store.get(tenant, &record_id, &data_cid).await {
                    Ok(Some(data)) => data,
                    Ok(None) => {
                        return Response::gone(
                            "Record data not available".to_string(),
                            Read {
                                entry: Some(ReadEntry {
                                    records_write: Some(matched_message.clone()),
                                    ..Default::default()
                                }),
                            },
                        )
                    }
                    Err(err) => return Response::internal_error(err.to_string()),
                };
                let mut data_stream = data.data_stream;
                let mut bytes = Vec::new();
                loop {
                    match data_stream.try_next().await {
                        Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
                        Ok(None) => break,
                        Err(err) => return store_error_reply(err.to_string()),
                    }
                }
                entry.encoded_data = Some(URL_SAFE_NO_PAD.encode(&bytes));
            }
            if let Err(details) = set_encoded_data(&mut matched_message, None) {
                return Response::bad_request(details.to_string());
            }
            entry.records_write = Some(matched_message.clone());

            if !is_initial_write(
                &matched_message,
                extract_author(&matched_message)
                    .as_deref()
                    .unwrap_or_default(),
            )
            .unwrap_or(false)
            {
                if let Some(record_id) = record_id(&matched_message) {
                    if let Ok(Some(initial_write)) =
                        fetch_initial_write_message(tenant, &record_id, &self.message_store).await
                    {
                        entry.initial_write = Some(initial_write.clone());
                    }
                }
            }

            Response::ok().with_reply(Read { entry: Some(entry) })
        }
    }
}

impl<MessageStore, DataStore> RecordsReadHandler<MessageStore, DataStore> {
    pub fn new(
        message_store: MessageStore,
        data_store: DataStore,
        did_resolver: Option<Arc<dyn DidResolver>>,
    ) -> Self {
        Self {
            message_store,
            data_store,
            did_resolver,
        }
    }
}
