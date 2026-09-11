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
    fetch_initial_write_message, fetch_newest_write, filter_map, message_record_id,
    message_record_limit_policy, published_sort_name, records_delete_descriptor,
    records_filter_to_filter_map, set_encoded_data, store_error_reply, string_filter,
    IdentityProjector, RecordsProjector,
};
use crate::handlers::records::control;
use crate::permissions::{self};
use crate::replies::records::{Read, ReadEntry};
use crate::Response;
use crate::{canonical_rfc3339, replies, Pagination};

use super::{RECORDS_INTERFACE, WRITE_METHOD};

const CANDIDATE_PAGE_SIZE: u64 = 25;

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

            if descriptor.filter.published == Some(false) {
                if let Some(sort_name) = published_sort_name(&descriptor.date_sort) {
                    return Response::bad_request(format!(
                        "RecordsReadParseFilterPublishedSortInvalid: reads must not filter for `published:false` and sort by {sort_name}"
                    ));
                }
            }

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
            let filters = Filters::from(filter);
            let sort = date_sort_to_message_sort(descriptor.date_sort.as_ref(), true);
            let point_read = descriptor.filter.record_id.is_some();
            let mut cursor = None;
            // A broad Read is a top-1 query over the readable population. Scan
            // bounded pages so hidden records cannot shadow the first visible
            // one without materializing an unbounded result set. Exact-ID
            // reads retain their 401/404 shape.
            let mut matched_message = 'pages: loop {
                let result = match self
                    .message_store
                    .query(
                        tenant,
                        filters.clone(),
                        Some(sort),
                        Some(Pagination::new(cursor, Some(CANDIDATE_PAGE_SIZE))),
                        None,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(err) => return store_error_reply(err.to_string()),
                };
                if result.messages.is_empty() {
                    return Response::not_found();
                }
                cursor = result.cursor;

                for candidate in result.messages {
                    if records_delete_descriptor(&candidate).is_ok() {
                        let record_id = message_record_id(&candidate).unwrap_or_default();
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
                        let newest_write =
                            fetch_newest_write(tenant, &record_id, &self.message_store)
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
                            if point_read {
                                return Response::unauthorized(detail);
                            }
                            continue;
                        }
                        return Response::new(
                            replies::Status::new(404, "Not Found"),
                            Read {
                                entry: Some(ReadEntry {
                                    records_delete: Some(candidate),
                                    initial_write: Some(initial_write),
                                    records_write: None,
                                    encoded_data: None,
                                }),
                            },
                        );
                    }

                    let mut projected =
                        match IdentityProjector.project_writes(vec![candidate]).await {
                            Ok(projected) => projected,
                            Err(detail) => {
                                return store_error_reply(format!(
                                    "failed to project records: {detail}"
                                ))
                            }
                        };
                    let Some(candidate) = projected.pop() else {
                        continue;
                    };

                    let occupant = match message_record_limit_policy(
                        tenant,
                        &candidate,
                        &self.message_store,
                        &canonical_rfc3339(descriptor.message_timestamp),
                    )
                    .await
                    {
                        Ok(None) => true,
                        Ok(Some(policy)) => {
                            let Some(candidate_record_id) = record_id(&candidate) else {
                                return Response::bad_request(
                                    "RecordsReadMissingRecordId: recordId is required".to_string(),
                                );
                            };
                            let occupant_filter = filter_map([
                                ("interface", string_filter(RECORDS_INTERFACE)),
                                ("method", string_filter(WRITE_METHOD)),
                                ("isLatestBaseState", bool_filter(true)),
                                ("protocol", string_filter(&policy.protocol)),
                                ("protocolPath", string_filter(&policy.protocol_path)),
                                ("recordId", string_filter(&candidate_record_id)),
                            ]);
                            match self
                                .message_store
                                .count(tenant, Filters::from(occupant_filter), None, Some(policy))
                                .await
                            {
                                Ok(count) => count > 0,
                                Err(err) => return store_error_reply(err.to_string()),
                            }
                        }
                        Err(detail) => return store_error_reply(detail),
                    };
                    if !occupant {
                        continue;
                    }

                    let authorized = if control::ControlKind::of(&candidate).is_some() {
                        match control::can_read(
                            tenant,
                            &message,
                            signature.as_ref(),
                            &candidate,
                            Some(&descriptor.filter),
                            &self.message_store,
                        )
                        .await
                        {
                            Ok(true) => Ok(()),
                            Ok(false) => Err("EncryptionControlReadUnauthorized: requester is not authorized to read the encryption control record".to_string()),
                            Err(control::ControlValidationError::Internal(detail)) => {
                                return store_error_reply(detail)
                            }
                            Err(error) => Err(error.to_string()),
                        }
                    } else {
                        authorize_records_read(
                            tenant,
                            &message,
                            signature.as_ref(),
                            &candidate,
                            &self.message_store,
                        )
                        .await
                    };
                    if let Err(detail) = authorized {
                        if point_read {
                            return Response::unauthorized(detail);
                        }
                        continue;
                    }
                    break 'pages candidate;
                }
                if cursor.is_none() {
                    return Response::not_found();
                }
            };

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
                    match fetch_initial_write_message(tenant, &record_id, &self.message_store).await
                    {
                        Ok(Some(initial_write)) => {
                            entry.initial_write = Some(initial_write.clone());
                        }
                        Ok(None) => {
                            return Response::internal_error(
                                format!(
                                    "RecordsWriteGetInitialWriteNotFound: initial write not found for record {record_id}"
                                ),
                            );
                        }
                        Err(detail) => return store_error_reply(detail),
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
