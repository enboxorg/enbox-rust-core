use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::TryStreamExt;
use serde_json::{json, Value as JsonValue};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::auth::JwsPublicKeyResolver;
use crate::descriptors::ReadDescriptor;
use crate::dwn::{DwnReply, HandlesDescriptor, MethodHandler, MethodHandlerRequest};
use crate::filters::{FilterKey, Filters};
use crate::handlers::records::common::{
    authorize_records_read, bool_filter, date_sort_to_message_sort, extract_author,
    fetch_initial_write_message, fetch_newest_write, is_initial_write, message_record_id,
    not_found_reply, parse_message, record_id, records_delete_descriptor,
    records_filter_to_filter_map, records_read_descriptor, records_write_descriptor,
    store_error_reply, string_filter, write_fields,
};
use crate::permissions::{self};
use crate::Pagination;

use super::RECORDS_INTERFACE;

#[derive(Clone)]
pub struct RecordsReadHandler<MessageStore, DataStore> {
    message_store: MessageStore,
    data_store: DataStore,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MessageStore, DataStore> HandlesDescriptor for RecordsReadHandler<MessageStore, DataStore> {
    type Descriptor = ReadDescriptor;
}

impl<MessageStore, DataStore> RecordsReadHandler<MessageStore, DataStore> {
    pub fn new(message_store: MessageStore, data_store: DataStore) -> Self {
        Self {
            message_store,
            data_store,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        data_store: DataStore,
        public_key_resolver: impl JwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            data_store,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }

    pub fn with_optional_resolver(
        message_store: MessageStore,
        data_store: DataStore,
        public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
    ) -> Self {
        Self {
            message_store,
            data_store,
            public_key_resolver,
        }
    }
}

impl<MessageStore, DataStore> MethodHandler for RecordsReadHandler<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_read(request.tenant, request.message).await })
    }
}

impl<MessageStore, DataStore> RecordsReadHandler<MessageStore, DataStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    DataStore: crate::stores::DataStore + Clone + Send + Sync + 'static,
{
    pub async fn handle_read(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match records_read_descriptor(&message) {
            Ok(descriptor) => descriptor.clone(),
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let signature = match permissions::validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
            false,
        ) {
            Ok(signature) => signature,
            Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                return DwnReply::bad_request(detail)
            }
            Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
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
        let Some(matched_message) = result.messages.first() else {
            return not_found_reply();
        };

        if records_delete_descriptor(matched_message).is_ok() {
            let record_id = message_record_id(matched_message).unwrap_or_default();
            let initial_write = match fetch_initial_write_message(
                tenant,
                &record_id,
                &self.message_store,
            )
            .await
            {
                Ok(Some(message)) => message,
                Ok(None) => return DwnReply::bad_request(
                    "RecordsReadInitialWriteNotFound: initial write for deleted record not found",
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
                return DwnReply::unauthorized(detail);
            }
            return DwnReply::new(404, "Not Found").with_body(
                "entry",
                json!({
                    "recordsDelete": matched_message,
                    "initialWrite": initial_write,
                }),
            );
        }

        if let Err(detail) = authorize_records_read(
            tenant,
            &message,
            signature.as_ref(),
            matched_message,
            &self.message_store,
        )
        .await
        {
            return DwnReply::unauthorized(detail);
        }

        let mut entry = serde_json::Map::new();
        let mut records_write = serde_json::to_value(matched_message).unwrap_or(JsonValue::Null);
        if let Some(encoded_data) = write_fields(matched_message)
            .ok()
            .and_then(|fields| fields.encoded_data.clone())
        {
            if let Some(object) = records_write.as_object_mut() {
                object.remove("encodedData");
            }
            entry.insert("encodedData".to_string(), JsonValue::String(encoded_data));
        } else {
            let Some(record_id) = record_id(matched_message) else {
                return DwnReply::bad_request("RecordsReadMissingRecordId: recordId is required");
            };
            let data_cid = match records_write_descriptor(matched_message) {
                Ok(descriptor) => descriptor.data_cid.clone(),
                Err(detail) => return DwnReply::bad_request(detail),
            };
            let data = match self.data_store.get(tenant, &record_id, &data_cid).await {
                Ok(Some(data)) => data,
                Ok(None) => {
                    return DwnReply::new(410, "Record data not available")
                        .with_body("entry", json!({ "recordsWrite": matched_message }))
                }
                Err(err) => return store_error_reply(err.to_string()),
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
            entry.insert(
                "encodedData".to_string(),
                JsonValue::String(URL_SAFE_NO_PAD.encode(bytes)),
            );
        }
        entry.insert("recordsWrite".to_string(), records_write);

        if !is_initial_write(
            matched_message,
            extract_author(matched_message)
                .as_deref()
                .unwrap_or_default(),
        )
        .unwrap_or(false)
        {
            if let Some(record_id) = record_id(matched_message) {
                if let Ok(Some(initial_write)) =
                    fetch_initial_write_message(tenant, &record_id, &self.message_store).await
                {
                    entry.insert(
                        "initialWrite".to_string(),
                        serde_json::to_value(initial_write).unwrap(),
                    );
                }
            }
        }

        DwnReply::ok().with_body("entry", JsonValue::Object(entry))
    }
}
