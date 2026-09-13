//! Data processing for records writes: integrity-checking the bytes the
//! descriptor commits to, running payload validation where bytes are in hand,
//! and staging the encoded data or the data-store write.

use bytes::Bytes;
use futures_util::stream;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::cid::generate_dag_pb_cid_from_bytes;
use crate::descriptors::{
    messages::record_id,
    records::{records_write_descriptor, write_fields},
    Descriptor,
};
use crate::encryption::control::ControlKind;
use crate::encryption::protocol::validate_encryption_delivery;
use crate::encryption::ENCRYPTION_PROTOCOL_URI;
use crate::errors::{DwnError, DwnErrorCode};
use crate::handlers::records::common::{set_encoded_data, validate_data_integrity};
use crate::handlers::records::control;
use crate::Message;

use super::write::RecordsWriteValidationError;
use super::MAX_ENCODED_DATA_SIZE;

pub(crate) async fn process_message_with_data_stream<MessageStore, DataStore>(
    tenant: &str,
    message: &mut Message<Descriptor>,
    data: Bytes,
    message_store: &MessageStore,
    data_store: &DataStore,
) -> Result<(), RecordsWriteValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
    DataStore: crate::stores::DataStore + Sync,
{
    let descriptor = records_write_descriptor(message)
        .map_err(|error| error.to_string())?
        .clone();
    let actual_data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    validate_data_integrity(
        &descriptor.data_cid,
        descriptor.data_size,
        &actual_data_cid,
        data.len() as u64,
    )?;

    // An audience record's payload is part of its admission contract: the
    // key it publishes and the seal over that key are checked here, once
    // the bytes the descriptor commits to are actually in hand.
    if let Some(kind) = ControlKind::from_protocol_path(&descriptor.protocol_path) {
        control::validate_payload(tenant, message, kind, &data, message_store)
            .await
            .map_err(RecordsWriteValidationError::from)?;
    }

    if descriptor.data_size <= MAX_ENCODED_DATA_SIZE {
        // Grant-key payload validation runs where the bytes are in hand;
        // the post-processing hook below re-runs the descriptor half with
        // no data, which is what lets dataless initial writes through.
        // Only the encryption check runs here: the permissions check
        // reads back the encoded data set below, so it stays post-hoc.
        if descriptor.protocol.as_str() == ENCRYPTION_PROTOCOL_URI {
            validate_encryption_delivery(message, &data).map_err(|error| match error.code() {
                Some(code) => RecordsWriteValidationError::Dwn(DwnError::new(code, error.detail())),
                None => RecordsWriteValidationError::Internal(error.to_string()),
            })?;
        }
        set_encoded_data(message, Some(URL_SAFE_NO_PAD.encode(&data)))
            .map_err(RecordsWriteValidationError::from)?;
        return Ok(());
    }

    let record_id = record_id(message)
        .ok_or_else(|| "RecordsWriteMissingRecordId: recordId is required".to_string())?;
    let put_result = data_store
        .put(
            tenant,
            &record_id,
            &descriptor.data_cid,
            stream::iter(vec![data]),
        )
        .await
        .map_err(|err| RecordsWriteValidationError::Internal(err.to_string()))?;
    if put_result.data_size as u64 != descriptor.data_size {
        let _ = data_store
            .delete(tenant, &record_id, &descriptor.data_cid)
            .await;
        return Err(DwnError::new(
            DwnErrorCode::RecordsWriteDataSizeMismatch,
            format!(
                "actual data size {} bytes does not match dataSize in descriptor: {}",
                put_result.data_size, descriptor.data_size
            ),
        )
        .into());
    }
    set_encoded_data(message, None).map_err(RecordsWriteValidationError::from)
}

pub(crate) async fn process_message_without_data_stream<DataStore>(
    tenant: &str,
    message: &mut Message<Descriptor>,
    newest_existing_write: &Message<Descriptor>,
    data_store: &DataStore,
) -> Result<(), RecordsWriteValidationError>
where
    DataStore: crate::stores::DataStore + Sync,
{
    let descriptor = records_write_descriptor(message)
        .map_err(|error| error.to_string())?
        .clone();
    let newest_descriptor =
        records_write_descriptor(newest_existing_write).map_err(|error| error.to_string())?;
    validate_data_integrity(
        &descriptor.data_cid,
        descriptor.data_size,
        &newest_descriptor.data_cid,
        newest_descriptor.data_size,
    )?;

    if descriptor.data_size <= MAX_ENCODED_DATA_SIZE {
        let encoded_data = write_fields(newest_existing_write)
            .map_err(|error| error.to_string())?
            .encoded_data
            .clone()
            .ok_or_else(|| {
                DwnError::new(
                    DwnErrorCode::RecordsWriteMissingEncodedDataInPrevious,
                    "No dataStream was provided and unable to get data from previous message",
                )
            })?;
        set_encoded_data(message, Some(encoded_data)).map_err(RecordsWriteValidationError::from)?;
        return Ok(());
    }

    let record_id = record_id(newest_existing_write)
        .ok_or_else(|| "RecordsWriteMissingRecordId: previous recordId is required".to_string())?;
    let has_data = data_store
        .get(tenant, &record_id, &descriptor.data_cid)
        .await
        .map_err(|err| err.to_string())?
        .is_some();
    if !has_data {
        return Err(DwnError::new(
            DwnErrorCode::RecordsWriteMissingDataInPrevious,
            "No dataStream was provided and unable to get data from previous message",
        )
        .into());
    }
    set_encoded_data(message, None).map_err(RecordsWriteValidationError::from)
}
