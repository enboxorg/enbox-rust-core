use dwn_rs_core::errors::StoreError;

pub mod conn;
pub mod data_store;
pub mod message_store;
mod query;
pub mod store;

pub use self::conn::SqliteConnection;
pub(crate) use self::store::sqlite_store_error;
pub use self::store::SqliteStore;

pub(crate) fn json_store_error(error: serde_json::Error) -> StoreError {
    StoreError::InternalException(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use futures_util::TryStreamExt;

    use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
    use dwn_rs_core::descriptors::{Records, RecordsWriteDescriptor};
    use dwn_rs_core::fields::WriteFields;
    use dwn_rs_core::filters::{Filter, FilterKey};
    use dwn_rs_core::Fields;

    use super::*;

    #[tokio::test]
    async fn message_store_roundtrips_inline_data_without_changing_message_cid() {
        let mut store = SqliteStore::in_memory();
        MessageStore::open(&mut store).await.unwrap();
        let message = message(
            "2025-01-01T00:00:00.000000Z",
            Some("https://example.com/protocol/notes"),
            Some("aGVsbG8"),
        );
        let mut cid_message = message.clone();
        cid_message.fields.encoded_data();
        let cid = cid_message.cid().unwrap().to_string();

        MessageStore::put(
            &store,
            "did:example:alice",
            message.clone(),
            indexes(&message),
        )
        .await
        .unwrap();

        assert_eq!(
            MessageStore::get(&store, "did:example:alice", &cid)
                .await
                .unwrap()
                .unwrap(),
            message
        );
    }

    #[tokio::test]
    async fn message_store_persists_across_reopen() {
        let path = temp_db_path("message-store");
        let _ = std::fs::remove_file(&path);
        let message = message("2025-01-01T00:00:00.000000Z", None, None);
        let mut cid_message = message.clone();
        cid_message.fields.encoded_data();
        let cid = cid_message.cid().unwrap().to_string();

        let mut store = SqliteStore::new(&path);
        MessageStore::open(&mut store).await.unwrap();
        MessageStore::put(
            &store,
            "did:example:alice",
            message.clone(),
            indexes(&message),
        )
        .await
        .unwrap();
        MessageStore::close(&mut store).await;

        let mut reopened = SqliteStore::new(&path);
        MessageStore::open(&mut reopened).await.unwrap();
        assert_eq!(
            MessageStore::get(&reopened, "did:example:alice", &cid)
                .await
                .unwrap(),
            Some(message)
        );
        MessageStore::close(&mut reopened).await;
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn message_store_filters_sorts_counts_and_paginates() {
        let mut store = SqliteStore::in_memory();
        MessageStore::open(&mut store).await.unwrap();
        let first = message(
            "2025-01-01T00:00:00.000000Z",
            Some("https://example.com/protocol/notes"),
            None,
        );
        let second = message(
            "2025-01-01T00:00:01.000000Z",
            Some("https://example.com/protocol/notes"),
            None,
        );
        let third = message(
            "2025-01-01T00:00:02.000000Z",
            Some("https://example.com/protocol/tasks"),
            None,
        );

        for message in [&first, &second, &third] {
            MessageStore::put(
                &store,
                "did:example:alice",
                message.clone(),
                indexes(message),
            )
            .await
            .unwrap();
        }
        let mut third_indexes = indexes(&third);
        third_indexes.insert(
            "recipient".to_string(),
            Value::Array(vec![
                Value::String("did:example:bob".to_string()),
                Value::String("did:example:carol".to_string()),
            ]),
        );
        MessageStore::put(&store, "did:example:alice", third.clone(), third_indexes)
            .await
            .unwrap();
        let published = message(
            "2025-01-01T00:00:03.000000Z",
            Some("https://example.com/protocol/published"),
            None,
        );
        let mut published_indexes = indexes(&published);
        published_indexes.insert(
            "datePublished".to_string(),
            Value::String("2025-01-01T00:00:03.000000Z".to_string()),
        );
        MessageStore::put(
            &store,
            "did:example:alice",
            published.clone(),
            published_indexes,
        )
        .await
        .unwrap();

        let filters = Filters::from([[(
            FilterKey::Index("protocol".to_string()),
            Filter::Equal(Value::String(
                "https://example.com/protocol/notes".to_string(),
            )),
        )]]);
        assert_eq!(
            store
                .count("did:example:alice", filters.clone(), None)
                .await
                .unwrap(),
            2
        );

        let result = store
            .query(
                "did:example:alice",
                filters.clone(),
                Some(MessageSort::Timestamp(SortDirection::Descending)),
                Some(Pagination::with_limit(1)),
            )
            .await
            .unwrap();
        assert_eq!(result.messages, vec![second.clone()]);
        assert!(result.cursor.is_some());

        let result = store
            .query(
                "did:example:alice",
                filters,
                Some(MessageSort::Timestamp(SortDirection::Descending)),
                Some(Pagination::new(result.cursor, Some(1))),
            )
            .await
            .unwrap();
        assert_eq!(result.messages, vec![first]);
        assert!(result.cursor.is_none());

        let result = store
            .query(
                "did:example:alice",
                Filters::from([[(
                    FilterKey::Index("recipient".to_string()),
                    Filter::Equal(Value::String("did:example:bob".to_string())),
                )]]),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.messages, vec![third]);

        let result = store
            .query(
                "did:example:alice",
                Filters::default(),
                Some(MessageSort::DatePublished(SortDirection::Ascending)),
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.messages, vec![published]);

        let result = store
            .query(
                "did:example:alice",
                Filters::default(),
                Some(MessageSort::Timestamp(SortDirection::Ascending)),
                Some(Pagination::with_limit(0)),
            )
            .await
            .unwrap();
        assert!(result.messages.is_empty());
        assert!(result.cursor.is_none());
    }

    #[tokio::test]
    async fn data_store_shares_content_addressed_blocks_and_refs() {
        let mut store = SqliteStore::in_memory();
        DataStore::open(&mut store).await.unwrap();
        let bytes = Bytes::from_static(b"hello sqlite data");
        let data_cid = generate_dag_pb_cid_from_bytes(&bytes).to_string();

        let put = DataStore::put(
            &store,
            "did:example:alice",
            "record-1",
            &data_cid,
            stream::iter(vec![bytes.clone()]),
        )
        .await
        .unwrap();
        assert_eq!(put.data_size, bytes.len());

        let duplicate = DataStore::put(
            &store,
            "did:example:alice",
            "record-1",
            &data_cid,
            stream::iter(vec![Bytes::from_static(b"ignored duplicate stream")]),
        )
        .await
        .unwrap();
        assert_eq!(duplicate.data_size, bytes.len());

        let shared = DataStore::put(
            &store,
            "did:example:alice",
            "record-2",
            &data_cid,
            stream::iter(vec![Bytes::from_static(b"ignored shared stream")]),
        )
        .await
        .unwrap();
        assert_eq!(shared.data_size, bytes.len());

        DataStore::delete(&store, "did:example:alice", "record-1", &data_cid)
            .await
            .unwrap();
        let stored = DataStore::get(&store, "did:example:alice", "record-2", &data_cid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.data_size, bytes.len());
        let read = stored
            .data_stream
            .try_fold(Vec::new(), |mut read, chunk| async move {
                read.extend_from_slice(&chunk);
                Ok(read)
            })
            .await
            .unwrap();
        assert_eq!(read, bytes.to_vec());

        DataStore::delete(&store, "did:example:alice", "record-2", &data_cid)
            .await
            .unwrap();
        assert!(
            DataStore::get(&store, "did:example:alice", "record-2", &data_cid)
                .await
                .unwrap()
                .is_none()
        );
    }

    fn message(
        timestamp: &str,
        protocol: Option<&str>,
        encoded_data: Option<&str>,
    ) -> Message<Descriptor> {
        let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
            .unwrap()
            .with_timezone(&chrono::Utc);
        let descriptor =
            Descriptor::Records(Box::new(Records::Write(Box::new(RecordsWriteDescriptor {
                protocol: protocol.map(ToString::to_string),
                protocol_path: protocol.map(|_| "note".to_string()),
                recipient: None,
                schema: None,
                tags: None,
                parent_id: None,
                data_cid: "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e".to_string(),
                data_size: 11,
                date_created: timestamp,
                message_timestamp: timestamp,
                published: None,
                date_published: None,
                data_format: "text/plain".to_string(),
                permission_grant_id: None,
                squash: None,
            }))));
        let fields = Fields::Write(WriteFields {
            record_id: Some(format!("record-{timestamp}")),
            encoded_data: encoded_data.map(ToString::to_string),
            ..Default::default()
        });

        Message { descriptor, fields }
    }

    fn indexes(message: &Message<Descriptor>) -> KeyValues {
        let mut indexes = BTreeMap::new();
        indexes.insert(
            "messageTimestamp".to_string(),
            Value::String(
                serde_json::to_value(&message.descriptor).unwrap()["messageTimestamp"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
        );
        indexes.insert(
            "interface".to_string(),
            Value::String("Records".to_string()),
        );
        indexes.insert("method".to_string(), Value::String("Write".to_string()));
        if let Some(protocol) =
            serde_json::to_value(&message.descriptor).unwrap()["protocol"].as_str()
        {
            indexes.insert("protocol".to_string(), Value::String(protocol.to_string()));
        }
        indexes
    }

    fn temp_db_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dwn-rs-{name}-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ))
    }
}
