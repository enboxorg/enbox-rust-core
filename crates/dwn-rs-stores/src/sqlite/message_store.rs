use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use dwn_rs_core::descriptors::MessageDescriptor;
use rusqlite::{params, OptionalExtension};

use dwn_rs_core::errors::MessageStoreError;
use dwn_rs_core::fields::MessageFields;
use dwn_rs_core::filters::Filters;
use dwn_rs_core::stores::{KeyValues, MessageQueryResult, MessageStore};
use dwn_rs_core::{Descriptor, Message, MessageSort, Pagination, Query};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::sqlite::query::SqliteQuery;
use crate::store::sqlite_store_error;
use crate::SqliteStore;

#[derive(Debug, Clone)]
struct MessageRow {
    cid: String,
    message: Message<Descriptor>,
    indexes: KeyValues,
}

impl MessageStore for SqliteStore {
    async fn open(&mut self) -> Result<(), MessageStoreError> {
        self.connection()
            .await
            .map(|_| ())
            .map_err(MessageStoreError::from)
    }

    async fn close(&mut self) {
        self.connection().await.ok().map(|conn| conn.close());
    }

    async fn put<D>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: KeyValues,
    ) -> Result<(), MessageStoreError>
    where
        D: MessageDescriptor + Serialize + Send,
    {
        let tenant = tenant.to_string();
        let data = message.fields.clone().encoded_data();

        let message_cid = message.cid()?.to_string();

        let message_json = serde_json::to_string(&message)?;
        let indexes_json = serde_json::to_string(&indexes)?;

        self.connection()
            .await?
            .clone()
            .with_writer(move |connection| {
                let tx = connection.transaction().map_err(sqlite_store_error)?;
                tx.execute(
                    "INSERT OR REPLACE INTO messages \
                             (tenant, message_cid, message_json, indexes_json) \
                             VALUES (?1, ?2, ?3, ?4)",
                    params![tenant, message_cid, message_json, indexes_json],
                );

                if let Some(value) = data {
                    let enc_data = STANDARD.encode(&value.to_bytes());
                    tx.execute(
                        "INSERT OR REPLACE INTO message_data \
                         (message_cid, data, data_size) \
                         VALUES (?1, ?2, ?3)",
                        params![message_cid, enc_data, value.len() as i64],
                    );
                }

                tx.commit().map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .map_err(MessageStoreError::from)
    }

    async fn get<D>(&self, tenant: &str, cid: &str) -> Result<Option<Message<D>>, MessageStoreError>
    where
        D: MessageDescriptor + Serialize + Send,
        Message<D>: DeserializeOwned,
    {
        let tenant = tenant.to_string();
        let cid = cid.to_string();

        let message_json = self
            .connection()
            .await?
            .clone()
            .with_reader(move |connection| {
                connection
                    .query_row(
                        "SELECT message_json FROM messages \
                             WHERE tenant = ?1 AND message_cid = ?2
                            LIMIT 1",
                        params![tenant, cid],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sqlite_store_error)
            })
            .await
            .map_err(MessageStoreError::from)?;

        message_json // fix #1 + #3: thread the Option
            .map(|json| serde_json::from_str::<Message<D>>(&json))
            .transpose()
            .map_err(MessageStoreError::from)
    }

    async fn query(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
        pagination: Option<Pagination>,
    ) -> Result<MessageQueryResult, MessageStoreError> {
        let conn = self.connection().await?.clone();

        let mut q = SqliteQuery::<Message<Descriptor>, MessageSort>::new(
            conn,
            tenant.to_string(),
            "message_cid",
            "message_json",
            "indexes_json",
        );

        q.from("messages")
            .filter(&filters)?
            .sort(sort)
            .page(pagination.as_ref());

        let (messages, cursor) = q.query().await?;

        return Ok(MessageQueryResult { messages, cursor });
    }

    async fn count(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
    ) -> Result<u64, MessageStoreError> {
        let conn = self.connection().await?.clone();

        let mut q = SqliteQuery::<Message<Descriptor>, MessageSort>::new(
            conn,
            tenant.to_string(),
            "message_cid",
            "message_json",
            "indexes_json",
        );

        q.from("messages").filter(&filters)?.sort(sort);

        Ok(q.count().await?)
    }

    async fn delete(&self, tenant: &str, cid: &str) -> Result<(), MessageStoreError> {
        let conn = self.connection().await?.clone();
        let tenant = tenant.to_string();
        let cid = cid.to_string();

        conn.with_writer(move |connection| {
            connection
                .execute(
                    "DELETE FROM messages WHERE tenant = ?1 AND message_cid = ?2",
                    params![tenant, cid],
                )
                .map_err(sqlite_store_error)?;
            Ok(())
        })
        .await
        .map_err(MessageStoreError::from)
    }

    async fn clear(&self) -> Result<(), MessageStoreError> {
        let conn = self.connection().await?.clone();

        async move {
            conn.with_writer(move |connection| {
                connection
                    .execute("DELETE FROM messages", [])
                    .map_err(sqlite_store_error)?;
                Ok(())
            })
            .await
            .map_err(MessageStoreError::from)
        }
        .await
    }
}
