use std::collections::BTreeMap;

use dwn_rs_core::descriptors::records::write_tag_protocol;
use dwn_rs_core::descriptors::MessageDescriptor;
use dwn_rs_core::stores::replication_feed_reader::{
    fingerprint_scopes, fold_cid_into_domain, is_feed_message, scopes_unchanged, Fingerprint,
};
use dwn_rs_core::stores::wake::Wake;
use rusqlite::{params, OptionalExtension, Transaction};

use dwn_rs_core::errors::{MessageReplicationError, MessageStoreError, StoreError};
use dwn_rs_core::fields::MessageFields;
use dwn_rs_core::filters::Filters;
use dwn_rs_core::stores::{KeyValues, MessageQueryResult, MessageStore};
use dwn_rs_core::{Descriptor, Message, MessageSort, Pagination, Query};
use serde::Serialize;
use serde_rusqlite::from_row;
use uuid::Uuid;

use crate::replication_feed_reader::FeedEntry;
use crate::sqlite::query::SqliteQuery;
use crate::store::sqlite_store_error;
use crate::SqliteStore;

impl MessageStore for SqliteStore {
    async fn open(&mut self) -> Result<(), MessageStoreError> {
        let conn = self.connection().await.map_err(MessageStoreError::from)?;
        Ok(())
    }

    async fn close(&mut self) {
        if let Ok(conn) = self.connection().await {
            conn.close()
        }
    }

    async fn put<D>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: KeyValues,
    ) -> Result<(), MessageStoreError>
    where
        D: MessageDescriptor + Serialize + Send,
        Message<Descriptor>: From<Message<D>>,
    {
        let tenant = tenant.to_string();
        let message_json = serde_json::to_string(&message)?;
        let mut message: Message<Descriptor> = message.into();
        message.fields.encoded_data(); // strip inline encodedData so the CID is canonical
        let message_cid = message.cid()?.to_string();
        let indexes_json = serde_json::to_string(&indexes)?;
        let msg_scopes = fingerprint_scopes(write_tag_protocol(&message), &indexes);

        let wake = self
            .connection()
            .await?
            .clone()
            .with_writer(move |connection| {
                let tx = connection.transaction().map_err(sqlite_store_error)?;

                if !is_feed_message(&message) {
                    insert_message(&tx, &tenant, &message_cid, &message_json, &indexes_json)?;
                    return Ok(None);
                }

                let feed_entry = select_feed_entry(&tx, &tenant, &message_cid)?;
                let wake: Option<Wake> = match feed_entry {
                    Some(entry) => {
                        if !scopes_unchanged(&entry.fingerprint_scopes, &msg_scopes) {
                            return Err(StoreError::ReplicationError(
                                MessageReplicationError::FingerprintScopesMismatch,
                            ));
                        }

                        insert_message(&tx, &tenant, &message_cid, &message_json, &indexes_json)?;
                        update_feed_entry_indexes(&tx, &tenant, &entry, &indexes)?;
                        None
                    }
                    None => {
                        let next = next_position(&tx, &tenant)?;
                        insert_message(&tx, &tenant, &message_cid, &message_json, &indexes_json)?;
                        insert_feed_entry(
                            &tx,
                            &FeedEntry {
                                tenant: tenant.clone(),
                                position: next,
                                message_cid: message_cid.clone(),
                                message_json: message_json.clone(),
                                indexes_json: indexes_json.clone(),
                                fingerprint_scopes: msg_scopes.clone(),
                            },
                        )?;
                        update_feed_head(&tx, &tenant, next)?;
                        upsert_feed_fingerprint(&tx, &tenant, &message_cid, &msg_scopes)?;

                        Some(Wake {
                            tenant: tenant.clone(),
                            position: next as u64,
                        })
                    }
                };

                tx.commit().map_err(sqlite_store_error)?;
                Ok(wake)
            })
            .await
            .map_err(MessageStoreError::from)?;

        if let Some(wake) = wake {
            let _ = self.waker_publisher.publish(wake);
        }

        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        cid: &str,
    ) -> Result<Option<Message<Descriptor>>, MessageStoreError> {
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
            .map(|json| serde_json::from_str::<Message<Descriptor>>(&json))
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

        Ok(MessageQueryResult { messages, cursor })
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
            let tx = connection.transaction().map_err(sqlite_store_error)?;

            let feed_entry = match select_feed_entry(&tx, &tenant, &cid)? {
                Some(entry) => Some((entry.message_cid, entry.fingerprint_scopes)),
                None => None,
            };

            tx.execute(
                "DELETE FROM messages WHERE tenant = ?1 AND message_cid = ?2",
                params![tenant, cid],
            )
            .map_err(sqlite_store_error)?;

            tx.execute(
                "DELETE FROM feed_entries WHERE tenant = ?1 AND message_cid = ?2",
                params![tenant, cid],
            )
            .map_err(sqlite_store_error)?;

            if let Some((feed_cid, ref scopes)) = feed_entry {
                upsert_feed_fingerprint(&tx, &tenant, &feed_cid, scopes)?;
            }

            tx.commit().map_err(sqlite_store_error)?;

            Ok(())
        })
        .await
        .map_err(MessageStoreError::from)
    }

    async fn clear(&self) -> Result<(), MessageStoreError> {
        let conn = self.connection().await?.clone();

        async move {
            conn.with_writer(move |connection| {
                let tx = connection.transaction().map_err(sqlite_store_error)?;
                tx.execute(
                    "
                        DELETE FROM messages;
                        DELETE FROM feed_metadata;
                        DELETE FROM feed_entries;
                        DELETE FROM feed_fingerprints;
                        DELETE FROM feed_heads;
                    ",
                    [],
                )
                .map_err(sqlite_store_error)?;

                generate_epoch(&tx)?;

                Ok(())
            })
            .await
            .map_err(MessageStoreError::from)
        }
        .await
    }
}

pub(crate) fn generate_epoch(tx: &Transaction) -> Result<usize, StoreError> {
    tx.execute(
        "INSERT INTO feed_metadata (id, epoch) VALUES (1, ?1)",
        [Uuid::new_v4().to_string()],
    )
    .map_err(sqlite_store_error)
}

fn insert_message(
    tx: &Transaction,
    tenant: &str,
    message_cid: &str,
    message_json: &str,
    indexes_json: &str,
) -> Result<usize, StoreError> {
    tx.execute(
        "INSERT OR REPLACE INTO messages \
                             (tenant, message_cid, message_json, indexes_json) \
                             VALUES (?1, ?2, ?3, ?4)",
        params![tenant, message_cid, message_json, indexes_json],
    )
    .map_err(sqlite_store_error)
}

fn select_feed_entry(
    tx: &Transaction,
    tenant: &str,
    message_cid: &str,
) -> Result<Option<FeedEntry>, StoreError> {
    let mut stmt = tx
        .prepare(
            "SELECT tenant, position, message_cid, indexes_json, fingerprint_scopes_json \
            FROM feed_entries \
            WHERE tenant = ?1 AND message_cid = ?2
            LIMIT 1",
        )
        .map_err(sqlite_store_error)?;

    stmt.query_row(params![tenant, message_cid], |row| {
        from_row::<FeedEntry>(row)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))
    })
    .optional()
    .map_err(sqlite_store_error)
}

fn update_feed_entry_indexes(
    tx: &Transaction,
    tenant: &str,
    entry: &FeedEntry,
    indexes: &KeyValues,
) -> Result<usize, StoreError> {
    let indexes_json = serde_json::to_string(indexes)
        .map_err(|err| StoreError::InternalException(err.to_string()))?;

    tx.execute(
        "UPDATE feed_entries 
            SET indexes_json = ?3
            WHERE tenant = ?1 AND message_cid = ?2
        ",
        params![tenant, entry.message_cid, indexes_json],
    )
    .map_err(sqlite_store_error)
}

fn insert_feed_entry(tx: &Transaction, entry: &FeedEntry) -> Result<usize, StoreError> {
    let fingerprint_scopes_json = serde_json::to_string(&entry.fingerprint_scopes)
        .map_err(|err| StoreError::InternalException(err.to_string()))?;

    tx.execute(
        "INSERT INTO feed_entries \
            (tenant, position, message_cid, indexes_json, fingerprint_scopes_json) \
            VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            entry.tenant,
            entry.position,
            entry.message_cid,
            entry.indexes_json,
            fingerprint_scopes_json
        ],
    )
    .map_err(sqlite_store_error)
}

fn next_position(tx: &Transaction, tenant: &str) -> Result<i64, StoreError> {
    let position: Option<i64> = tx
        .query_row(
            "SELECT head FROM feed_heads WHERE tenant = ?1",
            params![tenant],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_store_error)?;

    position
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(StoreError::ReplicationError(
            MessageReplicationError::FeedPositionOverflow,
        ))
}

fn update_feed_head(tx: &Transaction, tenant: &str, position: i64) -> Result<usize, StoreError> {
    tx.execute(
        "INSERT INTO feed_heads (tenant, head) VALUES (?1, ?2) \
            ON CONFLICT(tenant) DO UPDATE SET head = excluded.head",
        params![tenant, position],
    )
    .map_err(sqlite_store_error)
}

fn upsert_feed_fingerprint(
    tx: &Transaction,
    tenant: &str,
    message_cid: &str,
    scopes: &[String],
) -> Result<(), StoreError> {
    // select all the feed_fingerprints for the tenant across all the
    // provided scopes
    let mut fingerprints: BTreeMap<(String, String), Fingerprint> = tx
        .prepare(
            "SELECT tenant, domain, value FROM feed_fingerprints \
            WHERE tenant = ?1 AND domain IN (SELECT value FROM json_each(?2))",
        )
        .map_err(sqlite_store_error)?
        .query_map(
            params![tenant, serde_json::to_string(scopes).unwrap()],
            |row| {
                Ok((
                    (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                    row.get::<_, [u8; 32]>(2)?,
                ))
            },
        )
        .map_err(sqlite_store_error)?
        .map(|res| res.map(|(scope, fingerprint)| (scope, fingerprint.into())))
        .collect::<Result<BTreeMap<(String, String), Fingerprint>, rusqlite::Error>>()
        .map_err(sqlite_store_error)?;

    fold_cid_into_domain(&mut fingerprints, tenant, message_cid, scopes);

    for ((_, scope), fp) in fingerprints.iter() {
        tx.execute(
            "INSERT INTO feed_fingerprints (tenant, scope, fingerprint) VALUES (?1, ?2, ?3) \
                ON CONFLICT(tenant, scope) DO UPDATE SET fingerprint = excluded.fingerprint",
            params![tenant, scope, fp.as_slice()],
        )
        .map_err(sqlite_store_error)?;
    }

    Ok(())
}
