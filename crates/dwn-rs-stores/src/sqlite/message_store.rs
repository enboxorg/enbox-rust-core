use std::collections::BTreeMap;

use dwn_rs_core::descriptors::records::write_tag_protocol;
use dwn_rs_core::descriptors::MessageDescriptor;
use dwn_rs_core::stores::replication_feed_reader::{
    build_token, fingerprint_scopes, fold_cid_into_domain, is_feed_message, scopes_unchanged,
    Fingerprint,
};
use dwn_rs_core::stores::wake::Wake;
use rusqlite::{params, OptionalExtension, Transaction};

use dwn_rs_core::errors::{MessageReplicationError, MessageStoreError, StoreError};
use dwn_rs_core::filters::Filters;
use dwn_rs_core::stores::{
    KeyValues, LatestStateMutation, LatestStateTransition, LatestStateTransitionResult,
    MessageQueryResult, MessageStore,
};
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
        self.connection().await.map_err(MessageStoreError::from)?;
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
        let message: Message<Descriptor> = message.into();
        let wake = self
            .connection()
            .await?
            .clone()
            .with_writer(move |connection| {
                let tx = connection.transaction().map_err(sqlite_store_error)?;
                let result =
                    put_message_tx(&tx, &tenant, LatestStateMutation { message, indexes })?;

                tx.commit().map_err(sqlite_store_error)?;
                Ok(result.wake)
            })
            .await
            .map_err(MessageStoreError::from)?;

        if let Some(wake) = wake {
            let _ = self.waker_publisher.publish(wake);
        }

        Ok(())
    }

    async fn commit_latest_state(
        &self,
        tenant: &str,
        transition: LatestStateTransition,
    ) -> Result<LatestStateTransitionResult, MessageStoreError> {
        transition.validate()?;
        let tenant = tenant.to_string();
        let (wake, position) = self
            .connection()
            .await?
            .clone()
            .with_writer(move |connection| {
                let tx = connection.transaction().map_err(sqlite_store_error)?;
                let epoch = SqliteStore::epoch_tx(&tx)?;
                let put_result = put_message_tx(&tx, &tenant, transition.put)?;
                for retained in transition.retains {
                    let retained_cid = retained
                        .message
                        .cid()
                        .map_err(|error| StoreError::InternalException(error.to_string()))?
                        .to_string();
                    if !message_exists(&tx, &tenant, &retained_cid)? {
                        return Err(StoreError::InternalException(format!(
                            "MessageStoreLatestStateRetainMissing: retained message '{retained_cid}' does not exist"
                        )));
                    }
                    put_message_tx(&tx, &tenant, retained)?;
                }
                for cid in transition.deletes {
                    delete_message_tx(&tx, &tenant, &cid)?;
                }

                let position = put_result.position.map(|(position, cid)| {
                    build_token(&tenant, &epoch, position as u64, Some(&cid))
                });
                tx.commit().map_err(sqlite_store_error)?;
                Ok((put_result.wake, position))
            })
            .await
            .map_err(MessageStoreError::from)?;

        if let Some(wake) = wake {
            let _ = self.waker_publisher.publish(wake);
        }
        Ok(LatestStateTransitionResult { position })
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
            delete_message_tx(&tx, &tenant, &cid)?;

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
                tx.execute_batch(
                    "
                        DELETE FROM messages;
                        DELETE FROM feed_metadata;
                        DELETE FROM feed_entries;
                        DELETE FROM feed_fingerprints;
                        DELETE FROM feed_heads;
                    ",
                )
                .map_err(sqlite_store_error)?;

                generate_epoch(&tx)?;

                tx.commit().map_err(sqlite_store_error)?;

                Ok(())
            })
            .await
            .map_err(MessageStoreError::from)
        }
        .await
    }
}

impl SqliteStore {
    fn index_update_error(code: &str, detail: String) -> MessageStoreError {
        MessageStoreError::from(StoreError::InternalException(format!("{code}: {detail}")))
    }

    /// Replaces a message's indexes wholesale (TS `updateIndexes`).
    ///
    /// Same row and feed position; stale columns disappear because the
    /// indexes document is replaced, not merged. Fingerprint scopes must be
    /// unchanged, exactly as for same-CID puts.
    pub async fn update_indexes(
        &self,
        tenant: &str,
        cid: &str,
        indexes: KeyValues,
    ) -> Result<(), MessageStoreError> {
        let conn = self.connection().await?.clone();
        let tenant = tenant.to_string();
        let cid = cid.to_string();

        conn.with_writer(move |connection| {
            let tx = connection.transaction().map_err(sqlite_store_error)?;
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM messages WHERE tenant = ?1 AND message_cid = ?2)",
                    params![tenant, cid],
                    |row| row.get(0),
                )
                .map_err(sqlite_store_error)?;
            if !exists {
                return Err(StoreError::InternalException(format!(
                    "MessageStoreUpdateIndexesMessageNotFound: no message {cid} for tenant {tenant}"
                )));
            }

            let indexes_json = serde_json::to_string(&indexes)
                .map_err(|err| StoreError::InternalException(err.to_string()))?;
            if let Some(entry) = select_feed_entry(&tx, &tenant, &cid)? {
                let msg_scopes = fingerprint_scopes_from_indexes(&indexes);
                if !scopes_unchanged(&entry.fingerprint_scopes, &msg_scopes) {
                    return Err(StoreError::InternalException(
                        "MessageStoreFingerprintScopeMutation: replacement indexes change fingerprint scopes"
                            .to_string(),
                    ));
                }
                update_feed_entry_indexes(&tx, &tenant, &entry, &indexes)?;
            }
            tx.execute(
                "UPDATE messages SET indexes_json = ?3 WHERE tenant = ?1 AND message_cid = ?2",
                params![tenant, cid, indexes_json],
            )
            .map_err(sqlite_store_error)?;
            tx.commit().map_err(sqlite_store_error)?;
            Ok(())
        })
        .await
        .map_err(MessageStoreError::from)?;
        Ok(())
    }

    /// Replaces a message payload and its indexes (TS `updateMessageAndIndexes`).
    ///
    /// Rejects replacements whose CID does not match the target, without
    /// touching the stored row.
    pub async fn update_message_and_indexes(
        &self,
        tenant: &str,
        cid: &str,
        message: Message<Descriptor>,
        indexes: KeyValues,
    ) -> Result<(), MessageStoreError> {
        let computed = message
            .cid()
            .map_err(|err| {
                Self::index_update_error(
                    "MessageStoreUpdateMessageAndIndexesCidMismatch",
                    format!("cannot compute replacement CID: {err}"),
                )
            })?
            .to_string();
        if computed != cid {
            return Err(Self::index_update_error(
                "MessageStoreUpdateMessageAndIndexesCidMismatch",
                format!("replacement message CID {computed} does not match target CID {cid}"),
            ));
        }
        let message_json = serde_json::to_string(&message).map_err(MessageStoreError::from)?;

        let conn = self.connection().await?.clone();
        let tenant = tenant.to_string();
        let cid = cid.to_string();

        conn.with_writer(move |connection| {
            let tx = connection.transaction().map_err(sqlite_store_error)?;
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM messages WHERE tenant = ?1 AND message_cid = ?2)",
                    params![tenant, cid],
                    |row| row.get(0),
                )
                .map_err(sqlite_store_error)?;
            if !exists {
                return Err(StoreError::InternalException(format!(
                    "MessageStoreUpdateMessageAndIndexesMessageNotFound: no message {cid} for tenant {tenant}"
                )));
            }

            let indexes_json = serde_json::to_string(&indexes)
                .map_err(|err| StoreError::InternalException(err.to_string()))?;
            if let Some(entry) = select_feed_entry(&tx, &tenant, &cid)? {
                let msg_scopes = fingerprint_scopes_from_indexes(&indexes);
                if !scopes_unchanged(&entry.fingerprint_scopes, &msg_scopes) {
                    return Err(StoreError::InternalException(
                        "MessageStoreFingerprintScopeMutation: replacement indexes change fingerprint scopes"
                            .to_string(),
                    ));
                }
                update_feed_entry_indexes(&tx, &tenant, &entry, &indexes)?;
            }
            tx.execute(
                "UPDATE messages SET message_json = ?3, indexes_json = ?4 WHERE tenant = ?1 AND message_cid = ?2",
                params![tenant, cid, message_json, indexes_json],
            )
            .map_err(sqlite_store_error)?;
            tx.commit().map_err(sqlite_store_error)?;
            Ok(())
        })
        .await
        .map_err(MessageStoreError::from)?;
        Ok(())
    }
}

/// Fingerprint scopes derived from replacement indexes without a message.
///
/// `fingerprint_scopes` needs the descriptor tag protocol, which replacement
/// indexes may not carry; scope membership for the mutation check comes from
/// the `protocol` / `tag.protocol` indexes, matching how puts compute it for
/// index-only updates.
fn fingerprint_scopes_from_indexes(indexes: &KeyValues) -> Vec<String> {
    fingerprint_scopes(None, indexes)
}

pub(crate) fn generate_epoch(tx: &Transaction) -> Result<usize, StoreError> {
    tx.execute(
        "INSERT INTO feed_metadata (id, epoch) VALUES (1, ?1)",
        [Uuid::new_v4().to_string()],
    )
    .map_err(sqlite_store_error)
}

struct PutMessageResult {
    wake: Option<Wake>,
    position: Option<(i64, String)>,
}

fn put_message_tx(
    tx: &Transaction,
    tenant: &str,
    mutation: LatestStateMutation,
) -> Result<PutMessageResult, StoreError> {
    let LatestStateMutation { message, indexes } = mutation;
    let message_json = serde_json::to_string(&message)
        .map_err(|error| StoreError::InternalException(error.to_string()))?;
    let message_cid = message
        .cid()
        .map_err(|error| StoreError::InternalException(error.to_string()))?
        .to_string();
    let indexes_json = serde_json::to_string(&indexes)
        .map_err(|error| StoreError::InternalException(error.to_string()))?;

    if !is_feed_message(&message) {
        insert_message(tx, tenant, &message_cid, &message_json, &indexes_json)?;
        return Ok(PutMessageResult {
            wake: None,
            position: None,
        });
    }

    let msg_scopes = fingerprint_scopes(write_tag_protocol(&message), &indexes);
    match select_feed_entry(tx, tenant, &message_cid)? {
        Some(entry) => {
            if !scopes_unchanged(&entry.fingerprint_scopes, &msg_scopes) {
                return Err(StoreError::ReplicationError(
                    MessageReplicationError::FingerprintScopesMismatch,
                ));
            }
            insert_message(tx, tenant, &message_cid, &message_json, &indexes_json)?;
            update_feed_entry_indexes(tx, tenant, &entry, &indexes)?;
            Ok(PutMessageResult {
                wake: None,
                position: Some((entry.position, message_cid)),
            })
        }
        None => {
            let next = next_position(tx, tenant)?;
            insert_message(tx, tenant, &message_cid, &message_json, &indexes_json)?;
            insert_feed_entry(
                tx,
                &FeedEntry {
                    tenant: tenant.to_string(),
                    position: next,
                    message_cid: message_cid.clone(),
                    indexes,
                    fingerprint_scopes: msg_scopes.clone(),
                },
            )?;
            update_feed_head(tx, tenant, next)?;
            upsert_feed_fingerprint(tx, tenant, &message_cid, &msg_scopes)?;
            Ok(PutMessageResult {
                wake: Some(Wake {
                    tenant: tenant.to_string(),
                    position: next as u64,
                }),
                position: Some((next, message_cid)),
            })
        }
    }
}

fn delete_message_tx(tx: &Transaction, tenant: &str, cid: &str) -> Result<(), StoreError> {
    let feed_entry = select_feed_entry(tx, tenant, cid)?
        .map(|entry| (entry.message_cid, entry.fingerprint_scopes));

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

    if let Some((feed_cid, scopes)) = feed_entry {
        upsert_feed_fingerprint(tx, tenant, &feed_cid, &scopes)?;
    }
    Ok(())
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

fn message_exists(tx: &Transaction, tenant: &str, message_cid: &str) -> Result<bool, StoreError> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM messages WHERE tenant = ?1 AND message_cid = ?2)",
        params![tenant, message_cid],
        |row| row.get(0),
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

pub(crate) fn select_feed_entry_by_position(
    tx: &Transaction,
    tenant: &str,
    position: i64,
) -> Result<Option<FeedEntry>, StoreError> {
    let mut stmt = tx
        .prepare(
            "SELECT tenant, position, message_cid, indexes_json, fingerprint_scopes_json \
            FROM feed_entries \
            WHERE tenant = ?1 AND position = ?2
            LIMIT 1",
        )
        .map_err(sqlite_store_error)?;

    stmt.query_row(params![tenant, position], |row| {
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

    let indexes_json = serde_json::to_string(&entry.indexes)
        .map_err(|err| StoreError::InternalException(err.to_string()))?;

    tx.execute(
        "INSERT INTO feed_entries \
            (tenant, position, message_cid, indexes_json, fingerprint_scopes_json) \
            VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            entry.tenant,
            entry.position,
            entry.message_cid,
            indexes_json,
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
    let mut fingerprints = get_feed_fingerprints(tx, tenant, scopes)?;
    fold_cid_into_domain(&mut fingerprints, tenant, message_cid, scopes);

    for ((_, scope), fp) in fingerprints.iter() {
        tx.execute(
            "INSERT INTO feed_fingerprints (tenant, domain, value) VALUES (?1, ?2, ?3) \
                ON CONFLICT(tenant, domain) DO UPDATE SET value = excluded.value",
            params![tenant, scope, fp.as_slice()],
        )
        .map_err(sqlite_store_error)?;
    }

    Ok(())
}

// select all the feed_fingerprints for the tenant across all the
// provided scopes
pub(crate) fn get_feed_fingerprints(
    tx: &Transaction,
    tenant: &str,
    scopes: &[String],
) -> Result<BTreeMap<(String, String), Fingerprint>, StoreError> {
    tx.prepare(
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
    .map_err(sqlite_store_error)
}

pub(crate) fn get_single_feed_fingerprint(
    tx: &Transaction,
    tenant: &str,
    scope: &str,
) -> Result<Option<Fingerprint>, StoreError> {
    tx.query_row(
        "SELECT value FROM feed_fingerprints \
            WHERE tenant = ?1 AND domain = ?2
            LIMIT 1",
        params![tenant, scope],
        |row| row.get::<_, [u8; 32]>(0),
    )
    .optional()
    .map(|opt| opt.map(Fingerprint::from))
    .map_err(sqlite_store_error)
}
