use std::cmp::Ordering;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use rusqlite::{params, Connection, OptionalExtension};

use dwn_rs_core::errors::{DataStoreError, MessageStoreError, StoreError};
use dwn_rs_core::fields::MessageFields;
use dwn_rs_core::filters::{compare_values, matches_filters, Filters};
use dwn_rs_core::stores::{
    EnboxDataStore, EnboxDataStoreGetResult, EnboxDataStorePutResult, EnboxMessageQueryResult,
    EnboxMessageStore, KeyValues,
};
use dwn_rs_core::{Cursor, Descriptor, Message, MessageSort, Pagination, SortDirection, Value};

#[derive(Debug, Clone)]
pub struct SqliteStore {
    path: Arc<PathBuf>,
    connection: Arc<Mutex<Option<Connection>>>,
}

#[derive(Debug, Clone)]
struct MessageRow {
    cid: String,
    message: Message<Descriptor>,
    indexes: KeyValues,
}

#[derive(Debug, Clone, Copy)]
struct DataBlockInfo {
    data_size: usize,
    ref_count: i64,
}

impl Default for SqliteStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl SqliteStore {
    pub fn in_memory() -> Self {
        Self::new(":memory:")
    }

    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: Arc::new(path.as_ref().to_path_buf()),
            connection: Arc::new(Mutex::new(None)),
        }
    }

    fn open_connection(&self) -> Result<(), StoreError> {
        let mut connection = self.lock_connection()?;
        if connection.is_some() {
            return Ok(());
        }

        let db = Connection::open(self.path.as_path()).map_err(sqlite_store_error)?;
        migrate(&db)?;
        *connection = Some(db);
        Ok(())
    }

    fn close_connection(&self) {
        if let Ok(mut connection) = self.connection.lock() {
            *connection = None;
        }
    }

    fn with_connection<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let connection = self.lock_connection()?;
        let connection = connection.as_ref().ok_or(StoreError::NoInitError)?;
        f(connection)
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Option<Connection>>, StoreError> {
        self.connection.lock().map_err(|_| {
            StoreError::InternalException("SQLite connection lock poisoned".to_string())
        })
    }
}

impl EnboxMessageStore for SqliteStore {
    async fn open(&mut self) -> Result<(), MessageStoreError> {
        self.open_connection().map_err(MessageStoreError::from)
    }

    async fn close(&mut self) {
        self.close_connection();
    }

    fn put(
        &self,
        tenant: &str,
        message: Message<Descriptor>,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        async move {
            let mut cid_message = message.clone();
            cid_message.fields.encoded_data();
            let message_cid = cid_message
                .cid()
                .map_err(MessageStoreError::SerdeEncodeError)?
                .to_string();
            let message_json = serde_json::to_string(&message).map_err(message_json_error)?;
            let indexes_json = serde_json::to_string(&indexes).map_err(message_json_error)?;

            store
                .with_connection(|connection| {
                    connection
                        .execute(
                            "INSERT OR REPLACE INTO messages \
                             (tenant, message_cid, message_json, indexes_json) \
                             VALUES (?1, ?2, ?3, ?4)",
                            params![tenant, message_cid, message_json, indexes_json],
                        )
                        .map_err(sqlite_store_error)?;
                    Ok(())
                })
                .map_err(MessageStoreError::from)
        }
    }

    fn get(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<Option<Message<Descriptor>>, MessageStoreError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        let cid = cid.to_string();
        async move {
            let message_json = store
                .with_connection(|connection| {
                    connection
                        .query_row(
                            "SELECT message_json FROM messages \
                             WHERE tenant = ?1 AND message_cid = ?2",
                            params![tenant, cid],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .map_err(sqlite_store_error)
                })
                .map_err(MessageStoreError::from)?;

            message_json
                .map(|message_json| {
                    serde_json::from_str::<Message<Descriptor>>(&message_json)
                        .map_err(message_json_error)
                })
                .transpose()
        }
    }

    fn query(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
        pagination: Option<Pagination>,
    ) -> impl Future<Output = Result<EnboxMessageQueryResult, MessageStoreError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        async move {
            let mut rows = store
                .with_connection(|connection| load_message_rows(connection, &tenant))
                .map_err(MessageStoreError::from)?;
            rows.retain(|row| matches_filters(&row.indexes, Some(&filters)));
            let sort = sort.unwrap_or_default();
            retain_sortable_rows(&mut rows, sort);
            sort_message_rows(&mut rows, sort);

            let (rows, cursor) = apply_pagination(rows, sort, pagination)?;
            Ok(EnboxMessageQueryResult {
                messages: rows.into_iter().map(|row| row.message).collect(),
                cursor,
            })
        }
    }

    fn count(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
    ) -> impl Future<Output = Result<u64, MessageStoreError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        async move {
            let mut rows = store
                .with_connection(|connection| load_message_rows(connection, &tenant))
                .map_err(MessageStoreError::from)?;
            rows.retain(|row| matches_filters(&row.indexes, Some(&filters)));
            retain_sortable_rows(&mut rows, sort.unwrap_or_default());
            Ok(rows.len() as u64)
        }
    }

    fn delete(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        let cid = cid.to_string();
        async move {
            store
                .with_connection(|connection| {
                    connection
                        .execute(
                            "DELETE FROM messages WHERE tenant = ?1 AND message_cid = ?2",
                            params![tenant, cid],
                        )
                        .map_err(sqlite_store_error)?;
                    Ok(())
                })
                .map_err(MessageStoreError::from)
        }
    }

    fn clear(&self) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
        let store = self.clone();
        async move {
            store
                .with_connection(|connection| {
                    connection
                        .execute("DELETE FROM messages", [])
                        .map_err(sqlite_store_error)?;
                    Ok(())
                })
                .map_err(MessageStoreError::from)
        }
    }
}

impl EnboxDataStore for SqliteStore {
    async fn open(&mut self) -> Result<(), DataStoreError> {
        self.open_connection().map_err(DataStoreError::from)
    }

    async fn close(&mut self) {
        self.close_connection();
    }

    fn put<T: Stream<Item = Bytes> + Send + Unpin>(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
        data_stream: T,
    ) -> impl Future<Output = Result<EnboxDataStorePutResult, DataStoreError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        let record_id = record_id.to_string();
        let data_cid = data_cid.to_string();
        async move {
            if let Some(data_size) = store
                .with_connection(|connection| {
                    let tx = connection
                        .unchecked_transaction()
                        .map_err(sqlite_store_error)?;
                    if let Some(data_size) = data_ref_size(&tx, &tenant, &record_id, &data_cid)? {
                        tx.commit().map_err(sqlite_store_error)?;
                        return Ok(Some(data_size));
                    }
                    if let Some(block) = data_block_info(&tx, &data_cid)? {
                        increment_data_block_ref_count(&tx, &data_cid, block.ref_count + 1)?;
                        insert_data_ref(&tx, &tenant, &record_id, &data_cid, block.data_size)?;
                        tx.commit().map_err(sqlite_store_error)?;
                        return Ok(Some(block.data_size));
                    }
                    tx.commit().map_err(sqlite_store_error)?;
                    Ok(None)
                })
                .map_err(DataStoreError::from)?
            {
                return Ok(EnboxDataStorePutResult { data_size });
            }

            let bytes = collect_stream(data_stream).await?;
            let pending_data_size = bytes.len();
            let data_size = store
                .with_connection(|connection| {
                    let tx = connection
                        .unchecked_transaction()
                        .map_err(sqlite_store_error)?;
                    if let Some(data_size) = data_ref_size(&tx, &tenant, &record_id, &data_cid)? {
                        tx.commit().map_err(sqlite_store_error)?;
                        return Ok(data_size);
                    }
                    if let Some(block) = data_block_info(&tx, &data_cid)? {
                        increment_data_block_ref_count(&tx, &data_cid, block.ref_count + 1)?;
                        insert_data_ref(&tx, &tenant, &record_id, &data_cid, block.data_size)?;
                        tx.commit().map_err(sqlite_store_error)?;
                        return Ok(block.data_size);
                    }
                    tx.execute(
                        "INSERT INTO data_blocks \
                         (data_cid, data, data_size, ref_count) \
                         VALUES (?1, ?2, ?3, 1)",
                        params![data_cid, bytes, pending_data_size as i64],
                    )
                    .map_err(sqlite_store_error)?;
                    insert_data_ref(&tx, &tenant, &record_id, &data_cid, pending_data_size)?;
                    tx.commit().map_err(sqlite_store_error)?;
                    Ok(pending_data_size)
                })
                .map_err(DataStoreError::from)?;

            Ok(EnboxDataStorePutResult { data_size })
        }
    }

    fn get(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> impl Future<Output = Result<Option<EnboxDataStoreGetResult>, DataStoreError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        let record_id = record_id.to_string();
        let data_cid = data_cid.to_string();
        async move {
            let result = store
                .with_connection(|connection| {
                    let Some(data_size) =
                        data_ref_size(connection, &tenant, &record_id, &data_cid)?
                    else {
                        return Ok(None);
                    };
                    let data = connection
                        .query_row(
                            "SELECT data FROM data_blocks WHERE data_cid = ?1",
                            params![data_cid],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .optional()
                        .map_err(sqlite_store_error)?;
                    Ok(data.map(|data| (data_size, data)))
                })
                .map_err(DataStoreError::from)?;

            Ok(result.map(|(data_size, data)| EnboxDataStoreGetResult {
                data_size,
                data_stream: Box::pin(stream::once(async move { Ok(Bytes::from(data)) })),
            }))
        }
    }

    fn delete(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> impl Future<Output = Result<(), DataStoreError>> + Send {
        let store = self.clone();
        let tenant = tenant.to_string();
        let record_id = record_id.to_string();
        let data_cid = data_cid.to_string();
        async move {
            store
                .with_connection(|connection| {
                    let tx = connection
                        .unchecked_transaction()
                        .map_err(sqlite_store_error)?;
                    let deleted = tx
                        .execute(
                            "DELETE FROM data_refs \
                             WHERE tenant = ?1 AND record_id = ?2 AND data_cid = ?3",
                            params![tenant, record_id, data_cid],
                        )
                        .map_err(sqlite_store_error)?;
                    if deleted > 0 {
                        if let Some(ref_count) = data_block_ref_count(&tx, &data_cid)? {
                            if ref_count <= 1 {
                                tx.execute(
                                    "DELETE FROM data_blocks WHERE data_cid = ?1",
                                    params![data_cid],
                                )
                                .map_err(sqlite_store_error)?;
                            } else {
                                tx.execute(
                                    "UPDATE data_blocks SET ref_count = ?1 WHERE data_cid = ?2",
                                    params![ref_count - 1, data_cid],
                                )
                                .map_err(sqlite_store_error)?;
                            }
                        }
                    }
                    tx.commit().map_err(sqlite_store_error)?;
                    Ok(())
                })
                .map_err(DataStoreError::from)
        }
    }

    fn clear(&self) -> impl Future<Output = Result<(), DataStoreError>> + Send {
        let store = self.clone();
        async move {
            store
                .with_connection(|connection| {
                    connection
                        .execute("DELETE FROM data_refs", [])
                        .map_err(sqlite_store_error)?;
                    connection
                        .execute("DELETE FROM data_blocks", [])
                        .map_err(sqlite_store_error)?;
                    Ok(())
                })
                .map_err(DataStoreError::from)
        }
    }
}

fn migrate(connection: &Connection) -> Result<(), StoreError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                tenant TEXT NOT NULL,
                message_cid TEXT NOT NULL,
                message_json TEXT NOT NULL,
                indexes_json TEXT NOT NULL,
                PRIMARY KEY (tenant, message_cid)
            );

            CREATE TABLE IF NOT EXISTS data_blocks (
                data_cid TEXT PRIMARY KEY,
                data BLOB NOT NULL,
                data_size INTEGER NOT NULL,
                ref_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS data_refs (
                tenant TEXT NOT NULL,
                record_id TEXT NOT NULL,
                data_cid TEXT NOT NULL,
                data_size INTEGER NOT NULL,
                PRIMARY KEY (tenant, record_id, data_cid),
                FOREIGN KEY (data_cid) REFERENCES data_blocks(data_cid)
            );",
        )
        .map_err(sqlite_store_error)
}

fn load_message_rows(connection: &Connection, tenant: &str) -> Result<Vec<MessageRow>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT message_cid, message_json, indexes_json FROM messages \
             WHERE tenant = ?1",
        )
        .map_err(sqlite_store_error)?;
    let rows = statement
        .query_map(params![tenant], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_store_error)?;

    let mut messages = Vec::new();
    for row in rows {
        let (cid, message_json, indexes_json) = row.map_err(sqlite_store_error)?;
        messages.push(MessageRow {
            cid,
            message: serde_json::from_str(&message_json).map_err(json_store_error)?,
            indexes: serde_json::from_str(&indexes_json).map_err(json_store_error)?,
        });
    }
    Ok(messages)
}

fn retain_sortable_rows(rows: &mut Vec<MessageRow>, sort: MessageSort) {
    let (property, _) = sort_property(&sort);
    rows.retain(|row| row.indexes.contains_key(property));
}

fn sort_message_rows(rows: &mut [MessageRow], sort: MessageSort) {
    let (property, direction) = sort_property(&sort);
    rows.sort_by(|left, right| {
        let value_order = compare_sort_values(
            left.indexes.get(property),
            right.indexes.get(property),
            direction,
        );
        value_order.then_with(|| compare_strings(&left.cid, &right.cid, direction))
    });
}

fn apply_pagination(
    rows: Vec<MessageRow>,
    sort: MessageSort,
    pagination: Option<Pagination>,
) -> Result<(Vec<MessageRow>, Option<Cursor>), MessageStoreError> {
    let Some(pagination) = pagination else {
        return Ok((rows, None));
    };

    let start = pagination
        .cursor
        .as_ref()
        .map(|cursor| cursor_start(&rows, sort, cursor))
        .unwrap_or(0);
    let mut page = rows.into_iter().skip(start).collect::<Vec<_>>();

    let cursor = if let Some(limit) = pagination.limit {
        let limit = limit as usize;
        if limit == 0 {
            page.clear();
            return Ok((page, None));
        }
        if limit > 0 && page.len() > limit {
            page.truncate(limit);
            page.last()
                .map(|last| message_cursor(last, sort))
                .transpose()?
        } else {
            None
        }
    } else {
        None
    };

    Ok((page, cursor))
}

fn cursor_start(rows: &[MessageRow], sort: MessageSort, cursor: &Cursor) -> usize {
    let (property, direction) = sort_property(&sort);
    let cursor_cid = cursor.cursor.to_string();
    let Some(cursor_value) = cursor.value.as_ref() else {
        return rows
            .iter()
            .position(|row| row.cid == cursor_cid)
            .map(|position| position + 1)
            .unwrap_or(rows.len());
    };

    rows.iter()
        .position(|row| {
            let Some(row_value) = row.indexes.get(property) else {
                return false;
            };
            let ordering = compare_sort_values_inner(row_value, cursor_value)
                .unwrap_or(Ordering::Equal)
                .then_with(|| row.cid.cmp(&cursor_cid));
            match direction {
                SortDirection::Ascending => ordering == Ordering::Greater,
                SortDirection::Descending => ordering == Ordering::Less,
            }
        })
        .unwrap_or(rows.len())
}

fn message_cursor(row: &MessageRow, sort: MessageSort) -> Result<Cursor, MessageStoreError> {
    let (property, _) = sort_property(&sort);
    Ok(Cursor {
        cursor: row.cid.parse().map_err(|err| {
            MessageStoreError::StoreError(StoreError::InternalException(format!(
                "invalid SQLite message CID: {err}"
            )))
        })?,
        value: row.indexes.get(property).cloned(),
    })
}

fn sort_property(sort: &MessageSort) -> (&'static str, SortDirection) {
    match sort {
        MessageSort::DateCreated(direction) => ("dateCreated", *direction),
        MessageSort::DatePublished(direction) => ("datePublished", *direction),
        MessageSort::Timestamp(direction) => ("messageTimestamp", *direction),
    }
}

fn compare_sort_values(
    left: Option<&Value>,
    right: Option<&Value>,
    direction: SortDirection,
) -> Ordering {
    let order = match (left, right) {
        (Some(left), Some(right)) => {
            compare_sort_values_inner(left, right).unwrap_or(Ordering::Equal)
        }
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    };
    apply_direction(order, direction)
}

fn compare_strings(left: &str, right: &str, direction: SortDirection) -> Ordering {
    apply_direction(left.cmp(right), direction)
}

fn apply_direction(order: Ordering, direction: SortDirection) -> Ordering {
    match direction {
        SortDirection::Ascending => order,
        SortDirection::Descending => order.reverse(),
    }
}

/// Sort-time comparison that falls back to string-coerced ordering when
/// the two values are not naturally comparable. The shared filter engine
/// in `dwn_rs_core::filters::compare_values` deliberately returns `None`
/// in that case (range filters should not match across variants); SQLite
/// sorting needs a total order, so we keep this softer comparator here.
fn compare_sort_values_inner(left: &Value, right: &Value) -> Option<Ordering> {
    if let Some(order) = compare_values(left, right) {
        return Some(order);
    }
    value_as_string(left)?.partial_cmp(&value_as_string(right)?)
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::DateTime(value) => Some(value.to_rfc3339()),
        Value::Cid(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Float(value) => Some(value.to_string()),
        Value::Null | Value::Map(_) | Value::Array(_) => None,
    }
}

fn data_ref_size(
    connection: &Connection,
    tenant: &str,
    record_id: &str,
    data_cid: &str,
) -> Result<Option<usize>, StoreError> {
    connection
        .query_row(
            "SELECT data_size FROM data_refs \
             WHERE tenant = ?1 AND record_id = ?2 AND data_cid = ?3",
            params![tenant, record_id, data_cid],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_store_error)
        .map(|size| size.map(|size| size as usize))
}

fn data_block_info(
    connection: &Connection,
    data_cid: &str,
) -> Result<Option<DataBlockInfo>, StoreError> {
    connection
        .query_row(
            "SELECT data_size, ref_count FROM data_blocks WHERE data_cid = ?1",
            params![data_cid],
            |row| {
                Ok(DataBlockInfo {
                    data_size: row.get::<_, i64>(0)? as usize,
                    ref_count: row.get::<_, i64>(1)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_store_error)
}

fn increment_data_block_ref_count(
    connection: &Connection,
    data_cid: &str,
    ref_count: i64,
) -> Result<(), StoreError> {
    connection
        .execute(
            "UPDATE data_blocks SET ref_count = ?1 WHERE data_cid = ?2",
            params![ref_count, data_cid],
        )
        .map_err(sqlite_store_error)?;
    Ok(())
}

fn insert_data_ref(
    connection: &Connection,
    tenant: &str,
    record_id: &str,
    data_cid: &str,
    data_size: usize,
) -> Result<(), StoreError> {
    connection
        .execute(
            "INSERT INTO data_refs \
             (tenant, record_id, data_cid, data_size) \
             VALUES (?1, ?2, ?3, ?4)",
            params![tenant, record_id, data_cid, data_size as i64],
        )
        .map_err(sqlite_store_error)?;
    Ok(())
}

fn data_block_ref_count(
    connection: &Connection,
    data_cid: &str,
) -> Result<Option<i64>, StoreError> {
    connection
        .query_row(
            "SELECT ref_count FROM data_blocks WHERE data_cid = ?1",
            params![data_cid],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_store_error)
}

async fn collect_stream<T: Stream<Item = Bytes> + Send + Unpin>(
    mut stream: T,
) -> Result<Vec<u8>, DataStoreError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn sqlite_store_error(error: rusqlite::Error) -> StoreError {
    StoreError::InternalException(error.to_string())
}

fn message_json_error(error: serde_json::Error) -> MessageStoreError {
    MessageStoreError::StoreError(json_store_error(error))
}

fn json_store_error(error: serde_json::Error) -> StoreError {
    StoreError::InternalException(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use futures_util::TryStreamExt;

    use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
    use dwn_rs_core::descriptors::{Records, RecordsWriteDescriptor};
    use dwn_rs_core::fields::WriteFields;
    use dwn_rs_core::filters::{Filter, FilterKey};
    use dwn_rs_core::Fields;

    use super::*;

    #[tokio::test]
    async fn sqlite_store_migrates_schema_on_open() {
        let mut store = SqliteStore::in_memory();
        EnboxMessageStore::open(&mut store).await.unwrap();

        let tables = store
            .with_connection(|connection| {
                let mut statement = connection
                    .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
                    .map_err(sqlite_store_error)?;
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(sqlite_store_error)?;
                let mut tables = BTreeSet::new();
                for row in rows {
                    tables.insert(row.map_err(sqlite_store_error)?);
                }
                Ok(tables)
            })
            .unwrap();

        assert!(tables.contains("messages"));
        assert!(tables.contains("data_blocks"));
        assert!(tables.contains("data_refs"));
    }

    #[tokio::test]
    async fn message_store_roundtrips_inline_data_without_changing_message_cid() {
        let mut store = SqliteStore::in_memory();
        EnboxMessageStore::open(&mut store).await.unwrap();
        let message = message(
            "2025-01-01T00:00:00.000000Z",
            Some("https://example.com/protocol/notes"),
            Some("aGVsbG8"),
        );
        let mut cid_message = message.clone();
        cid_message.fields.encoded_data();
        let cid = cid_message.cid().unwrap().to_string();

        EnboxMessageStore::put(
            &store,
            "did:example:alice",
            message.clone(),
            indexes(&message),
        )
        .await
        .unwrap();

        assert_eq!(
            EnboxMessageStore::get(&store, "did:example:alice", &cid)
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
        EnboxMessageStore::open(&mut store).await.unwrap();
        EnboxMessageStore::put(
            &store,
            "did:example:alice",
            message.clone(),
            indexes(&message),
        )
        .await
        .unwrap();
        EnboxMessageStore::close(&mut store).await;

        let mut reopened = SqliteStore::new(&path);
        EnboxMessageStore::open(&mut reopened).await.unwrap();
        assert_eq!(
            EnboxMessageStore::get(&reopened, "did:example:alice", &cid)
                .await
                .unwrap(),
            Some(message)
        );
        EnboxMessageStore::close(&mut reopened).await;
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn message_store_filters_sorts_counts_and_paginates() {
        let mut store = SqliteStore::in_memory();
        EnboxMessageStore::open(&mut store).await.unwrap();
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
            EnboxMessageStore::put(
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
        EnboxMessageStore::put(&store, "did:example:alice", third.clone(), third_indexes)
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
        EnboxMessageStore::put(
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
        EnboxDataStore::open(&mut store).await.unwrap();
        let bytes = Bytes::from_static(b"hello sqlite data");
        let data_cid = generate_dag_pb_cid_from_bytes(&bytes).to_string();

        let put = EnboxDataStore::put(
            &store,
            "did:example:alice",
            "record-1",
            &data_cid,
            stream::iter(vec![bytes.clone()]),
        )
        .await
        .unwrap();
        assert_eq!(put.data_size, bytes.len());

        let duplicate = EnboxDataStore::put(
            &store,
            "did:example:alice",
            "record-1",
            &data_cid,
            stream::iter(vec![Bytes::from_static(b"ignored duplicate stream")]),
        )
        .await
        .unwrap();
        assert_eq!(duplicate.data_size, bytes.len());

        let shared = EnboxDataStore::put(
            &store,
            "did:example:alice",
            "record-2",
            &data_cid,
            stream::iter(vec![Bytes::from_static(b"ignored shared stream")]),
        )
        .await
        .unwrap();
        assert_eq!(shared.data_size, bytes.len());

        EnboxDataStore::delete(&store, "did:example:alice", "record-1", &data_cid)
            .await
            .unwrap();
        let stored = EnboxDataStore::get(&store, "did:example:alice", "record-2", &data_cid)
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

        EnboxDataStore::delete(&store, "did:example:alice", "record-2", &data_cid)
            .await
            .unwrap();
        assert!(
            EnboxDataStore::get(&store, "did:example:alice", "record-2", &data_cid)
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
