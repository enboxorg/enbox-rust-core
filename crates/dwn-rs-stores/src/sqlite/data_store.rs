use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use dwn_rs_core::errors::{DataStoreError, StoreError};
use dwn_rs_core::stores::{DataStore, DataStoreGetResult, DataStorePutResult};

use crate::store::sqlite_store_error;
use crate::SqliteStore;

#[derive(Debug, Clone, Copy)]
struct DataBlockInfo {
    data_size: usize,
    ref_count: i64,
}

impl DataStore for SqliteStore {
    async fn open(&mut self) -> Result<(), DataStoreError> {
        self.connection()
            .await
            .map(|_| ())
            .map_err(DataStoreError::from)
    }

    async fn close(&mut self) {
        self.connection().await.ok().map(|conn| conn.close());
    }

    async fn put<T: Stream<Item = Bytes> + Send + Unpin>(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
        data_stream: T,
    ) -> Result<DataStorePutResult, DataStoreError> {
        let conn = self.connection().await?.clone();

        let (tenant, record_id, data_cid) = (
            tenant.to_string(),
            record_id.to_string(),
            data_cid.to_string(),
        );

        let (t, r, d) = (tenant.clone(), record_id.clone(), data_cid.clone());

        if let Some(data_size) = conn
            .with_writer(move |c| {
                let tx = c.transaction().map_err(sqlite_store_error)?;
                if let Some(sz) = data_ref_size(&tx, &t, &r, &d)? {
                    tx.commit().map_err(sqlite_store_error)?;
                    return Ok(Some(sz));
                }

                if let Some(b) = data_block_info(&tx, &d)? {
                    increment_data_block_ref_count(&tx, &d, b.ref_count + 1)?;
                    insert_data_ref(&tx, &t, &r, &d, b.data_size)?;
                    tx.commit().map_err(sqlite_store_error)?;
                    return Ok(Some(b.data_size));
                }
                tx.commit().map_err(sqlite_store_error)?;
                Ok(None)
            })
            .await
            .map_err(DataStoreError::from)?
        {
            return Ok(DataStorePutResult { data_size });
        }

        let bytes = collect_stream(data_stream).await?;
        let pending = bytes.len();
        let data_size = conn
            .with_writer(move |c| {
                let tx = c.transaction().map_err(sqlite_store_error)?;
                if let Some(sz) = data_ref_size(&tx, &tenant, &record_id, &data_cid)? {
                    tx.commit().map_err(sqlite_store_error)?;
                    return Ok(sz);
                }

                if let Some(b) = data_block_info(&tx, &data_cid)? {
                    increment_data_block_ref_count(&tx, &data_cid, b.ref_count + 1)?;
                    insert_data_ref(&tx, &tenant, &record_id, &data_cid, b.data_size)?;
                    tx.commit().map_err(sqlite_store_error)?;
                    return Ok(b.data_size);
                }

                tx.execute(
                    "INSERT INTO data_blocks (data_cid, data, data_size, ref_count) \
                 VALUES (?1, ?2, ?3, 1)",
                    params![data_cid, bytes, pending as i64],
                )
                .map_err(sqlite_store_error)?;

                insert_data_ref(&tx, &tenant, &record_id, &data_cid, pending)?;

                tx.commit().map_err(sqlite_store_error)?;

                Ok(pending)
            })
            .await
            .map_err(DataStoreError::from)?;

        Ok(DataStorePutResult { data_size })
    }

    async fn get(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> Result<Option<DataStoreGetResult>, DataStoreError> {
        let conn = self.connection().await?.clone();
        let tenant = tenant.to_string();
        let record_id = record_id.to_string();
        let data_cid = data_cid.to_string();
        let result = conn
            .with_reader(move |connection| {
                let Some(data_size) = data_ref_size(connection, &tenant, &record_id, &data_cid)?
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
            .await
            .map_err(DataStoreError::from)?;

        Ok(result.map(|(data_size, data)| DataStoreGetResult {
            data_size,
            data_stream: Box::pin(stream::once(async move { Ok(Bytes::from(data)) })),
        }))
    }

    async fn delete(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> Result<(), DataStoreError> {
        let conn = self.connection().await?.clone();

        let tenant = tenant.to_string();
        let record_id = record_id.to_string();
        let data_cid = data_cid.to_string();
        conn.with_writer(move |connection| {
            let tx = connection.transaction().map_err(sqlite_store_error)?;
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
        .await
        .map_err(DataStoreError::from)
    }

    async fn clear(&self) -> Result<(), DataStoreError> {
        let conn = self.connection().await?.clone();
        conn.with_writer(|connection| {
            let tx = connection.transaction().map_err(sqlite_store_error)?;

            tx.execute("DELETE FROM data_refs", [])
                .map_err(sqlite_store_error)?;
            tx.execute("DELETE FROM data_blocks", [])
                .map_err(sqlite_store_error)?;

            tx.commit().map_err(sqlite_store_error)?;
            Ok(())
        })
        .await
        .map_err(DataStoreError::from)
    }
}

fn data_ref_size(
    tx: &Connection,
    tenant: &str,
    record_id: &str,
    data_cid: &str,
) -> Result<Option<usize>, StoreError> {
    tx.query_row(
        "SELECT data_size FROM data_refs \
             WHERE tenant = ?1 AND record_id = ?2 AND data_cid = ?3",
        params![tenant, record_id, data_cid],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map_err(sqlite_store_error)
    .map(|size| size.map(|size| size as usize))
}

fn data_block_info(tx: &Transaction, data_cid: &str) -> Result<Option<DataBlockInfo>, StoreError> {
    tx.query_row(
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
    tx: &Transaction,
    data_cid: &str,
    ref_count: i64,
) -> Result<(), StoreError> {
    tx.execute(
        "UPDATE data_blocks SET ref_count = ?1 WHERE data_cid = ?2",
        params![ref_count, data_cid],
    )
    .map_err(sqlite_store_error)?;
    Ok(())
}

fn insert_data_ref(
    tx: &Transaction,
    tenant: &str,
    record_id: &str,
    data_cid: &str,
    data_size: usize,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO data_refs \
             (tenant, record_id, data_cid, data_size) \
             VALUES (?1, ?2, ?3, ?4)",
        params![tenant, record_id, data_cid, data_size as i64],
    )
    .map_err(sqlite_store_error)?;
    Ok(())
}

fn data_block_ref_count(tx: &Transaction, data_cid: &str) -> Result<Option<i64>, StoreError> {
    tx.query_row(
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
