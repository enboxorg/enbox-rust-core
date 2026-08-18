use crate::sqlite::migrations::rust::durable_message_feed::run as durable_message_feed;
use dwn_rs_core::errors::StoreError;
use rusqlite::{params, Connection, Transaction};

use super::sqlite_store_error;

pub(crate) struct DataMigration {
    pub(crate) version: i64,
    pub(crate) name: &'static str,
    pub(crate) migrate: fn(&Transaction<'_>) -> Result<(), StoreError>,
}

pub(crate) const DATA_MIGRATIONS: &[DataMigration] = &[DataMigration {
    version: 1,
    name: "initialize_durable_message_feed",
    migrate: durable_message_feed,
}];

pub(crate) fn run_data_migrations(
    connection: &mut Connection,
    migrations: &[DataMigration],
) -> Result<(), StoreError> {
    for migration in migrations {
        let tx = connection.transaction().map_err(sqlite_store_error)?;

        if rust_migration_applied(&tx, migration.version)? {
            tx.commit().map_err(sqlite_store_error)?;
            continue;
        }

        (migration.migrate)(&tx)?;
        record_rust_migration(&tx, migration.version, migration.name)?;
        tx.commit().map_err(sqlite_store_error)?;
    }

    Ok(())
}

pub(crate) fn rust_migration_applied(
    tx: &Transaction<'_>,
    version: i64,
) -> Result<bool, StoreError> {
    let mut stmt = tx
        .prepare("SELECT COUNT(*) FROM migrations WHERE version = ?")
        .map_err(|e| StoreError::InternalException(e.to_string()))?;

    let count: i64 = stmt
        .query_row([version], |row| row.get(0))
        .map_err(|e| StoreError::InternalException(e.to_string()))?;

    Ok(count > 0)
}

pub(crate) fn record_rust_migration(
    tx: &Transaction<'_>,
    version: i64,
    name: &'static str,
) -> Result<(), StoreError> {
    let applied_at = chrono::Utc::now().to_rfc3339();
    tx.execute(
        "INSERT INTO migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
        params![version, name, applied_at],
    )
    .map_err(|e| StoreError::InternalException(e.to_string()))?;

    Ok(())
}
