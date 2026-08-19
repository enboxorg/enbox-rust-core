use dwn_rs_core::errors::StoreError;
use rusqlite::Transaction;
use uuid::Uuid;

use crate::{message_store::generate_epoch, sqlite_store_error};

pub(crate) fn run(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let message_count = tx
        .query_row("SELECT COUNT(*) FROM messages", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(sqlite_store_error)?;

    if message_count != 0 {
        return Err(StoreError::IncompatibleDatabase {
            reason: format!(
                "found {message_count} message(s) without trustworthy durable-feed ordering"
            ),
            action: "export the existing data and import it into a fresh database".to_string(),
        });
    }

    generate_epoch(tx)?;

    Ok(())
}
