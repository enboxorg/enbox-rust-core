//! SQLite-backed durable sync replication ledger.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use dwn_rs_core::errors::StoreError;
use rusqlite::{params, Connection, OptionalExtension};

use dwn_rs_core::sync::{
    DeadLetterCategory, DeadLetterEntry, SyncCheckpoint, SyncDirection, SyncError, SyncResult,
    SyncRunStatus,
};
use dwn_rs_core::sync_ledger::{SyncLedger, SyncLedgerSnapshot};

use crate::sqlite::{json_store_error, sqlite_store_error, SqliteConnection, SqliteStore};

/// SQLite-backed [`SyncLedger`] persisted alongside the native DWN database.
#[derive(Debug, Clone)]
pub struct SqliteSyncLedger {
    store: SqliteStore,
}

impl Default for SqliteSyncLedger {
    fn default() -> Self {
        Self::new(&SqliteStore::in_memory())
    }
}

impl SqliteSyncLedger {
    pub fn new(store: &SqliteStore) -> Self {
        Self {
            store: store.clone(),
        }
    }

    async fn with_writer<T, F>(&self, f: F) -> SyncResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        self.store
            .connection()
            .await
            .map_err(|e| SyncError::transient("SyncLedgerOpenFailed", e.to_string()))?
            .with_writer(f)
            .await
            .map_err(|e| SyncError::permanent("SyncLedgerWriteFailed", e.to_string()))
    }
}

impl SyncLedger for SqliteSyncLedger {
    async fn load(&self) -> SyncResult<SyncLedgerSnapshot> {
        self.with_writer(|connection| {
            let mut checkpoints = BTreeMap::new();
            let mut statement = connection
                .prepare(
                    "SELECT key, tenant, remote, scope_id, direction, local_root, remote_root, \
                     pending_pull_prefixes_json, pending_push_prefixes_json, pull_cursor_json, \
                     push_cursor_json, records_pulled, records_pushed, bytes_downloaded, \
                     bytes_uploaded, last_error_json, updated_at \
                     FROM sync_checkpoints",
                )
                .map_err(sqlite_store_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, i64>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, i64>(14)?,
                        row.get::<_, Option<String>>(15)?,
                        row.get::<_, String>(16)?,
                    ))
                })
                .map_err(sqlite_store_error)?;
            for row in rows {
                let (
                    key,
                    tenant,
                    remote,
                    scope_id,
                    direction,
                    local_root,
                    remote_root,
                    pending_pull_json,
                    pending_push_json,
                    pull_cursor_json,
                    push_cursor_json,
                    records_pulled,
                    records_pushed,
                    bytes_downloaded,
                    bytes_uploaded,
                    last_error_json,
                    updated_at,
                ) = row.map_err(sqlite_store_error)?;
                let direction = parse_direction(&direction)?;
                let checkpoint = SyncCheckpoint {
                    key,
                    tenant,
                    remote,
                    scope_id,
                    direction,
                    local_root,
                    remote_root,
                    pending_pull_prefixes: serde_json::from_str(&pending_pull_json)
                        .map_err(json_store_error)?,
                    pending_push_prefixes: serde_json::from_str(&pending_push_json)
                        .map_err(json_store_error)?,
                    pull_cursor: pull_cursor_json
                        .map(|json| serde_json::from_str(&json))
                        .transpose()
                        .map_err(json_store_error)?,
                    push_cursor: push_cursor_json
                        .map(|json| serde_json::from_str(&json))
                        .transpose()
                        .map_err(json_store_error)?,
                    records_pulled: records_pulled as u64,
                    records_pushed: records_pushed as u64,
                    bytes_downloaded: bytes_downloaded as u64,
                    bytes_uploaded: bytes_uploaded as u64,
                    last_error: last_error_json
                        .map(|json| serde_json::from_str(&json))
                        .transpose()
                        .map_err(json_store_error)?,
                    updated_at: parse_rfc3339(&updated_at)?,
                };
                checkpoints.insert(checkpoint.key.clone(), checkpoint);
            }

            let mut dead_letters = Vec::new();
            let mut statement = connection
                .prepare(
                    "SELECT id, tenant, remote, scope_id, message_cid, entry_json, category, \
                     error_json, attempts, last_attempt_at \
                     FROM sync_dead_letters ORDER BY last_attempt_at ASC",
                )
                .map_err(sqlite_store_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                })
                .map_err(sqlite_store_error)?;
            for row in rows {
                let (
                    id,
                    tenant,
                    remote,
                    scope_id,
                    message_cid,
                    entry_json,
                    category,
                    error_json,
                    attempts,
                    last_attempt_at,
                ) = row.map_err(sqlite_store_error)?;
                dead_letters.push(DeadLetterEntry {
                    id,
                    tenant,
                    remote,
                    scope_id,
                    message_cid,
                    entry: entry_json
                        .map(|json| serde_json::from_str(&json))
                        .transpose()
                        .map_err(json_store_error)?,
                    category: parse_dead_letter_category(&category)?,
                    error: serde_json::from_str(&error_json).map_err(json_store_error)?,
                    attempts: attempts as u32,
                    last_attempt_at: parse_rfc3339(&last_attempt_at)?,
                });
            }

            let mut echo_cache = BTreeMap::new();
            let mut statement = connection
                .prepare("SELECT key, remembered_at FROM sync_echo_cache")
                .map_err(sqlite_store_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(sqlite_store_error)?;
            for row in rows {
                let (key, remembered_at) = row.map_err(sqlite_store_error)?;
                echo_cache.insert(key, parse_rfc3339(&remembered_at)?);
            }

            let mut last_status = BTreeMap::new();
            let mut statement = connection
                .prepare("SELECT key, status FROM sync_last_status")
                .map_err(sqlite_store_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(sqlite_store_error)?;
            for row in rows {
                let (key, status) = row.map_err(sqlite_store_error)?;
                last_status.insert(key, parse_run_status(&status)?);
            }

            Ok(SyncLedgerSnapshot {
                checkpoints,
                dead_letters,
                echo_cache,
                last_status,
            })
        })
        .await
    }

    async fn upsert_checkpoint(&self, checkpoint: &SyncCheckpoint) -> SyncResult<()> {
        let checkpoint = checkpoint.clone();
        self.with_writer(move |connection| {
            connection
                .execute(
                    "INSERT OR REPLACE INTO sync_checkpoints \
                     (key, tenant, remote, scope_id, direction, local_root, remote_root, \
                      pending_pull_prefixes_json, pending_push_prefixes_json, pull_cursor_json, \
                      push_cursor_json, records_pulled, records_pushed, bytes_downloaded, \
                      bytes_uploaded, last_error_json, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                    params![
                        checkpoint.key,
                        checkpoint.tenant,
                        checkpoint.remote,
                        checkpoint.scope_id,
                        format!("{:?}", checkpoint.direction),
                        checkpoint.local_root,
                        checkpoint.remote_root,
                        serde_json::to_string(&checkpoint.pending_pull_prefixes)
                            .map_err(json_store_error)?,
                        serde_json::to_string(&checkpoint.pending_push_prefixes)
                            .map_err(json_store_error)?,
                        checkpoint
                            .pull_cursor
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()
                            .map_err(json_store_error)?,
                        checkpoint
                            .push_cursor
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()
                            .map_err(json_store_error)?,
                        checkpoint.records_pulled as i64,
                        checkpoint.records_pushed as i64,
                        checkpoint.bytes_downloaded as i64,
                        checkpoint.bytes_uploaded as i64,
                        checkpoint
                            .last_error
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()
                            .map_err(json_store_error)?,
                        checkpoint
                            .updated_at
                            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                    ],
                )
                .map_err(sqlite_store_error)?;
            Ok(())
        }).await
    }

    async fn insert_dead_letter(&self, entry: &DeadLetterEntry) -> SyncResult<()> {
        let entry = entry.clone();
        self.with_writer(move |connection| {
            connection
                .execute(
                    "INSERT INTO sync_dead_letters \
                     (id, tenant, remote, scope_id, message_cid, entry_json, category, error_json, \
                      attempts, last_attempt_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        entry.id,
                        entry.tenant,
                        entry.remote,
                        entry.scope_id,
                        entry.message_cid,
                        entry
                            .entry
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()
                            .map_err(json_store_error)?,
                        format!("{:?}", entry.category),
                        serde_json::to_string(&entry.error).map_err(json_store_error)?,
                        entry.attempts as i64,
                        entry
                            .last_attempt_at
                            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                    ],
                )
                .map_err(sqlite_store_error)?;
            Ok(())
        })
        .await
    }

    async fn update_dead_letter(&self, entry: &DeadLetterEntry) -> SyncResult<()> {
        let entry = entry.clone();
        self.with_writer(move |connection| {
            connection
                .execute(
                    "UPDATE sync_dead_letters \
                     SET error_json = ?2, attempts = ?3, last_attempt_at = ?4, entry_json = ?5 \
                     WHERE id = ?1",
                    params![
                        entry.id,
                        serde_json::to_string(&entry.error).map_err(json_store_error)?,
                        entry.attempts as i64,
                        entry
                            .last_attempt_at
                            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                        entry
                            .entry
                            .as_ref()
                            .map(serde_json::to_string)
                            .transpose()
                            .map_err(json_store_error)?,
                    ],
                )
                .map_err(sqlite_store_error)?;
            Ok(())
        })
        .await
    }

    async fn remove_dead_letter(&self, id: &str) -> SyncResult<bool> {
        let id = id.to_string();
        self.with_writer(move |connection| {
            let changed = connection
                .execute("DELETE FROM sync_dead_letters WHERE id = ?1", params![id])
                .map_err(sqlite_store_error)?;
            Ok(changed > 0)
        })
        .await
    }

    async fn remember_echo(&self, key: &str, at: DateTime<Utc>) -> SyncResult<()> {
        let key = key.to_string();
        self.with_writer(move |connection| {
            connection
                .execute(
                    "INSERT OR REPLACE INTO sync_echo_cache (key, remembered_at) VALUES (?1, ?2)",
                    params![key, at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)],
                )
                .map_err(sqlite_store_error)?;
            Ok(())
        })
        .await
    }

    async fn contains_echo(&self, key: &str) -> SyncResult<bool> {
        let key = key.to_string();
        self.with_writer(move |connection| {
            connection
                .query_row(
                    "SELECT 1 FROM sync_echo_cache WHERE key = ?1 LIMIT 1",
                    params![key],
                    |_| Ok(()),
                )
                .optional()
                .map_err(sqlite_store_error)
                .map(|value| value.is_some())
        })
        .await
    }

    async fn set_last_status(&self, key: &str, status: SyncRunStatus) -> SyncResult<()> {
        let key = key.to_string();
        self.with_writer(move |connection| {
            connection
                .execute(
                    "INSERT OR REPLACE INTO sync_last_status (key, status) VALUES (?1, ?2)",
                    params![key, format!("{status:?}")],
                )
                .map_err(sqlite_store_error)?;
            Ok(())
        })
        .await
    }
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, dwn_rs_core::errors::StoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|err| {
            dwn_rs_core::errors::StoreError::InternalException(format!(
                "invalid RFC3339 timestamp: {err}"
            ))
        })
}

fn parse_direction(value: &str) -> Result<SyncDirection, dwn_rs_core::errors::StoreError> {
    match value {
        "Pull" => Ok(SyncDirection::Pull),
        "Push" => Ok(SyncDirection::Push),
        "Bidirectional" => Ok(SyncDirection::Bidirectional),
        other => Err(dwn_rs_core::errors::StoreError::InternalException(format!(
            "invalid sync direction {other}"
        ))),
    }
}

fn parse_dead_letter_category(
    value: &str,
) -> Result<DeadLetterCategory, dwn_rs_core::errors::StoreError> {
    match value {
        "PullApply" => Ok(DeadLetterCategory::PullApply),
        "PushApply" => Ok(DeadLetterCategory::PushApply),
        "Authorization" => Ok(DeadLetterCategory::Authorization),
        "Permanent" => Ok(DeadLetterCategory::Permanent),
        "Transient" => Ok(DeadLetterCategory::Transient),
        other => Err(dwn_rs_core::errors::StoreError::InternalException(format!(
            "invalid dead letter category {other}"
        ))),
    }
}

fn parse_run_status(value: &str) -> Result<SyncRunStatus, dwn_rs_core::errors::StoreError> {
    match value {
        "Completed" => Ok(SyncRunStatus::Completed),
        "Partial" => Ok(SyncRunStatus::Partial),
        "NoConnectivity" => Ok(SyncRunStatus::NoConnectivity),
        "AlreadyRunning" => Ok(SyncRunStatus::AlreadyRunning),
        "Failed" => Ok(SyncRunStatus::Failed),
        "Repairing" => Ok(SyncRunStatus::Repairing),
        "DegradedPoll" => Ok(SyncRunStatus::DegradedPoll),
        "Started" => Ok(SyncRunStatus::Started),
        "Stopped" => Ok(SyncRunStatus::Stopped),
        other => Err(dwn_rs_core::errors::StoreError::InternalException(format!(
            "invalid sync run status {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dwn_rs_core::sync::{SyncError, SyncScope};

    #[tokio::test]
    async fn sqlite_sync_ledger_survives_reopen() {
        let path =
            std::env::temp_dir().join(format!("enbox-sync-ledger-{}.sqlite", ulid::Ulid::new()));
        let store = SqliteStore::new(&path);
        let ledger = SqliteSyncLedger::new(&store);
        let checkpoint = SyncCheckpoint {
            key: "did:example:alice|https://peer|global|Pull".to_string(),
            tenant: "did:example:alice".to_string(),
            remote: "https://peer".to_string(),
            scope_id: SyncScope::Full.id(),
            direction: SyncDirection::Pull,
            local_root: Some("abc".to_string()),
            remote_root: None,
            pending_pull_prefixes: vec!["10".to_string()],
            pending_push_prefixes: Vec::new(),
            pull_cursor: None,
            push_cursor: None,
            records_pulled: 2,
            records_pushed: 0,
            bytes_downloaded: 20,
            bytes_uploaded: 0,
            last_error: Some(SyncError::transient("ProgressGap", "gap")),
            updated_at: Utc::now(),
        };
        ledger.upsert_checkpoint(&checkpoint).await.unwrap();
        ledger
            .remember_echo("did:example:alice|https://peer|cid", Utc::now())
            .await
            .unwrap();

        let reopened = SqliteSyncLedger::new(&store);
        let loaded = reopened.load().await.unwrap();
        assert_eq!(loaded.checkpoints.len(), 1);
        assert_eq!(
            loaded.checkpoints[&checkpoint.key].records_pulled,
            checkpoint.records_pulled
        );
        assert!(reopened
            .contains_echo("did:example:alice|https://peer|cid")
            .await
            .unwrap());

        let _ = std::fs::remove_file(path);
    }
}
