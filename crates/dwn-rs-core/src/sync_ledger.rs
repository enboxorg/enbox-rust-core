//! Durable and in-memory replication ledgers for [`NativeSyncEngine`](crate::sync::NativeSyncEngine).

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};

use crate::sync::{DeadLetterEntry, SyncCheckpoint, SyncError, SyncResult, SyncRunStatus};

/// Snapshot loaded from a ledger on engine startup.
#[derive(Debug, Default, Clone)]
pub struct SyncLedgerSnapshot {
    pub checkpoints: BTreeMap<String, SyncCheckpoint>,
    pub dead_letters: Vec<DeadLetterEntry>,
    pub echo_cache: BTreeMap<String, DateTime<Utc>>,
    pub last_status: BTreeMap<String, SyncRunStatus>,
}

/// Persistence for sync checkpoints, dead letters, and echo suppression.
pub trait SyncLedger: Send + Sync {
    fn load(&self) -> impl Future<Output = SyncResult<SyncLedgerSnapshot>> + Send;

    fn upsert_checkpoint(
        &self,
        checkpoint: &SyncCheckpoint,
    ) -> impl Future<Output = SyncResult<()>> + Send;

    fn insert_dead_letter(
        &self,
        entry: &DeadLetterEntry,
    ) -> impl Future<Output = SyncResult<()>> + Send;

    fn update_dead_letter(
        &self,
        entry: &DeadLetterEntry,
    ) -> impl Future<Output = SyncResult<()>> + Send;

    fn remove_dead_letter(&self, id: &str) -> impl Future<Output = SyncResult<bool>> + Send;

    fn remember_echo(
        &self,
        key: &str,
        at: DateTime<Utc>,
    ) -> impl Future<Output = SyncResult<()>> + Send;

    fn contains_echo(&self, key: &str) -> impl Future<Output = SyncResult<bool>> + Send;

    fn set_last_status(
        &self,
        key: &str,
        status: SyncRunStatus,
    ) -> impl Future<Output = SyncResult<()>> + Send;
}

/// In-memory ledger used by default and in unit tests.
#[derive(Debug, Default, Clone)]
pub struct MemorySyncLedger {
    state: Arc<RwLock<SyncLedgerSnapshot>>,
}

impl MemorySyncLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshot(snapshot: SyncLedgerSnapshot) -> Self {
        Self {
            state: Arc::new(RwLock::new(snapshot)),
        }
    }
}

impl SyncLedger for MemorySyncLedger {
    async fn load(&self) -> SyncResult<SyncLedgerSnapshot> {
        self.state
            .read()
            .map(|state| state.clone())
            .map_err(SyncError::lock_poisoned)
    }

    async fn upsert_checkpoint(&self, checkpoint: &SyncCheckpoint) -> SyncResult<()> {
        self.state
            .write()
            .map_err(SyncError::lock_poisoned)?
            .checkpoints
            .insert(checkpoint.key.clone(), checkpoint.clone());
        Ok(())
    }

    async fn insert_dead_letter(&self, entry: &DeadLetterEntry) -> SyncResult<()> {
        self.state
            .write()
            .map_err(SyncError::lock_poisoned)?
            .dead_letters
            .push(entry.clone());
        Ok(())
    }

    async fn update_dead_letter(&self, entry: &DeadLetterEntry) -> SyncResult<()> {
        let mut state = self.state.write().map_err(SyncError::lock_poisoned)?;
        if let Some(existing) = state
            .dead_letters
            .iter_mut()
            .find(|item| item.id == entry.id)
        {
            *existing = entry.clone();
        }
        Ok(())
    }

    async fn remove_dead_letter(&self, id: &str) -> SyncResult<bool> {
        let mut state = self.state.write().map_err(SyncError::lock_poisoned)?;
        let before = state.dead_letters.len();
        state.dead_letters.retain(|entry| entry.id != id);
        Ok(before != state.dead_letters.len())
    }

    async fn remember_echo(&self, key: &str, at: DateTime<Utc>) -> SyncResult<()> {
        self.state
            .write()
            .map_err(SyncError::lock_poisoned)?
            .echo_cache
            .insert(key.to_string(), at);
        Ok(())
    }

    async fn contains_echo(&self, key: &str) -> SyncResult<bool> {
        Ok(self
            .state
            .read()
            .map_err(SyncError::lock_poisoned)?
            .echo_cache
            .contains_key(key))
    }

    async fn set_last_status(&self, key: &str, status: SyncRunStatus) -> SyncResult<()> {
        self.state
            .write()
            .map_err(SyncError::lock_poisoned)?
            .last_status
            .insert(key.to_string(), status);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{DeadLetterCategory, SyncDirection, SyncScope};

    #[tokio::test]
    async fn memory_ledger_persists_checkpoint_and_echo_entries() {
        let ledger = MemorySyncLedger::new();
        let checkpoint = SyncCheckpoint {
            key: "did:example:alice|https://peer|global|Pull".to_string(),
            tenant: "did:example:alice".to_string(),
            remote: "https://peer".to_string(),
            scope_id: SyncScope::Full.id(),
            direction: SyncDirection::Pull,
            local_root: Some("root".to_string()),
            remote_root: None,
            pending_pull_prefixes: Vec::new(),
            pending_push_prefixes: Vec::new(),
            pull_cursor: None,
            push_cursor: None,
            records_pulled: 1,
            records_pushed: 0,
            bytes_downloaded: 10,
            bytes_uploaded: 0,
            last_error: None,
            updated_at: Utc::now(),
        };
        ledger.upsert_checkpoint(&checkpoint).await.unwrap();
        ledger
            .remember_echo("did:example:alice|https://peer|cid", Utc::now())
            .await
            .unwrap();

        let loaded = ledger.load().await.unwrap();
        assert_eq!(loaded.checkpoints.len(), 1);
        assert!(ledger
            .contains_echo("did:example:alice|https://peer|cid")
            .await
            .unwrap());

        let dead_letter = DeadLetterEntry {
            id: "dead-1".to_string(),
            tenant: "did:example:alice".to_string(),
            remote: "https://peer".to_string(),
            scope_id: SyncScope::Full.id(),
            message_cid: Some("cid".to_string()),
            entry: None,
            category: DeadLetterCategory::PullApply,
            error: SyncError::transient("ApplyFailed", "boom"),
            attempts: 1,
            last_attempt_at: Utc::now(),
        };
        ledger.insert_dead_letter(&dead_letter).await.unwrap();
        assert_eq!(ledger.load().await.unwrap().dead_letters.len(), 1);
        assert!(ledger.remove_dead_letter("dead-1").await.unwrap());
        assert!(ledger.load().await.unwrap().dead_letters.is_empty());
    }
}
