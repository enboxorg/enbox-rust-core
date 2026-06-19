//! Integration tests for durable sync ledger + engine persistence.

use dwn_rs_core::stores::{ProgressToken, SubscriptionMessage};
use dwn_rs_core::sync::{
    NativeSyncEngine, SyncDirection, SyncIdentityOptions, SyncOnceRequest, SyncProtocols,
    SyncRunStatus, SyncScope,
};
use dwn_rs_core::sync::ledger::SyncLedger;
use dwn_rs_stores::{SqliteStore, SqliteSyncLedger};

mod mock_endpoint {
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, RwLock};

    use dwn_rs_core::sync::{MessagesSyncDiff, SyncEndpoint, SyncMessageEntry, SyncResult};

    #[derive(Clone, Default)]
    pub struct MockEndpoint {
        state: Arc<RwLock<MockEndpointState>>,
    }

    #[derive(Default)]
    struct MockEndpointState {
        root: String,
    }

    impl MockEndpoint {
        pub fn set_root(&self, root: &str) {
            self.state.write().unwrap().root = root.to_string();
        }
    }

    impl SyncEndpoint for MockEndpoint {
        fn root<'a>(
            &'a self,
            _tenant: &'a str,
            _scope: &'a dwn_rs_core::sync::SyncScope,
        ) -> Pin<Box<dyn Future<Output = SyncResult<String>> + Send + 'a>> {
            Box::pin(async move { Ok(self.state.read().unwrap().root.clone()) })
        }

        fn subtree_hashes<'a>(
            &'a self,
            _tenant: &'a str,
            _scope: &'a dwn_rs_core::sync::SyncScope,
            _depth: u8,
        ) -> Pin<Box<dyn Future<Output = SyncResult<BTreeMap<String, String>>> + Send + 'a>>
        {
            Box::pin(async move { Ok(BTreeMap::new()) })
        }

        fn diff<'a>(
            &'a self,
            _tenant: &'a str,
            _scope: &'a dwn_rs_core::sync::SyncScope,
            _depth: u8,
            _hashes: BTreeMap<String, String>,
        ) -> Pin<Box<dyn Future<Output = SyncResult<MessagesSyncDiff>> + Send + 'a>> {
            Box::pin(async move {
                Ok(MessagesSyncDiff {
                    only_remote: Vec::new(),
                    only_local: Vec::new(),
                })
            })
        }

        fn apply<'a>(
            &'a self,
            _tenant: &'a str,
            _entry: SyncMessageEntry,
        ) -> Pin<Box<dyn Future<Output = SyncResult<()>> + Send + 'a>> {
            Box::pin(async move { Ok(()) })
        }
    }
}

use mock_endpoint::MockEndpoint;

const TENANT: &str = "did:example:alice";
const REMOTE: &str = "https://peer.example";

#[tokio::test]
async fn sync_engine_resumes_checkpoints_from_sqlite_ledger() {
    let path = std::env::temp_dir().join(format!(
        "enbox-sync-engine-ledger-{}.sqlite",
        ulid::Ulid::new()
    ));
    let store = SqliteStore::new(&path);
    let ledger = SqliteSyncLedger::new(&store);

    {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        local.set_root("local-root");
        remote.set_root("remote-root");
        let engine =
            NativeSyncEngine::with_ledger(local, remote, ledger.clone()).with_diff_depth(2);
        engine
            .register_identity(SyncIdentityOptions {
                did: TENANT.to_string(),
                protocols: SyncProtocols::All,
                delegate_did: None,
            })
            .await
            .expect("register identity");

        let result = engine
            .sync_once(SyncOnceRequest::new(TENANT, REMOTE, SyncDirection::Pull))
            .await;
        assert_eq!(result.status, SyncRunStatus::Completed);
        assert!(!result.checkpoints.is_empty());
    }

    let loaded = ledger.load().await.expect("reload ledger");
    assert!(!loaded.checkpoints.is_empty());
    assert_eq!(loaded.checkpoints.values().next().unwrap().tenant, TENANT);

    {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        local.set_root("local-root");
        remote.set_root("remote-root");
        let engine = NativeSyncEngine::open(local, remote, ledger)
            .await
            .expect("open sync engine")
            .with_diff_depth(2);
        engine
            .register_identity(SyncIdentityOptions {
                did: TENANT.to_string(),
                protocols: SyncProtocols::All,
                delegate_did: None,
            })
            .await
            .expect("register identity");

        let status = engine
            .sync_status(dwn_rs_core::sync::SyncStatusQuery {
                tenant: TENANT.to_string(),
                remote: Some(REMOTE.to_string()),
                protocol: None,
            })
            .await;
        assert!(!status.checkpoints.is_empty());
        assert_eq!(status.checkpoints[0].scope_id, SyncScope::Full.id());
    }

    let _ = std::fs::remove_file(path);
}

async fn registered_engine(
    ledger: SqliteSyncLedger,
) -> NativeSyncEngine<MockEndpoint, MockEndpoint, SqliteSyncLedger> {
    let local = MockEndpoint::default();
    let remote = MockEndpoint::default();
    let engine = NativeSyncEngine::with_ledger(local, remote, ledger).with_diff_depth(2);
    engine
        .register_identity(SyncIdentityOptions {
            did: TENANT.to_string(),
            protocols: SyncProtocols::All,
            delegate_did: None,
        })
        .await
        .expect("register identity");
    engine
}

fn sample_progress_token(position: &str, message_cid: &str) -> ProgressToken {
    ProgressToken {
        stream_id: TENANT.to_string(),
        epoch: "1".to_string(),
        position: position.to_string(),
        message_cid: message_cid.to_string(),
    }
}

#[tokio::test]
async fn sync_engine_persists_eose_pull_cursor_to_sqlite_ledger() {
    let path = std::env::temp_dir().join(format!(
        "enbox-sync-eose-ledger-{}.sqlite",
        ulid::Ulid::new()
    ));
    let store = SqliteStore::new(&path);
    let ledger = SqliteSyncLedger::new(&store);
    let engine = registered_engine(ledger.clone()).await;
    let cursor = sample_progress_token("2", "cid-2");

    let result = engine
        .handle_remote_subscription_message(
            TENANT,
            REMOTE,
            SyncScope::Full,
            SubscriptionMessage::Eose {
                cursor: cursor.clone(),
            },
        )
        .await;

    assert_eq!(result.status, SyncRunStatus::Completed);
    let loaded = ledger.load().await.expect("reload ledger");
    let checkpoint = loaded.checkpoints.values().next().expect("checkpoint");
    assert_eq!(checkpoint.pull_cursor.as_ref(), Some(&cursor));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn sync_engine_persists_progress_gap_as_repairing_in_sqlite_ledger() {
    let path = std::env::temp_dir().join(format!(
        "enbox-sync-gap-ledger-{}.sqlite",
        ulid::Ulid::new()
    ));
    let store = SqliteStore::new(&path);
    let ledger = SqliteSyncLedger::new(&store);
    let engine = registered_engine(ledger.clone()).await;

    let result = engine
        .handle_progress_gap(TENANT, REMOTE, SyncScope::Full, "token_too_old")
        .await;

    assert_eq!(result.status, SyncRunStatus::Repairing);
    assert_eq!(result.error.as_ref().unwrap().code, "ProgressGap");
    let loaded = ledger.load().await.expect("reload ledger");
    let status_key = format!("{TENANT}|{REMOTE}");
    assert_eq!(
        loaded.last_status.get(&status_key),
        Some(&SyncRunStatus::Repairing)
    );
    let checkpoint = loaded.checkpoints.values().next().expect("checkpoint");
    assert_eq!(
        checkpoint.last_error.as_ref().unwrap().detail,
        "token_too_old"
    );

    let _ = std::fs::remove_file(path);
}
