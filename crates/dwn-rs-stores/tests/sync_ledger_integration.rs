//! Integration tests for durable sync ledger + engine persistence.

use dwn_rs_core::sync::{
    NativeSyncEngine, SyncDirection, SyncIdentityOptions, SyncOnceRequest, SyncProtocols,
    SyncRunStatus, SyncScope,
};
use dwn_rs_core::sync_ledger::SyncLedger;
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
            .expect("register identity");

        let result = engine
            .sync_once(SyncOnceRequest::new(TENANT, REMOTE, SyncDirection::Pull))
            .await;
        assert_eq!(result.status, SyncRunStatus::Completed);
        assert!(!result.checkpoints.is_empty());
    }

    let loaded = ledger.load().expect("reload ledger");
    assert!(!loaded.checkpoints.is_empty());
    assert_eq!(loaded.checkpoints.values().next().unwrap().tenant, TENANT);

    {
        let local = MockEndpoint::default();
        let remote = MockEndpoint::default();
        local.set_root("local-root");
        remote.set_root("remote-root");
        let engine = NativeSyncEngine::with_ledger(local, remote, ledger).with_diff_depth(2);
        engine
            .register_identity(SyncIdentityOptions {
                did: TENANT.to_string(),
                protocols: SyncProtocols::All,
                delegate_did: None,
            })
            .expect("register identity");

        let status = engine.sync_status(dwn_rs_core::sync::SyncStatusQuery {
            tenant: TENANT.to_string(),
            remote: Some(REMOTE.to_string()),
            protocol: None,
        });
        assert!(!status.checkpoints.is_empty());
        assert_eq!(status.checkpoints[0].scope_id, SyncScope::Full.id());
    }

    let _ = std::fs::remove_file(path);
}
