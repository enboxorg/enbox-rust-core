//! Convenience entry point for a SQLite-backed native DWN node.

use std::collections::BTreeMap;
use std::sync::Arc;

use dwn_rs_core::auth::StaticPublicKeyResolver;
use dwn_rs_core::dwn::builder::{
    build_native_dwn_with_resolver, open_native_stores, NativeDwnConfig, NativeDwnOpenError,
    NativeDwnStores,
};
use dwn_rs_core::dwn::Dwn;
use dwn_rs_core::handlers::records::{RecordsEventLogSubscribeHandler, RecordsSubscribeReply};
use dwn_rs_core::stores::SubscriptionListener;
use dwn_rs_core::sync::endpoint::{DirectSyncEndpoint, HttpSyncEndpoint, SyncRequestAuthorizer};
use dwn_rs_core::sync::{
    NativeSyncEngine, SyncError, SyncIdentityOptions, SyncOnceRequest, SyncOnceResult, SyncResult,
    SyncRunStatus,
};
use tokio::sync::RwLock;

use crate::{
    SqliteEventLog, SqliteResumableTaskStore, SqliteStateIndex, SqliteStore, SqliteSyncLedger,
};

type NativeDwn = Dwn<
    SqliteStore,
    SqliteStore,
    SqliteStateIndex,
    SqliteEventLog,
    SqliteResumableTaskStore,
    (),
    dwn_rs_core::AllowAllTenantGate,
>;

/// SQLite-backed native DWN with durable auxiliary stores.
pub struct SqliteNativeDwn {
    store: SqliteStore,
    state_index: SqliteStateIndex,
    sync_ledger: SqliteSyncLedger,
    dwn: Arc<NativeDwn>,
    records_subscribe: RecordsEventLogSubscribeHandler<SqliteStore, SqliteEventLog>,
    sync_identities: Arc<RwLock<BTreeMap<String, SyncIdentityOptions>>>,
}

impl SqliteNativeDwn {
    /// Open an in-memory SQLite native node with the supplied public-key resolver.
    pub async fn open_in_memory(
        public_key_resolver: StaticPublicKeyResolver,
    ) -> Result<Self, NativeDwnOpenError> {
        Self::open(SqliteStore::in_memory(), public_key_resolver).await
    }

    /// Open a SQLite native node at `path` with the supplied public-key resolver.
    pub async fn open_at(
        path: impl AsRef<std::path::Path>,
        public_key_resolver: StaticPublicKeyResolver,
    ) -> Result<Self, NativeDwnOpenError> {
        Self::open(SqliteStore::new(path), public_key_resolver).await
    }

    pub async fn open(
        store: SqliteStore,
        public_key_resolver: StaticPublicKeyResolver,
    ) -> Result<Self, NativeDwnOpenError> {
        store
            .connection()
            .await
            .map_err(NativeDwnOpenError::StateIndex)?;

        let state_index = SqliteStateIndex::new(&store);
        let event_log = SqliteEventLog::new(&store);
        let resumable_task_store = SqliteResumableTaskStore::new(&store);
        let sync_ledger = SqliteSyncLedger::new(&store);
        let stores = open_native_stores(NativeDwnStores {
            message_store: store.clone(),
            data_store: store.clone(),
            state_index: state_index.clone(),
            event_log,
            resumable_task_store,
        })
        .await?;

        let dwn = Arc::new(build_native_dwn_with_resolver(
            NativeDwnConfig {
                stores: stores.clone(),
                tenant_gate: dwn_rs_core::AllowAllTenantGate,
            },
            public_key_resolver.clone(),
        ));
        let records_subscribe = RecordsEventLogSubscribeHandler::new(
            store.clone(),
            stores.event_log,
            Some(Arc::new(public_key_resolver)),
        );

        Ok(Self {
            store,
            state_index,
            sync_ledger,
            dwn,
            records_subscribe,
            sync_identities: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }

    pub fn dwn(&self) -> &NativeDwn {
        &self.dwn
    }

    pub fn dwn_mut(&mut self) -> &mut NativeDwn {
        Arc::get_mut(&mut self.dwn).expect("DWN is shared; cannot borrow mutably")
    }

    pub async fn process_message_with_data(
        &self,
        tenant: &str,
        message: serde_json::Value,
        data: Option<bytes::Bytes>,
    ) -> dwn_rs_core::dwn::DwnReply {
        self.dwn
            .process_message_with_data(tenant, message, data)
            .await
    }

    /// Subscribe to record updates via the event log (used by WebSocket loopback).
    pub async fn subscribe_records(
        &self,
        tenant: &str,
        message: serde_json::Value,
        listener: SubscriptionListener,
    ) -> RecordsSubscribeReply {
        self.records_subscribe
            .handle_subscribe(tenant, &message, listener)
            .await
    }

    pub fn store(&self) -> &SqliteStore {
        &self.store
    }

    pub fn sync_ledger(&self) -> &SqliteSyncLedger {
        &self.sync_ledger
    }

    /// Register a tenant DID and protocol scope for sync runs on this node.
    pub async fn register_sync_identity(&self, options: SyncIdentityOptions) -> SyncResult<()> {
        dwn_rs_core::sync::validate_identity_options(&options)?;
        let mut identities = self.sync_identities.write().await;
        if identities.contains_key(&options.did) {
            return Err(SyncError::permanent(
                "SyncIdentityAlreadyRegistered",
                format!("Identity with DID {} is already registered", options.did),
            ));
        }
        identities.insert(options.did.clone(), options);
        Ok(())
    }

    /// Run one sync cycle against a remote `@enbox/dwn-server` over HTTP JSON-RPC.
    pub async fn sync_once_with_http<A>(
        &self,
        remote_url: impl AsRef<str>,
        authorizer: A,
        request: SyncOnceRequest,
    ) -> SyncOnceResult
    where
        A: SyncRequestAuthorizer,
    {
        let engine = match self.build_http_sync_engine(remote_url, authorizer).await {
            Ok(engine) => engine,
            Err(result) => return result,
        };
        engine.sync_once(request).await
    }

    /// Poll-based pull reconciliation against an HTTP remote (live-degraded fallback).
    pub async fn poll_reconcile_with_http<A>(
        &self,
        remote_url: impl AsRef<str>,
        authorizer: A,
        request: SyncOnceRequest,
    ) -> SyncOnceResult
    where
        A: SyncRequestAuthorizer,
    {
        let engine = match self.build_http_sync_engine(remote_url, authorizer).await {
            Ok(engine) => engine,
            Err(result) => return result,
        };
        engine.poll_reconcile(request).await
    }

    /// Run a closure against a freshly built HTTP [`NativeSyncEngine`] for this node.
    pub async fn run_with_http_sync_engine<A, F, Fut, R>(
        &self,
        remote_url: impl AsRef<str>,
        authorizer: A,
        f: F,
    ) -> Result<R, SyncOnceResult>
    where
        A: SyncRequestAuthorizer,
        F: FnOnce(
            NativeSyncEngine<
                DirectSyncEndpoint<NativeDwn, SqliteStore, SqliteStore, SqliteStateIndex>,
                HttpSyncEndpoint<A>,
                SqliteSyncLedger,
            >,
        ) -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let engine = self.build_http_sync_engine(remote_url, authorizer).await?;
        Ok(f(engine).await)
    }

    /// Run one sync cycle against another in-process [`SqliteNativeDwn`] peer.
    pub async fn sync_once_with_peer(
        &self,
        peer: &SqliteNativeDwn,
        request: SyncOnceRequest,
    ) -> SyncOnceResult {
        let local = DirectSyncEndpoint::from_arc(
            Arc::clone(&self.dwn),
            self.store.clone(),
            self.store.clone(),
            self.state_index.clone(),
        );
        let remote = DirectSyncEndpoint::from_arc(
            Arc::clone(&peer.dwn),
            peer.store.clone(),
            peer.store.clone(),
            peer.state_index.clone(),
        );
        let engine = match NativeSyncEngine::open(local, remote, self.sync_ledger.clone()).await {
            Ok(engine) => engine.with_diff_depth(2),
            Err(e) => return failed_sync_once(e),
        };
        if let Err(result) = self.register_sync_identities_on_engine(&engine).await {
            return result;
        }
        engine.sync_once(request).await
    }

    async fn build_http_sync_engine<A>(
        &self,
        remote_url: impl AsRef<str>,
        authorizer: A,
    ) -> Result<
        NativeSyncEngine<
            DirectSyncEndpoint<NativeDwn, SqliteStore, SqliteStore, SqliteStateIndex>,
            HttpSyncEndpoint<A>,
            SqliteSyncLedger,
        >,
        SyncOnceResult,
    >
    where
        A: SyncRequestAuthorizer,
    {
        let local = DirectSyncEndpoint::from_arc(
            Arc::clone(&self.dwn),
            self.store.clone(),
            self.store.clone(),
            self.state_index.clone(),
        );
        let remote =
            HttpSyncEndpoint::new(remote_url.as_ref(), authorizer).map_err(failed_sync_once)?;
        let engine = NativeSyncEngine::open(local, remote, self.sync_ledger.clone())
            .await
            .map_err(failed_sync_once)?
            .with_diff_depth(2);
        self.register_sync_identities_on_engine(&engine).await?;
        Ok(engine)
    }

    async fn register_sync_identities_on_engine<Local, Remote>(
        &self,
        engine: &NativeSyncEngine<Local, Remote, SqliteSyncLedger>,
    ) -> Result<(), SyncOnceResult>
    where
        Local: dwn_rs_core::sync::SyncEndpoint,
        Remote: dwn_rs_core::sync::SyncEndpoint,
    {
        let identities = self.sync_identities.read().await;
        for options in identities.values() {
            if let Err(error) = engine.register_identity(options.clone()).await {
                return Err(failed_sync_once(error));
            }
        }
        Ok(())
    }
}

fn failed_sync_once(error: SyncError) -> SyncOnceResult {
    SyncOnceResult {
        status: SyncRunStatus::Failed,
        checkpoints: Vec::new(),
        records_pulled: 0,
        records_pushed: 0,
        bytes_downloaded: 0,
        bytes_uploaded: 0,
        next_recommended_delay_ms: None,
        error: Some(error),
    }
}
