//! Convenience entry point for a SQLite-backed native DWN node.

use dwn_rs_core::auth::StaticPublicKeyResolver;
use dwn_rs_core::dwn::Dwn;
use dwn_rs_core::native_dwn::{
    build_native_dwn_with_resolver, open_native_stores, NativeDwnConfig, NativeDwnOpenError,
    NativeDwnStores,
};

use crate::sqlite_aux::{SqliteEventLog, SqliteResumableTaskStore, SqliteStateIndex};
use crate::SqliteStore;

/// SQLite-backed native DWN with durable auxiliary stores.
pub struct SqliteNativeDwn {
    store: SqliteStore,
    dwn: Dwn<
        SqliteStore,
        SqliteStore,
        SqliteStateIndex,
        SqliteEventLog,
        SqliteResumableTaskStore,
        (),
        dwn_rs_core::AllowAllTenantGate,
    >,
}

impl SqliteNativeDwn {
    /// Open an in-memory SQLite native node with the supplied public-key resolver.
    pub async fn open_in_memory(
        public_key_resolver: StaticPublicKeyResolver,
    ) -> Result<Self, NativeDwnOpenError> {
        Self::open_at(":memory:", public_key_resolver).await
    }

    /// Open a SQLite native node at `path` with the supplied public-key resolver.
    pub async fn open_at(
        path: impl AsRef<std::path::Path>,
        public_key_resolver: StaticPublicKeyResolver,
    ) -> Result<Self, NativeDwnOpenError> {
        let store = SqliteStore::new(path);
        let state_index = SqliteStateIndex::new(&store);
        let event_log = SqliteEventLog::new(&store);
        let resumable_task_store = SqliteResumableTaskStore::new(&store);
        let stores = open_native_stores(NativeDwnStores {
            message_store: store.clone(),
            data_store: store.clone(),
            state_index,
            event_log,
            resumable_task_store,
        })
        .await?;

        let dwn = build_native_dwn_with_resolver(
            NativeDwnConfig {
                stores,
                tenant_gate: dwn_rs_core::AllowAllTenantGate,
            },
            public_key_resolver,
        );

        Ok(Self { store, dwn })
    }

    pub fn dwn(
        &self,
    ) -> &Dwn<
        SqliteStore,
        SqliteStore,
        SqliteStateIndex,
        SqliteEventLog,
        SqliteResumableTaskStore,
        (),
        dwn_rs_core::AllowAllTenantGate,
    > {
        &self.dwn
    }

    pub fn dwn_mut(
        &mut self,
    ) -> &mut Dwn<
        SqliteStore,
        SqliteStore,
        SqliteStateIndex,
        SqliteEventLog,
        SqliteResumableTaskStore,
        (),
        dwn_rs_core::AllowAllTenantGate,
    > {
        &mut self.dwn
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

    pub fn store(&self) -> &SqliteStore {
        &self.store
    }
}
