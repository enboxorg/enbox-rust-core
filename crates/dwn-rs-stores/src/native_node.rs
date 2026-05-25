//! Convenience entry point for a SQLite-backed native DWN node.

use dwn_rs_core::auth::StaticPublicKeyResolver;
use dwn_rs_core::dwn::Dwn;
use dwn_rs_core::local::{MemoryEventLog, MemoryResumableTaskStore};
use dwn_rs_core::native_dwn::{
    build_native_dwn_with_resolver, open_native_stores, NativeDwnConfig, NativeDwnOpenError,
    NativeDwnStores,
};
use dwn_rs_core::state_index::MemoryStateIndex;

use crate::SqliteStore;

/// SQLite-backed native DWN using in-memory auxiliary stores for StateIndex,
/// EventLog, and resumable tasks.
///
/// Durable SQLite persistence for those auxiliary stores is tracked in
/// <https://github.com/enboxorg/enbox-rust-core/issues/80>.
pub struct SqliteNativeDwn {
    store: SqliteStore,
    dwn: Dwn<
        SqliteStore,
        SqliteStore,
        MemoryStateIndex,
        MemoryEventLog,
        MemoryResumableTaskStore,
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
        let stores = open_native_stores(NativeDwnStores {
            message_store: store.clone(),
            data_store: store.clone(),
            state_index: MemoryStateIndex::default(),
            event_log: MemoryEventLog::default(),
            resumable_task_store: MemoryResumableTaskStore::default(),
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
        MemoryStateIndex,
        MemoryEventLog,
        MemoryResumableTaskStore,
        (),
        dwn_rs_core::AllowAllTenantGate,
    > {
        &self.dwn
    }

    pub fn store(&self) -> &SqliteStore {
        &self.store
    }
}
