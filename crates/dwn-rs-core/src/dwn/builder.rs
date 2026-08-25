//! Helpers for constructing a [`Dwn`] wired with the real Enbox method handlers.
//!
//! This mirrors TypeScript `Dwn.create()` handler registration while leaving
//! store selection to the caller (in-memory scaffolds, SQLite, etc.).

use std::sync::Arc;

use crate::auth::resolver::{DidResolver, UniversalResolver};
use crate::auth::StaticPublicKeyResolver;
use crate::dwn::{AllowAllTenantGate, Dwn, DwnConfig, TenantGate};
use crate::errors::{
    DataStoreError, EventLogError, MessageStoreError, ResumableTaskStoreError, StoreError,
};
use crate::handlers::messages::query::MessagesQueryHandler;
use crate::handlers::{
    messages::{
        read::MessagesReadHandler, subscribe::MessagesSubscribeHandler, sync::MessagesSyncHandler,
    },
    protocols::{configure::ProtocolsConfigureHandler, query::ProtocolsQueryHandler},
    records::{
        count::RecordsCountHandler, delete::RecordsDeleteHandler, query::RecordsQueryHandler,
        read::RecordsReadHandler, subscribe::RecordsSubscribeHandler, write::RecordsWriteHandler,
    },
};
use crate::stores::{
    DataStore as DataStoreTrait, EventLog as EventLogTrait, MessageStore as MessageStoreTrait,
    ResumableTaskStore as ResumableTaskStoreTrait, StateIndex as StateIndexTrait,
};

/// Bundled store dependencies required by the native handler set.
#[derive(Clone)]
pub struct NativeDwnStores<MS, DS, SI, EL, RTS> {
    pub message_store: MS,
    pub data_store: DS,
    pub state_index: SI,
    pub event_log: EL,
    pub resumable_task_store: RTS,
}

/// Configuration for [`build_native_dwn`].
pub struct NativeDwnConfig<MS, DS, SI, EL, RTS, Gate = AllowAllTenantGate> {
    pub stores: NativeDwnStores<MS, DS, SI, EL, RTS>,
    pub tenant_gate: Gate,
}

/// Error opening one or more native store backends.
#[derive(Debug, thiserror::Error)]
pub enum NativeDwnOpenError {
    #[error("message store: {0}")]
    MessageStore(#[from] MessageStoreError),
    #[error("data store: {0}")]
    DataStore(#[from] DataStoreError),
    #[error("state index and store: {0}")]
    StateIndex(#[from] StoreError),
    #[error("event log: {0}")]
    EventLog(#[from] EventLogError),
    #[error("resumable task store: {0}")]
    ResumableTaskStore(#[from] ResumableTaskStoreError),
}

/// Open every store in `stores` and resume pending resumable tasks.
pub async fn open_native_stores<MS, DS, SI, EL, RTS>(
    mut stores: NativeDwnStores<MS, DS, SI, EL, RTS>,
) -> Result<NativeDwnStores<MS, DS, SI, EL, RTS>, NativeDwnOpenError>
where
    MS: MessageStoreTrait + Clone + Send + Sync + 'static,
    DS: DataStoreTrait + Clone + Send + Sync + 'static,
    SI: StateIndexTrait + Clone + Send + Sync + 'static,
    EL: EventLogTrait,
    RTS: ResumableTaskStoreTrait + Clone + Send + Sync + 'static,
{
    stores.message_store.open().await?;
    stores.data_store.open().await?;
    stores.state_index.open().await?;
    stores.event_log.open().await?;
    stores.resumable_task_store.open().await?;

    let storage_controller = crate::tasks::controller::StorageController::new(
        stores.message_store.clone(),
        stores.data_store.clone(),
        stores.state_index.clone(),
    );
    let task_manager = crate::tasks::manager::ResumableTaskManager::new(
        stores.resumable_task_store.clone(),
        storage_controller,
    );
    task_manager.resume_tasks_and_wait_for_completion().await?;

    Ok(stores)
}

/// Construct a [`Dwn`] with all current Enbox method handlers registered.
///
/// Messages that require JWS verification will fail authorization unless
/// [`build_native_dwn_with_resolver`] is used.
pub fn build_native_dwn<MS, DS, SI, EL, RTS, Gate>(
    config: NativeDwnConfig<MS, DS, SI, EL, RTS, Gate>,
) -> Dwn<MS, DS, SI, EL, RTS, (), Gate>
where
    MS: MessageStoreTrait + Clone + Send + Sync + 'static,
    DS: DataStoreTrait + Clone + Send + Sync + 'static,
    SI: StateIndexTrait + Clone + Send + Sync + 'static,
    EL: EventLogTrait + Clone + Send + Sync + 'static,
    RTS: ResumableTaskStoreTrait + Clone + Send + Sync + 'static,
    Gate: TenantGate + 'static,
{
    let stores = config.stores;

    let mut dwn = Dwn::new(DwnConfig {
        did_resolver: None,
        tenant_gate: config.tenant_gate,
        message_store: Some(stores.message_store.clone()),
        data_store: Some(stores.data_store.clone()),
        state_index: Some(stores.state_index.clone()),
        event_log: Some(stores.event_log.clone()),
        resumable_task_store: Some(stores.resumable_task_store.clone()),
        handlers: crate::dwn::default_method_handlers(),
    });

    register_native_handlers(&mut dwn, stores, None);
    dwn
}

/// Construct a [`Dwn`] with all handlers registered and JWS verification enabled.
pub fn build_native_dwn_with_resolver<MS, DS, SI, EL, RTS, Gate>(
    config: NativeDwnConfig<MS, DS, SI, EL, RTS, Gate>,
    static_keys: StaticPublicKeyResolver,
) -> Dwn<MS, DS, SI, EL, RTS, (), Gate>
where
    MS: MessageStoreTrait + Clone + Send + Sync + 'static,
    DS: DataStoreTrait + Clone + Send + Sync + 'static,
    SI: StateIndexTrait + Clone + Send + Sync + 'static,
    EL: EventLogTrait + Clone + Send + Sync + 'static,
    RTS: ResumableTaskStoreTrait + Clone + Send + Sync + 'static,
    Gate: TenantGate + 'static,
{
    build_native_dwn_with_did_resolver(config, resolver_with_static_keys(static_keys))
}

fn resolver_with_static_keys(static_keys: StaticPublicKeyResolver) -> UniversalResolver {
    UniversalResolver::with_fallback(static_keys)
}

/// Construct a [`Dwn`] with all handlers registered and a complete DID resolver.
pub fn build_native_dwn_with_did_resolver<MS, DS, SI, EL, RTS, Gate, R>(
    config: NativeDwnConfig<MS, DS, SI, EL, RTS, Gate>,
    resolver: R,
) -> Dwn<MS, DS, SI, EL, RTS, (), Gate>
where
    MS: MessageStoreTrait + Clone + Send + Sync + 'static,
    DS: DataStoreTrait + Clone + Send + Sync + 'static,
    SI: StateIndexTrait + Clone + Send + Sync + 'static,
    EL: EventLogTrait + Clone + Send + Sync + 'static,
    RTS: ResumableTaskStoreTrait + Clone + Send + Sync + 'static,
    Gate: TenantGate + 'static,
    R: DidResolver + 'static,
{
    let stores = config.stores;

    let mut dwn = Dwn::new(DwnConfig {
        did_resolver: None,
        tenant_gate: config.tenant_gate,
        message_store: Some(stores.message_store.clone()),
        data_store: Some(stores.data_store.clone()),
        state_index: Some(stores.state_index.clone()),
        event_log: Some(stores.event_log.clone()),
        resumable_task_store: Some(stores.resumable_task_store.clone()),
        handlers: crate::dwn::default_method_handlers(),
    });

    let resolver: Arc<dyn DidResolver> = Arc::new(resolver);
    register_native_handlers(&mut dwn, stores, Some(resolver));
    dwn
}

/// Register every native handler, deriving each dispatch kind from the handler's descriptor
/// (`Dwn::register`). `resolver` is wired into all handlers (`None` disables JWS verification).
fn register_native_handlers<MS, DS, SI, EL, RTS, Gate>(
    dwn: &mut Dwn<MS, DS, SI, EL, RTS, (), Gate>,
    stores: NativeDwnStores<MS, DS, SI, EL, RTS>,
    resolver: Option<Arc<dyn DidResolver>>,
) where
    MS: MessageStoreTrait + Clone + Send + Sync + 'static,
    DS: DataStoreTrait + Clone + Send + Sync + 'static,
    SI: StateIndexTrait + Clone + Send + Sync + 'static,
    EL: EventLogTrait + Clone + Send + Sync + 'static,
    RTS: ResumableTaskStoreTrait + Clone + Send + Sync + 'static,
    Gate: TenantGate + 'static,
{
    let NativeDwnStores {
        message_store,
        data_store,
        state_index,
        event_log,
        resumable_task_store: _,
    } = stores;

    dwn.register(MessagesReadHandler::new(
        message_store.clone(),
        data_store.clone(),
        resolver.clone(),
    ));
    dwn.register(MessagesQueryHandler::new(
        message_store.clone(),
        resolver.clone(),
    ));
    dwn.register(MessagesSubscribeHandler::new(
        message_store.clone(),
        event_log.clone(),
        resolver.clone(),
    ));
    dwn.register(MessagesSyncHandler::new(
        message_store.clone(),
        data_store.clone(),
        state_index.clone(),
        resolver.clone(),
    ));
    dwn.register(ProtocolsConfigureHandler::new(
        message_store.clone(),
        state_index.clone(),
        resolver.clone(),
    ));
    dwn.register(ProtocolsQueryHandler::new(
        message_store.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsWriteHandler::new(
        message_store.clone(),
        data_store.clone(),
        state_index.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsReadHandler::new(
        message_store.clone(),
        data_store.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsQueryHandler::new(
        message_store.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsCountHandler::new(
        message_store.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsDeleteHandler::new(
        message_store.clone(),
        data_store.clone(),
        state_index.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsSubscribeHandler::new(message_store, resolver));
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ssi_jwk::JWK;

    use super::*;
    use crate::auth::resolver::ResolverError;

    #[tokio::test]
    async fn static_key_builder_keeps_native_web_resolution_authoritative() {
        let web_did = "did:web:127.0.0.1";
        let fallback_did = "did:example:alice";
        let resolver = resolver_with_static_keys(StaticPublicKeyResolver::new(BTreeMap::from([
            (format!("{web_did}#key-1"), JWK::generate_ed25519().unwrap()),
            (
                format!("{fallback_did}#key-1"),
                JWK::generate_ed25519().unwrap(),
            ),
        ])));

        // Native did:web rejects loopback before issuing a request instead of accepting the
        // matching compatibility key from the builder's fallback map.
        assert_eq!(
            resolver.resolve(web_did).await,
            Err(ResolverError::NotFound)
        );

        // Unregistered methods retain the builder's static-key compatibility behavior.
        assert!(resolver.resolve(fallback_did).await.is_ok());
    }
}
