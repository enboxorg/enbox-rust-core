//! Helpers for constructing a [`Dwn`] wired with the real Enbox method handlers.
//!
//! This mirrors TypeScript `Dwn.create()` handler registration while leaving
//! store selection to the caller (in-memory scaffolds, SQLite, etc.).

use std::sync::Arc;

use crate::auth::{JwsPublicKeyResolver, UniversalResolver};
use crate::dwn::{AllowAllTenantGate, Dwn, DwnConfig, TenantGate};
use crate::errors::{
    DataStoreError, EventLogError, MessageStoreError, ResumableTaskStoreError, StoreError,
};
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

impl<MS, DS, SI, EL, RTS, Gate> Default for NativeDwnConfig<MS, DS, SI, EL, RTS, Gate>
where
    MS: Default,
    DS: Default,
    SI: Default,
    EL: Default,
    RTS: Default,
    Gate: Default,
{
    fn default() -> Self {
        Self {
            stores: NativeDwnStores {
                message_store: MS::default(),
                data_store: DS::default(),
                state_index: SI::default(),
                event_log: EL::default(),
                resumable_task_store: RTS::default(),
            },
            tenant_gate: Gate::default(),
        }
    }
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
pub fn build_native_dwn_with_resolver<MS, DS, SI, EL, RTS, Gate, R>(
    config: NativeDwnConfig<MS, DS, SI, EL, RTS, Gate>,
    public_key_resolver: R,
) -> Dwn<MS, DS, SI, EL, RTS, (), Gate>
where
    MS: MessageStoreTrait + Clone + Send + Sync + 'static,
    DS: DataStoreTrait + Clone + Send + Sync + 'static,
    SI: StateIndexTrait + Clone + Send + Sync + 'static,
    EL: EventLogTrait + Clone + Send + Sync + 'static,
    RTS: ResumableTaskStoreTrait + Clone + Send + Sync + 'static,
    Gate: TenantGate + 'static,
    R: JwsPublicKeyResolver + Send + Sync + Clone + 'static,
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

    let resolver: Arc<dyn JwsPublicKeyResolver + Send + Sync> =
        Arc::new(UniversalResolver::with_fallback(public_key_resolver));
    register_native_handlers(&mut dwn, stores, Some(resolver));
    dwn
}

/// Register every native handler, deriving each dispatch kind from the handler's descriptor
/// (`Dwn::register`). `resolver` is wired into all handlers (`None` disables JWS verification).
fn register_native_handlers<MS, DS, SI, EL, RTS, Gate>(
    dwn: &mut Dwn<MS, DS, SI, EL, RTS, (), Gate>,
    stores: NativeDwnStores<MS, DS, SI, EL, RTS>,
    resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
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

    dwn.register(MessagesReadHandler::with_optional_resolver(
        message_store.clone(),
        data_store.clone(),
        resolver.clone(),
    ));
    dwn.register(MessagesSubscribeHandler::with_optional_resolver(
        message_store.clone(),
        event_log.clone(),
        resolver.clone(),
    ));
    dwn.register(MessagesSyncHandler::with_optional_resolver(
        message_store.clone(),
        data_store.clone(),
        state_index.clone(),
        resolver.clone(),
    ));
    dwn.register(ProtocolsConfigureHandler::with_optional_resolver(
        message_store.clone(),
        state_index.clone(),
        resolver.clone(),
    ));
    dwn.register(ProtocolsQueryHandler::with_optional_resolver(
        message_store.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsWriteHandler::with_optional_resolver(
        message_store.clone(),
        data_store.clone(),
        state_index.clone(),
        event_log.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsReadHandler::with_optional_resolver(
        message_store.clone(),
        data_store.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsQueryHandler::with_optional_resolver(
        message_store.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsCountHandler::with_optional_resolver(
        message_store.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsDeleteHandler::with_optional_resolver(
        message_store.clone(),
        data_store.clone(),
        state_index.clone(),
        resolver.clone(),
    ));
    dwn.register(RecordsSubscribeHandler::with_optional_resolver(
        message_store,
        resolver,
    ));
}
