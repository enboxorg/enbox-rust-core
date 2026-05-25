//! Helpers for constructing a [`Dwn`] wired with the real Enbox method handlers.
//!
//! This mirrors TypeScript `Dwn.create()` handler registration while leaving
//! store selection to the caller (in-memory scaffolds, SQLite, etc.).

use crate::auth::JwsPublicKeyResolver;
use crate::descriptors::{
    CONFIGURE, COUNT, DELETE, MESSAGES, PROTOCOLS, QUERY, READ, RECORDS, SUBSCRIBE, SYNC, WRITE,
};
use crate::dwn::{AllowAllTenantGate, Dwn, DwnConfig, MessageKind, TenantGate};
use crate::errors::{
    DataStoreError, EventLogError, MessageStoreError, ResumableTaskStoreError, StoreError,
};
use crate::handlers::records::{
    RecordsCountHandler, RecordsDeleteHandler, RecordsQueryHandler, RecordsReadHandler,
    RecordsSubscribeHandler, RecordsWriteHandler,
};
use crate::handlers::{
    MessagesReadHandler, MessagesSubscribeHandler, MessagesSyncHandler, ProtocolsConfigureHandler,
    ProtocolsQueryHandler,
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
    #[error("state index: {0}")]
    StateIndex(#[from] StoreError),
    #[error("event log: {0}")]
    EventLog(#[from] EventLogError),
    #[error("resumable task store: {0}")]
    ResumableTaskStore(#[from] ResumableTaskStoreError),
}

/// Open every store in `stores`. Mirrors the `Dwn.open()` lifecycle from TypeScript.
pub async fn open_native_stores<MS, DS, SI, EL, RTS>(
    mut stores: NativeDwnStores<MS, DS, SI, EL, RTS>,
) -> Result<NativeDwnStores<MS, DS, SI, EL, RTS>, NativeDwnOpenError>
where
    MS: MessageStoreTrait,
    DS: DataStoreTrait,
    SI: StateIndexTrait,
    EL: EventLogTrait,
    RTS: ResumableTaskStoreTrait,
{
    stores.message_store.open().await?;
    stores.data_store.open().await?;
    stores.state_index.open().await?;
    stores.event_log.open().await?;
    stores.resumable_task_store.open().await?;
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

    register_native_handlers_without_resolver(&mut dwn, stores);
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

    register_native_handlers_with_resolver(&mut dwn, stores, public_key_resolver);
    dwn
}

fn register_native_handlers_without_resolver<MS, DS, SI, EL, RTS, Gate>(
    dwn: &mut Dwn<MS, DS, SI, EL, RTS, (), Gate>,
    stores: NativeDwnStores<MS, DS, SI, EL, RTS>,
) where
    MS: MessageStoreTrait + Clone + Send + Sync + 'static,
    DS: DataStoreTrait + Clone + Send + Sync + 'static,
    SI: StateIndexTrait + Clone + Send + Sync + 'static,
    EL: EventLogTrait + Clone + Send + Sync + 'static,
    RTS: ResumableTaskStoreTrait + Clone + Send + Sync + 'static,
    Gate: TenantGate + 'static,
{
    let message_store = stores.message_store;
    let data_store = stores.data_store;
    let state_index = stores.state_index;
    let event_log = stores.event_log;

    dwn.register_handler(
        MessageKind::new(MESSAGES, READ),
        MessagesReadHandler::new(message_store.clone(), data_store.clone()),
    );
    dwn.register_handler(
        MessageKind::new(MESSAGES, SUBSCRIBE),
        MessagesSubscribeHandler::new(message_store.clone(), event_log.clone()),
    );
    dwn.register_handler(
        MessageKind::new(MESSAGES, SYNC),
        MessagesSyncHandler::new(
            message_store.clone(),
            data_store.clone(),
            state_index.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(PROTOCOLS, CONFIGURE),
        ProtocolsConfigureHandler::new(message_store.clone(), state_index.clone()),
    );
    dwn.register_handler(
        MessageKind::new(PROTOCOLS, QUERY),
        ProtocolsQueryHandler::new(message_store.clone()),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, WRITE),
        RecordsWriteHandler::new(
            message_store.clone(),
            data_store.clone(),
            state_index.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, READ),
        RecordsReadHandler::new(message_store.clone(), data_store.clone()),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, QUERY),
        RecordsQueryHandler::new(message_store.clone()),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, COUNT),
        RecordsCountHandler::new(message_store.clone()),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, DELETE),
        RecordsDeleteHandler::new(
            message_store.clone(),
            data_store.clone(),
            state_index.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, SUBSCRIBE),
        RecordsSubscribeHandler::new(message_store),
    );
}

fn register_native_handlers_with_resolver<MS, DS, SI, EL, RTS, Gate, R>(
    dwn: &mut Dwn<MS, DS, SI, EL, RTS, (), Gate>,
    stores: NativeDwnStores<MS, DS, SI, EL, RTS>,
    resolver: R,
) where
    MS: MessageStoreTrait + Clone + Send + Sync + 'static,
    DS: DataStoreTrait + Clone + Send + Sync + 'static,
    SI: StateIndexTrait + Clone + Send + Sync + 'static,
    EL: EventLogTrait + Clone + Send + Sync + 'static,
    RTS: ResumableTaskStoreTrait + Clone + Send + Sync + 'static,
    Gate: TenantGate + 'static,
    R: JwsPublicKeyResolver + Send + Sync + Clone + 'static,
{
    let message_store = stores.message_store;
    let data_store = stores.data_store;
    let state_index = stores.state_index;
    let event_log = stores.event_log;

    dwn.register_handler(
        MessageKind::new(MESSAGES, READ),
        MessagesReadHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            resolver.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(MESSAGES, SUBSCRIBE),
        MessagesSubscribeHandler::with_public_key_resolver(
            message_store.clone(),
            event_log.clone(),
            resolver.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(MESSAGES, SYNC),
        MessagesSyncHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            state_index.clone(),
            resolver.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(PROTOCOLS, CONFIGURE),
        ProtocolsConfigureHandler::with_public_key_resolver(
            message_store.clone(),
            state_index.clone(),
            resolver.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(PROTOCOLS, QUERY),
        ProtocolsQueryHandler::with_public_key_resolver(message_store.clone(), resolver.clone()),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, WRITE),
        RecordsWriteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            state_index.clone(),
            resolver.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, READ),
        RecordsReadHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            resolver.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, QUERY),
        RecordsQueryHandler::with_public_key_resolver(message_store.clone(), resolver.clone()),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, COUNT),
        RecordsCountHandler::with_public_key_resolver(message_store.clone(), resolver.clone()),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, DELETE),
        RecordsDeleteHandler::with_public_key_resolver(
            message_store.clone(),
            data_store.clone(),
            state_index.clone(),
            resolver.clone(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(RECORDS, SUBSCRIBE),
        RecordsSubscribeHandler::with_public_key_resolver(message_store, resolver),
    );
}
