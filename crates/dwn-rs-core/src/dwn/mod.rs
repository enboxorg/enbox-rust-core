pub mod builder;
pub mod core_protocol;
pub mod validation;

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::descriptors::MessageKind;
use crate::errors::{DwnError, DwnErrorCode};
use crate::interfaces::messages::descriptors::{
    ConcreteDescriptor, FromDescriptor, InterfaceUnion, Messages, Protocols, Records,
};
use crate::interfaces::replies::Status;
use crate::validation::{admit_message, ingress_rejection, parse_message};
use crate::{Descriptor, Message, Reply, Response};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantGateResult {
    pub is_active_tenant: bool,
    pub detail: Option<String>,
}

impl TenantGateResult {
    pub fn active() -> Self {
        Self {
            is_active_tenant: true,
            detail: None,
        }
    }

    pub fn inactive(detail: impl Into<String>) -> Self {
        Self {
            is_active_tenant: false,
            detail: Some(detail.into()),
        }
    }
}

pub trait TenantGate: Send + Sync {
    fn is_active_tenant<'a>(
        &'a self,
        tenant: &'a str,
    ) -> Pin<Box<dyn Future<Output = TenantGateResult> + Send + 'a>>;
}

#[derive(Debug, Default, Clone)]
pub struct AllowAllTenantGate;

impl TenantGate for AllowAllTenantGate {
    fn is_active_tenant<'a>(
        &'a self,
        _tenant: &'a str,
    ) -> Pin<Box<dyn Future<Output = TenantGateResult> + Send + 'a>> {
        Box::pin(async { TenantGateResult::active() })
    }
}

impl MessageKind {
    /// Recognize the `interface`/`method` pair, the first stage of admission.
    ///
    /// `detail` is the reply detail verbatim: upstream `validateMessageIntegrity` reports
    /// this stage without an error-code prefix.
    pub fn from_message(message: &Value) -> Result<Self, DwnError> {
        let descriptor = message.get("descriptor").and_then(Value::as_object);
        let interface = descriptor
            .and_then(|descriptor| descriptor.get("interface"))
            .and_then(Value::as_str);
        let method = descriptor
            .and_then(|descriptor| descriptor.get("method"))
            .and_then(Value::as_str);

        match (interface, method) {
            (Some(interface), Some(method)) => MessageKind::from_parts(interface, method)
                .ok_or_else(|| {
                    DwnError::new(
                        DwnErrorCode::MessageUnknownInterfaceOrMethod,
                        format!(
                            "Unknown interface/method combination, interface: {interface}, method: {method}"
                        ),
                    )
                }),
            _ => Err(DwnError::new(
                DwnErrorCode::MessageInterfaceOrMethodUndefined,
                format!(
                    "Both interface and method must be present, interface: {}, method: {}",
                    interface.unwrap_or("undefined"),
                    method.unwrap_or("undefined"),
                ),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DwnReply {
    pub status: Status,
    #[serde(flatten)]
    pub body: BTreeMap<String, Value>,
}

impl DwnReply {
    pub fn new(code: i32, detail: impl Into<String>) -> Self {
        Self {
            status: Status::new(code, detail),
            body: BTreeMap::new(),
        }
    }

    pub fn ok() -> Self {
        Self::new(200, "OK")
    }

    pub fn bad_request(detail: impl std::fmt::Display) -> Self {
        Self::new(400, detail.to_string())
    }

    pub fn unauthorized(detail: impl std::fmt::Display) -> Self {
        Self::new(401, detail.to_string())
    }

    pub fn not_implemented(detail: impl Into<String>) -> Self {
        Self::new(501, detail)
    }

    pub fn with_body(mut self, key: impl Into<String>, value: Value) -> Self {
        self.body.insert(key.into(), value);
        self
    }
}

/// A typed implementation of one DWN interface/method.
///
/// `Handler` is the only public method-handler API. Its associated [`Descriptor`]
/// determines which [`MessageKind`] it serves, and [`Dwn::register`] uses that fact
/// to install it in the dispatch table. [`Handler::run`] parses the admitted envelope
/// and converts the generic descriptor into `Self::Descriptor` before calling
/// [`Handler::handle`]. Implementations thus receive a descriptor already typed for
/// their method.
///
/// The returned future is deliberately not boxed. This keeps concrete handlers
/// lightweight; the private erasure boundary (`HandlerAdapter` over the crate-internal
/// `MethodHandler` dispatch interface) boxes it only when the handler is stored in
/// the heterogeneous registry.
pub trait Handler: Send + Sync {
    /// The descriptor accepted by this handler, such as `RecordsQueryDescriptor`.
    /// It supplies both the dispatch kind and conversion from the generic envelope.
    type Descriptor: ConcreteDescriptor + FromDescriptor + Clone;

    // Handler response type, which is serialized into the reply body. This is a generic parameter
    // so that the handler can return a concrete type (e.g. `RecordsQueryReply`) without boxing it.
    type Reply: Into<Reply> + Send + 'static + Default;

    /// Execute method-specific behavior after the shared request checks pass.
    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = Response<Self::Reply>> + Send;

    /// Run this typed handler from wire JSON.
    ///
    /// Post-admission: dispatch already ran `admit_message`, so this parses and downcasts.
    fn run(
        &self,
        tenant: &str,
        message: &Value,
        data: Option<bytes::Bytes>,
    ) -> impl Future<Output = Response<Self::Reply>> + Send {
        async move {
            let message = match parse_message(message) {
                Ok(message) => message,
                Err(error) => return ingress_rejection(error),
            };

            let descriptor = match Self::Descriptor::from_descriptor(&message.descriptor) {
                Ok(descriptor) => descriptor.clone(),
                Err(error) => {
                    return Response::bad_request(format!("Failed to parse descriptor: {error}"));
                }
            };

            self.handle(HandlerContext {
                tenant,
                message,
                descriptor,
                data,
            })
            .await
        }
    }
}

/// Adapts a typed [`Handler`] for storage in the heterogeneous dispatch map.
///
/// Each typed handler has a different `HandlerContext` descriptor and opaque future
/// type. This adapter erases those differences at the crate-internal `MethodHandler`
/// boundary while preserving the typed API inside the handler.
pub(crate) struct HandlerAdapter<H: Handler>(pub(crate) H);

/// The admitted, method-specific input passed to [`Handler::handle`].
///
/// No raw wire JSON: transports that must re-emit a message byte-for-byte (peer forwarding,
/// `$delivery` fan-out) keep their own copy.
pub struct HandlerContext<'a, D> {
    pub tenant: &'a str,
    pub message: Message<Descriptor>,
    pub descriptor: D,
    pub data: Option<bytes::Bytes>,
}

impl<H: Handler + 'static> MethodHandler for HandlerAdapter<H> {
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Response<Reply>> + Send + 'a>> {
        // The dispatch registry is `Arc<dyn MethodHandler>`, so this is the single boundary where
        // the handler's `impl Future` is boxed into a `Send` trait object.
        Box::pin(async move {
            let Response { status, reply } = self
                .0
                .run(request.tenant, request.message, request.data)
                .await;

            Response {
                status,
                reply: reply.into(),
            }
        })
    }
}

/// An untyped request at the dispatch boundary.
///
/// This is the common input for every entry in the crate-internal dispatch map: the
/// tenant, the raw message JSON a typed adapter parses, and the accompanying data.
pub(crate) struct MethodHandlerRequest<'a> {
    /// Tenant to which the message is addressed.
    pub tenant: &'a str,
    /// Raw message JSON; a typed adapter parses and validates it.
    pub message: &'a Value,
    /// Optional binary payload accompanying the message.
    pub data: Option<bytes::Bytes>,
}

/// Object-safe handler interface used by the DWN dispatch registry.
///
/// Crate-internal: method implementations implement [`Handler`] instead, which supplies
/// descriptor typing and shared validation; [`Dwn::register`] adapts one for dispatch.
pub(crate) trait MethodHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Response<Reply>> + Send + 'a>>;
}

/// Dispatch registry keyed by DWN `(interface, method)` kind.
///
/// Entries are shared trait objects so a [`Dwn`] can keep different concrete
/// handler types in one map and serve concurrent immutable requests.
pub(crate) type MethodHandlerMap = BTreeMap<MessageKind, Arc<dyn MethodHandler>>;

pub struct DwnConfig<
    MessageStore = (),
    DataStore = (),
    StateIndex = (),
    EventLog = (),
    ResumableTaskStore = (),
    ReplicationFeedReader = (),
    DidResolver = (),
    Gate = AllowAllTenantGate,
> {
    pub did_resolver: Option<DidResolver>,
    pub tenant_gate: Gate,
    pub message_store: Option<MessageStore>,
    pub data_store: Option<DataStore>,
    pub state_index: Option<StateIndex>,
    pub replication_feed_reader: Option<ReplicationFeedReader>,
    pub event_log: Option<EventLog>,
    pub resumable_task_store: Option<ResumableTaskStore>,
}

impl Default for DwnConfig {
    fn default() -> Self {
        Self {
            did_resolver: None,
            tenant_gate: AllowAllTenantGate,
            message_store: None,
            data_store: None,
            state_index: None,
            replication_feed_reader: None,
            event_log: None,
            resumable_task_store: None,
        }
    }
}

pub struct Dwn<
    MessageStore = (),
    DataStore = (),
    StateIndex = (),
    EventLog = (),
    ResumableTaskStore = (),
    ReplicationFeedReader = (),
    DidResolver = (),
    Gate = AllowAllTenantGate,
> {
    config: DwnConfig<
        MessageStore,
        DataStore,
        StateIndex,
        EventLog,
        ResumableTaskStore,
        ReplicationFeedReader,
        DidResolver,
        Gate,
    >,
    handlers: MethodHandlerMap,
}

impl Default for Dwn {
    fn default() -> Self {
        Self::new(DwnConfig::default())
    }
}

impl<
        MessageStore,
        DataStore,
        StateIndex,
        EventLog,
        ResumableTaskStore,
        ReplicationFeedReader,
        DidResolver,
        Gate,
    >
    Dwn<
        MessageStore,
        DataStore,
        StateIndex,
        EventLog,
        ResumableTaskStore,
        ReplicationFeedReader,
        DidResolver,
        Gate,
    >
where
    Gate: TenantGate,
{
    pub fn new(
        config: DwnConfig<
            MessageStore,
            DataStore,
            StateIndex,
            EventLog,
            ResumableTaskStore,
            ReplicationFeedReader,
            DidResolver,
            Gate,
        >,
    ) -> Self {
        Self {
            config,
            handlers: MethodHandlerMap::new(),
        }
    }

    pub(crate) fn register_handler(
        &mut self,
        kind: MessageKind,
        handler: impl MethodHandler + 'static,
    ) {
        self.handlers.insert(kind, Arc::new(handler));
    }

    /// Register a [`Handler`], deriving its [`MessageKind`] from the descriptor it serves
    /// ([`Handler::Descriptor`]) — no need to restate the interface/method at the call site.
    pub fn register<H>(&mut self, handler: H)
    where
        H: Handler + 'static,
    {
        self.register_handler(MessageKind::of::<H::Descriptor>(), HandlerAdapter(handler));
    }

    /// The dispatch kinds this node has a handler for.
    pub fn registered_kinds(&self) -> Vec<MessageKind> {
        self.handlers.keys().cloned().collect()
    }

    pub async fn process_message(&self, tenant: &str, raw_message: Value) -> Response<Reply> {
        self.process_message_with_data(tenant, raw_message, None)
            .await
    }

    pub async fn process_message_with_data(
        &self,
        tenant: &str,
        raw_message: Value,
        data: Option<bytes::Bytes>,
    ) -> Response<Reply> {
        if let Some(reply) = self.validate_tenant(tenant).await {
            return reply;
        }

        // Before lookup, so every registered handler — typed or crate-internal raw —
        // passes the same admission typed `Handler`s do.
        let kind = match admit_message(&raw_message) {
            Ok(kind) => kind,
            Err(error) => return ingress_rejection(error),
        };

        let Some(handler) = self.handlers.get(&kind) else {
            return Response::not_implemented(format!(
                "No handler registered for {}",
                kind.as_str()
            ));
        };

        handler
            .handle(MethodHandlerRequest {
                tenant,
                message: &raw_message,
                data,
            })
            .await
    }

    async fn validate_tenant(&self, tenant: &str) -> Option<Response<Reply>> {
        let result = self.config.tenant_gate.is_active_tenant(tenant).await;
        if result.is_active_tenant {
            return None;
        }

        Some(Response::unauthorized(result.detail.unwrap_or_else(|| {
            format!("DID {tenant} is not an active tenant.")
        })))
    }
}

/// The set of `(interface, method)` kinds this node dispatches handlers for.
///
/// Derived from the descriptor declarations: each interface union (`Records`/`Protocols`/
/// `Messages`) reports its kinds via [`InterfaceUnion::KINDS`] are filtered out. Adding
/// a handler-backed descriptor in a `#[interface]` module registers it here automatically
/// — no hand-maintained list to keep in sync.
pub fn current_handler_kinds() -> Vec<MessageKind> {
    Records::KINDS
        .iter()
        .chain(Messages::KINDS)
        .chain(Protocols::KINDS)
        .filter_map(|&(i, m)| MessageKind::from_parts(i, m))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;
    use crate::descriptors::records::RecordsMethod;

    #[tokio::test]
    async fn process_message_rejects_inactive_tenant_before_dispatch() {
        let mut dwn = Dwn::<(), (), (), (), (), (), (), StaticTenantGate>::new(DwnConfig {
            tenant_gate: StaticTenantGate(TenantGateResult::inactive("tenant disabled")),
            did_resolver: None,
            message_store: None,
            data_store: None,
            state_index: None,
            replication_feed_reader: None,
            event_log: None,
            resumable_task_store: None,
        });
        let handler = RecordingHandler::default();
        let calls = handler.calls.clone();
        dwn.register_handler(MessageKind::Records(RecordsMethod::Query), handler);

        let reply = dwn
            .process_message(
                "did:example:alice",
                json!({
                    "descriptor": {
                        "interface": "Records",
                        "method": "Query"
                    }
                }),
            )
            .await;

        assert_eq!(
            reply,
            Response::<Reply>::unauthorized("tenant disabled".to_string())
        );
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_message_validates_interface_and_method_presence() {
        let dwn = Dwn::default();

        let reply = dwn
            .process_message(
                "did:example:alice",
                json!({
                    "descriptor": {
                        "interface": "Records"
                    }
                }),
            )
            .await;

        assert_eq!(
            reply,
            Response::<Reply>::bad_request(
                "Both interface and method must be present, interface: Records, method: undefined"
                    .to_string(),
            )
        );
    }

    #[tokio::test]
    async fn process_message_rejects_unknown_interface_method() {
        let dwn = Dwn::default();

        // Both fields present but the method is not a known kind: the typed `MessageKind` can't be
        // built, so dispatch short-circuits to `bad_request` (preserving the pre-enum status, where
        // an unrecognized kind fell through to a schema-not-found `bad_request`).
        let reply = dwn
            .process_message(
                "did:example:alice",
                json!({
                    "descriptor": {
                        "interface": "Records",
                        "method": "Bogus"
                    }
                }),
            )
            .await;

        assert_eq!(reply.status.code, 400);
        assert_eq!(
            reply.status.detail,
            "Unknown interface/method combination, interface: Records, method: Bogus"
        );
    }

    #[tokio::test]
    async fn process_message_dispatches_by_interface_and_method() {
        let mut dwn = Dwn::default();
        let query_handler = RecordingHandler::default();
        let query_calls = query_handler.calls.clone();
        let write_handler = RecordingHandler::default();
        let write_calls = write_handler.calls.clone();
        dwn.register_handler(MessageKind::Records(RecordsMethod::Query), query_handler);
        dwn.register_handler(MessageKind::Records(RecordsMethod::Write), write_handler);

        let reply = dwn
            .process_message(
                "did:example:alice",
                json!({
                    "descriptor": {
                        "interface": "Records",
                        "method": "Query",
                        "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                        "filter": {
                            "protocol": "https://example.com/test"
                        }
                    }
                }),
            )
            .await;

        assert_eq!(reply.status.code, 200);
        assert_eq!(
            query_calls.lock().unwrap().as_slice(),
            &["did:example:alice".to_string()]
        );
        assert!(write_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unregistered_handler_reports_no_handler_registered() {
        let dwn = Dwn::default();
        assert!(dwn.registered_kinds().is_empty());

        let reply = dwn
            .process_message(
                "did:example:alice",
                json!({
                    "descriptor": {
                        "interface": "Records",
                        "method": "Query",
                        "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                        "filter": {
                            "protocol": "https://example.com/test"
                        }
                    }
                }),
            )
            .await;
        assert_eq!(reply.status.code, 501);
        assert_eq!(
            reply.status.detail,
            "No handler registered for RecordsQuery"
        );
    }

    #[derive(Clone)]
    struct StaticTenantGate(TenantGateResult);

    impl TenantGate for StaticTenantGate {
        fn is_active_tenant<'a>(
            &'a self,
            _tenant: &'a str,
        ) -> Pin<Box<dyn Future<Output = TenantGateResult> + Send + 'a>> {
            let result = self.0.clone();
            Box::pin(async move { result })
        }
    }

    #[derive(Default, Clone)]
    struct RecordingHandler {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl MethodHandler for RecordingHandler {
        fn handle<'a>(
            &'a self,
            request: MethodHandlerRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Response<Reply>> + Send + 'a>> {
            let calls = self.calls.clone();
            let tenant = request.tenant.to_string();

            Box::pin(async move {
                calls.lock().unwrap().push(tenant);
                Response::ok()
            })
        }
    }
}
