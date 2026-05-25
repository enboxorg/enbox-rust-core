use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::interfaces::messages::descriptors::{
    CONFIGURE, COUNT, DELETE, MESSAGES, PROTOCOLS, QUERY, READ, RECORDS, SUBSCRIBE, SYNC, WRITE,
};
use crate::interfaces::replies::Status;
use crate::message_validation;

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageKind {
    pub interface: String,
    pub method: String,
}

impl MessageKind {
    pub fn new(interface: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            method: method.into(),
        }
    }

    pub fn from_message(message: &Value) -> Result<Self, DwnValidationError> {
        let descriptor = message.get("descriptor").and_then(Value::as_object);
        let interface = descriptor
            .and_then(|descriptor| descriptor.get("interface"))
            .and_then(Value::as_str);
        let method = descriptor
            .and_then(|descriptor| descriptor.get("method"))
            .and_then(Value::as_str);

        match (interface, method) {
            (Some(interface), Some(method)) => Ok(Self::new(interface, method)),
            _ => Err(DwnValidationError::MissingInterfaceMethod {
                interface: descriptor_field_detail(descriptor, "interface"),
                method: descriptor_field_detail(descriptor, "method"),
            }),
        }
    }

    pub fn handler_key(&self) -> String {
        format!("{}{}", self.interface, self.method)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DwnValidationError {
    MissingInterfaceMethod { interface: String, method: String },
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
            status: Status {
                code,
                detail: detail.into(),
            },
            body: BTreeMap::new(),
        }
    }

    pub fn ok() -> Self {
        Self::new(200, "OK")
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(400, detail)
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(401, detail)
    }

    pub fn not_implemented(detail: impl Into<String>) -> Self {
        Self::new(501, detail)
    }

    pub fn with_body(mut self, key: impl Into<String>, value: Value) -> Self {
        self.body.insert(key.into(), value);
        self
    }
}

#[derive(Clone)]
pub struct MethodHandlerRequest<'a> {
    pub tenant: &'a str,
    pub message: &'a Value,
    pub kind: MessageKind,
}

pub trait MethodHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>>;
}

pub type MethodHandlerMap = BTreeMap<MessageKind, Arc<dyn MethodHandler>>;

pub struct DwnConfig<
    MessageStore = (),
    DataStore = (),
    StateIndex = (),
    EventLog = (),
    ResumableTaskStore = (),
    DidResolver = (),
    Gate = AllowAllTenantGate,
> {
    pub did_resolver: Option<DidResolver>,
    pub tenant_gate: Gate,
    pub message_store: Option<MessageStore>,
    pub data_store: Option<DataStore>,
    pub state_index: Option<StateIndex>,
    pub event_log: Option<EventLog>,
    pub resumable_task_store: Option<ResumableTaskStore>,
    pub handlers: MethodHandlerMap,
}

impl Default for DwnConfig {
    fn default() -> Self {
        Self {
            did_resolver: None,
            tenant_gate: AllowAllTenantGate,
            message_store: None,
            data_store: None,
            state_index: None,
            event_log: None,
            resumable_task_store: None,
            handlers: default_method_handlers(),
        }
    }
}

pub struct Dwn<
    MessageStore = (),
    DataStore = (),
    StateIndex = (),
    EventLog = (),
    ResumableTaskStore = (),
    DidResolver = (),
    Gate = AllowAllTenantGate,
> {
    config: DwnConfig<
        MessageStore,
        DataStore,
        StateIndex,
        EventLog,
        ResumableTaskStore,
        DidResolver,
        Gate,
    >,
}

impl Default for Dwn {
    fn default() -> Self {
        Self::new(DwnConfig::default())
    }
}

impl<MessageStore, DataStore, StateIndex, EventLog, ResumableTaskStore, DidResolver, Gate>
    Dwn<MessageStore, DataStore, StateIndex, EventLog, ResumableTaskStore, DidResolver, Gate>
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
            DidResolver,
            Gate,
        >,
    ) -> Self {
        Self { config }
    }

    pub fn register_handler(&mut self, kind: MessageKind, handler: impl MethodHandler + 'static) {
        self.config.handlers.insert(kind, Arc::new(handler));
    }

    pub fn handlers(&self) -> &MethodHandlerMap {
        &self.config.handlers
    }

    pub async fn process_message(&self, tenant: &str, raw_message: Value) -> DwnReply {
        if let Some(reply) = self.validate_tenant(tenant).await {
            return reply;
        }

        let kind = match MessageKind::from_message(&raw_message) {
            Ok(kind) => kind,
            Err(DwnValidationError::MissingInterfaceMethod { interface, method }) => {
                return DwnReply::bad_request(format!(
                    "Both interface and method must be present, interface: {interface}, method: {method}"
                ));
            }
        };

        if let Err(error) = message_validation::validate_message(&raw_message) {
            return DwnReply::bad_request(error.to_string());
        }

        let Some(handler) = self.config.handlers.get(&kind) else {
            return DwnReply::not_implemented(format!(
                "No handler registered for {}",
                kind.handler_key()
            ));
        };

        handler
            .handle(MethodHandlerRequest {
                tenant,
                message: &raw_message,
                kind,
            })
            .await
    }

    async fn validate_tenant(&self, tenant: &str) -> Option<DwnReply> {
        let result = self.config.tenant_gate.is_active_tenant(tenant).await;
        if result.is_active_tenant {
            return None;
        }

        Some(DwnReply::unauthorized(result.detail.unwrap_or_else(|| {
            format!("DID {tenant} is not an active tenant.")
        })))
    }
}

pub fn default_method_handlers() -> MethodHandlerMap {
    current_handler_kinds()
        .into_iter()
        .map(|kind| {
            (
                kind,
                Arc::new(NotImplementedHandler) as Arc<dyn MethodHandler>,
            )
        })
        .collect()
}

pub fn current_handler_kinds() -> Vec<MessageKind> {
    vec![
        MessageKind::new(MESSAGES, READ),
        MessageKind::new(MESSAGES, SUBSCRIBE),
        MessageKind::new(MESSAGES, SYNC),
        MessageKind::new(PROTOCOLS, CONFIGURE),
        MessageKind::new(PROTOCOLS, QUERY),
        MessageKind::new(RECORDS, COUNT),
        MessageKind::new(RECORDS, DELETE),
        MessageKind::new(RECORDS, QUERY),
        MessageKind::new(RECORDS, READ),
        MessageKind::new(RECORDS, SUBSCRIBE),
        MessageKind::new(RECORDS, WRITE),
    ]
}

#[derive(Debug, Clone, Copy)]
struct NotImplementedHandler;

impl MethodHandler for NotImplementedHandler {
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move {
            DwnReply::not_implemented(format!(
                "{} handler is not implemented",
                request.kind.handler_key()
            ))
        })
    }
}

fn descriptor_field_detail(
    descriptor: Option<&serde_json::Map<String, Value>>,
    field: &str,
) -> String {
    match descriptor.and_then(|descriptor| descriptor.get(field)) {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) => "null".to_string(),
        Some(value) => value.to_string(),
        None => "undefined".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn process_message_rejects_inactive_tenant_before_dispatch() {
        let mut dwn = Dwn::<(), (), (), (), (), (), StaticTenantGate>::new(DwnConfig {
            tenant_gate: StaticTenantGate(TenantGateResult::inactive("tenant disabled")),
            handlers: MethodHandlerMap::new(),
            did_resolver: None,
            message_store: None,
            data_store: None,
            state_index: None,
            event_log: None,
            resumable_task_store: None,
        });
        let handler = RecordingHandler::default();
        let calls = handler.calls.clone();
        dwn.register_handler(MessageKind::new(RECORDS, QUERY), handler);

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

        assert_eq!(reply, DwnReply::unauthorized("tenant disabled"));
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
            DwnReply::bad_request(
                "Both interface and method must be present, interface: Records, method: undefined"
            )
        );
    }

    #[tokio::test]
    async fn process_message_dispatches_by_interface_and_method() {
        let mut dwn = Dwn::default();
        let handler = RecordingHandler::default();
        let calls = handler.calls.clone();
        dwn.register_handler(MessageKind::new(RECORDS, QUERY), handler);

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
        assert_eq!(reply.body["handler"], "RecordsQuery");
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[(
                "did:example:alice".to_string(),
                MessageKind::new(RECORDS, QUERY)
            )]
        );
    }

    #[tokio::test]
    async fn default_handler_set_matches_current_typescript_methods() {
        let dwn = Dwn::default();

        for kind in current_handler_kinds() {
            assert!(
                dwn.handlers().contains_key(&kind),
                "missing default handler for {}",
                kind.handler_key()
            );
        }

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
            "RecordsQuery handler is not implemented"
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
        calls: Arc<Mutex<Vec<(String, MessageKind)>>>,
    }

    impl MethodHandler for RecordingHandler {
        fn handle<'a>(
            &'a self,
            request: MethodHandlerRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
            let calls = self.calls.clone();
            let tenant = request.tenant.to_string();
            let kind = request.kind.clone();

            Box::pin(async move {
                calls.lock().unwrap().push((tenant, kind.clone()));
                DwnReply::ok().with_body("handler", json!(kind.handler_key()))
            })
        }
    }
}
