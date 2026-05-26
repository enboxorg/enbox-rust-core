//! Loopback HTTP server for desktop local DWN nodes.
//!
//! Implements the minimal `@enbox/dwn-server` surface used by `@enbox/dwn-clients`:
//! `GET /health`, `GET /info`, and `POST /` with JSON-RPC in the `dwn-request` header.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{ws::WebSocketUpgrade, FromRequest, State},
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;

use crate::desktop::{
    DesktopError, DesktopFuture, DesktopLocalServer, DesktopMessageProcessor,
    DesktopProcessMessageRequest, DesktopProcessMessageResult, DesktopResult, DesktopServerConfig,
    DesktopServerStatus, LOCAL_DWN_SERVER_NAME,
};
use crate::desktop_ws;
use crate::dwn::{Dwn, TenantGate};

pub const PROCESS_MESSAGE_METHOD: &str = "dwn.processMessage";
pub use crate::desktop_ws::SharedDesktopSubscribeProcessor;

type ProcessorFn = dyn Fn(
        DesktopProcessMessageRequest,
    ) -> Pin<Box<dyn Future<Output = DesktopResult<DesktopProcessMessageResult>> + Send>>
    + Send
    + Sync;

#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct SharedDesktopMessageProcessor {
    inner: Arc<ProcessorFn>,
}

impl SharedDesktopMessageProcessor {
    pub fn new<F, Fut>(handler: F) -> Self
    where
        F: Fn(DesktopProcessMessageRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = DesktopResult<DesktopProcessMessageResult>> + Send + 'static,
    {
        Self {
            inner: Arc::new(move |request| Box::pin(handler(request))),
        }
    }

    pub async fn process(
        &self,
        request: DesktopProcessMessageRequest,
    ) -> DesktopResult<DesktopProcessMessageResult> {
        (self.inner)(request).await
    }
}

impl DesktopMessageProcessor for SharedDesktopMessageProcessor {
    fn process_message<'a>(
        &'a self,
        request: DesktopProcessMessageRequest,
    ) -> DesktopFuture<'a, DesktopProcessMessageResult> {
        let inner = self.inner.clone();
        Box::pin(async move { inner(request).await })
    }
}

pub struct DwnDesktopMessageProcessor<D> {
    dwn: Arc<D>,
}

impl<D> Clone for DwnDesktopMessageProcessor<D> {
    fn clone(&self) -> Self {
        Self {
            dwn: self.dwn.clone(),
        }
    }
}

impl<D> DwnDesktopMessageProcessor<D> {
    pub fn new(dwn: D) -> Self {
        Self { dwn: Arc::new(dwn) }
    }

    pub fn from_arc(dwn: Arc<D>) -> Self {
        Self { dwn }
    }
}

impl<D> DesktopMessageProcessor for DwnDesktopMessageProcessor<D>
where
    D: DwnProcessMessage + Send + Sync + 'static,
{
    fn process_message<'a>(
        &'a self,
        request: DesktopProcessMessageRequest,
    ) -> DesktopFuture<'a, DesktopProcessMessageResult> {
        let dwn = self.dwn.clone();
        Box::pin(async move {
            let data = request.data.clone();
            let reply = dwn
                .process_message_with_data(
                    &request.tenant,
                    request.message,
                    data.clone().map(bytes::Bytes::from),
                )
                .await;
            Ok(DesktopProcessMessageResult {
                status_code: reply.status.code as u16,
                status_detail: reply.status.detail,
                body: serde_json::to_value(&reply.body)
                    .unwrap_or_else(|err| json!({ "serializationError": err.to_string() })),
                data,
            })
        })
    }
}

pub trait DwnProcessMessage: Send + Sync {
    fn process_message(
        &self,
        tenant: &str,
        message: JsonValue,
    ) -> Pin<Box<dyn Future<Output = crate::dwn::DwnReply> + Send + '_>>;

    fn process_message_with_data(
        &self,
        tenant: &str,
        message: JsonValue,
        data: Option<bytes::Bytes>,
    ) -> Pin<Box<dyn Future<Output = crate::dwn::DwnReply> + Send + '_>> {
        let _ = data;
        self.process_message(tenant, message)
    }
}

impl<MS, DS, SI, EL, RTS, DR, Gate> DwnProcessMessage for Dwn<MS, DS, SI, EL, RTS, DR, Gate>
where
    MS: Send + Sync + 'static,
    DS: Send + Sync + 'static,
    SI: Send + Sync + 'static,
    EL: Send + Sync + 'static,
    RTS: Send + Sync + 'static,
    DR: Send + Sync + 'static,
    Gate: TenantGate + Send + Sync + 'static,
{
    fn process_message(
        &self,
        tenant: &str,
        message: JsonValue,
    ) -> Pin<Box<dyn Future<Output = crate::dwn::DwnReply> + Send + '_>> {
        let tenant = tenant.to_string();
        Box::pin(async move { self.process_message(&tenant, message).await })
    }

    fn process_message_with_data(
        &self,
        tenant: &str,
        message: JsonValue,
        data: Option<bytes::Bytes>,
    ) -> Pin<Box<dyn Future<Output = crate::dwn::DwnReply> + Send + '_>> {
        let tenant = tenant.to_string();
        Box::pin(async move { self.process_message_with_data(&tenant, message, data).await })
    }
}

impl<MS, DS, SI, EL, RTS, DR, Gate> DwnProcessMessage for Arc<Dwn<MS, DS, SI, EL, RTS, DR, Gate>>
where
    MS: Send + Sync + 'static,
    DS: Send + Sync + 'static,
    SI: Send + Sync + 'static,
    EL: Send + Sync + 'static,
    RTS: Send + Sync + 'static,
    DR: Send + Sync + 'static,
    Gate: TenantGate + Send + Sync + 'static,
{
    fn process_message(
        &self,
        tenant: &str,
        message: JsonValue,
    ) -> Pin<Box<dyn Future<Output = crate::dwn::DwnReply> + Send + '_>> {
        let tenant = tenant.to_string();
        let dwn = Arc::clone(self);
        Box::pin(async move { dwn.process_message(&tenant, message).await })
    }

    fn process_message_with_data(
        &self,
        tenant: &str,
        message: JsonValue,
        data: Option<bytes::Bytes>,
    ) -> Pin<Box<dyn Future<Output = crate::dwn::DwnReply> + Send + '_>> {
        let tenant = tenant.to_string();
        let dwn = Arc::clone(self);
        Box::pin(async move { dwn.process_message_with_data(&tenant, message, data).await })
    }
}

#[derive(Clone)]
struct AppState {
    processor: SharedDesktopMessageProcessor,
    subscribe: Option<SharedDesktopSubscribeProcessor>,
    websocket_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerInfo {
    server: String,
    web_socket_support: bool,
    max_file_size: u64,
    max_in_flight: u32,
    registration_requirements: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    id: JsonValue,
    method: String,
    params: JsonValue,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcErrorObject>,
}

#[derive(Debug, Serialize)]
struct JsonRpcErrorObject {
    code: i32,
    message: String,
}

struct RunningServer {
    shutdown: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

#[derive(Clone)]
pub struct LoopbackDwnServer {
    processor: SharedDesktopMessageProcessor,
    subscribe: Option<SharedDesktopSubscribeProcessor>,
    running: Arc<Mutex<Option<RunningServer>>>,
    status: Arc<Mutex<DesktopServerStatus>>,
}

impl LoopbackDwnServer {
    pub fn new(processor: SharedDesktopMessageProcessor) -> Self {
        Self {
            processor,
            subscribe: None,
            running: Arc::new(Mutex::new(None)),
            status: Arc::new(Mutex::new(DesktopServerStatus::default())),
        }
    }

    pub fn with_subscribe(
        processor: SharedDesktopMessageProcessor,
        subscribe: SharedDesktopSubscribeProcessor,
    ) -> Self {
        Self {
            processor,
            subscribe: Some(subscribe),
            running: Arc::new(Mutex::new(None)),
            status: Arc::new(Mutex::new(DesktopServerStatus::default())),
        }
    }

    pub fn with_message_processor<P>(processor: P) -> Self
    where
        P: DesktopMessageProcessor + 'static,
    {
        let processor = processor.clone();
        Self::new(SharedDesktopMessageProcessor::new(move |request| {
            let processor = processor.clone();
            async move { processor.process_message(request).await }
        }))
    }
}

impl DesktopLocalServer for LoopbackDwnServer {
    fn start<'a>(&'a self, config: DesktopServerConfig) -> DesktopFuture<'a, DesktopServerStatus> {
        Box::pin(async move {
            if !super::desktop::is_loopback_host(&config.bind_host) {
                return Err(DesktopError::new(
                    "DesktopLoopbackOnly",
                    format!(
                        "desktop local server must bind to a loopback host, got {}",
                        config.bind_host
                    ),
                ));
            }

            let mut running = self.running.lock().await;
            if running.is_some() {
                return Err(DesktopError::new(
                    "DesktopNodeAlreadyRunning",
                    "loopback server is already running",
                ));
            }

            let addr: SocketAddr = format!("{}:{}", config.bind_host, config.port)
                .parse()
                .map_err(|err| {
                    DesktopError::new(
                        "DesktopServerBindFailed",
                        format!("invalid bind address: {err}"),
                    )
                })?;

            let listener = tokio::net::TcpListener::bind(addr).await.map_err(|err| {
                DesktopError::new(
                    "DesktopServerBindFailed",
                    format!("failed to bind {addr}: {err}"),
                )
            })?;
            let bound_port = listener
                .local_addr()
                .map_err(|err| {
                    DesktopError::new(
                        "DesktopServerBindFailed",
                        format!("failed to read bound address: {err}"),
                    )
                })?
                .port();

            let endpoint = super::desktop::endpoint_url("http", &config.bind_host, bound_port);
            let websocket_endpoint = config
                .websocket_enabled
                .then(|| super::desktop::endpoint_url("ws", &config.bind_host, bound_port));

            let state = AppState {
                processor: self.processor.clone(),
                subscribe: self.subscribe.clone(),
                websocket_enabled: config.websocket_enabled,
            };
            let app = Router::new()
                .route("/health", get(health))
                .route("/info", get(info))
                .route("/", post(json_rpc).get(root_get))
                .with_state(state);

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let join = tokio::spawn(async move {
                if let Err(err) = axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                {
                    tracing::error!("loopback dwn server exited with error: {err}");
                }
            });

            *running = Some(RunningServer {
                shutdown: shutdown_tx,
                join,
            });
            let status = DesktopServerStatus {
                running: true,
                server_name: Some(config.server_name),
                endpoint: Some(endpoint),
                websocket_endpoint,
                bind_host: Some(config.bind_host),
                port: Some(bound_port),
                websocket_enabled: config.websocket_enabled,
            };
            *self.status.lock().await = status.clone();
            Ok(status)
        })
    }

    fn stop<'a>(&'a self) -> DesktopFuture<'a, ()> {
        Box::pin(async move {
            if let Some(server) = self.running.lock().await.take() {
                let _ = server.shutdown.send(());
                let _ = server.join.await;
            }
            *self.status.lock().await = DesktopServerStatus::default();
            Ok(())
        })
    }

    fn status(&self) -> DesktopServerStatus {
        self.status
            .try_lock()
            .map(|status| status.clone())
            .unwrap_or_default()
    }
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

async fn root_get(State(state): State<AppState>, req: Request<axum::body::Body>) -> Response {
    if state.websocket_enabled && is_websocket_upgrade(req.headers()) {
        match WebSocketUpgrade::from_request(req, &()).await {
            Ok(ws) => {
                let processor = state.processor.clone();
                let subscribe = state.subscribe.clone();
                return ws
                    .on_upgrade(move |socket| {
                        desktop_ws::handle_websocket(socket, processor, subscribe)
                    })
                    .into_response();
            }
            Err(rejection) => return rejection.into_response(),
        }
    }
    root_hint().await.into_response()
}

async fn root_hint() -> impl IntoResponse {
    (
        StatusCode::OK,
        "please use an enbox client, for example: https://github.com/enboxorg/enbox",
    )
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && headers.contains_key("sec-websocket-key")
}

async fn info(State(state): State<AppState>) -> impl IntoResponse {
    Json(ServerInfo {
        server: LOCAL_DWN_SERVER_NAME.to_string(),
        web_socket_support: state.websocket_enabled,
        max_file_size: 30_000_000,
        max_in_flight: 256,
        registration_requirements: Vec::new(),
    })
}

async fn json_rpc(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(request_header) = headers
        .get("dwn-request")
        .and_then(|value| value.to_str().ok())
    else {
        return json_rpc_error(
            json!(null),
            -32600,
            "request payload required.".to_string(),
            StatusCode::BAD_REQUEST,
        );
    };

    let request: JsonRpcRequest = match serde_json::from_str(request_header) {
        Ok(request) => request,
        Err(err) => {
            return json_rpc_error(
                json!(null),
                -32600,
                err.to_string(),
                StatusCode::BAD_REQUEST,
            )
        }
    };

    if request.method != PROCESS_MESSAGE_METHOD {
        return json_rpc_error(
            request.id,
            -32601,
            format!("method not found: {}", request.method),
            StatusCode::OK,
        );
    }

    let target = request
        .params
        .get("target")
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_string();
    let message = request
        .params
        .get("message")
        .cloned()
        .unwrap_or(JsonValue::Null);
    let data = if body.is_empty() {
        None
    } else {
        Some(body.to_vec())
    };

    let result = state
        .processor
        .process(DesktopProcessMessageRequest {
            tenant: target,
            message,
            data,
        })
        .await;

    match result {
        Ok(reply) => {
            let response = JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: Some(json!({
                    "reply": {
                        "status": {
                            "code": reply.status_code,
                            "detail": reply.status_detail,
                        },
                        "body": reply.body,
                    }
                })),
                error: None,
            };
            let header_value = serde_json::to_string(&response).unwrap_or_default();
            Response::builder()
                .status(StatusCode::OK)
                .header("dwn-response", header_value)
                .body(axum::body::Body::empty())
                .unwrap()
        }
        Err(error) => json_rpc_error(
            request.id,
            -32603,
            format!("{}: {}", error.code, error.detail),
            StatusCode::OK,
        ),
    }
}

fn json_rpc_error(id: JsonValue, code: i32, message: String, status: StatusCode) -> Response {
    let response = JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcErrorObject { code, message }),
    };
    (status, Json(response)).into_response()
}
