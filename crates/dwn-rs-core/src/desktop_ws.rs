//! JSON-RPC over WebSocket for loopback DWN servers.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use tokio::sync::mpsc;

use crate::desktop::{
    DesktopProcessMessageRequest, DesktopProcessMessageResult, DesktopResult,
};
use crate::desktop_server::{SharedDesktopMessageProcessor, PROCESS_MESSAGE_METHOD};
use crate::handlers::records::RecordsSubscribeReply;
use crate::stores::{ProgressToken, SubscriptionMessage};

pub const SUBSCRIBE_PROCESS_MESSAGE_METHOD: &str = "rpc.subscribe.dwn.processMessage";
pub const SUBSCRIBE_CLOSE_METHOD: &str = "rpc.subscribe.close";
pub const SUBSCRIBE_ACK_METHOD: &str = "rpc.ack";
pub const RPC_PING_METHOD: &str = "rpc.ping";

const DEFAULT_MAX_IN_FLIGHT: usize = 32;

type SharedSubscriptionListener =
    Arc<dyn Fn(SubscriptionMessage) + Send + Sync + 'static>;

#[derive(Clone)]
pub struct SharedDesktopSubscribeProcessor {
    inner: Arc<
        dyn Fn(
                DesktopProcessMessageRequest,
                SharedSubscriptionListener,
            ) -> Pin<
                Box<dyn Future<Output = DesktopResult<RecordsSubscribeReply>> + Send>,
            > + Send
            + Sync,
    >,
}

impl SharedDesktopSubscribeProcessor {
    pub fn new<F, Fut>(handler: F) -> Self
    where
        F: Fn(DesktopProcessMessageRequest, SharedSubscriptionListener) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = DesktopResult<RecordsSubscribeReply>> + Send + 'static,
    {
        Self {
            inner: Arc::new(move |request, listener| {
                Box::pin(handler(request, listener))
            }),
        }
    }

    pub fn process_subscribe(
        &self,
        request: DesktopProcessMessageRequest,
        listener: SharedSubscriptionListener,
    ) -> Pin<Box<dyn Future<Output = DesktopResult<RecordsSubscribeReply>> + Send>> {
        (self.inner)(request, listener)
    }
}

pub async fn handle_websocket(
    socket: WebSocket,
    processor: SharedDesktopMessageProcessor,
    subscribe: Option<SharedDesktopSubscribeProcessor>,
) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let connection = Arc::new(Mutex::new(WsConnection {
        subscriptions: HashMap::new(),
        max_in_flight: DEFAULT_MAX_IN_FLIGHT,
    }));

    let send_task = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if sender.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(message) = receiver.next().await {
        let Ok(Message::Text(text)) = message else {
            break;
        };
        if let Some(response) = handle_json_rpc(
            &text,
            &processor,
            subscribe.as_ref(),
            &connection,
            &tx,
        )
        .await
        {
            let _ = tx.send(response);
        }
    }

    drop(tx);
    let _ = send_task.await;
}

async fn handle_json_rpc(
    payload: &str,
    processor: &SharedDesktopMessageProcessor,
    subscribe: Option<&SharedDesktopSubscribeProcessor>,
    connection: &Arc<Mutex<WsConnection>>,
    tx: &mpsc::UnboundedSender<String>,
) -> Option<String> {
    let request: JsonRpcRequest = match serde_json::from_str(payload) {
        Ok(request) => request,
        Err(err) => {
            return Some(serde_json::to_string(&json_rpc_error(
                JsonValue::Null,
                -32600,
                err.to_string(),
            ))
            .unwrap_or_default());
        }
    };

    match request.method.as_str() {
        RPC_PING_METHOD => Some(
            serde_json::to_string(&json_rpc_success(
                request.id.unwrap_or(JsonValue::Null),
                json!({ "reply": { "status": { "code": 200, "detail": "OK" } } }),
            ))
            .unwrap_or_default(),
        ),
        SUBSCRIBE_ACK_METHOD => {
            handle_ack(&request, connection);
            request.id.map(|id| {
                serde_json::to_string(&json_rpc_success(
                    id,
                    json!({ "reply": { "status": { "code": 200, "detail": "OK" } } }),
                ))
                .unwrap_or_default()
            })
        }
        SUBSCRIBE_CLOSE_METHOD => {
            Some(handle_close(&request, connection).await)
        }
        SUBSCRIBE_PROCESS_MESSAGE_METHOD | PROCESS_MESSAGE_METHOD => {
            Some(
                handle_process_message(&request, processor, subscribe, connection, tx).await,
            )
        }
        other => Some(
            serde_json::to_string(&json_rpc_error(
                request.id.unwrap_or(JsonValue::Null),
                -32601,
                format!("method not found: {other}"),
            ))
            .unwrap_or_default(),
        ),
    }
}

async fn handle_process_message(
    request: &JsonRpcRequest,
    processor: &SharedDesktopMessageProcessor,
    subscribe: Option<&SharedDesktopSubscribeProcessor>,
    connection: &Arc<Mutex<WsConnection>>,
    tx: &mpsc::UnboundedSender<String>,
) -> String {
    let request_id = request.id.clone().unwrap_or(JsonValue::Null);
    let tenant = request
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
    let is_subscribe = request.method == SUBSCRIBE_PROCESS_MESSAGE_METHOD;
    let subscription_id = request.subscription.as_ref().and_then(|s| s.id.clone());

    if is_subscribe {
        let Some(subscription_id) = subscription_id else {
            return serde_json::to_string(&json_rpc_error(
                request_id,
                -32602,
                "subscription options are required".to_string(),
            ))
            .unwrap_or_default();
        };
        let Some(subscribe_processor) = subscribe else {
            return serde_json::to_string(&json_rpc_error(
                request_id,
                -32603,
                "subscriptions are not enabled on this server".to_string(),
            ))
            .unwrap_or_default();
        };
        if connection.lock().unwrap().subscriptions.contains_key(&subscription_id) {
            return serde_json::to_string(&json_rpc_error(
                request_id,
                -32602,
                format!("the subscribe id: {subscription_id} is in use by an active subscription"),
            ))
            .unwrap_or_default();
        }

        let max_in_flight = connection.lock().unwrap().max_in_flight;
        let flow = FlowController::new(subscription_id.clone(), tx.clone(), max_in_flight);
        let flow_for_listener = flow.clone();
        let listener: SharedSubscriptionListener = Arc::new(move |message| {
            flow_for_listener.push(message);
        });

        let result = subscribe_processor
            .process_subscribe(
                DesktopProcessMessageRequest {
                    tenant,
                    message,
                    data: None,
                },
                listener,
            )
            .await;

        match result {
            Ok(subscribe_reply) => {
                if let Some(subscription) = subscribe_reply.subscription {
                    connection.lock().unwrap().subscriptions.insert(
                        subscription_id.clone(),
                        ActiveSubscription {
                            flow,
                            close: subscription.close,
                        },
                    );
                }
                let mut reply_json = dwn_reply_json(&subscribe_reply.reply);
                if let Some(object) = reply_json.as_object_mut() {
                    object.insert(
                        "subscription".to_string(),
                        json!({ "id": subscription_id }),
                    );
                }
                serde_json::to_string(&json_rpc_success(
                    request_id,
                    json!({ "reply": reply_json }),
                ))
                .unwrap_or_default()
            }
            Err(error) => serde_json::to_string(&json_rpc_error(
                request_id,
                -32603,
                format!("{}: {}", error.code, error.detail),
            ))
            .unwrap_or_default(),
        }
    } else {
        let result = processor
            .process(DesktopProcessMessageRequest {
                tenant,
                message,
                data: None,
            })
            .await;
        match result {
            Ok(reply) => {
                let reply_json = desktop_reply_json(&reply);
                serde_json::to_string(&json_rpc_success(request_id, json!({ "reply": reply_json })))
                    .unwrap_or_default()
            }
            Err(error) => serde_json::to_string(&json_rpc_error(
                request_id,
                -32603,
                format!("{}: {}", error.code, error.detail),
            ))
            .unwrap_or_default(),
        }
    }
}

fn handle_ack(request: &JsonRpcRequest, connection: &Arc<Mutex<WsConnection>>) {
    let Some(subscription) = &request.subscription else {
        return;
    };
    let Some(subscription_id) = &subscription.id else {
        return;
    };
    let Some(cursor) = request
        .params
        .get("cursor")
        .and_then(|value| serde_json::from_value::<ProgressToken>(value.clone()).ok())
    else {
        return;
    };
    if let Some(active) = connection
        .lock()
        .unwrap()
        .subscriptions
        .get(subscription_id)
    {
        active.flow.ack(&cursor);
    }
}

async fn handle_close(request: &JsonRpcRequest, connection: &Arc<Mutex<WsConnection>>) -> String {
    let request_id = request.id.clone().unwrap_or(JsonValue::Null);
    let Some(subscription) = &request.subscription else {
        return serde_json::to_string(&json_rpc_error(
            request_id,
            -32600,
            "subscribe options do not exist".to_string(),
        ))
        .unwrap_or_default();
    };
    let Some(subscription_id) = &subscription.id else {
        return serde_json::to_string(&json_rpc_error(
            request_id,
            -32600,
            "subscribe options do not exist".to_string(),
        ))
        .unwrap_or_default();
    };

    let close = connection
        .lock()
        .unwrap()
        .subscriptions
        .remove(subscription_id)
        .map(|active| active.close);
    match close {
        Some(close) => {
            let _ = (close)().await;
            serde_json::to_string(&json_rpc_success(
                request_id,
                json!({ "reply": { "status": { "code": 200, "detail": "Accepted" } } }),
            ))
            .unwrap_or_default()
        }
        None => serde_json::to_string(&json_rpc_error(
            request_id,
            -32602,
            format!("subscription {subscription_id} does not exist."),
        ))
        .unwrap_or_default(),
    }
}

struct WsConnection {
    subscriptions: HashMap<JsonValue, ActiveSubscription>,
    max_in_flight: usize,
}

struct ActiveSubscription {
    flow: FlowController,
    close: crate::stores::EventSubscriptionClose,
}

#[derive(Clone)]
struct FlowController {
    subscription_id: JsonValue,
    tx: mpsc::UnboundedSender<String>,
    state: Arc<Mutex<FlowControllerState>>,
}

struct FlowControllerState {
    unacked: Vec<ProgressToken>,
    buffer: Vec<SubscriptionMessage>,
    max_in_flight: usize,
}

impl FlowController {
    fn new(
        subscription_id: JsonValue,
        tx: mpsc::UnboundedSender<String>,
        max_in_flight: usize,
    ) -> Self {
        Self {
            subscription_id,
            tx,
            state: Arc::new(Mutex::new(FlowControllerState {
                unacked: Vec::new(),
                buffer: Vec::new(),
                max_in_flight,
            })),
        }
    }

    fn push(&self, message: SubscriptionMessage) {
        let cursor = match &message {
            SubscriptionMessage::Event { cursor, .. } => cursor.clone(),
            SubscriptionMessage::Eose { cursor } => cursor.clone(),
        };
        let mut state = self.state.lock().unwrap();
        if state.unacked.len() < state.max_in_flight {
            drop(state);
            self.send_message(message, cursor);
        } else {
            state.buffer.push(message);
        }
    }

    fn ack(&self, cursor: &ProgressToken) {
        let mut state = self.state.lock().unwrap();
        let Some(index) = state.unacked.iter().position(|token| {
            token.stream_id == cursor.stream_id
                && token.epoch == cursor.epoch
                && token.position == cursor.position
                && token.message_cid == cursor.message_cid
        }) else {
            return;
        };
        state.unacked.drain(0..=index);
        while state.unacked.len() < state.max_in_flight {
            let Some(message) = state.buffer.first().cloned() else {
                break;
            };
            state.buffer.remove(0);
            let cursor = match &message {
                SubscriptionMessage::Event { cursor, .. } => cursor.clone(),
                SubscriptionMessage::Eose { cursor } => cursor.clone(),
            };
            drop(state);
            self.send_message(message, cursor);
            state = self.state.lock().unwrap();
        }
    }

    fn send_message(&self, message: SubscriptionMessage, cursor: ProgressToken) {
        let subscription =
            serde_json::to_value(message).unwrap_or(JsonValue::Null);
        let response = json_rpc_success(
            self.subscription_id.clone(),
            json!({ "subscription": subscription }),
        );
        if let Ok(text) = serde_json::to_string(&response) {
            let _ = self.tx.send(text);
        }
        self.state.lock().unwrap().unacked.push(cursor);
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    id: Option<JsonValue>,
    method: String,
    params: JsonValue,
    subscription: Option<JsonRpcSubscription>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcSubscription {
    id: Option<JsonValue>,
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

fn json_rpc_success(id: JsonValue, result: JsonValue) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

fn json_rpc_error(id: JsonValue, code: i32, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcErrorObject { code, message }),
    }
}

fn dwn_reply_json(reply: &crate::dwn::DwnReply) -> JsonValue {
    json!({
        "status": {
            "code": reply.status.code,
            "detail": reply.status.detail,
        },
        "body": reply.body,
    })
}

fn desktop_reply_json(reply: &DesktopProcessMessageResult) -> JsonValue {
    json!({
        "status": {
            "code": reply.status_code,
            "detail": reply.status_detail,
        },
        "body": reply.body,
    })
}
