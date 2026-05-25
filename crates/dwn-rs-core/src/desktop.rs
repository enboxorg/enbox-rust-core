use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub const LOCAL_DWN_SERVER_NAME: &str = "@enbox/dwn-server";
pub const DESKTOP_LOCAL_DWN_PORT_CANDIDATES: &[u16] = &[
    3000, 55500, 55501, 55502, 55503, 55504, 55505, 55506, 55507, 55508, 55509,
];

pub type DesktopResult<T> = Result<T, DesktopError>;
pub type DesktopFuture<'a, T> = Pin<Box<dyn Future<Output = DesktopResult<T>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopError {
    pub code: String,
    pub detail: String,
}

impl DesktopError {
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }

    fn already_running() -> Self {
        Self::new(
            "DesktopNodeAlreadyRunning",
            "desktop local node is already running",
        )
    }

    fn not_running() -> Self {
        Self::new("DesktopNodeNotRunning", "desktop local node is not running")
    }

    fn non_loopback_host(host: &str) -> Self {
        Self::new(
            "DesktopLoopbackOnly",
            format!("desktop local server must bind to a loopback host, got {host}"),
        )
    }

    pub(crate) fn lock_poisoned<E: Display>(err: E) -> Self {
        Self::new(
            "DesktopLockPoisoned",
            format!("desktop runtime lock poisoned: {err}"),
        )
    }
}

impl Display for DesktopError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for DesktopError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DesktopNodeMode {
    Embedded,
    LoopbackServer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopNodeConfig {
    pub node_id: String,
    pub app_id: String,
    #[serde(default)]
    pub discovery: DesktopDiscoveryConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

impl DesktopNodeConfig {
    pub fn new(node_id: impl Into<String>, app_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            app_id: app_id.into(),
            discovery: DesktopDiscoveryConfig::default(),
            pid: current_process_id(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopDiscoveryConfig {
    pub publish: bool,
    pub service_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_file_path: Option<String>,
}

impl Default for DesktopDiscoveryConfig {
    fn default() -> Self {
        Self {
            publish: true,
            service_name: LOCAL_DWN_SERVER_NAME.to_string(),
            discovery_file_path: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopDiscoveryRecord {
    pub endpoint: String,
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopNodeAdvert {
    pub node_id: String,
    pub app_id: String,
    pub mode: DesktopNodeMode,
    pub service_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket_endpoint: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl DesktopNodeAdvert {
    pub fn discovery_record(&self) -> Option<DesktopDiscoveryRecord> {
        Some(DesktopDiscoveryRecord {
            endpoint: self.endpoint.clone()?,
            pid: self.pid?,
            capabilities: self.capabilities.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopServerConfig {
    pub server_name: String,
    pub bind_host: String,
    pub port: u16,
    pub websocket_enabled: bool,
}

impl Default for DesktopServerConfig {
    fn default() -> Self {
        Self {
            server_name: LOCAL_DWN_SERVER_NAME.to_string(),
            bind_host: "127.0.0.1".to_string(),
            port: DESKTOP_LOCAL_DWN_PORT_CANDIDATES[0],
            websocket_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopServerStatus {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub websocket_enabled: bool,
}

impl DesktopServerStatus {
    fn capabilities(&self) -> Vec<String> {
        let mut capabilities = Vec::new();
        if self.endpoint.is_some() {
            capabilities.push("http".to_string());
        }
        if self.websocket_endpoint.is_some() {
            capabilities.push("ws".to_string());
        }
        capabilities
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum DesktopStartMode {
    Embedded,
    LoopbackServer { config: DesktopServerConfig },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopStartRequest {
    pub mode: DesktopStartMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopRuntimeStatus {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<DesktopNodeMode>,
    pub server: DesktopServerStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advert: Option<DesktopNodeAdvert>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopProcessMessageRequest {
    pub tenant: String,
    pub message: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopProcessMessageResult {
    pub status_code: u16,
    pub status_detail: String,
    pub body: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DesktopDeliveryKind {
    EndpointForwarding,
    ProtocolDelivery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DesktopDeliveryMode {
    Local,
    Remote,
    StoreAndForward,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopDeliveryRequest {
    pub kind: DesktopDeliveryKind,
    pub mode: DesktopDeliveryMode,
    pub tenant: String,
    pub target_did: String,
    pub endpoint: String,
    pub message: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dedup_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopQueuedDelivery {
    pub id: String,
    pub request: DesktopDeliveryRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopDeliveryReceipt {
    pub delivery_id: String,
    pub queued: bool,
}

pub trait DesktopMessageProcessor: Clone + Send + Sync + 'static {
    fn process_message<'a>(
        &'a self,
        request: DesktopProcessMessageRequest,
    ) -> DesktopFuture<'a, DesktopProcessMessageResult>;
}

pub trait DesktopLocalServer: Clone + Send + Sync + 'static {
    fn start<'a>(&'a self, config: DesktopServerConfig) -> DesktopFuture<'a, DesktopServerStatus>;
    fn stop<'a>(&'a self) -> DesktopFuture<'a, ()>;
    fn status(&self) -> DesktopServerStatus;
}

pub trait DesktopDiscoveryRegistry: Clone + Send + Sync + 'static {
    fn publish<'a>(&'a self, advert: DesktopNodeAdvert) -> DesktopFuture<'a, ()>;
    fn remove<'a>(&'a self, node_id: &'a str) -> DesktopFuture<'a, ()>;
    fn resolve<'a>(&'a self, node_id: &'a str) -> DesktopFuture<'a, Option<DesktopNodeAdvert>>;
    fn list<'a>(&'a self) -> DesktopFuture<'a, Vec<DesktopNodeAdvert>>;
}

pub trait DesktopDeliveryQueue: Clone + Send + Sync + 'static {
    fn enqueue<'a>(
        &'a self,
        delivery: DesktopQueuedDelivery,
    ) -> DesktopFuture<'a, DesktopDeliveryReceipt>;
    fn pending<'a>(
        &'a self,
        tenant: Option<String>,
    ) -> DesktopFuture<'a, Vec<DesktopQueuedDelivery>>;
    fn ack<'a>(&'a self, delivery_id: &'a str) -> DesktopFuture<'a, ()>;
}

#[derive(Clone)]
pub struct DesktopLocalNode<P, S, R, Q> {
    config: DesktopNodeConfig,
    processor: P,
    server: S,
    discovery: R,
    delivery_queue: Q,
    state: Arc<RwLock<DesktopNodeState>>,
}

#[derive(Debug, Default)]
struct DesktopNodeState {
    running: bool,
    mode: Option<DesktopNodeMode>,
    advert: Option<DesktopNodeAdvert>,
}

impl<P, S, R, Q> DesktopLocalNode<P, S, R, Q>
where
    P: DesktopMessageProcessor,
    S: DesktopLocalServer,
    R: DesktopDiscoveryRegistry,
    Q: DesktopDeliveryQueue,
{
    pub fn new(
        config: DesktopNodeConfig,
        processor: P,
        server: S,
        discovery: R,
        delivery_queue: Q,
    ) -> Self {
        Self {
            config,
            processor,
            server,
            discovery,
            delivery_queue,
            state: Arc::new(RwLock::new(DesktopNodeState::default())),
        }
    }

    pub async fn start(&self, request: DesktopStartRequest) -> DesktopResult<DesktopRuntimeStatus> {
        if self
            .state
            .read()
            .map_err(DesktopError::lock_poisoned)?
            .running
        {
            return Err(DesktopError::already_running());
        }

        let (mode, server_status) = match request.mode {
            DesktopStartMode::Embedded => {
                self.server.stop().await?;
                (DesktopNodeMode::Embedded, DesktopServerStatus::default())
            }
            DesktopStartMode::LoopbackServer { config } => {
                let status = self.server.start(config).await?;
                (DesktopNodeMode::LoopbackServer, status)
            }
        };

        let advert = self.build_advert(mode, &server_status);
        if self.config.discovery.publish {
            self.discovery.publish(advert.clone()).await?;
        }

        {
            let mut state = self.state.write().map_err(DesktopError::lock_poisoned)?;
            state.running = true;
            state.mode = Some(mode);
            state.advert = Some(advert);
        }

        Ok(self.status())
    }

    pub async fn stop(&self) -> DesktopResult<DesktopRuntimeStatus> {
        let node_id = self.config.node_id.clone();
        self.server.stop().await?;
        if self.config.discovery.publish {
            self.discovery.remove(&node_id).await?;
        }
        {
            let mut state = self.state.write().map_err(DesktopError::lock_poisoned)?;
            state.running = false;
            state.mode = None;
            state.advert = None;
        }
        Ok(self.status())
    }

    pub async fn process_message(
        &self,
        request: DesktopProcessMessageRequest,
    ) -> DesktopResult<DesktopProcessMessageResult> {
        self.ensure_running()?;
        self.processor.process_message(request).await
    }

    pub async fn enqueue_delivery(
        &self,
        request: DesktopDeliveryRequest,
    ) -> DesktopResult<DesktopDeliveryReceipt> {
        self.ensure_running()?;
        let delivery = DesktopQueuedDelivery {
            id: ulid::Ulid::new().to_string(),
            request,
        };
        self.delivery_queue.enqueue(delivery).await
    }

    pub async fn pending_deliveries(
        &self,
        tenant: Option<String>,
    ) -> DesktopResult<Vec<DesktopQueuedDelivery>> {
        self.ensure_running()?;
        self.delivery_queue.pending(tenant).await
    }

    pub async fn ack_delivery(&self, delivery_id: &str) -> DesktopResult<()> {
        self.ensure_running()?;
        self.delivery_queue.ack(delivery_id).await
    }

    pub async fn resolve_connection(
        &self,
        node_id: &str,
    ) -> DesktopResult<Option<DesktopNodeAdvert>> {
        self.discovery.resolve(node_id).await
    }

    pub async fn list_connections(&self) -> DesktopResult<Vec<DesktopNodeAdvert>> {
        self.discovery.list().await
    }

    pub fn status(&self) -> DesktopRuntimeStatus {
        let state = self
            .state
            .read()
            .expect("DesktopLocalNode state lock poisoned");
        DesktopRuntimeStatus {
            running: state.running,
            mode: state.mode,
            server: self.server.status(),
            advert: state.advert.clone(),
        }
    }

    fn build_advert(
        &self,
        mode: DesktopNodeMode,
        server_status: &DesktopServerStatus,
    ) -> DesktopNodeAdvert {
        let capabilities = match mode {
            DesktopNodeMode::Embedded => vec!["embedded".to_string()],
            DesktopNodeMode::LoopbackServer => server_status.capabilities(),
        };

        DesktopNodeAdvert {
            node_id: self.config.node_id.clone(),
            app_id: self.config.app_id.clone(),
            mode,
            service_name: self.config.discovery.service_name.clone(),
            pid: self.config.pid,
            endpoint: server_status.endpoint.clone(),
            websocket_endpoint: server_status.websocket_endpoint.clone(),
            capabilities,
        }
    }

    fn ensure_running(&self) -> DesktopResult<()> {
        if !self
            .state
            .read()
            .map_err(DesktopError::lock_poisoned)?
            .running
        {
            return Err(DesktopError::not_running());
        }
        Ok(())
    }
}

/// Scaffolding `DesktopLocalServer` that **does not actually start a server**.
///
/// `start` records the requested config in an in-memory status struct and
/// returns it; no socket is bound, no DWN is spun up, and `stop` simply
/// resets the status. Use this for unit tests and integration scaffolds;
/// production paths must wire a real implementation backed by `enbox-dwn-server`
/// or an embedded DWN engine.
#[derive(Clone, Default)]
pub struct MemoryDesktopLocalServer {
    status: Arc<RwLock<DesktopServerStatus>>,
}

impl DesktopLocalServer for MemoryDesktopLocalServer {
    fn start<'a>(&'a self, config: DesktopServerConfig) -> DesktopFuture<'a, DesktopServerStatus> {
        Box::pin(async move {
            if !is_loopback_host(&config.bind_host) {
                return Err(DesktopError::non_loopback_host(&config.bind_host));
            }

            let endpoint = endpoint_url("http", &config.bind_host, config.port);
            let websocket_endpoint = config
                .websocket_enabled
                .then(|| endpoint_url("ws", &config.bind_host, config.port));
            let status = DesktopServerStatus {
                running: true,
                server_name: Some(config.server_name),
                endpoint: Some(endpoint),
                websocket_endpoint,
                bind_host: Some(config.bind_host),
                port: Some(config.port),
                websocket_enabled: config.websocket_enabled,
            };
            *self.status.write().map_err(DesktopError::lock_poisoned)? = status.clone();
            Ok(status)
        })
    }

    fn stop<'a>(&'a self) -> DesktopFuture<'a, ()> {
        Box::pin(async move {
            *self.status.write().map_err(DesktopError::lock_poisoned)? =
                DesktopServerStatus::default();
            Ok(())
        })
    }

    fn status(&self) -> DesktopServerStatus {
        self.status
            .read()
            .expect("MemoryDesktopLocalServer status lock poisoned")
            .clone()
    }
}

/// In-memory `DesktopDiscoveryRegistry` for tests. Does **not** publish on
/// mDNS/Bonjour or any network protocol; it just records adverts in a map.
/// Production paths must wire a real `mdns-sd` (or equivalent) backend.
#[derive(Clone, Default)]
pub struct MemoryDesktopDiscoveryRegistry {
    adverts: Arc<RwLock<BTreeMap<String, DesktopNodeAdvert>>>,
}

impl DesktopDiscoveryRegistry for MemoryDesktopDiscoveryRegistry {
    fn publish<'a>(&'a self, advert: DesktopNodeAdvert) -> DesktopFuture<'a, ()> {
        Box::pin(async move {
            self.adverts
                .write()
                .map_err(DesktopError::lock_poisoned)?
                .insert(advert.node_id.clone(), advert);
            Ok(())
        })
    }

    fn remove<'a>(&'a self, node_id: &'a str) -> DesktopFuture<'a, ()> {
        Box::pin(async move {
            self.adverts
                .write()
                .map_err(DesktopError::lock_poisoned)?
                .remove(node_id);
            Ok(())
        })
    }

    fn resolve<'a>(&'a self, node_id: &'a str) -> DesktopFuture<'a, Option<DesktopNodeAdvert>> {
        Box::pin(async move {
            Ok(self
                .adverts
                .read()
                .map_err(DesktopError::lock_poisoned)?
                .get(node_id)
                .cloned())
        })
    }

    fn list<'a>(&'a self) -> DesktopFuture<'a, Vec<DesktopNodeAdvert>> {
        Box::pin(async move {
            Ok(self
                .adverts
                .read()
                .map_err(DesktopError::lock_poisoned)?
                .values()
                .cloned()
                .collect())
        })
    }
}

/// In-memory `DesktopDeliveryQueue` for tests. Holds enqueued deliveries
/// in a `BTreeMap`; no actual transport, no retries, no persistence.
/// Production paths must persist to the chosen store and integrate with
/// the underlying DWN's delivery semantics.
#[derive(Clone, Default)]
pub struct MemoryDesktopDeliveryQueue {
    inner: Arc<RwLock<DeliveryQueueInner>>,
}

#[derive(Debug, Default)]
struct DeliveryQueueInner {
    deliveries: BTreeMap<String, DesktopQueuedDelivery>,
    dedup_keys: BTreeMap<String, String>,
}

impl DesktopDeliveryQueue for MemoryDesktopDeliveryQueue {
    fn enqueue<'a>(
        &'a self,
        delivery: DesktopQueuedDelivery,
    ) -> DesktopFuture<'a, DesktopDeliveryReceipt> {
        Box::pin(async move {
            let mut inner = self.inner.write().map_err(DesktopError::lock_poisoned)?;
            if let Some(dedup_key) = &delivery.request.dedup_key {
                if let Some(delivery_id) = inner.dedup_keys.get(dedup_key) {
                    return Ok(DesktopDeliveryReceipt {
                        delivery_id: delivery_id.clone(),
                        queued: false,
                    });
                }
                inner
                    .dedup_keys
                    .insert(dedup_key.clone(), delivery.id.clone());
            }

            let delivery_id = delivery.id.clone();
            inner.deliveries.insert(delivery_id.clone(), delivery);
            Ok(DesktopDeliveryReceipt {
                delivery_id,
                queued: true,
            })
        })
    }

    fn pending<'a>(
        &'a self,
        tenant: Option<String>,
    ) -> DesktopFuture<'a, Vec<DesktopQueuedDelivery>> {
        Box::pin(async move {
            Ok(self
                .inner
                .read()
                .map_err(DesktopError::lock_poisoned)?
                .deliveries
                .values()
                .filter(|delivery| {
                    tenant
                        .as_ref()
                        .is_none_or(|tenant| delivery.request.tenant == *tenant)
                })
                .cloned()
                .collect())
        })
    }

    fn ack<'a>(&'a self, delivery_id: &'a str) -> DesktopFuture<'a, ()> {
        Box::pin(async move {
            let mut inner = self.inner.write().map_err(DesktopError::lock_poisoned)?;
            if let Some(delivery) = inner.deliveries.remove(delivery_id) {
                if let Some(dedup_key) = delivery.request.dedup_key {
                    inner.dedup_keys.remove(&dedup_key);
                }
            }
            Ok(())
        })
    }
}

/// Scaffolding `DesktopMessageProcessor` that echoes the request payload as
/// the response. **Does not run a DWN.** Use only for connectivity tests
/// against the desktop pipeline; real implementations must dispatch into
/// a real `Dwn::process_message` (see `crate::dwn::Dwn`).
#[derive(Clone, Default)]
pub struct EchoDesktopMessageProcessor;

impl DesktopMessageProcessor for EchoDesktopMessageProcessor {
    fn process_message<'a>(
        &'a self,
        request: DesktopProcessMessageRequest,
    ) -> DesktopFuture<'a, DesktopProcessMessageResult> {
        Box::pin(async move {
            Ok(DesktopProcessMessageResult {
                status_code: 202,
                status_detail: "Accepted".to_string(),
                body: request.message,
                data: request.data,
            })
        })
    }
}

fn endpoint_url(scheme: &str, host: &str, port: u16) -> String {
    let display_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("{scheme}://{display_host}:{port}")
}

fn is_loopback_host(host: &str) -> bool {
    let normalized = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    normalized == "localhost"
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|ip_address| ip_address.is_loopback())
}

fn current_process_id() -> Option<u32> {
    #[cfg(any(unix, windows))]
    {
        Some(std::process::id())
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn embedded_desktop_node_runs_without_webview_and_processes_messages() {
        let node = test_node("embedded-node");
        let err = node
            .process_message(DesktopProcessMessageRequest {
                tenant: "did:example:alice".to_string(),
                message: json!({"descriptor":{"interface":"Records","method":"Query"}}),
                data: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, "DesktopNodeNotRunning");

        let status = node
            .start(DesktopStartRequest {
                mode: DesktopStartMode::Embedded,
            })
            .await
            .unwrap();
        assert!(status.running);
        assert_eq!(status.mode, Some(DesktopNodeMode::Embedded));
        assert_eq!(status.advert.as_ref().unwrap().capabilities, ["embedded"]);
        assert!(status.server.endpoint.is_none());

        let advert = node
            .resolve_connection("embedded-node")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(advert.mode, DesktopNodeMode::Embedded);

        let reply = node
            .process_message(DesktopProcessMessageRequest {
                tenant: "did:example:alice".to_string(),
                message: json!({"ok": true}),
                data: Some(vec![1, 2, 3]),
            })
            .await
            .unwrap();
        assert_eq!(reply.status_code, 202);
        assert_eq!(reply.data, Some(vec![1, 2, 3]));

        let stopped = node.stop().await.unwrap();
        assert!(!stopped.running);
        assert!(node
            .resolve_connection("embedded-node")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn loopback_server_mode_advertises_connection_and_queues_delivery() {
        let node = test_node("loopback-node");
        let status = node
            .start(DesktopStartRequest {
                mode: DesktopStartMode::LoopbackServer {
                    config: DesktopServerConfig {
                        bind_host: "127.0.0.1".to_string(),
                        port: 55500,
                        ..DesktopServerConfig::default()
                    },
                },
            })
            .await
            .unwrap();

        assert_eq!(status.mode, Some(DesktopNodeMode::LoopbackServer));
        assert_eq!(
            status.server.endpoint.as_deref(),
            Some("http://127.0.0.1:55500")
        );
        assert_eq!(
            status.server.websocket_endpoint.as_deref(),
            Some("ws://127.0.0.1:55500")
        );

        let advert = node
            .resolve_connection("loopback-node")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(advert.capabilities, ["http", "ws"]);
        assert_eq!(
            advert.discovery_record().unwrap(),
            DesktopDiscoveryRecord {
                endpoint: "http://127.0.0.1:55500".to_string(),
                pid: 42,
                capabilities: vec!["http".to_string(), "ws".to_string()],
            }
        );

        let request = DesktopDeliveryRequest {
            kind: DesktopDeliveryKind::EndpointForwarding,
            mode: DesktopDeliveryMode::StoreAndForward,
            tenant: "did:example:alice".to_string(),
            target_did: "did:example:alice".to_string(),
            endpoint: "https://remote.example/dwn".to_string(),
            message: json!({"descriptor":{"interface":"Records","method":"Write"}}),
            data: Some(vec![9]),
            dedup_key: Some("fwd:did:example:alice:record1".to_string()),
        };
        let first = node.enqueue_delivery(request.clone()).await.unwrap();
        assert!(first.queued);

        let duplicate = node.enqueue_delivery(request).await.unwrap();
        assert!(!duplicate.queued);
        assert_eq!(duplicate.delivery_id, first.delivery_id);

        let pending = node
            .pending_deliveries(Some("did:example:alice".to_string()))
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, first.delivery_id);

        node.ack_delivery(&first.delivery_id).await.unwrap();
        assert!(node.pending_deliveries(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn loopback_server_rejects_non_local_bind_hosts() {
        let node = test_node("unsafe-node");
        let err = node
            .start(DesktopStartRequest {
                mode: DesktopStartMode::LoopbackServer {
                    config: DesktopServerConfig {
                        bind_host: "0.0.0.0".to_string(),
                        ..DesktopServerConfig::default()
                    },
                },
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, "DesktopLoopbackOnly");
    }

    fn test_node(
        node_id: &str,
    ) -> DesktopLocalNode<
        EchoDesktopMessageProcessor,
        MemoryDesktopLocalServer,
        MemoryDesktopDiscoveryRegistry,
        MemoryDesktopDeliveryQueue,
    > {
        let mut config = DesktopNodeConfig::new(node_id, "org.enbox.desktop-test");
        config.pid = Some(42);
        DesktopLocalNode::new(
            config,
            EchoDesktopMessageProcessor,
            MemoryDesktopLocalServer::default(),
            MemoryDesktopDiscoveryRegistry::default(),
            MemoryDesktopDeliveryQueue::default(),
        )
    }
}
