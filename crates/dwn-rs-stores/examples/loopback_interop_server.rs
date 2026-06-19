//! Loopback HTTP + WebSocket DWN server for TypeScript interop tests.
//!
//! Prints `READY <endpoint>` to stdout when listening, then waits for EOF on stdin.
//!
//! ```bash
//! cargo run -p dwn-rs-stores --example loopback_interop_server
//! ENBOX_TS_ROOT=../enbox bun test tools/interop/loopback-interop.test.ts
//! ```

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::sync::Arc;

use dwn_rs_core::auth::{JwsPublicJwk, StaticPublicKeyResolver};
use dwn_rs_core::runtime::desktop::{
    DesktopLocalNode, DesktopNodeConfig, DesktopProcessMessageResult, DesktopServerConfig,
    DesktopStartMode, DesktopStartRequest, MemoryDesktopDeliveryQueue,
    MemoryDesktopDiscoveryRegistry, LOCAL_DWN_SERVER_NAME,
};
use dwn_rs_core::runtime::desktop::server::{LoopbackDwnServer, SharedDesktopMessageProcessor};
use dwn_rs_core::runtime::desktop::ws::SharedDesktopSubscribeProcessor;
use dwn_rs_core::stores::SubscriptionListener;
use dwn_rs_stores::SqliteNativeDwn;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let node = SqliteNativeDwn::open_in_memory(test_resolver()).await?;
    let node = Arc::new(Mutex::new(node));
    let node_for_processor = node.clone();
    let node_for_subscribe = node.clone();

    let processor = SharedDesktopMessageProcessor::new(move |request| {
        let node = node_for_processor.clone();
        async move {
            let node = node.lock().await;
            let data = request.data.clone();
            let reply = node
                .dwn()
                .process_message_with_data(
                    &request.tenant,
                    request.message,
                    data.clone().map(bytes::Bytes::from),
                )
                .await;
            Ok(DesktopProcessMessageResult {
                status_code: reply.status.code as u16,
                status_detail: reply.status.detail,
                body: serde_json::to_value(&reply.body).unwrap_or_else(
                    |err| serde_json::json!({ "serializationError": err.to_string() }),
                ),
                data,
            })
        }
    });

    let subscribe = SharedDesktopSubscribeProcessor::new(move |request, listener| {
        let node = node_for_subscribe.clone();
        async move {
            let node = node.lock().await;
            let listener: SubscriptionListener = Box::new(move |message| listener(message));
            let reply = node
                .subscribe_records(&request.tenant, request.message, listener)
                .await;
            Ok(reply)
        }
    });

    let server = LoopbackDwnServer::with_subscribe(processor.clone(), subscribe);
    let mut config = DesktopNodeConfig::new("loopback-interop", "org.enbox.interop");
    config.discovery.publish = false;

    let local_node = DesktopLocalNode::new(
        config,
        processor,
        server,
        MemoryDesktopDiscoveryRegistry::default(),
        MemoryDesktopDeliveryQueue::default(),
    );

    local_node
        .start(DesktopStartRequest {
            mode: DesktopStartMode::LoopbackServer {
                config: DesktopServerConfig {
                    server_name: LOCAL_DWN_SERVER_NAME.to_string(),
                    bind_host: "127.0.0.1".to_string(),
                    port: 0,
                    websocket_enabled: true,
                },
            },
        })
        .await?;

    let endpoint = local_node
        .status()
        .server
        .endpoint
        .clone()
        .expect("loopback server endpoint");

    println!("READY {endpoint}");
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        if line.is_err() || line.unwrap_or_default().trim() == "stop" {
            break;
        }
    }

    local_node.stop().await?;
    Ok(())
}

fn test_resolver() -> StaticPublicKeyResolver {
    StaticPublicKeyResolver::new(BTreeMap::from([(
        "did:example:alice#key1".to_string(),
        JwsPublicJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
            y: None,
            kid: Some("did:example:alice#key1".to_string()),
            alg: Some("EdDSA".to_string()),
        },
    )]))
}
