//! Integration tests for the loopback desktop HTTP server.

use dwn_rs_core::runtime::desktop::DesktopProcessMessageResult;
use dwn_rs_core::runtime::desktop::{
    DesktopLocalNode, DesktopNodeConfig, DesktopServerConfig, DesktopStartMode,
    DesktopStartRequest, MemoryDesktopDeliveryQueue, MemoryDesktopDiscoveryRegistry,
    LOCAL_DWN_SERVER_NAME,
};
use dwn_rs_core::runtime::desktop::server::{
    LoopbackDwnServer, SharedDesktopMessageProcessor, PROCESS_MESSAGE_METHOD,
};
use serde_json::json;

#[tokio::test]
async fn loopback_server_exposes_info_and_processes_json_rpc() {
    let processor = SharedDesktopMessageProcessor::new(|request| async move {
        Ok(DesktopProcessMessageResult {
            status_code: 200,
            status_detail: "OK".to_string(),
            body: request.message,
            data: request.data,
        })
    });
    let server = LoopbackDwnServer::new(processor.clone());
    let mut config = DesktopNodeConfig::new("loopback-test", "org.enbox.test");
    config.discovery.publish = false;

    let node = DesktopLocalNode::new(
        config,
        processor,
        server,
        MemoryDesktopDiscoveryRegistry::default(),
        MemoryDesktopDeliveryQueue::default(),
    );

    node.start(DesktopStartRequest {
        mode: DesktopStartMode::LoopbackServer {
            config: DesktopServerConfig {
                server_name: LOCAL_DWN_SERVER_NAME.to_string(),
                bind_host: "127.0.0.1".to_string(),
                port: 0,
                websocket_enabled: false,
            },
        },
    })
    .await
    .expect("start loopback server");

    let endpoint = node
        .status()
        .server
        .endpoint
        .clone()
        .expect("server endpoint");

    let client = reqwest::Client::new();
    let info: serde_json::Value = client
        .get(format!("{endpoint}/info"))
        .send()
        .await
        .expect("info request")
        .json()
        .await
        .expect("info json");
    assert_eq!(info["server"], LOCAL_DWN_SERVER_NAME);

    let rpc = json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": PROCESS_MESSAGE_METHOD,
        "params": {
            "target": "did:example:alice",
            "message": {
                "descriptor": {
                    "interface": "Records",
                    "method": "Query",
                    "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                    "filter": { "protocol": "https://example.com/test" }
                }
            }
        }
    });
    let response = client
        .post(format!("{endpoint}/"))
        .header("dwn-request", rpc.to_string())
        .send()
        .await
        .expect("rpc request");
    assert!(response.status().is_success());
    let header = response
        .headers()
        .get("dwn-response")
        .expect("dwn-response header")
        .to_str()
        .expect("header utf8");
    let payload: serde_json::Value = serde_json::from_str(header).expect("response json");
    assert_eq!(payload["result"]["reply"]["status"]["code"], 200);

    node.stop().await.expect("stop loopback server");
}
