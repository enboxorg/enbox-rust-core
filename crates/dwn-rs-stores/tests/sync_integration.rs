//! Multi-node sync integration tests for direct and HTTP endpoints (#114).

use std::collections::BTreeMap;
use std::sync::Arc;

use dwn_rs_core::auth::{
    Jws, JwsPrivateJwk, JwsPublicJwk, PrivateJwkSigner, StaticPublicKeyResolver,
};
use dwn_rs_core::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
use dwn_rs_core::descriptors::ConfigureDescriptor;
use dwn_rs_core::desktop::{
    DesktopLocalNode, DesktopNodeConfig, DesktopProcessMessageResult, DesktopServerConfig,
    DesktopStartMode, DesktopStartRequest, MemoryDesktopDeliveryQueue,
    MemoryDesktopDiscoveryRegistry, LOCAL_DWN_SERVER_NAME,
};
use dwn_rs_core::desktop_server::{LoopbackDwnServer, SharedDesktopMessageProcessor};
use dwn_rs_core::interfaces::messages::descriptors::records::WriteDescriptor;
use dwn_rs_core::interfaces::messages::protocols::{
    Action, ActionWho, Can, Definition, RuleSet, Type, Who,
};
use dwn_rs_core::sync::{
    StartSyncParams, SyncDirection, SyncIdentityOptions, SyncMode, SyncOnceRequest,
    SyncProtocols, SyncRunStatus, SyncStatusQuery,
};
use dwn_rs_core::sync_endpoint::JwsSyncAuthorizer;
use dwn_rs_core::sync_ledger::SyncLedger;
use serde_json::{json, Value as JsonValue};
use tokio::sync::Mutex;

use dwn_rs_stores::SqliteNativeDwn;

const TENANT: &str = "did:example:alice";
const DIRECT_REMOTE: &str = "direct://peer";
const HTTP_REMOTE: &str = "http://loopback-remote";

#[tokio::test]
async fn direct_bidirectional_sync_converges_after_peer_write() {
    let resolver = test_resolver();
    let peer = open_configured_peer(&resolver, "2025-01-01T00:00:00.000000Z").await;
    let local = open_configured_local(&resolver).await;

    peer_write(
        &peer,
        signed_default_test_protocol_records_write(
            "2025-01-01T00:00:01.000000Z",
            b"direct-sync-payload-v1",
        ),
        b"direct-sync-payload-v1",
    )
    .await;

    let pull = local
        .sync_once_with_peer(
            &peer,
            SyncOnceRequest::new(TENANT, DIRECT_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_completed_with_pulls(&pull, 1, "direct initial pull");

    assert_nodes_converged(&local, &peer, "direct initial pull").await;
}

#[tokio::test]
async fn direct_incremental_sync_pulls_only_new_peer_records() {
    let resolver = test_resolver();
    let peer = open_configured_peer(&resolver, "2025-01-01T00:00:00.000000Z").await;
    let local = open_configured_local(&resolver).await;

    peer_write(
        &peer,
        signed_default_test_protocol_records_write(
            "2025-01-01T00:00:01.000000Z",
            b"incremental-v1",
        ),
        b"incremental-v1",
    )
    .await;
    let first = local
        .sync_once_with_peer(
            &peer,
            SyncOnceRequest::new(TENANT, DIRECT_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_completed_with_pulls(&first, 1, "direct first pull");

    peer_write(
        &peer,
        signed_default_test_protocol_records_write(
            "2025-01-01T00:00:02.000000Z",
            b"incremental-v2",
        ),
        b"incremental-v2",
    )
    .await;
    let second = local
        .sync_once_with_peer(
            &peer,
            SyncOnceRequest::new(TENANT, DIRECT_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_completed_with_pulls(&second, 1, "direct incremental pull");

    assert_nodes_converged(&local, &peer, "direct incremental sync").await;
}

#[tokio::test]
async fn http_sync_pulls_from_loopback_remote() {
    let resolver = test_resolver();
    let remote = start_loopback_peer_server(resolver.clone()).await;
    install_protocol_on_locked(&remote.peer, "2025-01-01T00:00:00.000000Z").await;
    peer_write_locked(
        &remote.peer,
        signed_default_test_protocol_records_write(
            "2025-01-01T00:00:01.000000Z",
            b"http-sync-payload",
        ),
        b"http-sync-payload",
    )
    .await;

    let local = open_configured_local(&resolver).await;
    let authorizer = JwsSyncAuthorizer::new(test_signer());
    let result = local
        .sync_once_with_http(
            &remote.endpoint,
            authorizer,
            SyncOnceRequest::new(TENANT, HTTP_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_completed_with_pulls(&result, 1, "http pull via loopback");

    assert_nodes_converged_remote(&local, &remote, "http pull via loopback").await;
    remote.stop().await;
}

#[tokio::test]
async fn http_incremental_sync_reconnects_using_persisted_ledger_checkpoint() {
    let resolver = test_resolver();
    let remote = start_loopback_peer_server(resolver.clone()).await;
    install_protocol_on_locked(&remote.peer, "2025-01-01T00:00:00.000000Z").await;

    peer_write_locked(
        &remote.peer,
        signed_default_test_protocol_records_write("2025-01-01T00:00:01.000000Z", b"gap-v1"),
        b"gap-v1",
    )
    .await;

    let local = open_configured_local(&resolver).await;
    let authorizer = JwsSyncAuthorizer::new(test_signer());
    let first = local
        .sync_once_with_http(
            &remote.endpoint,
            authorizer.clone(),
            SyncOnceRequest::new(TENANT, HTTP_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_completed_with_pulls(&first, 1, "http first pull");
    let ledger_after_first = local.sync_ledger().load().expect("ledger after first pull");
    assert!(
        !ledger_after_first.checkpoints.is_empty(),
        "expected persisted checkpoint after first HTTP sync"
    );

    peer_write_locked(
        &remote.peer,
        signed_default_test_protocol_records_write("2025-01-01T00:00:02.000000Z", b"gap-v2"),
        b"gap-v2",
    )
    .await;

    let second = local
        .sync_once_with_http(
            &remote.endpoint,
            authorizer,
            SyncOnceRequest::new(TENANT, HTTP_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_completed_with_pulls(&second, 1, "http reconnect pull after gap");

    assert_nodes_converged_remote(&local, &remote, "http reconnect sync").await;
    remote.stop().await;
}

#[tokio::test]
async fn http_poll_reconcile_pulls_incremental_records() {
    let resolver = test_resolver();
    let remote = start_loopback_peer_server(resolver.clone()).await;
    install_protocol_on_locked(&remote.peer, "2025-01-01T00:00:00.000000Z").await;

    peer_write_locked(
        &remote.peer,
        signed_default_test_protocol_records_write("2025-01-01T00:00:01.000000Z", b"poll-v1"),
        b"poll-v1",
    )
    .await;

    let local = open_configured_local(&resolver).await;
    let authorizer = JwsSyncAuthorizer::new(test_signer());
    let first = local
        .poll_reconcile_with_http(
            &remote.endpoint,
            authorizer.clone(),
            SyncOnceRequest::new(TENANT, HTTP_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_completed_with_pulls(&first, 1, "http poll reconcile first pull");

    peer_write_locked(
        &remote.peer,
        signed_default_test_protocol_records_write("2025-01-01T00:00:02.000000Z", b"poll-v2"),
        b"poll-v2",
    )
    .await;

    let second = local
        .poll_reconcile_with_http(
            &remote.endpoint,
            authorizer,
            SyncOnceRequest::new(TENANT, HTTP_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_completed_with_pulls(&second, 1, "http poll reconcile incremental pull");

    assert_nodes_converged_remote(&local, &remote, "http poll reconcile").await;
    remote.stop().await;
}

#[tokio::test]
async fn live_poll_handoff_catches_up_after_subscription_drop() {
    let resolver = test_resolver();
    let remote = start_loopback_peer_server(resolver.clone()).await;
    install_protocol_on_locked(&remote.peer, "2025-01-01T00:00:00.000000Z").await;

    peer_write_locked(
        &remote.peer,
        signed_default_test_protocol_records_write("2025-01-01T00:00:01.000000Z", b"live-v1"),
        b"live-v1",
    )
    .await;

    let local = open_configured_local(&resolver).await;
    let authorizer = JwsSyncAuthorizer::new(test_signer());
    let endpoint = remote.endpoint.clone();
    let peer = remote.peer.clone();

    let baseline = local
        .poll_reconcile_with_http(
            &endpoint,
            authorizer.clone(),
            SyncOnceRequest::new(TENANT, HTTP_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_completed_with_pulls(&baseline, 1, "baseline poll before live start");

    local
        .run_with_http_sync_engine(&endpoint, authorizer.clone(), |engine| async move {
            let live_start = engine
                .start_sync(StartSyncParams {
                    tenant: TENANT.to_string(),
                    remote: HTTP_REMOTE.to_string(),
                    mode: SyncMode::Live,
                    interval_ms: None,
                    protocol: None,
                })
                .await;
            assert_eq!(
                live_start.status,
                SyncRunStatus::Started,
                "live start on converged nodes: {live_start:?}"
            );
        })
        .await
        .expect("live start");

    peer_write_locked(
        &peer,
        signed_default_test_protocol_records_write("2025-01-01T00:00:02.000000Z", b"live-v2"),
        b"live-v2",
    )
    .await;

    local
        .run_with_http_sync_engine(&endpoint, authorizer, |engine| async move {
            let reconcile = engine
                .reconcile_after_live_disconnect(SyncOnceRequest::new(
                    TENANT,
                    HTTP_REMOTE,
                    SyncDirection::Pull,
                ))
                .await;
            assert_completed_with_pulls(&reconcile, 1, "degraded poll catch-up after live drop");
            assert!(
                reconcile.records_pulled >= 1,
                "poll should apply at least the record missed during live outage"
            );

            let status = engine.sync_status(SyncStatusQuery {
                tenant: TENANT.to_string(),
                remote: Some(HTTP_REMOTE.to_string()),
                protocol: None,
            });
            assert_eq!(
                status.last_status,
                Some(SyncRunStatus::Completed),
                "successful poll reconcile should recover link status"
            );
            assert!(
                status.active_live_links.is_empty(),
                "degraded poll should not keep live links active"
            );
        })
        .await
        .expect("live poll handoff reconcile");

    let idle = local
        .poll_reconcile_with_http(
            &endpoint,
            JwsSyncAuthorizer::new(test_signer()),
            SyncOnceRequest::new(TENANT, HTTP_REMOTE, SyncDirection::Pull),
        )
        .await;
    assert_eq!(
        idle.status,
        SyncRunStatus::Completed,
        "post-handoff poll should be idle: {idle:?}"
    );
    assert_eq!(
        idle.records_pulled, 0,
        "post-handoff poll should not re-apply converged records"
    );

    assert_nodes_converged_remote(&local, &remote, "live poll handoff").await;
    remote.stop().await;
}

struct LoopbackRemote {
    endpoint: String,
    peer: Arc<Mutex<SqliteNativeDwn>>,
    node: DesktopLocalNode<
        SharedDesktopMessageProcessor,
        LoopbackDwnServer,
        MemoryDesktopDiscoveryRegistry,
        MemoryDesktopDeliveryQueue,
    >,
}

impl LoopbackRemote {
    async fn stop(self) {
        let _ = self.node.stop().await;
    }
}

async fn start_loopback_peer_server(resolver: StaticPublicKeyResolver) -> LoopbackRemote {
    let peer = Arc::new(Mutex::new(
        SqliteNativeDwn::open_in_memory(resolver)
            .await
            .expect("open loopback peer"),
    ));
    let peer_for_processor = peer.clone();

    let processor = SharedDesktopMessageProcessor::new(move |request| {
        let peer = peer_for_processor.clone();
        async move {
            let peer = peer.lock().await;
            let data = request.data.clone();
            let reply = peer
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
                body: serde_json::to_value(&reply.body).unwrap_or(JsonValue::Null),
                data,
            })
        }
    });

    let server = LoopbackDwnServer::new(processor.clone());
    let mut config = DesktopNodeConfig::new("sync-http-peer", "org.enbox.sync");
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
    .expect("start loopback peer server");
    let endpoint = node
        .status()
        .server
        .endpoint
        .clone()
        .expect("loopback endpoint");
    LoopbackRemote {
        endpoint,
        peer,
        node,
    }
}

async fn open_configured_peer(
    resolver: &StaticPublicKeyResolver,
    configure_timestamp: &str,
) -> SqliteNativeDwn {
    let peer = SqliteNativeDwn::open_in_memory(resolver.clone())
        .await
        .expect("open peer");
    install_protocol_on_node(&peer, configure_timestamp).await;
    peer
}

async fn open_configured_local(resolver: &StaticPublicKeyResolver) -> SqliteNativeDwn {
    let local = SqliteNativeDwn::open_in_memory(resolver.clone())
        .await
        .expect("open local");
    install_protocol_on_node(&local, "2025-01-01T00:00:00.000000Z").await;
    local
        .register_sync_identity(SyncIdentityOptions {
            did: TENANT.to_string(),
            protocols: SyncProtocols::All,
            delegate_did: None,
        })
        .expect("register sync identity");
    local
}

async fn install_protocol_on_node(node: &SqliteNativeDwn, timestamp: &str) {
    let configure = signed_default_test_protocol_configure(timestamp);
    let reply = node.dwn().process_message(TENANT, configure).await;
    assert_eq!(reply.status.code, 202, "{reply:?}");
}

async fn install_protocol_on_locked(peer: &Arc<Mutex<SqliteNativeDwn>>, timestamp: &str) {
    let peer = peer.lock().await;
    install_protocol_on_node(&peer, timestamp).await;
}

async fn peer_write_locked(peer: &Arc<Mutex<SqliteNativeDwn>>, message: JsonValue, payload: &[u8]) {
    let peer = peer.lock().await;
    peer_write(&peer, message, payload).await;
}

async fn peer_write(node: &SqliteNativeDwn, message: JsonValue, payload: &[u8]) {
    let reply = node
        .process_message_with_data(TENANT, message, Some(bytes::Bytes::from(payload.to_vec())))
        .await;
    assert_eq!(reply.status.code, 202, "{reply:?}");
}

async fn published_record_count(node: &SqliteNativeDwn) -> usize {
    let reply = node
        .dwn()
        .process_message(
            TENANT,
            json!({
                "descriptor": {
                    "interface": "Records",
                    "method": "Query",
                    "messageTimestamp": "2025-01-01T00:10:00.000000Z",
                    "filter": {
                        "protocol": "http://test-protocol.xyz",
                        "published": true
                    }
                }
            }),
        )
        .await;
    assert_eq!(reply.status.code, 200, "{reply:?}");
    reply
        .body
        .get("entries")
        .and_then(JsonValue::as_array)
        .map(|entries| entries.len())
        .unwrap_or(0)
}

async fn assert_nodes_converged(local: &SqliteNativeDwn, peer: &SqliteNativeDwn, context: &str) {
    let local_count = published_record_count(local).await;
    let peer_count = published_record_count(peer).await;
    assert_eq!(
        local_count, peer_count,
        "{context}: local={local_count} peer={peer_count} diverged"
    );
}

async fn assert_nodes_converged_remote(
    local: &SqliteNativeDwn,
    remote: &LoopbackRemote,
    context: &str,
) {
    let peer = remote.peer.lock().await;
    assert_nodes_converged(local, &peer, context).await;
}

fn assert_completed_with_pulls(
    result: &dwn_rs_core::sync::SyncOnceResult,
    min_pulled: u64,
    context: &str,
) {
    assert_eq!(
        result.status,
        SyncRunStatus::Completed,
        "{context}: {result:?}"
    );
    assert!(
        result.records_pulled >= min_pulled,
        "{context}: expected >= {min_pulled} pulled, got {} ({result:?})",
        result.records_pulled
    );
    assert!(
        !result.checkpoints.is_empty(),
        "{context}: missing checkpoints ({result:?})"
    );
}

fn signed_default_test_protocol_configure(timestamp: &str) -> JsonValue {
    let definition = Definition {
        protocol: "http://test-protocol.xyz".to_string(),
        published: true,
        uses: None,
        types: BTreeMap::from([(
            "testRecord".to_string(),
            Type {
                schema: None,
                data_formats: None,
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([(
            "testRecord".to_string(),
            RuleSet {
                actions: vec![Action::Who(ActionWho {
                    who: Who::Anyone,
                    of: None,
                    can: vec![Can::Create, Can::Read],
                })],
                ..Default::default()
            },
        )]),
    };
    let descriptor = ConfigureDescriptor {
        message_timestamp: timestamp.parse().unwrap(),
        permission_grant_id: None,
        definition,
    };
    signed_descriptor_message(serde_json::to_value(descriptor).unwrap(), json!({}))
}

fn signed_default_test_protocol_records_write(timestamp: &str, payload: &[u8]) -> JsonValue {
    let data_cid = generate_dag_pb_cid_from_bytes(payload).to_string();
    let descriptor = WriteDescriptor {
        protocol: Some("http://test-protocol.xyz".to_string()),
        protocol_path: Some("testRecord".to_string()),
        recipient: None,
        schema: Some("foo/bar".to_string()),
        tags: None,
        parent_id: None,
        data_cid: data_cid.clone(),
        data_size: payload.len() as u64,
        date_created: timestamp.parse().unwrap(),
        message_timestamp: timestamp.parse().unwrap(),
        published: None,
        date_published: None,
        data_format: "application/json".to_string(),
        permission_grant_id: None,
        squash: None,
    };
    let record_id = records_write_entry_id(TENANT, &descriptor);
    let context_id = record_id.clone();
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let payload_json = json!({
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
        "recordId": record_id,
        "contextId": context_id,
    });
    let signature = Jws::create_general(
        serde_json::to_vec(&payload_json).unwrap().as_slice(),
        &[test_signer()],
    )
    .unwrap();
    json!({
        "descriptor": descriptor_json,
        "recordId": record_id,
        "contextId": context_id,
        "authorization": { "signature": signature }
    })
}

fn signed_descriptor_message(descriptor: JsonValue, fields: JsonValue) -> JsonValue {
    let descriptor_cid = generate_cid_from_json(&descriptor)
        .expect("descriptor cid")
        .to_string();
    let mut payload = json!({ "descriptorCid": descriptor_cid });
    if let JsonValue::Object(map) = fields {
        for (key, value) in map {
            payload[key] = value;
        }
    }
    let signature = Jws::create_general(
        serde_json::to_vec(&payload).unwrap().as_slice(),
        &[test_signer()],
    )
    .unwrap();
    json!({
        "descriptor": descriptor,
        "authorization": { "signature": signature }
    })
}

fn records_write_entry_id(author: &str, descriptor: &WriteDescriptor) -> String {
    let mut descriptor_json = serde_json::to_value(descriptor).expect("descriptor json");
    descriptor_json
        .as_object_mut()
        .expect("descriptor object")
        .insert("author".to_string(), JsonValue::String(author.to_string()));
    generate_cid_from_json(&descriptor_json)
        .expect("entry id cid")
        .to_string()
}

fn test_signer() -> PrivateJwkSigner {
    PrivateJwkSigner::new(
        "did:example:alice#key1",
        "EdDSA",
        JwsPrivateJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            d: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string(),
            x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
            y: None,
            kid: Some("did:example:alice#key1".to_string()),
            alg: Some("EdDSA".to_string()),
        },
    )
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
