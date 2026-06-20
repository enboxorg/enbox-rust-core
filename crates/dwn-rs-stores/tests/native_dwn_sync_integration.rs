//! End-to-end sync between two [`SqliteNativeDwn`] peers via [`DirectSyncEndpoint`].

use std::collections::BTreeMap;

use dwn_rs_core::auth::{
    Jws, JwsPrivateJwk, JwsPublicJwk, PrivateJwkSigner, StaticPublicKeyResolver,
};
use dwn_rs_core::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
use dwn_rs_core::descriptors::ConfigureDescriptor;
use dwn_rs_core::interfaces::messages::descriptors::records::WriteDescriptor;
use dwn_rs_core::interfaces::messages::protocols::{
    Action, ActionWho, Can, Definition, RuleSet, Type, Who,
};
use dwn_rs_core::sync::ledger::SyncLedger;
use dwn_rs_core::sync::{
    SyncDirection, SyncIdentityOptions, SyncOnceRequest, SyncProtocols, SyncRunStatus,
};
use serde_json::{json, Value as JsonValue};

use dwn_rs_stores::SqliteNativeDwn;

const TENANT: &str = "did:example:alice";
const REMOTE: &str = "direct://peer";

#[tokio::test]
async fn native_dwn_pulls_records_from_peer_via_direct_sync_endpoint() {
    let resolver = test_resolver();
    let peer = SqliteNativeDwn::open_in_memory(resolver.clone())
        .await
        .expect("open peer node");
    let local = SqliteNativeDwn::open_in_memory(resolver)
        .await
        .expect("open local node");

    let configure = signed_default_test_protocol_configure("2025-01-01T00:00:00.000000Z");
    let configure_reply = peer.dwn().process_message(TENANT, configure.clone()).await;
    assert_eq!(configure_reply.status.code, 202, "{configure_reply:?}");

    let local_configure_reply = local.dwn().process_message(TENANT, configure).await;
    assert_eq!(
        local_configure_reply.status.code, 202,
        "{local_configure_reply:?}"
    );

    let write = signed_default_test_protocol_records_write("2025-01-01T00:00:01.000000Z");
    let write_reply = peer
        .process_message_with_data(
            TENANT,
            write,
            Some(bytes::Bytes::from_static(b"loopback-test-payload")),
        )
        .await;
    assert_eq!(write_reply.status.code, 202, "{write_reply:?}");

    local
        .register_sync_identity(SyncIdentityOptions {
            did: TENANT.to_string(),
            protocols: SyncProtocols::All,
            delegate_did: None,
        })
        .await
        .expect("register sync identity");

    let result = local
        .sync_once_with_peer(
            &peer,
            SyncOnceRequest::new(TENANT, REMOTE, SyncDirection::Pull),
        )
        .await;

    assert_eq!(result.status, SyncRunStatus::Completed, "{result:?}");
    assert!(
        result.records_pulled >= 1,
        "expected at least one pulled record, got {}",
        result.records_pulled
    );
    assert!(!result.checkpoints.is_empty(), "{result:?}");

    let ledger = local
        .sync_ledger()
        .load()
        .await
        .expect("reload sync ledger");
    assert!(!ledger.checkpoints.is_empty());
    assert_eq!(ledger.checkpoints.values().next().unwrap().tenant, TENANT);
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

fn signed_default_test_protocol_records_write(timestamp: &str) -> JsonValue {
    let data_cid = generate_dag_pb_cid_from_bytes(b"loopback-test-payload").to_string();
    let descriptor = WriteDescriptor {
        protocol: Some("http://test-protocol.xyz".to_string()),
        protocol_path: Some("testRecord".to_string()),
        recipient: None,
        schema: Some("foo/bar".to_string()),
        tags: None,
        parent_id: None,
        data_cid: data_cid.clone(),
        data_size: 21,
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
    let payload = json!({
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
        "recordId": record_id,
        "contextId": context_id,
    });
    let signature = Jws::create_general(
        serde_json::to_vec(&payload).unwrap().as_slice(),
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
