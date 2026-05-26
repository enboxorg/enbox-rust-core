//! End-to-end tests for [`SqliteNativeDwn`].

use std::collections::BTreeMap;

use dwn_rs_core::auth::{
    Jws, JwsPrivateJwk, JwsPublicJwk, PrivateJwkSigner, StaticPublicKeyResolver,
};
use dwn_rs_core::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
use dwn_rs_core::descriptors::ConfigureDescriptor;
use dwn_rs_core::dwn::current_handler_kinds;
use dwn_rs_core::filters::{Filter, FilterKey, Filters};
use dwn_rs_core::handlers::protocols::fetch_protocol_definition;
use dwn_rs_core::interfaces::messages::descriptors::records::WriteDescriptor;
use dwn_rs_core::interfaces::messages::protocols::ActionWho;
use dwn_rs_core::interfaces::messages::protocols::{Action, Can, Definition, RuleSet, Type, Who};
use dwn_rs_core::stores::MessageStore;
use dwn_rs_core::Value;
use serde_json::{json, Value as JsonValue};

use dwn_rs_stores::SqliteNativeDwn;

const TENANT: &str = "did:example:alice";

#[tokio::test]
async fn native_dwn_registers_all_current_handlers() {
    let node = SqliteNativeDwn::open_in_memory(test_resolver())
        .await
        .expect("open native node");

    for kind in current_handler_kinds() {
        assert!(
            node.dwn().handlers().contains_key(&kind),
            "missing handler for {}",
            kind.handler_key()
        );
    }
}

#[tokio::test]
async fn native_dwn_handlers_do_not_return_not_implemented() {
    let node = SqliteNativeDwn::open_in_memory(test_resolver())
        .await
        .expect("open native node");

    for kind in current_handler_kinds() {
        let reply = node
            .dwn()
            .process_message(
                TENANT,
                json!({
                    "descriptor": {
                        "interface": kind.interface,
                        "method": kind.method,
                    }
                }),
            )
            .await;
        assert_ne!(
            reply.status.code,
            501,
            "{} should be registered",
            kind.handler_key()
        );
    }
}

#[tokio::test]
async fn native_dwn_processes_protocols_configure_and_messages_read() {
    let node = SqliteNativeDwn::open_in_memory(test_resolver())
        .await
        .expect("open native node");

    let configure = signed_configure_message(
        "http://example.com/native-dwn",
        true,
        "2025-01-01T00:00:00.000000Z",
    );
    let configure_cid = generate_cid_from_json(&configure)
        .expect("configure cid")
        .to_string();

    let configure_reply = node.dwn().process_message(TENANT, configure).await;
    assert_eq!(configure_reply.status.code, 202, "{configure_reply:?}");

    let read = signed_messages_read(&configure_cid, "2025-01-01T00:00:01.000000Z");
    let read_reply = node.dwn().process_message(TENANT, read).await;
    assert_eq!(read_reply.status.code, 200, "{read_reply:?}");
    assert_eq!(
        read_reply.body["entry"]["messageCid"].as_str(),
        Some(configure_cid.as_str())
    );
    assert!(read_reply.body["entry"]["message"].is_object());
}

fn signed_configure_message(protocol: &str, published: bool, timestamp: &str) -> JsonValue {
    let descriptor = configure_descriptor(protocol, published, timestamp);
    signed_descriptor_message(descriptor, json!({}))
}

fn signed_messages_read(message_cid: &str, timestamp: &str) -> JsonValue {
    let descriptor = json!({
        "interface": "Messages",
        "method": "Read",
        "messageCid": message_cid,
        "messageTimestamp": timestamp,
    });
    signed_descriptor_message(descriptor, json!({}))
}

fn signed_descriptor_message(descriptor: JsonValue, extra_payload: JsonValue) -> JsonValue {
    let mut payload = json!({
        "descriptorCid": generate_cid_from_json(&descriptor).unwrap().to_string(),
    });
    if let (Some(payload_obj), Some(extra_obj)) =
        (payload.as_object_mut(), extra_payload.as_object())
    {
        for (key, value) in extra_obj {
            payload_obj.insert(key.clone(), value.clone());
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

fn configure_descriptor(protocol: &str, published: bool, timestamp: &str) -> JsonValue {
    let definition = Definition {
        protocol: protocol.to_string(),
        published,
        uses: None,
        types: BTreeMap::from([(
            "note".to_string(),
            Type {
                schema: Some("http://schema.example.com/note".to_string()),
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([(
            "note".to_string(),
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
    serde_json::to_value(descriptor).unwrap()
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

#[tokio::test]
async fn fetch_protocol_definition_after_example_native_dwn_configure() {
    let node = SqliteNativeDwn::open_in_memory(test_resolver())
        .await
        .expect("open native node");

    let configure = signed_configure_message(
        "http://example.com/native-dwn",
        true,
        "2025-01-01T00:00:00.000000Z",
    );
    let configure_reply = node.dwn().process_message(TENANT, configure).await;
    assert_eq!(configure_reply.status.code, 202, "{configure_reply:?}");

    let definition =
        fetch_protocol_definition(TENANT, "http://example.com/native-dwn", node.store(), None)
            .await
            .expect("latest protocol definition should be found");
    assert_eq!(definition.protocol, "http://example.com/native-dwn");
}

#[tokio::test]
async fn fetch_protocol_definition_after_default_test_protocol_configure() {
    let node = SqliteNativeDwn::open_in_memory(test_resolver())
        .await
        .expect("open native node");

    let configure = signed_default_test_protocol_configure("2025-01-01T00:00:00.000000Z");
    let configure_reply = node.dwn().process_message(TENANT, configure).await;
    assert_eq!(configure_reply.status.code, 202, "{configure_reply:?}");

    let protocol_only = Filters::from(vec![BTreeMap::from([(
        FilterKey::Index("protocol".to_string()),
        Filter::Equal(Value::String("http://test-protocol.xyz".to_string())),
    )])]);
    let stored = node
        .store()
        .query(TENANT, protocol_only, None, None)
        .await
        .expect("query stored configure messages");
    assert!(
        !stored.messages.is_empty(),
        "configure message should be indexed by protocol"
    );

    let definition_latest =
        fetch_protocol_definition(TENANT, "http://test-protocol.xyz", node.store(), None)
            .await
            .expect("latest protocol definition should be found");
    assert_eq!(definition_latest.protocol, "http://test-protocol.xyz");

    let definition = fetch_protocol_definition(
        TENANT,
        "http://test-protocol.xyz",
        node.store(),
        Some("2025-01-01T00:00:01.000000Z"),
    )
    .await
    .expect("temporal protocol definition should be found");
    assert_eq!(definition.protocol, "http://test-protocol.xyz");
}

#[tokio::test]
async fn native_dwn_records_write_after_default_test_protocol_configure() {
    let node = SqliteNativeDwn::open_in_memory(test_resolver())
        .await
        .expect("open native node");

    let configure = signed_default_test_protocol_configure("2025-01-01T00:00:00.000000Z");
    let configure_reply = node.dwn().process_message(TENANT, configure).await;
    assert_eq!(configure_reply.status.code, 202, "{configure_reply:?}");

    let write = signed_default_test_protocol_records_write("2025-01-01T00:00:01.000000Z");
    let write_reply = node
        .process_message_with_data(
            TENANT,
            write,
            Some(bytes::Bytes::from_static(b"loopback-test-payload")),
        )
        .await;
    assert_eq!(write_reply.status.code, 202, "{write_reply:?}");
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
