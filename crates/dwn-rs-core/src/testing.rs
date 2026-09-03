//! Signed-message fixtures for tests (behind `test-utils`).
//!
//! Builders for signed RecordsWrite/Delete, protocol installs, and unsigned
//! RecordsQuery/Count/Read envelopes at the pinned Enbox baseline. These are
//! fixture helpers, not normative vectors: they exist so handler,
//! conformance, and store-battery tests across crates sign identical inputs.
//!
//! Moved here from `handlers::records::tests`; behavior is unchanged.

use std::collections::BTreeMap;

use serde_json::json;
use ssi_jwk::Algorithm;

use crate::auth::{ed25519_jwk, Jws, PrivateJwkSigner, StaticPublicKeyResolver, JWK};
use crate::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
use crate::descriptors::{
    records::entry_id, ConfigureDescriptor, DeleteDescriptor, Protocols as ProtocolsDescriptor,
    RecordsWriteDescriptor, SubscribeDescriptor,
};
use crate::fields::WriteFields;
use crate::filters::Records as RecordsFilter;
use crate::handlers::records::common::message_cid;
use crate::interfaces::messages::protocols::{ActionWho, Type};
use crate::protocols::{Action, Can, Definition, RuleSet, Who};
use crate::stores::MessageStore;
use crate::{Descriptor, Fields, MapValue, Message, ProgressToken, Value};

#[derive(Clone)]
pub struct WriteSpec {
    pub author: String,
    pub signer: PrivateJwkSigner,
    pub timestamp: String,
    pub date_created: String,
    pub record_id: Option<String>,
    pub context_id: Option<String>,
    pub parent_id: Option<String>,
    pub parent_context_id: Option<String>,
    pub protocol: String,
    pub protocol_path: String,
    pub recipient: Option<String>,
    pub tags: Option<MapValue>,
    pub data_cid: String,
    pub data_size: u64,
    pub data_format: String,
    pub published: Option<bool>,
    pub permission_grant_id: Option<String>,
    pub squash: Option<bool>,
}

impl WriteSpec {
    pub fn new(timestamp: &str) -> Self {
        Self {
            author: "did:example:alice".to_string(),
            signer: test_signer(),
            timestamp: timestamp.to_string(),
            date_created: timestamp.to_string(),
            record_id: None,
            context_id: None,
            parent_id: None,
            parent_context_id: None,
            protocol: "http://example.com/notes".to_string(),
            protocol_path: "note".to_string(),
            recipient: None,
            tags: None,
            data_cid: generate_dag_pb_cid_from_bytes([]).to_string(),
            data_size: 0,
            data_format: "text/plain".to_string(),
            published: None,
            permission_grant_id: None,
            squash: None,
        }
    }
}

pub async fn signed_write_message(spec: WriteSpec) -> serde_json::Value {
    let descriptor = RecordsWriteDescriptor {
        protocol: spec.protocol,
        protocol_path: spec.protocol_path,
        recipient: spec.recipient,
        schema: None,
        tags: spec.tags,
        parent_id: spec.parent_id.clone(),
        data_cid: spec.data_cid,
        data_size: spec.data_size,
        date_created: parse_time(&spec.date_created),
        message_timestamp: parse_time(&spec.timestamp),
        published: spec.published,
        date_published: spec.published.map(|_| parse_time(&spec.timestamp)),
        data_format: spec.data_format,
        permission_grant_id: spec.permission_grant_id.clone(),
        squash: spec.squash,
    };
    let record_id = spec
        .record_id
        .clone()
        .unwrap_or_else(|| entry_id(&spec.author, &descriptor).unwrap());
    let context_id = spec.context_id.unwrap_or_else(|| {
        spec.parent_context_id
            .filter(|context| !context.is_empty())
            .map(|parent| format!("{parent}/{record_id}"))
            .unwrap_or_else(|| record_id.clone())
    });
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature_payload =
        payload_with_permission_grant(&record_id, &context_id, spec.permission_grant_id.as_deref());
    let signature =
        signature_for_descriptor(&descriptor_json, signature_payload, spec.signer).await;
    json!({
        "descriptor": descriptor_json,
        "recordId": record_id,
        "contextId": context_id,
        "authorization": { "signature": signature }
    })
}

pub async fn with_author_delegated_grant(
    mut message: serde_json::Value,
    grant: &serde_json::Value,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    let grant_message: Message<Descriptor> = serde_json::from_value(grant.clone()).unwrap();
    let grant_cid = message_cid(&grant_message).unwrap();
    let descriptor_json = message["descriptor"].clone();
    let signature = signature_for_descriptor(
        &descriptor_json,
        json!({
            "recordId": message["recordId"].as_str().unwrap(),
            "contextId": message["contextId"].as_str().unwrap(),
            "delegatedGrantId": grant_cid,
        }),
        signer,
    )
    .await;
    message["authorization"] = json!({
        "signature": signature,
        "authorDelegatedGrant": grant,
    });
    message
}

pub async fn signed_delete_message(
    record_id: &str,
    prune: bool,
    timestamp: &str,
) -> serde_json::Value {
    let descriptor = DeleteDescriptor {
        message_timestamp: parse_time(timestamp),
        record_id: record_id.to_string(),
        prune,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(&descriptor_json, json!({}), test_signer()).await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

pub async fn stored_note_message(timestamp: &str) -> Message<Descriptor> {
    serde_json::from_value(
        signed_write_message(WriteSpec {
            protocol: "http://example.com/notes".to_string(),
            protocol_path: "note".to_string(),
            ..WriteSpec::new(timestamp)
        })
        .await,
    )
    .unwrap()
}

pub async fn signed_records_subscribe_message(
    filter: RecordsFilter,
    cursor: Option<ProgressToken>,
    timestamp: &str,
) -> serde_json::Value {
    let descriptor = SubscribeDescriptor {
        message_timestamp: parse_time(timestamp),
        filter,
        date_sort: None,
        pagination: None,
        cursor,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(&descriptor_json, json!({}), test_signer()).await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

pub fn unsigned_query_message(filter: serde_json::Value) -> serde_json::Value {
    json!({
        "descriptor": {
            "interface": "Records",
            "method": "Query",
            "messageTimestamp": "2025-01-01T00:10:00.000000Z",
            "filter": filter
        }
    })
}

pub fn unsigned_count_message(filter: serde_json::Value) -> serde_json::Value {
    json!({
        "descriptor": {
            "interface": "Records",
            "method": "Count",
            "messageTimestamp": "2025-01-01T00:10:00.000000Z",
            "filter": filter
        }
    })
}

pub fn unsigned_read_message(filter: serde_json::Value) -> serde_json::Value {
    json!({
        "descriptor": {
            "interface": "Records",
            "method": "Read",
            "messageTimestamp": "2025-01-01T00:10:00.000000Z",
            "filter": filter
        }
    })
}

pub async fn put_squash_protocol<M>(tenant: &str, message_store: &M)
where
    M: MessageStore,
{
    let definition = Definition {
        protocol: "http://example.com/notes".to_string(),
        published: true,
        uses: None,
        types: BTreeMap::from([(
            "note".to_string(),
            Type {
                schema: None,
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([(
            "note".to_string(),
            RuleSet {
                squash: Some(true),
                actions: vec![Action::Who(ActionWho {
                    who: Who::Anyone,
                    of: None,
                    can: vec![Can::Create, Can::Read, Can::Squash],
                })],
                ..Default::default()
            },
        )]),
    };
    let descriptor = ConfigureDescriptor {
        message_timestamp: parse_time("2024-12-31T00:00:00.000000Z"),
        definition,
        permission_grant_id: None,
    };
    let message = Message {
        descriptor: Descriptor::Protocols(Box::new(ProtocolsDescriptor::Configure(descriptor))),
        fields: Fields::Write(WriteFields::default()),
    };
    let indexes = BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Protocols".to_string()),
        ),
        ("method".to_string(), Value::String("Configure".to_string())),
        (
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        ),
        ("published".to_string(), Value::Bool(true)),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "messageTimestamp".to_string(),
            Value::String("2024-12-31T00:00:00.000000Z".to_string()),
        ),
    ]);
    message_store.put(tenant, message, indexes).await.unwrap();
}

pub async fn put_notes_protocol_without_actions<M>(tenant: &str, message_store: &M)
where
    M: MessageStore,
{
    let definition = Definition {
        protocol: "http://example.com/notes".to_string(),
        published: false,
        uses: None,
        types: BTreeMap::from([(
            "note".to_string(),
            Type {
                schema: None,
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([("note".to_string(), RuleSet::default())]),
    };
    let descriptor = ConfigureDescriptor {
        message_timestamp: parse_time("2024-12-31T00:00:00.000000Z"),
        definition,
        permission_grant_id: None,
    };
    let message = Message {
        descriptor: Descriptor::Protocols(Box::new(ProtocolsDescriptor::Configure(descriptor))),
        fields: Fields::Write(WriteFields::default()),
    };
    let indexes = BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Protocols".to_string()),
        ),
        ("method".to_string(), Value::String("Configure".to_string())),
        (
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        ),
        ("published".to_string(), Value::Bool(false)),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "messageTimestamp".to_string(),
            Value::String("2024-12-31T00:00:00.000000Z".to_string()),
        ),
    ]);
    message_store.put(tenant, message, indexes).await.unwrap();
}

pub async fn signature_for_descriptor(
    descriptor: &serde_json::Value,
    extra_payload: serde_json::Value,
    signer: PrivateJwkSigner,
) -> Jws {
    let mut payload = extra_payload.as_object().cloned().unwrap_or_default();
    payload.insert(
        "descriptorCid".to_string(),
        serde_json::Value::String(generate_cid_from_json(descriptor).unwrap().to_string()),
    );
    Jws::create(
        serde_json::to_vec(&serde_json::Value::Object(payload))
            .unwrap()
            .as_slice(),
        &[signer],
    )
    .await
    .unwrap()
}

pub fn payload_with_permission_grant(
    record_id: &str,
    context_id: &str,
    permission_grant_id: Option<&str>,
) -> serde_json::Value {
    let mut payload = serde_json::Map::from_iter([
        (
            "recordId".to_string(),
            serde_json::Value::String(record_id.to_string()),
        ),
        (
            "contextId".to_string(),
            serde_json::Value::String(context_id.to_string()),
        ),
    ]);
    if let Some(permission_grant_id) = permission_grant_id {
        payload.insert(
            "permissionGrantId".to_string(),
            serde_json::Value::String(permission_grant_id.to_string()),
        );
    }
    serde_json::Value::Object(payload)
}

pub fn parse_time(value: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

pub fn test_signer() -> PrivateJwkSigner {
    signer_for("did:example:alice")
}

pub fn bob_signer() -> PrivateJwkSigner {
    signer_for("did:example:bob")
}

pub fn signer_for(did: &str) -> PrivateJwkSigner {
    let key_id = format!("{did}#key1");
    PrivateJwkSigner::new(
        &key_id,
        Algorithm::EdDSA,
        ed25519_jwk(
            "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"),
            Some(&key_id),
        )
        .unwrap(),
    )
}

pub fn test_resolver() -> StaticPublicKeyResolver {
    StaticPublicKeyResolver::new(BTreeMap::from([
        (
            "did:example:alice#key1".to_string(),
            test_public_jwk("did:example:alice#key1"),
        ),
        (
            "did:example:bob#key1".to_string(),
            test_public_jwk("did:example:bob#key1"),
        ),
    ]))
}

pub fn test_public_jwk(key_id: &str) -> JWK {
    ed25519_jwk(
        "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        None,
        Some(key_id),
    )
    .unwrap()
}
