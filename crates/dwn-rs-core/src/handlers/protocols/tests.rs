use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::auth::{Jws, JwsPrivateJwk, JwsPublicJwk, PrivateJwkSigner, StaticPublicKeyResolver};
use crate::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
use crate::descriptors::{
    ConfigureDescriptor, Descriptor, ProtocolQueryDescriptor, Protocols, RecordsWriteDescriptor,
};
use crate::dwn::{Dwn, MessageKind};
use crate::fields::WriteFields;
use crate::interfaces::messages::protocols::{
    self as protocol_types, Action, ActionRole, ActionWho, Can, Definition, Type, Who,
};
use crate::state_index::MemoryStateIndex;
use crate::stores::{MessageQueryResult, MessageStore, StateIndex};
use crate::{Fields, MapValue, Message, Pagination, Value};

use super::common::*;
use super::*;

const QUERY_METHOD_FOR_TESTS: &str = "Query";

#[tokio::test]
async fn protocols_configure_stores_latest_base_state() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let handler = ProtocolsConfigureHandler::with_public_key_resolver(
        message_store.clone(),
        state_index,
        test_resolver(),
    );
    let older = signed_configure_message(
        "http://example.com/protocol",
        true,
        "2025-01-01T00:00:00.000000Z",
    );
    let newer = signed_configure_message(
        "http://example.com/protocol",
        false,
        "2025-01-01T00:00:01.000000Z",
    );

    assert_eq!(
        handler
            .handle_configure("did:example:alice", &older)
            .await
            .status
            .code,
        202
    );
    assert_eq!(
        handler
            .handle_configure("did:example:alice", &newer)
            .await
            .status
            .code,
        202
    );
    assert_eq!(
        handler
            .handle_configure("did:example:alice", &newer)
            .await
            .status
            .code,
        409
    );

    let latest = message_store
        .query(
            "did:example:alice",
            protocol_configure_filters("http://example.com/protocol", true),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(latest.messages.len(), 1);
    assert!(
        !protocols_configure_descriptor(&latest.messages[0])
            .unwrap()
            .definition
            .published
    );
}

#[tokio::test]
async fn protocols_query_unsigned_returns_only_published_latest_configures() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let configure_handler = ProtocolsConfigureHandler::with_public_key_resolver(
        message_store.clone(),
        state_index,
        test_resolver(),
    );
    let query_handler = ProtocolsQueryHandler::new(message_store.clone());

    configure_handler
        .handle_configure(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/public",
                true,
                "2025-01-01T00:00:00.000000Z",
            ),
        )
        .await;
    configure_handler
        .handle_configure(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/private",
                false,
                "2025-01-01T00:00:01.000000Z",
            ),
        )
        .await;

    let reply = query_handler
        .handle_query("did:example:alice", &unsigned_query_message(None))
        .await;
    assert_eq!(reply.status.code, 200);
    let entries = reply.body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["descriptor"]["definition"]["protocol"].as_str(),
        Some("http://example.com/public")
    );
}

#[tokio::test]
async fn protocols_query_signed_by_tenant_returns_private_configures() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let configure_handler = ProtocolsConfigureHandler::with_public_key_resolver(
        message_store.clone(),
        state_index,
        test_resolver(),
    );
    let query_handler =
        ProtocolsQueryHandler::with_public_key_resolver(message_store.clone(), test_resolver());

    configure_handler
        .handle_configure(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/private",
                false,
                "2025-01-01T00:00:00.000000Z",
            ),
        )
        .await;

    let reply = query_handler
        .handle_query(
            "did:example:alice",
            &signed_query_message(None, test_signer_with_key_id("did:example:alice#key1")),
        )
        .await;
    assert_eq!(reply.status.code, 200);
    let entries = reply.body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["descriptor"]["definition"]["published"].as_bool(),
        Some(false)
    );
}

#[tokio::test]
async fn protocols_query_signed_by_non_tenant_falls_back_to_published_configures() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let configure_handler = ProtocolsConfigureHandler::with_public_key_resolver(
        message_store.clone(),
        state_index,
        test_resolver(),
    );
    let query_handler = ProtocolsQueryHandler::with_public_key_resolver(
        message_store.clone(),
        test_resolver_with_bob(),
    );

    configure_handler
        .handle_configure(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/public",
                true,
                "2025-01-01T00:00:00.000000Z",
            ),
        )
        .await;
    configure_handler
        .handle_configure(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/private",
                false,
                "2025-01-01T00:00:01.000000Z",
            ),
        )
        .await;

    let reply = query_handler
        .handle_query(
            "did:example:alice",
            &signed_query_message(None, test_signer_with_key_id("did:example:bob#key1")),
        )
        .await;
    assert_eq!(reply.status.code, 200);
    let entries = reply.body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["descriptor"]["definition"]["protocol"].as_str(),
        Some("http://example.com/public")
    );
}

#[tokio::test]
async fn protocols_query_with_permission_grant_returns_private_configure() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let configure_handler = ProtocolsConfigureHandler::with_public_key_resolver(
        message_store.clone(),
        state_index,
        test_resolver(),
    );
    let query_handler = ProtocolsQueryHandler::with_public_key_resolver(
        message_store.clone(),
        test_resolver_with_bob(),
    );

    configure_handler
        .handle_configure(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/private",
                false,
                "2025-01-01T00:00:00.000000Z",
            ),
        )
        .await;
    put_protocols_query_grant(
        "did:example:alice",
        &message_store,
        "grant-protocols-query",
        Some("http://example.com/private"),
    )
    .await;

    let reply = query_handler
        .handle_query(
            "did:example:alice",
            &signed_query_message_with_grant(
                Some("http://example.com/private"),
                test_signer_with_key_id("did:example:bob#key1"),
                "grant-protocols-query",
            ),
        )
        .await;
    assert_eq!(reply.status.code, 200);
    let entries = reply.body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["descriptor"]["definition"]["published"].as_bool(),
        Some(false)
    );
}

#[tokio::test]
async fn protocols_configure_rejects_tampered_descriptor_cid_as_bad_request() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let handler = ProtocolsConfigureHandler::with_public_key_resolver(
        message_store,
        state_index,
        test_resolver(),
    );
    let mut message = signed_configure_message(
        "http://example.com/original",
        true,
        "2025-01-01T00:00:00.000000Z",
    );
    message["descriptor"]["definition"]["protocol"] =
        JsonValue::String("http://example.com/tampered".to_string());

    let reply = handler
        .handle_configure("did:example:alice", &message)
        .await;
    assert_eq!(reply.status.code, 400);
}

#[tokio::test]
async fn protocols_configure_rejects_non_tenant_signer() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let handler = ProtocolsConfigureHandler::with_public_key_resolver(
        message_store,
        state_index,
        test_resolver_with_bob(),
    );

    let reply = handler
        .handle_configure(
            "did:example:alice",
            &signed_configure_message_with_signer(
                "http://example.com/protocol",
                true,
                "2025-01-01T00:00:00.000000Z",
                test_signer_with_key_id("did:example:bob#key1"),
            ),
        )
        .await;
    assert_eq!(reply.status.code, 401);
}

#[tokio::test]
async fn fetch_protocol_definition_supports_latest_and_temporal_lookup() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let handler = ProtocolsConfigureHandler::with_public_key_resolver(
        message_store.clone(),
        state_index,
        test_resolver(),
    );

    handler
        .handle_configure(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/versioned",
                true,
                "2025-01-01T00:00:00.000000Z",
            ),
        )
        .await;
    handler
        .handle_configure(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/versioned",
                false,
                "2025-01-01T00:10:00.000000Z",
            ),
        )
        .await;

    let historical = fetch_protocol_definition(
        "did:example:alice",
        "http://example.com/versioned",
        &message_store,
        Some("2025-01-01T00:05:00.000000Z"),
    )
    .await
    .unwrap();
    assert!(historical.published);

    let latest = fetch_protocol_definition(
        "did:example:alice",
        "http://example.com/versioned",
        &message_store,
        None,
    )
    .await
    .unwrap();
    assert!(!latest.published);
}

#[tokio::test]
async fn protocols_configure_validates_composition_dependencies() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();
    let handler = ProtocolsConfigureHandler::with_public_key_resolver(
        message_store,
        state_index,
        test_resolver(),
    );

    let missing_dependency = signed_configure_descriptor(composed_descriptor(
        "http://example.com/composed-missing",
        "threads:thread/participant",
    ));
    assert_eq!(
        handler
            .handle_configure("did:example:alice", &missing_dependency)
            .await
            .status
            .code,
        400
    );

    assert_eq!(
        handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_descriptor(base_thread_descriptor()),
            )
            .await
            .status
            .code,
        202
    );
    assert_eq!(
        handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_descriptor(composed_descriptor(
                    "http://example.com/composed",
                    "threads:thread/participant",
                )),
            )
            .await
            .status
            .code,
        202
    );
    assert_eq!(
        handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_descriptor(composed_descriptor(
                    "http://example.com/composed-invalid-role",
                    "threads:thread/missing",
                )),
            )
            .await
            .status
            .code,
        400
    );
}

#[tokio::test]
async fn protocol_handlers_integrate_with_dwn_dispatch() {
    let mut message_store = TestMessageStore::default();
    let mut state_index = MemoryStateIndex::default();
    message_store.open().await.unwrap();
    state_index.open().await.unwrap();

    let mut dwn = Dwn::default();
    dwn.register_handler(
        MessageKind::new(PROTOCOLS_INTERFACE, CONFIGURE_METHOD),
        ProtocolsConfigureHandler::with_public_key_resolver(
            message_store.clone(),
            state_index,
            test_resolver(),
        ),
    );
    dwn.register_handler(
        MessageKind::new(PROTOCOLS_INTERFACE, QUERY_METHOD_FOR_TESTS),
        ProtocolsQueryHandler::new(message_store),
    );

    let configure = signed_configure_message(
        "http://example.com/dispatch",
        true,
        "2025-01-01T00:00:00.000000Z",
    );
    let configure_reply = dwn.process_message("did:example:alice", configure).await;
    assert_eq!(configure_reply.status.code, 202);

    let query_reply = dwn
        .process_message("did:example:alice", unsigned_query_message(None))
        .await;
    assert_eq!(query_reply.status.code, 200);
    assert_eq!(query_reply.body["entries"].as_array().unwrap().len(), 1);
}

#[derive(Clone, Default)]
struct TestMessageStore {
    rows: Arc<RwLock<Vec<TestMessageRow>>>,
}

#[derive(Clone)]
struct TestMessageRow {
    tenant: String,
    cid: String,
    message: Message<Descriptor>,
    indexes: KeyValues,
}

impl MessageStore for TestMessageStore {
    async fn open(&mut self) -> Result<(), crate::errors::MessageStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    fn put<D: crate::descriptors::MessageDescriptor + Send>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), crate::errors::MessageStoreError>> + Send {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        async move {
            let value = serde_json::to_value(&message)?;
            let message: Message<Descriptor> = serde_json::from_value(value)?;
            let cid = message_cid(&message).map_err(test_store_error)?;
            rows.write().unwrap().push(TestMessageRow {
                tenant,
                cid,
                message,
                indexes,
            });
            Ok(())
        }
    }

    fn get(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<Option<Message<Descriptor>>, crate::errors::MessageStoreError>> + Send
    {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        let cid = cid.to_string();
        async move {
            Ok(rows
                .read()
                .unwrap()
                .iter()
                .find(|row| row.tenant == tenant && row.cid == cid)
                .map(|row| row.message.clone()))
        }
    }

    fn query(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
        pagination: Option<Pagination>,
    ) -> impl Future<Output = Result<MessageQueryResult, crate::errors::MessageStoreError>> + Send
    {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        async move {
            let mut rows = rows
                .read()
                .unwrap()
                .iter()
                .filter(|row| {
                    row.tenant == tenant && matches_filters(&row.indexes, filters.clone())
                })
                .cloned()
                .collect::<Vec<_>>();
            if let Some(sort) = sort {
                let (property, direction) = match sort {
                    MessageSort::DateCreated(direction) => ("dateCreated", direction),
                    MessageSort::DatePublished(direction) => ("datePublished", direction),
                    MessageSort::Timestamp(direction) => ("messageTimestamp", direction),
                };
                rows.sort_by(|left, right| {
                    let order = value_string(left.indexes.get(property))
                        .cmp(&value_string(right.indexes.get(property)));
                    match direction {
                        SortDirection::Ascending => order,
                        SortDirection::Descending => order.reverse(),
                    }
                });
            }
            if let Some(limit) = pagination.and_then(|pagination| pagination.limit) {
                rows.truncate(limit as usize);
            }
            Ok(MessageQueryResult {
                messages: rows.into_iter().map(|row| row.message).collect(),
                cursor: None,
            })
        }
    }

    async fn count(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
    ) -> Result<u64, crate::errors::MessageStoreError> {
        Ok(self
            .query(tenant, filters, sort, None)
            .await?
            .messages
            .len() as u64)
    }

    fn delete(
        &self,
        tenant: &str,
        cid: &str,
    ) -> impl Future<Output = Result<(), crate::errors::MessageStoreError>> + Send {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        let cid = cid.to_string();
        async move {
            rows.write()
                .unwrap()
                .retain(|row| row.tenant != tenant || row.cid != cid);
            Ok(())
        }
    }

    fn clear(&self) -> impl Future<Output = Result<(), crate::errors::MessageStoreError>> + Send {
        let rows = self.rows.clone();
        async move {
            rows.write().unwrap().clear();
            Ok(())
        }
    }
}

fn signed_configure_message(protocol: &str, published: bool, timestamp: &str) -> JsonValue {
    signed_configure_message_with_signer(protocol, published, timestamp, test_signer())
}

fn signed_configure_message_with_signer(
    protocol: &str,
    published: bool,
    timestamp: &str,
    signer: PrivateJwkSigner,
) -> JsonValue {
    signed_configure_descriptor_with_signer(
        configure_descriptor(protocol, published, timestamp),
        signer,
    )
}

fn signed_configure_descriptor(descriptor: ConfigureDescriptor) -> JsonValue {
    signed_configure_descriptor_with_signer(descriptor, test_signer())
}

fn signed_configure_descriptor_with_signer(
    descriptor: ConfigureDescriptor,
    signer: PrivateJwkSigner,
) -> JsonValue {
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let payload = serde_json::json!({
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
    });
    let signature =
        Jws::create_general(serde_json::to_vec(&payload).unwrap().as_slice(), &[signer]).unwrap();
    serde_json::json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

fn signed_query_message(protocol: Option<&str>, signer: PrivateJwkSigner) -> JsonValue {
    let descriptor = query_descriptor(protocol);
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let payload = serde_json::json!({
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
    });
    let signature =
        Jws::create_general(serde_json::to_vec(&payload).unwrap().as_slice(), &[signer]).unwrap();
    serde_json::json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

fn signed_query_message_with_grant(
    protocol: Option<&str>,
    signer: PrivateJwkSigner,
    permission_grant_id: &str,
) -> JsonValue {
    let mut descriptor = query_descriptor(protocol);
    descriptor.permission_grant_id = Some(permission_grant_id.to_string());
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let payload = serde_json::json!({
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
        "permissionGrantId": permission_grant_id,
    });
    let signature =
        Jws::create_general(serde_json::to_vec(&payload).unwrap().as_slice(), &[signer]).unwrap();
    serde_json::json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

fn unsigned_query_message(protocol: Option<&str>) -> JsonValue {
    serde_json::json!({ "descriptor": query_descriptor(protocol) })
}

fn query_descriptor(protocol: Option<&str>) -> ProtocolQueryDescriptor {
    let filter = protocol.map(|protocol| serde_json::json!({ "protocol": protocol }));
    ProtocolQueryDescriptor {
        message_timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:10:00.000000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        filter: filter.map(|filter| serde_json::from_value(filter).unwrap()),
        permission_grant_id: None,
    }
}

async fn put_protocols_query_grant(
    tenant: &str,
    message_store: &TestMessageStore,
    grant_id: &str,
    protocol: Option<&str>,
) {
    let scope = match protocol {
        Some(protocol) => serde_json::json!({
            "interface": "Protocols",
            "method": "Query",
            "protocol": protocol,
        }),
        None => serde_json::json!({
            "interface": "Protocols",
            "method": "Query",
        }),
    };
    let data = serde_json::to_vec(&serde_json::json!({
        "dateExpires": "2025-02-01T00:00:00.000000Z",
        "scope": scope,
    }))
    .unwrap();
    let descriptor = RecordsWriteDescriptor {
        protocol: Some(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
        protocol_path: Some(permissions::PERMISSIONS_GRANT_PATH.to_string()),
        recipient: Some("did:example:bob".to_string()),
        schema: None,
        tags: protocol.map(|protocol| {
            MapValue::from([("protocol".to_string(), Value::String(protocol.to_string()))])
        }),
        parent_id: None,
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        date_created: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00.000000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        message_timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00.000000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        published: None,
        date_published: None,
        data_format: "application/json".to_string(),
        permission_grant_id: None,
        squash: None,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let payload = serde_json::json!({
        "recordId": grant_id,
        "contextId": grant_id,
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
    });
    let signature = Jws::create_general(
        serde_json::to_vec(&payload).unwrap().as_slice(),
        &[test_signer()],
    )
    .unwrap();
    let message: Message<Descriptor> = serde_json::from_value(serde_json::json!({
        "descriptor": descriptor_json,
        "recordId": grant_id,
        "contextId": grant_id,
        "authorization": { "signature": signature },
        "encodedData": URL_SAFE_NO_PAD.encode(data),
    }))
    .unwrap();
    let indexes = BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        ("method".to_string(), Value::String("Write".to_string())),
        (
            "protocol".to_string(),
            Value::String(permissions::PERMISSIONS_PROTOCOL_URI.to_string()),
        ),
        (
            "protocolPath".to_string(),
            Value::String(permissions::PERMISSIONS_GRANT_PATH.to_string()),
        ),
        (
            "recipient".to_string(),
            Value::String("did:example:bob".to_string()),
        ),
        ("recordId".to_string(), Value::String(grant_id.to_string())),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "messageTimestamp".to_string(),
            Value::String("2025-01-01T00:00:00.000000Z".to_string()),
        ),
    ]);
    message_store.put(tenant, message, indexes).await.unwrap();
}

fn configure_descriptor(protocol: &str, published: bool, timestamp: &str) -> ConfigureDescriptor {
    ConfigureDescriptor {
        message_timestamp: chrono::DateTime::parse_from_rfc3339(timestamp)
            .unwrap()
            .with_timezone(&chrono::Utc),
        definition: Definition {
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
        },
        permission_grant_id: None,
    }
}

fn base_thread_descriptor() -> ConfigureDescriptor {
    ConfigureDescriptor {
        message_timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00.000000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        definition: Definition {
            protocol: "http://example.com/thread-protocol".to_string(),
            published: true,
            uses: None,
            types: BTreeMap::from([
                (
                    "thread".to_string(),
                    Type {
                        schema: Some("http://schema.example.com/thread".to_string()),
                        data_formats: Some(vec!["application/json".to_string()]),
                        encryption_required: None,
                    },
                ),
                (
                    "participant".to_string(),
                    Type {
                        schema: Some("http://schema.example.com/participant".to_string()),
                        data_formats: Some(vec!["application/json".to_string()]),
                        encryption_required: None,
                    },
                ),
            ]),
            structure: BTreeMap::from([(
                "thread".to_string(),
                RuleSet {
                    actions: vec![Action::Who(ActionWho {
                        who: Who::Anyone,
                        of: None,
                        can: vec![Can::Create, Can::Read],
                    })],
                    rules: BTreeMap::from([(
                        "participant".to_string(),
                        RuleSet {
                            role: Some(true),
                            actions: vec![Action::Who(ActionWho {
                                who: Who::Anyone,
                                of: None,
                                can: vec![Can::Create, Can::Read],
                            })],
                            ..Default::default()
                        },
                    )]),
                    ..Default::default()
                },
            )]),
        },
        permission_grant_id: None,
    }
}

fn composed_descriptor(protocol: &str, role: &str) -> ConfigureDescriptor {
    ConfigureDescriptor {
        message_timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:01:00.000000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        definition: Definition {
            protocol: protocol.to_string(),
            published: true,
            uses: Some(BTreeMap::from([(
                "threads".to_string(),
                "http://example.com/thread-protocol".to_string(),
            )])),
            types: BTreeMap::from([(
                "comment".to_string(),
                Type {
                    schema: Some("http://schema.example.com/comment".to_string()),
                    data_formats: Some(vec!["text/plain".to_string()]),
                    encryption_required: None,
                },
            )]),
            structure: BTreeMap::from([(
                "thread".to_string(),
                RuleSet {
                    reference: Some("threads:thread".to_string()),
                    rules: BTreeMap::from([(
                        "comment".to_string(),
                        RuleSet {
                            actions: vec![Action::Role(ActionRole {
                                role: role.to_string(),
                                can: vec![Can::Create, Can::Read],
                            })],
                            ..Default::default()
                        },
                    )]),
                    ..Default::default()
                },
            )]),
        },
        permission_grant_id: None,
    }
}

fn test_signer() -> PrivateJwkSigner {
    test_signer_with_key_id("did:example:alice#key1")
}

fn test_signer_with_key_id(key_id: &str) -> PrivateJwkSigner {
    PrivateJwkSigner::new(
        key_id,
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
        test_public_jwk("did:example:alice#key1"),
    )]))
}

fn test_resolver_with_bob() -> StaticPublicKeyResolver {
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

fn test_public_jwk(key_id: &str) -> JwsPublicJwk {
    JwsPublicJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
        y: None,
        kid: Some(key_id.to_string()),
        alg: Some("EdDSA".to_string()),
    }
}

fn matches_filters(indexes: &KeyValues, filters: Filters) -> bool {
    let mut has_filter_set = false;
    for filter_set in filters {
        has_filter_set = true;
        if filter_set.into_iter().all(|(key, filter)| match key {
            FilterKey::Index(index) => indexes
                .get(&index)
                .is_some_and(|value| matches_filter(value, &filter)),
            FilterKey::Tag(_) => false,
        }) {
            return true;
        }
    }
    !has_filter_set
}

fn matches_filter(value: &Value, filter: &Filter<Value>) -> bool {
    match filter {
        Filter::Equal(expected) => value == expected,
        Filter::OneOf(values) => values.iter().any(|expected| value == expected),
        Filter::Prefix(prefix) => {
            value_string(Some(value)).starts_with(&value_string(Some(prefix)))
        }
        Filter::Range(RangeFilter::Numeric(lower, upper))
        | Filter::Range(RangeFilter::Criterion(lower, upper)) => {
            matches_lower_bound(value, lower) && matches_upper_bound(value, upper)
        }
    }
}

fn matches_lower_bound(value: &Value, bound: &Bound<Value>) -> bool {
    match bound {
        Bound::Included(bound) => value_string(Some(value)) >= value_string(Some(bound)),
        Bound::Excluded(bound) => value_string(Some(value)) > value_string(Some(bound)),
        Bound::Unbounded => true,
    }
}

fn matches_upper_bound(value: &Value, bound: &Bound<Value>) -> bool {
    match bound {
        Bound::Included(bound) => value_string(Some(value)) <= value_string(Some(bound)),
        Bound::Excluded(bound) => value_string(Some(value)) < value_string(Some(bound)),
        Bound::Unbounded => true,
    }
}

fn value_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

fn test_store_error(error: String) -> crate::errors::MessageStoreError {
    crate::errors::MessageStoreError::StoreError(crate::errors::StoreError::InternalException(
        error,
    ))
}

#[test]
fn generic_message_deserializes_typescript_authorization_shape() {
    let raw = signed_configure_message(
        "http://example.com/protocol",
        true,
        "2025-01-01T00:00:00.000000Z",
    );
    let message: Message<Descriptor> = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(serde_json::to_value(message).unwrap(), raw);

    let unsigned = serde_json::json!({ "descriptor": configure_descriptor("http://example.com/protocol", true, "2025-01-01T00:00:00.000000Z") });
    let message: Message<Descriptor> = serde_json::from_value(unsigned.clone()).unwrap();
    assert_eq!(serde_json::to_value(message).unwrap(), unsigned);
}

#[test]
fn validate_definition_rejects_invalid_protocol_rules() {
    let mut descriptor = configure_descriptor(
        "http://example.com/protocol",
        true,
        "2025-01-01T00:00:00.000000Z",
    );
    descriptor
        .definition
        .structure
        .get_mut("note")
        .unwrap()
        .size = Some(protocol_types::Size {
        min: Some(10),
        max: Some(1),
    });
    let error = protocol_types::validate_definition(&descriptor.definition).unwrap_err();
    assert_eq!(error.code, "ProtocolsConfigureInvalidSize");
}

#[allow(dead_code)]
fn _message_from_descriptor(descriptor: ConfigureDescriptor) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Protocols(Box::new(Protocols::Configure(descriptor))),
        fields: Fields::Write(WriteFields::default()),
    }
}
