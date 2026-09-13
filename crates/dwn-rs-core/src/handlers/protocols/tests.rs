use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Bound;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ssi_jwk::Algorithm;

use crate::auth::{ed25519_jwk, Jws, PrivateJwkSigner, StaticPublicKeyResolver, JWK};
use crate::cid::{generate_cid_from_json, generate_dag_pb_cid_from_bytes};
use crate::descriptors::{
    ConfigureDescriptor, Descriptor, ProtocolQueryDescriptor, Protocols, RecordsWriteDescriptor,
};
use crate::dwn::{Dwn, Handler};
use crate::encryption::{protocol::encryption_protocol_definition, ENCRYPTION_PROTOCOL_URI};
use crate::fields::WriteFields;
use crate::handlers::configure::{fetch_protocol_definition, ProtocolsConfigureHandler};
use crate::handlers::query::ProtocolsQueryHandler;
use crate::interfaces::messages::protocols::{
    self as protocol_types, Action, ActionRole, ActionWho, Can, Definition, ProtocolKeyAgreement,
    Type, Who,
};
use crate::protocols::RuleSet;
use crate::stores::memory::MemoryMessageStore;
use crate::stores::occupancy::{is_occupant, occupant_ids_for_rows};
use crate::stores::{
    KeyValues, LatestStateMutation, LatestStateTransition, LatestStateTransitionResult,
    MessageQueryResult, MessageStore, RecordLimitOccupancy, ReplicationFeedReader,
};
use crate::{
    permissions, Fields, Filter, FilterKey, Filters, MapValue, Message, MessageSort, Pagination,
    RangeFilter, SortDirection, Value,
};

use super::common::*;

#[tokio::test]
async fn protocols_configure_stores_latest_base_state() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    let older = signed_configure_message(
        "http://example.com/protocol",
        true,
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    let newer = signed_configure_message(
        "http://example.com/protocol",
        false,
        "2025-01-01T00:00:01.000000Z",
    )
    .await;

    assert_eq!(
        handler
            .run("did:example:alice", &older, None)
            .await
            .status
            .code,
        202
    );
    assert_eq!(
        handler
            .run("did:example:alice", &newer, None)
            .await
            .status
            .code,
        202
    );
    assert_eq!(
        handler
            .run("did:example:alice", &newer, None)
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
async fn protocols_configure_duplicate_preserves_feed_identity() {
    let mut message_store = MemoryMessageStore::default();
    message_store.open().await.unwrap();
    let handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    let configure = signed_configure_message(
        "http://example.com/duplicate",
        true,
        "2025-01-01T00:00:00.000000Z",
    )
    .await;

    assert_eq!(
        handler
            .run("did:example:alice", &configure, None)
            .await
            .status
            .code,
        202
    );
    let bounds_before = message_store.log_bounds("did:example:alice").await.unwrap();

    // Covers: DWN-REC-003, DWN-PROTO-004
    assert_eq!(
        handler
            .run("did:example:alice", &configure, None)
            .await
            .status
            .code,
        409
    );
    assert_eq!(
        message_store.log_bounds("did:example:alice").await.unwrap(),
        bounds_before
    );
}

#[tokio::test]
async fn protocols_configure_arrival_orders_converge_and_retain_history() {
    let left = signed_configure_message(
        "http://example.com/convergent",
        true,
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    let right = signed_configure_message(
        "http://example.com/convergent",
        false,
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    let left_message: Message<Descriptor> = serde_json::from_value(left.clone()).unwrap();
    let right_message: Message<Descriptor> = serde_json::from_value(right.clone()).unwrap();
    let expected_latest = message_cid(&left_message)
        .unwrap()
        .max(message_cid(&right_message).unwrap());

    // Covers: DWN-PROTO-004, DWN-REC-006
    for order in [[left.clone(), right.clone()], [right, left]] {
        let mut message_store = TestMessageStore::default();
        message_store.open().await.unwrap();
        let handler =
            ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
        for configure in order {
            assert_eq!(
                handler
                    .run("did:example:alice", &configure, None)
                    .await
                    .status
                    .code,
                202
            );
        }

        let retained = message_store
            .query(
                "did:example:alice",
                protocol_configure_filters("http://example.com/convergent", false),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(retained.messages.len(), 2);

        let latest = message_store
            .query(
                "did:example:alice",
                protocol_configure_filters("http://example.com/convergent", true),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(latest.messages.len(), 1);
        assert_eq!(message_cid(&latest.messages[0]).unwrap(), expected_latest);
    }
}

#[tokio::test]
async fn protocols_configure_failed_atomic_transition_preserves_previous_latest() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    let older = signed_configure_message(
        "http://example.com/rollback",
        true,
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    let newer = signed_configure_message(
        "http://example.com/rollback",
        false,
        "2025-01-01T00:00:01.000000Z",
    )
    .await;
    assert_eq!(
        handler
            .run("did:example:alice", &older, None)
            .await
            .status
            .code,
        202
    );

    message_store.fail_next_transition();
    assert_eq!(
        handler
            .run("did:example:alice", &newer, None)
            .await
            .status
            .code,
        500
    );

    // Covers: DWN-PROTO-004, DWN-REC-006
    let latest = message_store
        .query(
            "did:example:alice",
            protocol_configure_filters("http://example.com/rollback", true),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(latest.messages.len(), 1);
    assert!(
        protocols_configure_descriptor(&latest.messages[0])
            .unwrap()
            .definition
            .published
    );
    assert_eq!(
        message_store
            .query(
                "did:example:alice",
                protocol_configure_filters("http://example.com/rollback", false),
                None,
                None,
                None
            )
            .await
            .unwrap()
            .messages
            .len(),
        1
    );
}

/// `include_private` is decided from the parsed message's authorization, not from a raw-JSON
/// `authorization` probe. A present-but-empty `authorization` object is the only input where
/// the two predicates could disagree, and it never reaches the handler: `Authorization`
/// requires a signature, so `{}` matches no `Fields` variant and ingress rejects the message.
#[tokio::test]
async fn protocols_query_with_empty_authorization_is_rejected_at_ingress() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let query_handler = ProtocolsQueryHandler::new(message_store.clone(), None);

    let mut message = unsigned_query_message(None);
    message["authorization"] = serde_json::json!({});

    let reply = query_handler.run("did:example:alice", &message, None).await;

    assert_eq!(reply.status.code, 400);
    assert!(
        reply.status.detail.starts_with("Failed to parse message: "),
        "unexpected detail: {}",
        reply.status.detail
    );
}

#[tokio::test]
async fn protocols_query_unsigned_returns_only_published_latest_configures() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let configure_handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    let query_handler = ProtocolsQueryHandler::new(message_store.clone(), None);

    configure_handler
        .run(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/public",
                true,
                "2025-01-01T00:00:00.000000Z",
            )
            .await,
            None,
        )
        .await;
    configure_handler
        .run(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/private",
                false,
                "2025-01-01T00:00:01.000000Z",
            )
            .await,
            None,
        )
        .await;

    let reply = query_handler
        .run("did:example:alice", &unsigned_query_message(None), None)
        .await;
    assert_eq!(reply.status.code, 200);
    let body = serde_json::to_value(&reply.reply).unwrap();
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["descriptor"]["definition"]["protocol"].as_str(),
        Some("http://example.com/public")
    );
}

#[tokio::test]
async fn protocols_query_signed_by_tenant_returns_private_configures() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let configure_handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    let query_handler =
        ProtocolsQueryHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));

    configure_handler
        .run(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/private",
                false,
                "2025-01-01T00:00:00.000000Z",
            )
            .await,
            None,
        )
        .await;

    let reply = query_handler
        .run(
            "did:example:alice",
            &signed_query_message(None, test_signer_with_key_id("did:example:alice#key1")).await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200);
    let body = serde_json::to_value(&reply.reply).unwrap();
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["descriptor"]["definition"]["published"].as_bool(),
        Some(false)
    );
}

#[tokio::test]
async fn protocols_query_signed_by_non_tenant_falls_back_to_published_configures() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let configure_handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    let query_handler = ProtocolsQueryHandler::new(
        message_store.clone(),
        Some(Arc::new(test_resolver_with_bob())),
    );

    configure_handler
        .run(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/public",
                true,
                "2025-01-01T00:00:00.000000Z",
            )
            .await,
            None,
        )
        .await;
    configure_handler
        .run(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/private",
                false,
                "2025-01-01T00:00:01.000000Z",
            )
            .await,
            None,
        )
        .await;

    let reply = query_handler
        .run(
            "did:example:alice",
            &signed_query_message(None, test_signer_with_key_id("did:example:bob#key1")).await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200);
    let body = serde_json::to_value(&reply.reply).unwrap();
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["descriptor"]["definition"]["protocol"].as_str(),
        Some("http://example.com/public")
    );
}

#[tokio::test]
async fn protocols_query_with_permission_grant_returns_private_configure() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let configure_handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    let query_handler = ProtocolsQueryHandler::new(
        message_store.clone(),
        Some(Arc::new(test_resolver_with_bob())),
    );

    configure_handler
        .run(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/private",
                false,
                "2025-01-01T00:00:00.000000Z",
            )
            .await,
            None,
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
        .run(
            "did:example:alice",
            &signed_query_message_with_grant(
                Some("http://example.com/private"),
                test_signer_with_key_id("did:example:bob#key1"),
                "grant-protocols-query",
            )
            .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 200);
    let body = serde_json::to_value(&reply.reply).unwrap();
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["descriptor"]["definition"]["published"].as_bool(),
        Some(false)
    );
}

#[tokio::test]
async fn protocols_configure_rejects_tampered_descriptor_cid_as_bad_request() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let handler = ProtocolsConfigureHandler::new(message_store, Some(Arc::new(test_resolver())));
    let mut message = signed_configure_message(
        "http://example.com/original",
        true,
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    message["descriptor"]["definition"]["protocol"] =
        serde_json::Value::String("http://example.com/tampered".to_string());

    let reply = handler.run("did:example:alice", &message, None).await;
    assert_eq!(reply.status.code, 400);
}

#[tokio::test]
async fn protocols_configure_rejects_non_tenant_signer() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let handler =
        ProtocolsConfigureHandler::new(message_store, Some(Arc::new(test_resolver_with_bob())));

    let reply = handler
        .run(
            "did:example:alice",
            &signed_configure_message_with_signer(
                "http://example.com/protocol",
                true,
                "2025-01-01T00:00:00.000000Z",
                test_signer_with_key_id("did:example:bob#key1"),
            )
            .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 401);
}

#[tokio::test]
async fn fetch_protocol_definition_supports_latest_and_temporal_lookup() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));

    handler
        .run(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/versioned",
                true,
                "2025-01-01T00:00:00.000000Z",
            )
            .await,
            None,
        )
        .await;
    handler
        .run(
            "did:example:alice",
            &signed_configure_message(
                "http://example.com/versioned",
                false,
                "2025-01-01T00:10:00.000000Z",
            )
            .await,
            None,
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

// Covers: ENBOX-ENC-002
#[tokio::test]
async fn core_encryption_definition_takes_precedence_over_tenant_configure() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));

    // A tenant configuration at the core URI is accepted and stored ...
    let reply = handler
        .run(
            "did:example:alice",
            &signed_configure_message(ENCRYPTION_PROTOCOL_URI, true, "2025-01-01T00:00:00.000000Z")
                .await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // ... but never consulted: the registry definition wins over the stored one.
    let definition = fetch_protocol_definition(
        "did:example:alice",
        ENCRYPTION_PROTOCOL_URI,
        &message_store,
        None,
    )
    .await
    .unwrap();
    assert_eq!(definition, encryption_protocol_definition());
}

#[tokio::test]
async fn protocols_configure_validates_composition_dependencies() {
    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let handler = ProtocolsConfigureHandler::new(message_store, Some(Arc::new(test_resolver())));

    let missing_dependency = signed_configure_descriptor(composed_descriptor(
        "http://example.com/composed-missing",
        "threads:thread/participant",
    ))
    .await;
    assert_eq!(
        handler
            .run("did:example:alice", &missing_dependency, None)
            .await
            .status
            .code,
        400
    );

    assert_eq!(
        handler
            .run(
                "did:example:alice",
                &signed_configure_descriptor(base_thread_descriptor()).await,
                None,
            )
            .await
            .status
            .code,
        202
    );
    assert_eq!(
        handler
            .run(
                "did:example:alice",
                &signed_configure_descriptor(composed_descriptor(
                    "http://example.com/composed",
                    "threads:thread/participant",
                ))
                .await,
                None,
            )
            .await
            .status
            .code,
        202
    );
    assert_eq!(
        handler
            .run(
                "did:example:alice",
                &signed_configure_descriptor(composed_descriptor(
                    "http://example.com/composed-invalid-role",
                    "threads:thread/missing",
                ))
                .await,
                None,
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
    message_store.open().await.unwrap();

    let mut dwn = Dwn::default();
    dwn.register(ProtocolsConfigureHandler::new(
        message_store.clone(),
        Some(Arc::new(test_resolver())),
    ));
    dwn.register(ProtocolsQueryHandler::new(message_store, None));

    let configure = signed_configure_message(
        "http://example.com/dispatch",
        true,
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    let configure_reply = dwn.process_message("did:example:alice", configure).await;
    assert_eq!(configure_reply.status.code, 202);

    let query_reply = dwn
        .process_message("did:example:alice", unsigned_query_message(None))
        .await;
    assert_eq!(query_reply.status.code, 200);
    let crate::Reply::ProtocolsQuery(reply) = query_reply.reply else {
        panic!("expected ProtocolsQuery reply");
    };
    assert_eq!(reply.entries.as_ref().unwrap().len(), 1);
}

#[derive(Clone, Default)]
struct TestMessageStore {
    rows: Arc<RwLock<Vec<TestMessageRow>>>,
    fail_transition: Arc<AtomicBool>,
}

impl TestMessageStore {
    fn fail_next_transition(&self) {
        self.fail_transition.store(true, AtomicOrdering::SeqCst);
    }
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
            let mut rows = rows.write().unwrap();
            rows.retain(|row| row.tenant != tenant || row.cid != cid);
            rows.push(TestMessageRow {
                tenant,
                cid,
                message,
                indexes,
            });
            Ok(())
        }
    }

    async fn commit_latest_state(
        &self,
        tenant: &str,
        transition: LatestStateTransition,
    ) -> Result<LatestStateTransitionResult, crate::errors::MessageStoreError> {
        if self.fail_transition.swap(false, AtomicOrdering::SeqCst) {
            return Err(test_store_error("injected transition failure".to_string()));
        }
        transition.validate()?;
        let mut rows = self.rows.write().unwrap();
        let mut staged = rows.clone();

        put_test_message(&mut staged, tenant, transition.put)?;
        for retained in transition.retains {
            let cid = retained.message.cid()?.to_string();
            if !staged
                .iter()
                .any(|row| row.tenant == tenant && row.cid == cid)
            {
                return Err(test_store_error(format!(
                    "retained message '{cid}' does not exist"
                )));
            }
            put_test_message(&mut staged, tenant, retained)?;
        }
        for cid in transition.deletes {
            staged.retain(|row| row.tenant != tenant || row.cid != cid);
        }

        *rows = staged;
        Ok(LatestStateTransitionResult { position: None })
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
        record_limit: Option<RecordLimitOccupancy>,
    ) -> impl Future<Output = Result<MessageQueryResult, crate::errors::MessageStoreError>> + Send
    {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        async move {
            let occupants = match record_limit {
                None => None,
                Some(policy) => match occupant_ids_for_rows(
                    rows.read()
                        .unwrap()
                        .iter()
                        .map(|row| (row.tenant.as_str(), &row.indexes)),
                    &tenant,
                    &policy,
                ) {
                    Ok(Some(ids)) => Some(ids),
                    Ok(None) => {
                        return Ok(MessageQueryResult {
                            messages: Vec::new(),
                            cursor: None,
                        });
                    }
                    Err(detail) => return Err(test_store_error(detail)),
                },
            };
            let mut rows = rows
                .read()
                .unwrap()
                .iter()
                .filter(|row| {
                    row.tenant == tenant && matches_filters(&row.indexes, filters.clone())
                })
                .cloned()
                .collect::<Vec<_>>();
            if let Some(occupant_ids) = occupants.as_ref() {
                rows.retain(|row| is_occupant(&row.indexes, occupant_ids));
            }
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
        record_limit: Option<RecordLimitOccupancy>,
    ) -> Result<u64, crate::errors::MessageStoreError> {
        Ok(self
            .query(tenant, filters, sort, None, record_limit)
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

fn put_test_message(
    rows: &mut Vec<TestMessageRow>,
    tenant: &str,
    mutation: LatestStateMutation,
) -> Result<(), crate::errors::MessageStoreError> {
    let cid = mutation.message.cid()?.to_string();
    rows.retain(|row| row.tenant != tenant || row.cid != cid);
    rows.push(TestMessageRow {
        tenant: tenant.to_string(),
        cid,
        message: mutation.message,
        indexes: mutation.indexes,
    });
    Ok(())
}

async fn signed_configure_message(
    protocol: &str,
    published: bool,
    timestamp: &str,
) -> serde_json::Value {
    signed_configure_message_with_signer(protocol, published, timestamp, test_signer()).await
}

async fn signed_configure_message_with_signer(
    protocol: &str,
    published: bool,
    timestamp: &str,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    signed_configure_descriptor_with_signer(
        configure_descriptor(protocol, published, timestamp),
        signer,
    )
    .await
}

async fn signed_configure_descriptor(descriptor: ConfigureDescriptor) -> serde_json::Value {
    signed_configure_descriptor_with_signer(descriptor, test_signer()).await
}

async fn signed_configure_descriptor_with_signer(
    descriptor: ConfigureDescriptor,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let payload = serde_json::json!({
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
    });
    let signature = Jws::create(serde_json::to_vec(&payload).unwrap().as_slice(), &[signer])
        .await
        .unwrap();
    serde_json::json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

async fn signed_query_message(
    protocol: Option<&str>,
    signer: PrivateJwkSigner,
) -> serde_json::Value {
    let descriptor = query_descriptor(protocol);
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let payload = serde_json::json!({
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
    });
    let signature = Jws::create(serde_json::to_vec(&payload).unwrap().as_slice(), &[signer])
        .await
        .unwrap();
    serde_json::json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

async fn signed_query_message_with_grant(
    protocol: Option<&str>,
    signer: PrivateJwkSigner,
    permission_grant_id: &str,
) -> serde_json::Value {
    let mut descriptor = query_descriptor(protocol);
    descriptor.permission_grant_id = Some(permission_grant_id.to_string());
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let payload = serde_json::json!({
        "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
        "permissionGrantId": permission_grant_id,
    });
    let signature = Jws::create(serde_json::to_vec(&payload).unwrap().as_slice(), &[signer])
        .await
        .unwrap();
    serde_json::json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

fn unsigned_query_message(protocol: Option<&str>) -> serde_json::Value {
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
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
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
    let signature = Jws::create(
        serde_json::to_vec(&payload).unwrap().as_slice(),
        &[test_signer()],
    )
    .await
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
            key_agreement: None,
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
            key_agreement: None,
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
                                who: Who::Author,
                                of: Some("thread".to_string()),
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
            key_agreement: None,
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
        Algorithm::EdDSA,
        ed25519_jwk(
            "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"),
            Some(key_id),
        )
        .unwrap(),
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

fn test_public_jwk(key_id: &str) -> JWK {
    ed25519_jwk(
        "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        None,
        Some(key_id),
    )
    .unwrap()
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
        Filter::Subtree(subtree) => match value {
            Value::String(actual) => {
                *actual == subtree.subtree || actual.starts_with(&format!("{}/", subtree.subtree))
            }
            _ => false,
        },
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

#[tokio::test]
async fn generic_message_deserializes_typescript_authorization_shape() {
    let raw = signed_configure_message(
        "http://example.com/protocol",
        true,
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
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

fn enc_key_agreement() -> ProtocolKeyAgreement {
    ProtocolKeyAgreement {
        public_key_jwk: serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
        }))
        .unwrap(),
    }
}

fn enc_reader_definition() -> Definition {
    Definition {
        protocol: "http://example.com/enc".to_string(),
        published: true,
        uses: None,
        key_agreement: Some(enc_key_agreement()),
        types: BTreeMap::from([
            (
                "note".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["text/plain".to_string()]),
                    encryption_required: Some(true),
                },
            ),
            (
                "member".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["text/plain".to_string()]),
                    encryption_required: None,
                },
            ),
        ]),
        structure: BTreeMap::from([
            (
                "note".to_string(),
                RuleSet {
                    key_agreement: Some(enc_key_agreement()),
                    actions: vec![Action::Role(ActionRole {
                        role: "member".to_string(),
                        can: vec![Can::Create, Can::Read],
                    })],
                    ..Default::default()
                },
            ),
            (
                "member".to_string(),
                RuleSet {
                    role: Some(true),
                    key_agreement: Some(enc_key_agreement()),
                    actions: vec![Action::Who(ActionWho {
                        who: Who::Author,
                        of: Some("member".to_string()),
                        can: vec![Can::Create],
                    })],
                    ..Default::default()
                },
            ),
        ]),
    }
}

#[test]
fn validate_definition_accepts_keyed_encrypted_definition() {
    protocol_types::validate_definition(&enc_reader_definition())
        .expect("keyed encrypted definition must validate");
}

#[test]
fn validate_definition_rejects_encrypted_types_without_top_level_key() {
    let mut definition = enc_reader_definition();
    definition.key_agreement = None;
    let error = protocol_types::validate_definition(&definition).unwrap_err();
    assert_eq!(error.code, "ProtocolsConfigureMissingTopLevelKeyAgreement");
}

#[test]
fn validate_definition_rejects_encrypted_path_without_path_key() {
    let mut definition = enc_reader_definition();
    definition.structure.get_mut("note").unwrap().key_agreement = None;
    let error = protocol_types::validate_definition(&definition).unwrap_err();
    assert_eq!(
        error.code,
        "ProtocolsConfigureMissingEncryptedPathKeyAgreement"
    );
}

#[test]
fn validate_definition_rejects_encrypted_path_readable_by_anyone() {
    let mut definition = enc_reader_definition();
    definition
        .structure
        .get_mut("note")
        .unwrap()
        .actions
        .push(Action::Who(ActionWho {
            who: Who::Anyone,
            of: None,
            can: vec![Can::Create, Can::Read],
        }));
    let error = protocol_types::validate_definition(&definition).unwrap_err();
    assert_eq!(error.code, "ProtocolsConfigureInvalidEncryptedAnyoneRead");
}

#[test]
fn validate_definition_rejects_role_resolving_to_encrypted_type() {
    let mut definition = enc_reader_definition();
    definition
        .types
        .get_mut("member")
        .unwrap()
        .encryption_required = Some(true);
    let error = protocol_types::validate_definition(&definition).unwrap_err();
    assert_eq!(error.code, "ProtocolsConfigureInvalidEncryptedRoleType");
}

#[test]
fn validate_definition_rejects_read_role_without_owning_key() {
    let mut definition = enc_reader_definition();
    definition
        .structure
        .get_mut("member")
        .unwrap()
        .key_agreement = None;
    let error = protocol_types::validate_definition(&definition).unwrap_err();
    assert_eq!(
        error.code,
        "ProtocolsConfigureInvalidEncryptedRoleMissingKeyAgreement"
    );
}

// Covers: DWN-PROTO-001, DWN-PROTO-005
#[tokio::test]
async fn protocols_configure_rejects_cross_protocol_role_with_encrypted_type() {
    use crate::testing::put_protocol_definition;

    let mut message_store = MemoryMessageStore::default();
    message_store.open().await.unwrap();
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        Definition {
            protocol: "http://example.com/blog".to_string(),
            published: true,
            uses: None,
            key_agreement: Some(enc_key_agreement()),
            types: BTreeMap::from([(
                "member".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["text/plain".to_string()]),
                    encryption_required: Some(true),
                },
            )]),
            structure: BTreeMap::from([(
                "member".to_string(),
                RuleSet {
                    role: Some(true),
                    key_agreement: Some(enc_key_agreement()),
                    actions: vec![Action::Who(ActionWho {
                        who: Who::Author,
                        of: Some("member".to_string()),
                        can: vec![Can::Create],
                    })],
                    ..Default::default()
                },
            )]),
        },
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    let handler =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));

    let definition = Definition {
        protocol: "http://example.com/composed".to_string(),
        published: true,
        uses: Some(BTreeMap::from([(
            "blog".to_string(),
            "http://example.com/blog".to_string(),
        )])),
        key_agreement: None,
        types: BTreeMap::from([(
            "post".to_string(),
            Type {
                schema: None,
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([(
            "post".to_string(),
            RuleSet {
                actions: vec![Action::Role(ActionRole {
                    role: "blog:member".to_string(),
                    can: vec![Can::Create, Can::Read],
                })],
                ..Default::default()
            },
        )]),
    };
    let descriptor = ConfigureDescriptor {
        message_timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-02T00:00:00.000000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        definition,
        permission_grant_id: None,
    };
    let reply = handler
        .run(
            "did:example:alice",
            &signed_configure_descriptor(descriptor).await,
            None,
        )
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert!(
        reply
            .status
            .detail
            .contains("ProtocolsConfigureInvalidEncryptedRoleType"),
        "{}",
        reply.status.detail
    );
}

#[test]
fn validate_definition_rejects_cross_protocol_read_role_on_encrypted_path() {
    let mut definition = enc_reader_definition();
    definition.uses = Some(BTreeMap::from([(
        "blog".to_string(),
        "http://example.com/blog".to_string(),
    )]));
    definition.structure.get_mut("note").unwrap().actions = vec![Action::Role(ActionRole {
        role: "blog:member".to_string(),
        can: vec![Can::Create, Can::Read],
    })];
    let error = protocol_types::validate_definition(&definition).unwrap_err();
    assert_eq!(
        error.code,
        "ProtocolsConfigureInvalidEncryptedCrossProtocolRole"
    );
}

#[allow(dead_code)]
fn _message_from_descriptor(descriptor: ConfigureDescriptor) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Protocols(Box::new(Protocols::Configure(descriptor))),
        fields: Fields::Write(WriteFields::default()),
    }
}

use crate::encryption::{
    ContentEncryptionAlgorithm, EncryptionEnvelope, KeyAgreementAlgorithm, KeyEncryption,
};
use crate::handlers::records::write::RecordsWriteHandler;
use crate::stores::{DataStore, DataStoreGetResult, DataStorePutResult};
use crate::testing::{signed_write_message, WriteSpec};
use futures_util::{stream, Stream, StreamExt};

const FLIP_PROTOCOL: &str = "http://example.com/flip";
const FLIP_T1: &str = "2025-01-01T00:00:00.000000Z";
const FLIP_T1_5: &str = "2025-01-01T12:00:00.000000Z";
const FLIP_MID: &str = "2025-01-02T00:00:00.000000Z";
const FLIP_T2: &str = "2025-01-03T00:00:00.000000Z";
const FLIP_T3: &str = "2025-01-04T00:00:00.000000Z";
const FLIP_T4: &str = "2025-01-05T00:00:00.000000Z";
const FLIP_DATA: &[u8] = b"immutable note";
const ROTATED_X: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn flip_key_jwk(x: &str) -> JWK {
    serde_json::from_value(serde_json::json!({
        "kty": "OKP",
        "crv": "X25519",
        "x": x
    }))
    .unwrap()
}

fn flip_key_id(x: &str) -> String {
    flip_key_jwk(x).thumbprint().unwrap()
}

fn flip_keyed(encrypted: bool, x: &str) -> Definition {
    Definition {
        protocol: FLIP_PROTOCOL.to_string(),
        published: true,
        uses: None,
        key_agreement: Some(ProtocolKeyAgreement {
            public_key_jwk: flip_key_jwk(x),
        }),
        types: BTreeMap::from([(
            "note".to_string(),
            Type {
                schema: None,
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: if encrypted { Some(true) } else { None },
            },
        )]),
        structure: BTreeMap::from([(
            "note".to_string(),
            RuleSet {
                key_agreement: Some(ProtocolKeyAgreement {
                    public_key_jwk: flip_key_jwk(x),
                }),
                actions: vec![Action::Who(ActionWho {
                    who: Who::Author,
                    of: Some("note".to_string()),
                    can: vec![Can::Create, Can::Read],
                })],
                ..Default::default()
            },
        )]),
    }
}

fn flip_plain() -> Definition {
    Definition {
        protocol: FLIP_PROTOCOL.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
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
                actions: vec![Action::Who(ActionWho {
                    who: Who::Anyone,
                    of: None,
                    can: vec![Can::Create, Can::Read],
                })],
                ..Default::default()
            },
        )]),
    }
}

fn flip_envelope(key_id: &str) -> EncryptionEnvelope {
    EncryptionEnvelope {
        algorithm: ContentEncryptionAlgorithm::A256Ctr,
        initialization_vector: "oKGio6SlpqeoqaqrrK2urw".to_string(),
        key_encryption: vec![KeyEncryption::ProtocolPath {
            algorithm: KeyAgreementAlgorithm::X25519HkdfSha256A256Kw,
            key_id: key_id.to_string(),
            ephemeral_public_key: flip_key_jwk("C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"),
            encrypted_key: "a2V5".to_string(),
        }],
    }
}

type StubDataValues = BTreeMap<(String, String, String), bytes::Bytes>;

#[derive(Clone, Default)]
struct StubDataStore {
    values: Arc<std::sync::RwLock<StubDataValues>>,
}

impl DataStore for StubDataStore {
    async fn open(&mut self) -> Result<(), crate::errors::DataStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    fn put<T: Stream<Item = bytes::Bytes> + Send + Unpin>(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
        mut data_stream: T,
    ) -> impl Future<Output = Result<DataStorePutResult, crate::errors::DataStoreError>> + Send
    {
        let values = self.values.clone();
        let key = (
            tenant.to_string(),
            record_id.to_string(),
            data_cid.to_string(),
        );
        async move {
            let mut bytes = Vec::new();
            while let Some(chunk) = data_stream.next().await {
                bytes.extend_from_slice(&chunk);
            }
            let bytes = bytes::Bytes::from(bytes);
            let data_size = bytes.len();
            values.write().unwrap().insert(key, bytes);
            Ok(DataStorePutResult { data_size })
        }
    }

    fn get(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> impl Future<Output = Result<Option<DataStoreGetResult>, crate::errors::DataStoreError>> + Send
    {
        let values = self.values.clone();
        let key = (
            tenant.to_string(),
            record_id.to_string(),
            data_cid.to_string(),
        );
        async move {
            Ok(values.read().unwrap().get(&key).cloned().map(|bytes| {
                let data_size = bytes.len();
                DataStoreGetResult {
                    data_size,
                    data_stream: Box::pin(stream::iter(vec![Ok::<_, std::io::Error>(bytes)])),
                }
            }))
        }
    }

    fn delete(
        &self,
        _tenant: &str,
        _record_id: &str,
        _data_cid: &str,
    ) -> impl Future<Output = Result<(), crate::errors::DataStoreError>> + Send {
        async move { Ok(()) }
    }

    fn clear(&self) -> impl Future<Output = Result<(), crate::errors::DataStoreError>> + Send {
        async move { Ok(()) }
    }
}

async fn flip_harness() -> (
    ProtocolsConfigureHandler<MemoryMessageStore>,
    RecordsWriteHandler<MemoryMessageStore, StubDataStore>,
    MemoryMessageStore,
) {
    let mut message_store = MemoryMessageStore::default();
    message_store.open().await.unwrap();
    let configures =
        ProtocolsConfigureHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    let writes = RecordsWriteHandler::new(
        message_store.clone(),
        StubDataStore::default(),
        Some(Arc::new(test_resolver())),
    );
    (configures, writes, message_store)
}

async fn run_flip_configure<S>(
    configures: &ProtocolsConfigureHandler<S>,
    definition: Definition,
    timestamp: &str,
) -> crate::Response<crate::replies::protocols::Configure>
where
    S: MessageStore + Clone + Send + Sync + 'static,
{
    let descriptor = ConfigureDescriptor {
        message_timestamp: chrono::DateTime::parse_from_rfc3339(timestamp)
            .unwrap()
            .with_timezone(&chrono::Utc),
        definition,
        permission_grant_id: None,
    };
    configures
        .run(
            "did:example:alice",
            &signed_configure_descriptor(descriptor).await,
            None,
        )
        .await
}

async fn admit_flip_record<S>(
    writes: &RecordsWriteHandler<S, StubDataStore>,
    protocol: &str,
    protocol_path: &str,
    timestamp: &str,
    envelope: Option<EncryptionEnvelope>,
) -> crate::Response<crate::replies::records::Write>
where
    S: MessageStore + Clone + Send + Sync + 'static,
{
    use bytes::Bytes;

    let data = Bytes::from_static(FLIP_DATA);
    let message = signed_write_message(WriteSpec {
        protocol: protocol.to_string(),
        protocol_path: protocol_path.to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        encryption: envelope,
        ..WriteSpec::new(timestamp)
    })
    .await;
    writes.run("did:example:alice", &message, Some(data)).await
}

// Covers: DWN-PROTO-001, DWN-PROTO-004
#[tokio::test]
async fn protocols_configure_rejects_plaintext_to_encrypted_flip_after_use() {
    let (configures, writes, _) = flip_harness().await;
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(&writes, FLIP_PROTOCOL, "note", FLIP_MID, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T2).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert!(
        reply
            .status
            .detail
            .contains("ProtocolsConfigureEncryptionPolicyImmutable"),
        "{}",
        reply.status.detail
    );

    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T1).await;
    assert_eq!(reply.status.code, 409, "exact replay stays a conflict");
}

// Covers: DWN-PROTO-001, DWN-PROTO-004
#[tokio::test]
async fn protocols_configure_rejects_encrypted_to_plaintext_flip_after_use() {
    let (configures, writes, _) = flip_harness().await;
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(
        &writes,
        FLIP_PROTOCOL,
        "note",
        FLIP_MID,
        Some(flip_envelope(&flip_key_id(flip_x))),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T2).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert!(
        reply
            .status
            .detail
            .contains("ProtocolsConfigureEncryptionPolicyImmutable"),
        "{}",
        reply.status.detail
    );
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn protocols_configure_accepts_policy_change_without_records() {
    let (configures, _, _) = flip_harness().await;
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T2).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn protocols_configure_accepts_removed_populated_path() {
    let (configures, writes, _) = flip_harness().await;
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let mut v1 = flip_plain();
    v1.types.insert(
        "doc".to_string(),
        Type {
            schema: None,
            data_formats: Some(vec!["text/plain".to_string()]),
            encryption_required: Some(true),
        },
    );
    v1.key_agreement = Some(ProtocolKeyAgreement {
        public_key_jwk: flip_key_jwk(flip_x),
    });
    v1.structure.insert(
        "doc".to_string(),
        RuleSet {
            key_agreement: Some(ProtocolKeyAgreement {
                public_key_jwk: flip_key_jwk(flip_x),
            }),
            actions: vec![Action::Who(ActionWho {
                who: Who::Author,
                of: Some("doc".to_string()),
                can: vec![Can::Create, Can::Read],
            })],
            ..Default::default()
        },
    );
    let reply = run_flip_configure(&configures, v1, FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(
        &writes,
        FLIP_PROTOCOL,
        "doc",
        FLIP_MID,
        Some(flip_envelope(&flip_key_id(flip_x))),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T2).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn protocols_configure_accepts_key_rotation_and_governs_new_writes() {
    let (configures, writes, _) = flip_harness().await;
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(
        &writes,
        FLIP_PROTOCOL,
        "note",
        FLIP_MID,
        Some(flip_envelope(&flip_key_id(flip_x))),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_keyed(true, ROTATED_X), FLIP_T2).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(
        &writes,
        FLIP_PROTOCOL,
        "note",
        FLIP_T3,
        Some(flip_envelope(&flip_key_id(ROTATED_X))),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-004, DWN-PROTO-005
#[tokio::test]
async fn protocols_configure_rejects_composed_policy_flip() {
    const BLOG: &str = "http://example.com/blog";
    const COMPOSER: &str = "http://example.com/composer";

    let (configures, writes, _) = flip_harness().await;
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let blog_v1 = Definition {
        protocol: BLOG.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([(
            "post".to_string(),
            Type {
                schema: None,
                data_formats: None,
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([(
            "post".to_string(),
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
    let reply = run_flip_configure(&configures, blog_v1, FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let composer = Definition {
        protocol: COMPOSER.to_string(),
        published: true,
        uses: Some(BTreeMap::from([("blog".to_string(), BLOG.to_string())])),
        key_agreement: None,
        types: BTreeMap::new(),
        structure: BTreeMap::from([
            (
                "post".to_string(),
                RuleSet {
                    reference: Some("blog:post".to_string()),
                    ..Default::default()
                },
            ),
            (
                "article".to_string(),
                RuleSet {
                    reference: Some("blog:post".to_string()),
                    ..Default::default()
                },
            ),
        ]),
    };
    let reply = run_flip_configure(&configures, composer, FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(&writes, COMPOSER, "post", FLIP_MID, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(&writes, COMPOSER, "article", FLIP_MID, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let mut blog_v2 = flip_keyed(true, flip_x);
    blog_v2.protocol = BLOG.to_string();
    blog_v2.types = BTreeMap::from([(
        "post".to_string(),
        Type {
            schema: None,
            data_formats: None,
            encryption_required: Some(true),
        },
    )]);
    blog_v2.structure = BTreeMap::from([(
        "post".to_string(),
        RuleSet {
            key_agreement: Some(ProtocolKeyAgreement {
                public_key_jwk: flip_key_jwk(flip_x),
            }),
            actions: vec![Action::Who(ActionWho {
                who: Who::Author,
                of: Some("post".to_string()),
                can: vec![Can::Create, Can::Read],
            })],
            ..Default::default()
        },
    )]);
    let reply = run_flip_configure(&configures, blog_v2, FLIP_T2).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert!(
        reply.status.detail.contains("imported by protocol"),
        "{}",
        reply.status.detail
    );
    assert!(
        reply.status.detail.contains("'article'"),
        "differently named $ref root is evaluated: {}",
        reply.status.detail
    );
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn protocols_configure_out_of_order_arrival_uses_governing_definition() {
    let (configures, writes, _) = flip_harness().await;
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T2).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(&writes, FLIP_PROTOCOL, "note", FLIP_MID, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T4).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-001, DWN-PROTO-004
#[tokio::test]
async fn protocols_configure_rejects_historical_insert_matching_newest_policy() {
    let (configures, writes, _) = flip_harness().await;
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T2).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(&writes, FLIP_PROTOCOL, "note", FLIP_MID, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // Same policy as newest, but a retained record contradicts the incoming
    // representation: the scan judges records, not configurations.
    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T1_5).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert!(
        reply
            .status
            .detail
            .contains("ProtocolsConfigureEncryptionPolicyImmutable"),
        "{}",
        reply.status.detail
    );
}

// Covers: DWN-PROTO-001, DWN-PROTO-004
#[tokio::test]
async fn protocols_configure_rejects_historical_insert_contradicting_records() {
    let (configures, writes, _) = flip_harness().await;
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T2).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(&writes, FLIP_PROTOCOL, "note", FLIP_MID, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(
        &writes,
        FLIP_PROTOCOL,
        "note",
        FLIP_T4,
        Some(flip_envelope(&flip_key_id(flip_x))),
    )
    .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // Stale plaintext insert: the retained encrypted record contradicts it.
    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T1_5).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert!(
        reply
            .status
            .detail
            .contains("ProtocolsConfigureEncryptionPolicyImmutable"),
        "{}",
        reply.status.detail
    );
}

#[derive(Clone)]
struct FailRecordsQueries {
    inner: MemoryMessageStore,
}

fn is_protocol_records_query(filters: &Filters) -> bool {
    filters.set.iter().any(|entry| {
        let is_write = matches!(
            entry.get(&FilterKey::Index("method".to_string())),
            Some(Filter::Equal(Value::String(method))) if method == "Write"
        );
        let has_protocol = entry
            .keys()
            .any(|key| matches!(key, FilterKey::Index(name) if name == "protocol"));
        is_write && has_protocol
    })
}

impl MessageStore for FailRecordsQueries {
    async fn open(&mut self) -> Result<(), crate::errors::MessageStoreError> {
        self.inner.open().await
    }

    async fn close(&mut self) {
        self.inner.close().await
    }

    fn put<D: crate::descriptors::MessageDescriptor + Send>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), crate::errors::MessageStoreError>> + Send
    where
        Message<Descriptor>: From<Message<D>>,
    {
        self.inner.put(tenant, message, indexes)
    }

    async fn commit_latest_state(
        &self,
        tenant: &str,
        transition: LatestStateTransition,
    ) -> Result<LatestStateTransitionResult, crate::errors::MessageStoreError> {
        self.inner.commit_latest_state(tenant, transition).await
    }

    async fn get(
        &self,
        tenant: &str,
        cid: &str,
    ) -> Result<Option<Message<Descriptor>>, crate::errors::MessageStoreError> {
        self.inner.get(tenant, cid).await
    }

    fn query(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
        pagination: Option<Pagination>,
        record_limit: Option<RecordLimitOccupancy>,
    ) -> impl Future<Output = Result<MessageQueryResult, crate::errors::MessageStoreError>> + Send
    {
        let inner = self.inner.clone();
        let tenant = tenant.to_string();
        async move {
            if is_protocol_records_query(&filters) {
                return Err(crate::errors::MessageStoreError::StoreError(
                    crate::errors::StoreError::InternalException(
                        "injected records query failure".to_string(),
                    ),
                ));
            }
            inner
                .query(&tenant, filters, sort, pagination, record_limit)
                .await
        }
    }

    async fn count(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
        record_limit: Option<RecordLimitOccupancy>,
    ) -> Result<u64, crate::errors::MessageStoreError> {
        self.inner.count(tenant, filters, sort, record_limit).await
    }

    async fn delete(
        &self,
        tenant: &str,
        cid: &str,
    ) -> Result<(), crate::errors::MessageStoreError> {
        self.inner.delete(tenant, cid).await
    }

    async fn clear(&self) -> Result<(), crate::errors::MessageStoreError> {
        self.inner.clear().await
    }
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn protocols_configure_scan_failure_fails_closed() {
    let mut inner = MemoryMessageStore::default();
    inner.open().await.unwrap();
    let store = FailRecordsQueries { inner };
    let configures = ProtocolsConfigureHandler::new(store.clone(), Some(Arc::new(test_resolver())));
    let writes = RecordsWriteHandler::new(
        store.clone(),
        StubDataStore::default(),
        Some(Arc::new(test_resolver())),
    );
    let flip_x = "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc";

    let reply = run_flip_configure(&configures, flip_plain(), FLIP_T1).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = admit_flip_record(&writes, FLIP_PROTOCOL, "note", FLIP_MID, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = run_flip_configure(&configures, flip_keyed(true, flip_x), FLIP_T2).await;
    assert_eq!(reply.status.code, 500, "{}", reply.status.detail);
}

/// Placements of the reserved `$encryption` namespace, each with the detail it
/// must report. The `types` and root-`structure` cases share a key name, so the
/// expected wording is what keeps them from proving the same thing twice.
const RESERVED_NAMESPACE_PLACEMENTS: [(&str, &str); 4] = [
    ("types", "protocol type '$encryption'"),
    ("root", "protocol structure path '$encryption'"),
    ("nested", "protocol structure path 'thread/$encryption'"),
    // Deeper than the protocol's own 10-level nesting rule. The scan carries no
    // depth limit of its own, so the reservation is still named rather than
    // falling through to an anonymous schema failure.
    (
        "deep",
        "protocol structure path 'thread/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/d11/$encryption'",
    ),
];

fn definition_with_reserved_namespace(placement: &str) -> serde_json::Value {
    let mut definition = serde_json::json!({
        "protocol": "http://example.com/protocol",
        "published": true,
        "types": { "thread": {} },
        "structure": { "thread": {} }
    });
    match placement {
        "types" => definition["types"]["$encryption"] = serde_json::json!({}),
        "root" => definition["structure"]["$encryption"] = serde_json::json!({}),
        "nested" => definition["structure"]["thread"]["$encryption"] = serde_json::json!({}),
        "deep" => {
            let mut branch = &mut definition["structure"]["thread"];
            for level in 1..=11 {
                branch[format!("d{level}")] = serde_json::json!({});
                branch = &mut branch[format!("d{level}")];
            }
            branch["$encryption"] = serde_json::json!({});
        }
        other => panic!("unknown placement {other}"),
    }
    definition
}

fn configure_message_with_raw_definition(definition: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "descriptor": {
            "interface": "Protocols",
            "method": "Configure",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z",
            "definition": definition
        },
        "authorization": {
            "signature": { "payload": "", "signatures": [] }
        }
    })
}

// Covers: ENBOX-ENC-001
// The parsing route. `$encryption` is reserved for control
// records, so a definition may never declare it — as a type, as a root
// structure entry, or nested at any depth.
#[test]
fn reserved_encryption_namespace_is_named_before_schema_validation() {
    for (placement, expected_detail) in RESERVED_NAMESPACE_PLACEMENTS {
        let message =
            configure_message_with_raw_definition(definition_with_reserved_namespace(placement));

        let error = crate::validation::admit_message(&message)
            .expect_err("reserved namespace must be rejected");
        assert_eq!(
            error.code,
            crate::errors::DwnErrorCode::ProtocolsConfigureReservedEncryptionControlPath,
            "{placement} placement must name the reservation, got: {error}"
        );
        assert!(
            error.detail.contains(expected_detail),
            "{placement} placement must report \"{expected_detail}\", got: {}",
            error.detail
        );

        // The ordering is the point. Schema validation rejects every
        // `$`-prefixed key anonymously, so running it first would bury the
        // reservation under a generic failure.
        let schema_only = crate::validation::validate_message(&message)
            .expect_err("schema also rejects the reserved key");
        assert_eq!(
            schema_only.code,
            crate::errors::DwnErrorCode::SchemaValidatorFailure,
            "{placement} placement should otherwise surface only a schema failure"
        );
    }
}

// Covers: ENBOX-ENC-001
// The construction route. `RuleSet` absorbs unknown keys via
// `#[serde(flatten)]`, so a locally built definition can carry the reserved
// namespace without ever being parsed from the wire.
#[tokio::test]
async fn reserved_encryption_namespace_is_rejected_during_construction() {
    use crate::descriptors::MessageParameters;

    for (placement, expected_detail) in RESERVED_NAMESPACE_PLACEMENTS {
        let definition: Definition =
            serde_json::from_value(definition_with_reserved_namespace(placement))
                .expect("definition fixture must deserialize");

        let error = crate::descriptors::protocols::ConfigureParameters {
            message_timestamp: None,
            definition,
            permission_grant_id: None,
            delegated_grant: None,
        }
        .build()
        .await
        .expect_err("reserved namespace must not build");

        assert!(
            error
                .message
                .contains("ProtocolsConfigureReservedEncryptionControlPath"),
            "{placement} placement must name the reservation, got: {}",
            error.message
        );
        assert!(
            error.message.contains(expected_detail),
            "{placement} placement must report \"{expected_detail}\", got: {}",
            error.message
        );
    }
}

// Covers: ENBOX-ENC-001
// Why the reserved-namespace scan takes raw JSON rather than a typed
// `Definition`: when the reserved entry's *value* is malformed, the definition
// cannot be constructed at all, so a typed scan would never see the key it
// exists to reject and the reservation would fall through to an anonymous
// schema failure.
#[test]
fn reserved_namespace_is_named_even_when_the_definition_cannot_be_typed() {
    let untypeable = [
        (
            "reserved structure entry holding a non-rule-set",
            serde_json::json!({
                "protocol": "http://example.com/protocol", "published": true,
                "types": { "thread": {} },
                "structure": { "thread": { "$encryption": "garbage" } }
            }),
        ),
        (
            "reserved type holding a non-type",
            serde_json::json!({
                "protocol": "http://example.com/protocol", "published": true,
                "types": { "$encryption": 42 },
                "structure": { "thread": {} }
            }),
        ),
    ];

    for (label, raw) in untypeable {
        assert!(
            serde_json::from_value::<Definition>(raw.clone()).is_err(),
            "{label} must be untypeable, or this test proves nothing"
        );
        let error = crate::protocols::validate_reserved_control_namespace(&raw)
            .expect_err("reserved namespace must still be named");
        assert_eq!(
            error.code,
            crate::errors::DwnErrorCode::ProtocolsConfigureReservedEncryptionControlPath,
            "{label} must name the reservation, got: {error}"
        );
    }
}
