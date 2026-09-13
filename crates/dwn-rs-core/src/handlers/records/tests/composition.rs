//! Cross-protocol composition runtime: parent resolution and verification.
//!
//! A composing protocol references a base protocol through `$ref`. Runtime
//! admission must resolve every parent-bearing write in the protocol the
//! composing structure names, then require the declared path and context to
//! extend exactly that parent's (`DWN-PROTO-001`, `DWN-PROTO-005`).

use super::*;
use crate::descriptors::{
    DeleteDescriptor as RecordsDeleteDescriptor, ReadDescriptor as RecordsReadDescriptor,
    RecordsQueryDescriptor,
};
use crate::protocols::{Action, ActionRole, ActionWho, Can, ProtocolKeyAgreement, Who};

const TENANT: &str = "did:example:alice";
const BOB: &str = "did:example:bob";
const THREADS: &str = "https://threads.example.com";
const COMMENTS: &str = "https://comments.example.com";
const INSTALL: &str = "2024-12-31T00:00:00.000000Z";

const TS_THREAD: &str = "2025-01-01T00:00:00.000000Z";
const TS_ROLE: &str = "2025-01-01T00:00:30.000000Z";
const TS_COMMENT: &str = "2025-01-01T00:01:00.000000Z";
const TS_REACTION: &str = "2025-01-01T00:02:00.000000Z";

fn text_type() -> crate::protocols::Type {
    crate::protocols::Type {
        schema: None,
        data_formats: None,
        encryption_required: None,
    }
}

fn threads_definition() -> Definition {
    threads_definition_with_participant_role(true)
}

fn threads_definition_with_participant_role(participant_role: bool) -> Definition {
    Definition {
        protocol: THREADS.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([
            ("thread".to_string(), text_type()),
            ("participant".to_string(), text_type()),
            ("message".to_string(), text_type()),
        ]),
        structure: BTreeMap::from([(
            "thread".to_string(),
            RuleSet {
                actions: vec![Action::Who(ActionWho {
                    who: Who::Anyone,
                    of: None,
                    can: vec![Can::Create, Can::Read],
                })],
                rules: BTreeMap::from([
                    (
                        "participant".to_string(),
                        RuleSet {
                            role: participant_role.then_some(true),
                            actions: vec![
                                Action::Who(ActionWho {
                                    who: Who::Anyone,
                                    of: None,
                                    can: vec![Can::Read],
                                }),
                                Action::Who(ActionWho {
                                    who: Who::Author,
                                    of: Some("thread".to_string()),
                                    can: vec![Can::Create],
                                }),
                            ],
                            ..Default::default()
                        },
                    ),
                    (
                        "message".to_string(),
                        RuleSet {
                            actions: vec![Action::Role(ActionRole {
                                role: "thread/participant".to_string(),
                                can: vec![Can::Create, Can::Read],
                            })],
                            rules: BTreeMap::from([(
                                "participant".to_string(),
                                RuleSet {
                                    role: Some(true),
                                    ..Default::default()
                                },
                            )]),
                            ..Default::default()
                        },
                    ),
                ]),
                ..Default::default()
            },
        )]),
    }
}

fn comments_definition() -> Definition {
    Definition {
        protocol: COMMENTS.to_string(),
        published: true,
        uses: Some(BTreeMap::from([(
            "threads".to_string(),
            THREADS.to_string(),
        )])),
        key_agreement: None,
        types: BTreeMap::from([
            ("comment".to_string(), text_type()),
            ("reaction".to_string(), text_type()),
        ]),
        structure: BTreeMap::from([(
            "thread".to_string(),
            RuleSet {
                reference: Some("threads:thread".to_string()),
                rules: BTreeMap::from([(
                    "comment".to_string(),
                    RuleSet {
                        actions: vec![
                            Action::Who(ActionWho {
                                who: Who::Anyone,
                                of: None,
                                can: vec![Can::Create, Can::Read],
                            }),
                            Action::Role(ActionRole {
                                role: "threads:thread/participant".to_string(),
                                can: vec![Can::Read, Can::CoDelete, Can::CoUpdate],
                            }),
                        ],
                        rules: BTreeMap::from([(
                            "reaction".to_string(),
                            RuleSet {
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
                ..Default::default()
            },
        )]),
    }
}

struct CompositionFixture {
    message_store: TestMessageStore,
    write_handler: RecordsWriteHandler<TestMessageStore, TestDataStore>,
    delete_handler: RecordsDeleteHandler<TestMessageStore, TestDataStore>,
    read_handler: RecordsReadHandler<TestMessageStore, TestDataStore>,
    query_handler: RecordsQueryHandler<TestMessageStore>,
}

async fn composition_fixture() -> CompositionFixture {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_protocol_definition(TENANT, &message_store, threads_definition(), INSTALL).await;
    put_protocol_definition(TENANT, &message_store, comments_definition(), INSTALL).await;
    let write_handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let delete_handler = RecordsDeleteHandler::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let read_handler = RecordsReadHandler::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let query_handler =
        RecordsQueryHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    CompositionFixture {
        message_store,
        write_handler,
        delete_handler,
        read_handler,
        query_handler,
    }
}

/// Builds a data-bearing signed write. `parent` is the `(recordId, contextId)`
/// of the intended parent.
async fn write_record(
    protocol: &str,
    protocol_path: &str,
    timestamp: &str,
    parent: Option<(&str, &str)>,
    data: &'static [u8],
) -> (serde_json::Value, Bytes) {
    let bytes = Bytes::from_static(data);
    let data_cid = generate_dag_pb_cid_from_bytes(&bytes).to_string();
    let (parent_id, parent_context_id) = match parent {
        Some((record_id, context_id)) => {
            (Some(record_id.to_string()), Some(context_id.to_string()))
        }
        None => (None, None),
    };
    let message = signed_write_message(WriteSpec {
        protocol: protocol.to_string(),
        protocol_path: protocol_path.to_string(),
        parent_id,
        parent_context_id,
        data_cid,
        data_size: bytes.len() as u64,
        ..WriteSpec::new(timestamp)
    })
    .await;
    (message, bytes)
}

async fn seed_thread(fixture: &CompositionFixture, timestamp: &str) -> (String, String) {
    let (message, data) = write_record(THREADS, "thread", timestamp, None, b"thread").await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    (
        message["recordId"].as_str().unwrap().to_string(),
        message["contextId"].as_str().unwrap().to_string(),
    )
}

fn record_id(message: &serde_json::Value) -> String {
    message["recordId"].as_str().unwrap().to_string()
}

fn context_id(message: &serde_json::Value) -> String {
    message["contextId"].as_str().unwrap().to_string()
}

fn parsed(message: &serde_json::Value) -> Message<Descriptor> {
    crate::validation::parse_message(message).unwrap()
}

/// Writes a threads `thread/participant` role record assigning `recipient`.
async fn grant_participant(
    fixture: &CompositionFixture,
    thread: (&str, &str),
    recipient: &str,
    timestamp: &str,
) -> String {
    let bytes = Bytes::from_static(b"role");
    let message = signed_write_message(WriteSpec {
        protocol: THREADS.to_string(),
        protocol_path: "thread/participant".to_string(),
        parent_id: Some(thread.0.to_string()),
        parent_context_id: Some(thread.1.to_string()),
        recipient: Some(recipient.to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        ..WriteSpec::new(timestamp)
    })
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(bytes))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    record_id(&message)
}

/// Writes a comments `thread/comment` as the tenant and returns its
/// `(recordId, contextId)`.
async fn seed_comment(
    fixture: &CompositionFixture,
    thread: (&str, &str),
    timestamp: &str,
) -> (String, String) {
    let (message, data) = write_record(
        COMMENTS,
        "thread/comment",
        timestamp,
        Some(thread),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    (record_id(&message), context_id(&message))
}

/// A non-tenant create under `parent`, invoking `role`.
async fn bob_create(
    protocol: &str,
    protocol_path: &str,
    parent: (&str, &str),
    role: &str,
    timestamp: &str,
    data: &'static [u8],
) -> (serde_json::Value, Bytes) {
    let bytes = Bytes::from_static(data);
    let message = signed_write_message(WriteSpec {
        author: BOB.to_string(),
        signer: bob_signer(),
        protocol: protocol.to_string(),
        protocol_path: protocol_path.to_string(),
        parent_id: Some(parent.0.to_string()),
        parent_context_id: Some(parent.1.to_string()),
        protocol_role: Some(role.to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        ..WriteSpec::new(timestamp)
    })
    .await;
    (message, bytes)
}

/// A non-tenant update of an existing record, invoking `role`.
#[allow(clippy::too_many_arguments)]
async fn bob_update(
    protocol: &str,
    protocol_path: &str,
    record_id: &str,
    context_id: &str,
    parent_id: &str,
    date_created: &str,
    role: &str,
    timestamp: &str,
) -> (serde_json::Value, Bytes) {
    let bytes = Bytes::from_static(b"updated");
    let message = signed_write_message(WriteSpec {
        author: BOB.to_string(),
        signer: bob_signer(),
        protocol: protocol.to_string(),
        protocol_path: protocol_path.to_string(),
        record_id: Some(record_id.to_string()),
        context_id: Some(context_id.to_string()),
        parent_id: Some(parent_id.to_string()),
        date_created: date_created.to_string(),
        protocol_role: Some(role.to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        ..WriteSpec::new(timestamp)
    })
    .await;
    (message, bytes)
}

async fn bob_read(record_id: &str, role: &str, timestamp: &str) -> serde_json::Value {
    let descriptor = RecordsReadDescriptor {
        message_timestamp: parse_time(timestamp),
        filter: crate::filters::Records {
            record_id: Some(record_id.to_string()),
            ..Default::default()
        },
        permission_grant_id: None,
        date_sort: None,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(
        &descriptor_json,
        json!({ "protocolRole": role }),
        bob_signer(),
    )
    .await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

async fn bob_delete(record_id: &str, role: &str, timestamp: &str) -> serde_json::Value {
    let descriptor = RecordsDeleteDescriptor {
        message_timestamp: parse_time(timestamp),
        record_id: record_id.to_string(),
        prune: false,
        permission_grant_id: None,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(
        &descriptor_json,
        json!({ "protocolRole": role }),
        bob_signer(),
    )
    .await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

async fn bob_query(
    protocol: &str,
    protocol_path: &str,
    context_id: Option<&str>,
    role: &str,
    timestamp: &str,
) -> serde_json::Value {
    let descriptor = RecordsQueryDescriptor {
        message_timestamp: parse_time(timestamp),
        filter: crate::filters::Records {
            protocol: Some(protocol.to_string()),
            protocol_path: Some(protocol_path.to_string()),
            context_id: context_id.map(str::to_string),
            ..Default::default()
        },
        pagination: None,
        permission_grant_id: None,
        date_sort: None,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(
        &descriptor_json,
        json!({ "protocolRole": role }),
        bob_signer(),
    )
    .await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

// Covers: DWN-PROTO-005
#[tokio::test]
async fn cross_protocol_child_is_admitted_under_referenced_parent() {
    let fixture = composition_fixture().await;
    let (thread_id, thread_ctx) = seed_thread(&fixture, TS_THREAD).await;

    let (comment, data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&thread_id, &thread_ctx)),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-005
#[tokio::test]
async fn composed_grandchild_resolves_parent_in_composing_protocol() {
    let fixture = composition_fixture().await;
    let (thread_id, thread_ctx) = seed_thread(&fixture, TS_THREAD).await;

    let (comment, comment_data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&thread_id, &thread_ctx)),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(comment_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (reaction, data) = write_record(
        COMMENTS,
        "thread/comment/reaction",
        TS_REACTION,
        Some((&record_id(&comment), &context_id(&comment))),
        b"reaction",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &reaction, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-SYNC-003
#[tokio::test]
async fn missing_cross_protocol_parent_is_repairable() {
    let fixture = composition_fixture().await;

    let (comment, data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some(("missing-thread", "missing-context")),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationCrossProtocolParentNotFound")
    );
    assert_eq!(
        classify_apply_reply(&reply.status, &parsed(&comment), false),
        ReplicationApplyOutcome::Incomplete
    );
}

// Covers: DWN-SYNC-003
#[tokio::test]
async fn missing_local_parent_is_repairable() {
    let fixture = composition_fixture().await;

    let (message, data) = write_record(
        THREADS,
        "thread/message",
        TS_COMMENT,
        Some(("missing-thread", "missing-context")),
        b"message",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationParentRecordNotFound")
    );
    assert_eq!(
        classify_apply_reply(&reply.status, &parsed(&message), false),
        ReplicationApplyOutcome::Incomplete
    );
}

// Covers: DWN-PROTO-005
#[tokio::test]
async fn parent_with_matching_id_in_composing_protocol_does_not_satisfy_cross_protocol_child() {
    let fixture = composition_fixture().await;

    // A record at the `$ref` attachment point is written under the composing
    // protocol; a child of the referenced protocol must not accept it.
    let (ref_record, ref_data) = write_record(COMMENTS, "thread", TS_THREAD, None, b"thread").await;
    let reply = fixture
        .write_handler
        .run(TENANT, &ref_record, Some(ref_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (comment, data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&record_id(&ref_record), &context_id(&ref_record))),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationCrossProtocolParentNotFound")
    );
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn parent_path_must_be_the_declared_parent_segment() {
    let fixture = composition_fixture().await;
    let (thread_id, thread_ctx) = seed_thread(&fixture, TS_THREAD).await;

    // A deeper threads record; the child expects the local key `thread`, not
    // this parent's `thread/message` path.
    let (message, message_data) = write_record(
        THREADS,
        "thread/message",
        TS_COMMENT,
        Some((&thread_id, &thread_ctx)),
        b"message",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(message_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (comment, data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_REACTION,
        Some((&record_id(&message), &context_id(&message))),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationIncorrectProtocolPath")
    );
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn context_id_must_equal_parent_context_plus_record_id() {
    let fixture = composition_fixture().await;
    let (thread_id, thread_ctx) = seed_thread(&fixture, TS_THREAD).await;

    let (comment, data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&thread_id, &format!("{thread_ctx}/x"))),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationIncorrectContextId")
    );
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn parentless_nested_path_is_rejected() {
    let fixture = composition_fixture().await;

    let (comment, data) =
        write_record(COMMENTS, "thread/comment", TS_COMMENT, None, b"comment").await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationParentlessIncorrectProtocolPath")
    );
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn retained_initial_write_proves_a_dataless_parent() {
    let fixture = composition_fixture().await;

    // A dataless initial write has no latest-base-state write; the retained
    // initial write still names the parent.
    let thread = signed_write_message(WriteSpec {
        protocol: THREADS.to_string(),
        protocol_path: "thread".to_string(),
        ..WriteSpec::new(TS_THREAD)
    })
    .await;
    let reply = fixture.write_handler.run(TENANT, &thread, None).await;
    assert!(
        matches!(reply.status.code, 202 | 204),
        "{}",
        reply.status.detail
    );

    let (comment, data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&record_id(&thread), &context_id(&thread))),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn deleted_parent_is_not_found() {
    let fixture = composition_fixture().await;
    let (thread_id, thread_ctx) = seed_thread(&fixture, TS_THREAD).await;

    let delete = signed_delete_message(&thread_id, false, TS_COMMENT).await;
    let reply = fixture.delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (comment, data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_REACTION,
        Some((&thread_id, &thread_ctx)),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationCrossProtocolParentNotFound")
    );
}

// Covers: DWN-REC-004, DWN-SYNC-003
#[tokio::test]
async fn child_before_parent_converges_once_parent_arrives() {
    let (thread, thread_data) = write_record(THREADS, "thread", TS_THREAD, None, b"thread").await;
    let thread_id = record_id(&thread);
    let thread_ctx = context_id(&thread);
    let (comment, comment_data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&thread_id, &thread_ctx)),
        b"comment",
    )
    .await;

    // Parent-first order.
    let parent_first = composition_fixture().await;
    let reply = parent_first
        .write_handler
        .run(TENANT, &thread, Some(thread_data.clone()))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let reply = parent_first
        .write_handler
        .run(TENANT, &comment, Some(comment_data.clone()))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let expected = state_cids(&parent_first, &record_id(&comment)).await;

    // Child-first order: the same message is incomplete until the parent lands.
    let child_first = composition_fixture().await;
    let reply = child_first
        .write_handler
        .run(TENANT, &comment, Some(comment_data.clone()))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        classify_apply_reply(&reply.status, &parsed(&comment), false),
        ReplicationApplyOutcome::Incomplete
    );
    assert!(state_cids(&child_first, &record_id(&comment))
        .await
        .is_empty());

    let reply = child_first
        .write_handler
        .run(TENANT, &thread, Some(thread_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = child_first
        .write_handler
        .run(TENANT, &comment, Some(comment_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    assert_eq!(
        state_cids(&child_first, &record_id(&comment)).await,
        expected
    );
}

async fn state_cids(fixture: &CompositionFixture, record_id: &str) -> Vec<String> {
    let mut cids: Vec<String> = fetch_record_messages(TENANT, record_id, &fixture.message_store)
        .await
        .unwrap()
        .into_iter()
        .map(|message| message_cid(&message).unwrap())
        .collect();
    cids.sort();
    cids
}

const PARTICIPANT: &str = "threads:thread/participant";

// Covers: DWN-PROTO-002, DWN-PROTO-005
#[tokio::test]
async fn cross_protocol_role_authorizes_read_and_co_delete() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    grant_participant(&fixture, (&thread.0, &thread.1), BOB, TS_ROLE).await;
    let (comment_id, _) = seed_comment(&fixture, (&thread.0, &thread.1), TS_COMMENT).await;

    let read = bob_read(&comment_id, PARTICIPANT, TS_REACTION).await;
    let reply = fixture.read_handler.run(TENANT, &read, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);

    let delete = bob_delete(&comment_id, PARTICIPANT, TS_REACTION).await;
    let reply = fixture.delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-002, DWN-PROTO-005
#[tokio::test]
async fn cross_protocol_role_authorizes_query_and_co_update() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    grant_participant(&fixture, (&thread.0, &thread.1), BOB, TS_ROLE).await;
    let (comment_id, comment_ctx) =
        seed_comment(&fixture, (&thread.0, &thread.1), TS_COMMENT).await;

    let query = bob_query(
        COMMENTS,
        "thread/comment",
        Some(&thread.1),
        PARTICIPANT,
        TS_REACTION,
    )
    .await;
    let reply = fixture.query_handler.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);

    let (update, update_data) = bob_update(
        COMMENTS,
        "thread/comment",
        &comment_id,
        &comment_ctx,
        &thread.0,
        TS_COMMENT,
        PARTICIPANT,
        TS_REACTION,
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &update, Some(update_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-002, DWN-SYNC-003
#[tokio::test]
async fn cross_protocol_role_holder_without_record_is_repairable() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;

    let (message, data) = bob_create(
        COMMENTS,
        "thread/comment",
        (&thread.0, &thread.1),
        PARTICIPANT,
        TS_COMMENT,
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationMatchingRoleRecordNotFound")
    );
    assert_eq!(
        classify_apply_reply(&reply.status, &parsed(&message), false),
        ReplicationApplyOutcome::Incomplete
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn cross_protocol_role_in_sibling_context_does_not_authorize() {
    let fixture = composition_fixture().await;
    let first = seed_thread(&fixture, TS_THREAD).await;
    let second = seed_thread(&fixture, "2025-01-01T00:00:20.000000Z").await;
    grant_participant(&fixture, (&first.0, &first.1), BOB, TS_ROLE).await;

    let (message, data) = bob_create(
        COMMENTS,
        "thread/comment",
        (&second.0, &second.1),
        PARTICIPANT,
        TS_COMMENT,
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationMatchingRoleRecordNotFound")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn cross_protocol_role_revocation_denies() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    let role_id = grant_participant(&fixture, (&thread.0, &thread.1), BOB, TS_ROLE).await;

    let delete = signed_delete_message(&role_id, false, "2025-01-01T00:00:40.000000Z").await;
    let reply = fixture.delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (message, data) = bob_create(
        COMMENTS,
        "thread/comment",
        (&thread.0, &thread.1),
        PARTICIPANT,
        TS_COMMENT,
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationMatchingRoleRecordNotFound")
    );
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn cross_protocol_role_removed_from_referenced_definition_denies() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    grant_participant(&fixture, (&thread.0, &thread.1), BOB, TS_ROLE).await;
    put_protocol_definition(
        TENANT,
        &fixture.message_store,
        threads_definition_with_participant_role(false),
        "2025-01-01T00:00:40.000000Z",
    )
    .await;

    let (message, data) = bob_create(
        COMMENTS,
        "thread/comment",
        (&thread.0, &thread.1),
        PARTICIPANT,
        TS_COMMENT,
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationNotARole")
    );
}

// Covers: DWN-PROTO-005
#[tokio::test]
async fn unknown_cross_protocol_role_alias_denies() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;

    let (message, data) = bob_create(
        COMMENTS,
        "thread/comment",
        (&thread.0, &thread.1),
        "nope:thread/participant",
        TS_COMMENT,
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationNotARole")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn cross_protocol_nested_role_query_without_context_denies() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    grant_participant(&fixture, (&thread.0, &thread.1), BOB, TS_ROLE).await;

    let query = bob_query(COMMENTS, "thread", None, PARTICIPANT, TS_COMMENT).await;
    let reply = fixture.query_handler.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationMissingContextId")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn deep_cross_protocol_role_query_with_short_context_denies() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    grant_participant(&fixture, (&thread.0, &thread.1), BOB, TS_ROLE).await;

    let query = bob_query(
        COMMENTS,
        "thread/comment",
        Some("one-segment"),
        "threads:thread/message/participant",
        TS_COMMENT,
    )
    .await;
    let reply = fixture.query_handler.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationMissingContextId")
    );
}

// Covers: DWN-SYNC-003
#[tokio::test]
async fn referenced_definition_absent_is_repairable() {
    // Only the composing protocol is installed; the `$ref` target is missing.
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_protocol_definition(TENANT, &message_store, comments_definition(), INSTALL).await;
    let write_handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let (message, data) = write_record(COMMENTS, "thread", TS_THREAD, None, b"thread").await;
    let reply = write_handler.run(TENANT, &message, Some(data)).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationProtocolNotFound")
    );
    assert_eq!(
        classify_apply_reply(&reply.status, &parsed(&message), false),
        ReplicationApplyOutcome::Incomplete
    );
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn non_tenant_write_at_ref_position_is_unauthorized() {
    let fixture = composition_fixture().await;
    let bytes = Bytes::from_static(b"thread");
    let message = signed_write_message(WriteSpec {
        author: BOB.to_string(),
        signer: bob_signer(),
        protocol: COMMENTS.to_string(),
        protocol_path: "thread".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        ..WriteSpec::new(TS_COMMENT)
    })
    .await;
    // The `$ref` node carries no actions, so a non-tenant write is denied.
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(bytes))
        .await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-005
#[tokio::test]
async fn multi_segment_ref_target_makes_children_unattachable() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_protocol_definition(TENANT, &message_store, threads_definition(), INSTALL).await;
    let mut comments = comments_definition();
    comments.structure.insert(
        "thread".to_string(),
        RuleSet {
            reference: Some("threads:thread/participant".to_string()),
            rules: BTreeMap::from([(
                "comment".to_string(),
                RuleSet {
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
    );
    put_protocol_definition(TENANT, &message_store, comments, INSTALL).await;
    let write_handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    // A parent at the referenced target path `thread/participant`.
    let (thread, thread_data) = write_record(THREADS, "thread", TS_THREAD, None, b"thread").await;
    assert_eq!(
        write_handler
            .run(TENANT, &thread, Some(thread_data))
            .await
            .status
            .code,
        202
    );
    let (participant, participant_data) = write_record(
        THREADS,
        "thread/participant",
        TS_ROLE,
        Some((&record_id(&thread), &context_id(&thread))),
        b"role",
    )
    .await;
    assert_eq!(
        write_handler
            .run(TENANT, &participant, Some(participant_data))
            .await
            .status
            .code,
        202
    );

    let (comment, data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&record_id(&participant), &context_id(&participant))),
        b"comment",
    )
    .await;
    let reply = write_handler.run(TENANT, &comment, Some(data)).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationIncorrectProtocolPath")
    );
}

/// The threads fixture with an encrypted `thread` type and key agreement.
fn encrypted_threads_definition() -> Definition {
    let mut definition = threads_definition();
    definition
        .types
        .get_mut("thread")
        .expect("thread type")
        .encryption_required = Some(true);
    definition
        .structure
        .get_mut("thread")
        .expect("thread rule")
        .key_agreement = Some(ProtocolKeyAgreement {
        public_key_jwk: path_key_jwk(),
    });
    definition
}

/// The comments fixture with an encrypted `comment` type and key agreement.
fn encrypted_comments_definition() -> Definition {
    let mut definition = comments_definition();
    definition
        .types
        .get_mut("comment")
        .expect("comment type")
        .encryption_required = Some(true);
    definition
        .structure
        .get_mut("thread")
        .expect("thread rule")
        .rules
        .get_mut("comment")
        .expect("comment rule")
        .key_agreement = Some(ProtocolKeyAgreement {
        public_key_jwk: path_key_jwk(),
    });
    definition
}

async fn encrypted_write(
    protocol: &str,
    protocol_path: &str,
    timestamp: &str,
    parent: Option<(&str, &str)>,
    data: &'static [u8],
) -> (serde_json::Value, Bytes) {
    let bytes = Bytes::from_static(data);
    let envelope = envelope_with_entries(vec![protocol_path_entry(&path_key_id())]);
    let (parent_id, parent_context_id) = match parent {
        Some((record_id, context_id)) => {
            (Some(record_id.to_string()), Some(context_id.to_string()))
        }
        None => (None, None),
    };
    let message = signed_write_message(WriteSpec {
        protocol: protocol.to_string(),
        protocol_path: protocol_path.to_string(),
        parent_id,
        parent_context_id,
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        encryption: Some(envelope),
        ..WriteSpec::new(timestamp)
    })
    .await;
    (message, bytes)
}

// Covers: DWN-PROTO-005, DWN-PROTO-006, DWN-REC-004
#[tokio::test]
async fn encrypted_referenced_parent_admits_encrypted_composing_child() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_protocol_definition(
        TENANT,
        &message_store,
        encrypted_threads_definition(),
        INSTALL,
    )
    .await;
    put_protocol_definition(
        TENANT,
        &message_store,
        encrypted_comments_definition(),
        INSTALL,
    )
    .await;
    let write_handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let (thread, thread_data) =
        encrypted_write(THREADS, "thread", TS_THREAD, None, b"thread").await;
    let thread_id = record_id(&thread);
    let thread_ctx = context_id(&thread);
    let (comment, comment_data) = encrypted_write(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&thread_id, &thread_ctx)),
        b"comment",
    )
    .await;

    // Parent-first order admits both.
    assert_eq!(
        write_handler
            .run(TENANT, &thread, Some(thread_data.clone()))
            .await
            .status
            .code,
        202
    );
    assert_eq!(
        write_handler
            .run(TENANT, &comment, Some(comment_data.clone()))
            .await
            .status
            .code,
        202
    );

    // Child-first order: the child is repairable once the parent arrives.
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_protocol_definition(
        TENANT,
        &message_store,
        encrypted_threads_definition(),
        INSTALL,
    )
    .await;
    put_protocol_definition(
        TENANT,
        &message_store,
        encrypted_comments_definition(),
        INSTALL,
    )
    .await;
    let child_first = RecordsWriteHandler::<_, _>::new(
        message_store,
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let reply = child_first.run(TENANT, &comment, Some(comment_data)).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        classify_apply_reply(&reply.status, &parsed(&comment), false),
        ReplicationApplyOutcome::Incomplete
    );
    assert_eq!(
        child_first
            .run(TENANT, &thread, Some(thread_data))
            .await
            .status
            .code,
        202
    );
    let (retry, retry_data) = encrypted_write(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&thread_id, &thread_ctx)),
        b"comment",
    )
    .await;
    assert_eq!(
        child_first
            .run(TENANT, &retry, Some(retry_data))
            .await
            .status
            .code,
        202
    );
}

async fn owner_query(protocol: &str, timestamp: &str) -> serde_json::Value {
    let descriptor = RecordsQueryDescriptor {
        message_timestamp: parse_time(timestamp),
        filter: crate::filters::Records {
            protocol: Some(protocol.to_string()),
            ..Default::default()
        },
        pagination: None,
        permission_grant_id: None,
        date_sort: None,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(&descriptor_json, json!({}), test_signer()).await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn query_result_is_isolated_to_the_queried_protocol() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    seed_comment(&fixture, (&thread.0, &thread.1), TS_COMMENT).await;

    let query = owner_query(COMMENTS, TS_REACTION).await;
    let reply = fixture.query_handler.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    let entries = reply.reply.entries.unwrap_or_default();
    assert_eq!(
        entries.len(),
        1,
        "comments query must not return thread records"
    );
    assert_eq!(
        crate::descriptors::records::records_write_descriptor(&entries[0].message)
            .unwrap()
            .protocol,
        COMMENTS,
        "comments query returned a foreign protocol record"
    );

    let query = owner_query(THREADS, TS_REACTION).await;
    let reply = fixture.query_handler.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    let entries = reply.reply.entries.unwrap_or_default();
    assert_eq!(
        entries.len(),
        1,
        "threads query must not return comment records"
    );
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn composing_upgrade_adds_a_child_type() {
    // V1 has no `reaction` rule.
    let mut comments_v1 = comments_definition();
    comments_v1
        .structure
        .get_mut("thread")
        .unwrap()
        .rules
        .get_mut("comment")
        .unwrap()
        .rules
        .remove("reaction");

    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_protocol_definition(TENANT, &message_store, threads_definition(), INSTALL).await;
    put_protocol_definition(TENANT, &message_store, comments_v1, INSTALL).await;
    let write_handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );

    let (thread, thread_data) = write_record(THREADS, "thread", TS_THREAD, None, b"thread").await;
    assert_eq!(
        write_handler
            .run(TENANT, &thread, Some(thread_data))
            .await
            .status
            .code,
        202
    );
    let (comment, comment_data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_COMMENT,
        Some((&record_id(&thread), &context_id(&thread))),
        b"comment",
    )
    .await;
    assert_eq!(
        write_handler
            .run(TENANT, &comment, Some(comment_data))
            .await
            .status
            .code,
        202
    );

    let (reaction, reaction_data) = write_record(
        COMMENTS,
        "thread/comment/reaction",
        TS_REACTION,
        Some((&record_id(&comment), &context_id(&comment))),
        b"reaction",
    )
    .await;
    let reply = write_handler
        .run(TENANT, &reaction, Some(reaction_data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);

    // V2 adds `reaction`; a later write is admitted, an earlier one is not.
    put_protocol_definition(
        TENANT,
        &message_store,
        comments_definition(),
        "2025-01-01T00:02:30.000000Z",
    )
    .await;
    let (reaction, reaction_data) = write_record(
        COMMENTS,
        "thread/comment/reaction",
        "2025-01-01T00:03:00.000000Z",
        Some((&record_id(&comment), &context_id(&comment))),
        b"reaction",
    )
    .await;
    let reply = write_handler
        .run(TENANT, &reaction, Some(reaction_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-005
#[tokio::test]
async fn pruning_a_referenced_parent_cascades_to_composing_children() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    let (comment_id, _) = seed_comment(&fixture, (&thread.0, &thread.1), TS_COMMENT).await;

    let delete = signed_delete_message(&thread.0, true, TS_REACTION).await;
    let reply = fixture.delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let comments = fetch_record_messages(TENANT, &comment_id, &fixture.message_store)
        .await
        .unwrap();
    assert!(
        comments.is_empty(),
        "pruned parent must purge composing children"
    );
}
