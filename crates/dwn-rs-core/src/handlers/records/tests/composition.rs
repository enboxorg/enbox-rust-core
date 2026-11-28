//! Cross-module composition runtime: parent resolution and verification.
//!
//! A composing module references a base module through `$ref`. Runtime
//! admission must resolve every parent-bearing write in the module the
//! composing structure names, then require the declared path and context to
//! extend exactly that parent's.

use super::*;
use crate::descriptors::{
    DeleteDescriptor as RecordsDeleteDescriptor, ReadDescriptor as RecordsReadDescriptor,
    RecordsQueryDescriptor,
};
use crate::filters::Records as RecordsFilter;
use crate::modules::{Action, ActionRole, ActionWho, Can, ModuleKeyAgreement, Who};
use crate::replies::Status;

const TENANT: &str = "did:example:alice";
const BOB: &str = "did:example:bob";
const THREADS: &str = "https://threads.example.com";
const COMMENTS: &str = "https://comments.example.com";
const INSTALL: &str = "2024-12-31T00:00:00.000000Z";

const TS_THREAD: &str = "2025-01-01T00:00:00.000000Z";
const TS_ROLE: &str = "2025-01-01T00:00:30.000000Z";
const TS_COMMENT: &str = "2025-01-01T00:01:00.000000Z";
const TS_REACTION: &str = "2025-01-01T00:02:00.000000Z";

fn text_type() -> crate::modules::Type {
    crate::modules::Type {
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
        module: THREADS.to_string(),
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
                            actions: if participant_role {
                                vec![Action::Role(ActionRole {
                                    role: "thread/participant".to_string(),
                                    can: vec![Can::Create, Can::Read],
                                })]
                            } else {
                                vec![Action::Who(ActionWho {
                                    who: Who::Anyone,
                                    of: None,
                                    can: vec![Can::Create, Can::Read],
                                })]
                            },
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
        module: COMMENTS.to_string(),
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
    put_module_definition(TENANT, &message_store, threads_definition(), INSTALL).await;
    put_module_definition(TENANT, &message_store, comments_definition(), INSTALL).await;
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
    module: &str,
    module_path: &str,
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
        module: module.to_string(),
        module_path: module_path.to_string(),
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
        module: THREADS.to_string(),
        module_path: "thread/participant".to_string(),
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
    module: &str,
    module_path: &str,
    parent: (&str, &str),
    role: &str,
    timestamp: &str,
    data: &'static [u8],
) -> (serde_json::Value, Bytes) {
    let bytes = Bytes::from_static(data);
    let message = signed_write_message(WriteSpec {
        author: BOB.to_string(),
        signer: bob_signer(),
        module: module.to_string(),
        module_path: module_path.to_string(),
        parent_id: Some(parent.0.to_string()),
        parent_context_id: Some(parent.1.to_string()),
        module_role: Some(role.to_string()),
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
    module: &str,
    module_path: &str,
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
        module: module.to_string(),
        module_path: module_path.to_string(),
        record_id: Some(record_id.to_string()),
        context_id: Some(context_id.to_string()),
        parent_id: Some(parent_id.to_string()),
        date_created: date_created.to_string(),
        module_role: Some(role.to_string()),
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
        include_replication_support: None,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(
        &descriptor_json,
        json!({ "moduleRole": role }),
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
        json!({ "moduleRole": role }),
        bob_signer(),
    )
    .await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

async fn bob_query(
    module: &str,
    module_path: &str,
    context_id: Option<&str>,
    role: &str,
    timestamp: &str,
) -> serde_json::Value {
    let descriptor = RecordsQueryDescriptor {
        message_timestamp: parse_time(timestamp),
        filter: crate::filters::Records {
            module: Some(module.to_string()),
            module_path: Some(module_path.to_string()),
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
        json!({ "moduleRole": role }),
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
async fn cross_module_child_is_admitted_under_referenced_parent() {
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
async fn composed_grandchild_resolves_parent_in_composing_module() {
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
async fn missing_cross_module_parent_is_repairable() {
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
        Some("ModuleAuthorizationParentRecordNotFound")
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
        Some("ModuleAuthorizationParentRecordNotFound")
    );
    assert_eq!(
        classify_apply_reply(&reply.status, &parsed(&message), false),
        ReplicationApplyOutcome::Incomplete
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
        Some("ModuleAuthorizationIncorrectModulePath")
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
        Some("ModuleAuthorizationIncorrectContextId")
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
        Some("ModuleAuthorizationParentlessIncorrectModulePath")
    );
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn retained_initial_write_proves_a_dataless_parent() {
    let fixture = composition_fixture().await;

    // A dataless initial write has no latest-base-state write; the retained
    // initial write still names the parent.
    let thread = signed_write_message(WriteSpec {
        module: THREADS.to_string(),
        module_path: "thread".to_string(),
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

// Covers: DWN-REC-004, DWN-REC-005, DWN-SYNC-003
#[tokio::test]
async fn soft_deleted_parent_still_proves_structural_ancestry() {
    let fixture = composition_fixture().await;
    let (thread_id, thread_ctx) = seed_thread(&fixture, TS_THREAD).await;

    let delete = signed_delete_message(&thread_id, false, TS_COMMENT).await;
    let reply = fixture.delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // A soft delete removes the parent's visible state but not its retained
    // initial write, so a child written after the delete is still admissible.
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
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // The child stays reachable through its own record ID and filters.
    let child_id = record_id(&comment);
    let read = owner_read(&child_id, "2025-01-01T00:02:30.000000Z").await;
    let reply = fixture.read_handler.run(TENANT, &read, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);

    let query = owner_scoped_query(
        COMMENTS,
        "thread/comment",
        Some(&thread_ctx),
        "2025-01-01T00:02:31.000000Z",
    )
    .await;
    let reply = fixture.query_handler.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(reply.reply.entries.unwrap_or_default().len(), 1);

    // Soft deletion does not revive the parent: a direct read is still absent.
    let read = owner_read(&thread_id, "2025-01-01T00:02:32.000000Z").await;
    let reply = fixture.read_handler.run(TENANT, &read, None).await;
    assert_eq!(reply.status.code, 404, "{}", reply.status.detail);

    assert!(
        !record_has_prune(TENANT, &thread_id, &fixture.message_store)
            .await
            .unwrap()
    );
}

// Covers: DWN-REC-004, DWN-SYNC-003, DWN-SYNC-005
#[tokio::test]
async fn pruned_parent_rejects_child_as_terminal() {
    let fixture = composition_fixture().await;
    let (thread_id, thread_ctx) = seed_thread(&fixture, TS_THREAD).await;

    let delete = signed_delete_message(&thread_id, true, TS_COMMENT).await;
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
    // The public reply is the same generic missing-parent code as an absent
    // parent; prune is not disclosed on the wire.
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ModuleAuthorizationParentRecordNotFound")
    );
    // Without prune evidence the missing parent is a repairable dependency.
    assert_eq!(
        classify_apply_reply(&reply.status, &parsed(&comment), false),
        ReplicationApplyOutcome::Incomplete
    );
    // A receiver that can see the local prune settles the same reply as
    // superseded rather than a retryable dependency.
    let pruned = record_has_prune(TENANT, &thread_id, &fixture.message_store)
        .await
        .unwrap();
    assert!(pruned);
    assert_eq!(
        classify_apply_reply_with_parent_state(&reply.status, &parsed(&comment), false, pruned),
        ReplicationApplyOutcome::Superseded
    );
}

// Covers: DWN-REC-002, DWN-REC-005, DWN-PROTO-001
#[tokio::test]
async fn a_non_initial_parent_write_is_not_ancestry() {
    let fixture = composition_fixture().await;
    let (thread, thread_data) = write_record(THREADS, "thread", TS_THREAD, None, b"thread").await;
    let thread_id = record_id(&thread);
    let thread_ctx = context_id(&thread);

    // A later write for the same record, stored as latest state while the
    // initial write is absent. Structural ancestry must not treat it as a
    // substitute, even though it is the newest live write.
    let update = signed_write_message(WriteSpec {
        module: THREADS.to_string(),
        module_path: "thread".to_string(),
        record_id: Some(thread_id.clone()),
        context_id: Some(thread_ctx.clone()),
        date_created: TS_THREAD.to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(b"thread update").to_string(),
        data_size: b"thread update".len() as u64,
        timestamp: TS_COMMENT.to_string(),
        ..WriteSpec::new(TS_COMMENT)
    })
    .await;
    let parsed_update = parsed(&update);
    let author = extract_author(&parsed_update).unwrap();
    let indexes = records_write_indexes(&parsed_update, &author, true).unwrap();
    fixture
        .message_store
        .put(TENANT, parsed_update, indexes)
        .await
        .unwrap();

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
        Some("ModuleAuthorizationParentRecordNotFound")
    );

    // Control: a separate receiver that has the real initial write admits the
    // same child.
    let control = composition_fixture().await;
    let reply = control
        .write_handler
        .run(TENANT, &thread, Some(thread_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let reply = control
        .write_handler
        .run(TENANT, &comment, Some(Bytes::from_static(b"comment")))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-REC-005, DWN-PROTO-001
#[tokio::test]
async fn missing_and_pruned_parent_replies_are_indistinguishable() {
    let (thread, thread_data) = write_record(THREADS, "thread", TS_THREAD, None, b"thread").await;
    let thread_id = record_id(&thread);
    let thread_ctx = context_id(&thread);
    let (comment, data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_REACTION,
        Some((&thread_id, &thread_ctx)),
        b"comment",
    )
    .await;

    // Missing parent: never written.
    let missing_fixture = composition_fixture().await;
    let missing = missing_fixture
        .write_handler
        .run(TENANT, &comment, Some(data.clone()))
        .await;

    // Pruned parent: written, then removed as ancestry.
    let pruned_fixture = composition_fixture().await;
    let reply = pruned_fixture
        .write_handler
        .run(TENANT, &thread, Some(thread_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let prune = signed_delete_message(&thread_id, true, TS_COMMENT).await;
    let reply = pruned_fixture
        .delete_handler
        .run(TENANT, &prune, None)
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let pruned = pruned_fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;

    assert_eq!(missing.status.code, 400);
    assert_eq!(missing.status.error_code, pruned.status.error_code);
    assert_eq!(missing.status.detail, pruned.status.detail);
}

// Covers: DWN-PROTO-001, DWN-SYNC-002
#[tokio::test]
async fn another_tenants_prune_does_not_terminate_ancestry() {
    let other_tenant = "did:example:bob";
    let fixture = composition_fixture().await;

    // The same signed parent lives in the queried tenant. Prune evidence for
    // the same record ID exists in another tenant and must not leak over.
    let (thread, thread_data) = write_record(THREADS, "thread", TS_THREAD, None, b"thread").await;
    let thread_id = record_id(&thread);
    let thread_ctx = context_id(&thread);
    let reply = fixture
        .write_handler
        .run(TENANT, &thread, Some(thread_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let prune = parsed(&signed_delete_message(&thread_id, true, TS_COMMENT).await);
    let indexes: KeyValues = BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        ("method".to_string(), Value::String("Delete".to_string())),
        ("recordId".to_string(), Value::String(thread_id.clone())),
        ("prune".to_string(), Value::Bool(true)),
    ]);
    fixture
        .message_store
        .put(other_tenant, prune, indexes)
        .await
        .unwrap();
    assert!(
        record_has_prune(other_tenant, &thread_id, &fixture.message_store)
            .await
            .unwrap()
    );
    assert!(
        !record_has_prune(TENANT, &thread_id, &fixture.message_store)
            .await
            .unwrap()
    );

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
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-REC-003, DWN-REC-004
#[tokio::test]
async fn replay_of_a_retained_child_after_soft_delete_is_idempotent() {
    let fixture = composition_fixture().await;
    let (thread_id, thread_ctx) = seed_thread(&fixture, TS_THREAD).await;
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
        .run(TENANT, &comment, Some(data.clone()))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let before = state_cids(&fixture, &record_id(&comment)).await;

    let delete = signed_delete_message(&thread_id, false, TS_COMMENT).await;
    let reply = fixture.delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(data))
        .await;
    assert_eq!(reply.status.code, 409, "{}", reply.status.detail);
    assert_eq!(state_cids(&fixture, &record_id(&comment)).await, before);
}

#[derive(Clone)]
enum AncestryOp {
    Write(serde_json::Value, Bytes),
    Delete(serde_json::Value),
}

async fn apply_ancestry_op(fixture: &CompositionFixture, op: &AncestryOp) -> Status {
    match op {
        AncestryOp::Write(message, data) => {
            fixture
                .write_handler
                .run(TENANT, message, Some(data.clone()))
                .await
                .status
        }
        AncestryOp::Delete(message) => {
            fixture
                .delete_handler
                .run(TENANT, message, None)
                .await
                .status
        }
    }
}

/// Delivers `ops` in `order`, retrying only replies the receiver classifies as
/// repairable. A pruned parent is terminal through local prune evidence, so the
/// loop cannot spin on a rejection the receiver knows is unrepairable.
async fn admit_ancestry_ops(
    fixture: &CompositionFixture,
    ops: &[AncestryOp],
    order: &[usize],
    parent_id: &str,
) -> Vec<i32> {
    let mut pending: Vec<usize> = order.to_vec();
    let mut statuses = vec![0i32; ops.len()];
    loop {
        let mut next = Vec::new();
        let mut progressed = false;
        for index in std::mem::take(&mut pending) {
            let op = &ops[index];
            let status = apply_ancestry_op(fixture, op).await;
            statuses[index] = status.code;
            let message = match op {
                AncestryOp::Write(message, _) | AncestryOp::Delete(message) => message,
            };
            let pruned = record_has_prune(TENANT, parent_id, &fixture.message_store)
                .await
                .unwrap_or(false);
            let outcome =
                classify_apply_reply_with_parent_state(&status, &parsed(message), false, pruned);
            if outcome == ReplicationApplyOutcome::Incomplete {
                next.push(index);
            } else {
                progressed = true;
            }
        }
        if next.is_empty() || !progressed {
            break;
        }
        pending = next;
    }
    statuses
}

fn permutation_orders(count: usize) -> Vec<Vec<usize>> {
    let mut orders = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    fn recurse(count: usize, current: &mut Vec<usize>, orders: &mut Vec<Vec<usize>>) {
        if current.len() == count {
            orders.push(current.clone());
            return;
        }
        for index in 0..count {
            if current.contains(&index) {
                continue;
            }
            current.push(index);
            recurse(count, current, orders);
            current.pop();
        }
    }
    recurse(count, &mut current, &mut orders);
    orders
}

// Covers: DWN-REC-004, DWN-REC-005
#[tokio::test]
async fn soft_delete_parent_child_permutations_converge() {
    let (thread, thread_data) = write_record(THREADS, "thread", TS_THREAD, None, b"thread").await;
    let thread_id = record_id(&thread);
    let thread_ctx = context_id(&thread);
    let (comment, comment_data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_REACTION,
        Some((&thread_id, &thread_ctx)),
        b"comment",
    )
    .await;
    let delete = signed_delete_message(&thread_id, false, TS_COMMENT).await;
    let ops = [
        AncestryOp::Write(thread, thread_data),
        AncestryOp::Write(comment, comment_data),
        AncestryOp::Delete(delete),
    ];

    let mut observed: Option<Vec<String>> = None;
    for order in permutation_orders(ops.len()) {
        let fixture = composition_fixture().await;
        admit_ancestry_ops(&fixture, &ops, &order, &thread_id).await;
        let child_state = state_cids(&fixture, &record_id(&ops_child(&ops))).await;
        assert!(
            !child_state.is_empty(),
            "child must survive a soft delete (order {order:?})"
        );
        assert!(
            !record_has_prune(TENANT, &thread_id, &fixture.message_store)
                .await
                .unwrap(),
            "a soft delete is not prune evidence (order {order:?})"
        );
        match &observed {
            None => observed = Some(child_state),
            Some(expected) => assert_eq!(&child_state, expected, "order {order:?} diverged"),
        }
    }
}

// Covers: DWN-REC-004, ENBOX-REC-001, DWN-SYNC-003, DWN-SYNC-005
#[tokio::test]
async fn prune_parent_child_delete_permutations_converge() {
    let (thread, thread_data) = write_record(THREADS, "thread", TS_THREAD, None, b"thread").await;
    let thread_id = record_id(&thread);
    let thread_ctx = context_id(&thread);
    let (comment, comment_data) = write_record(
        COMMENTS,
        "thread/comment",
        TS_REACTION,
        Some((&thread_id, &thread_ctx)),
        b"comment",
    )
    .await;
    let soft_delete = signed_delete_message(&thread_id, false, TS_COMMENT).await;
    let prune = signed_delete_message(&thread_id, true, TS_REACTION).await;
    let ops = [
        AncestryOp::Write(thread, thread_data),
        AncestryOp::Write(comment, comment_data),
        AncestryOp::Delete(soft_delete),
        AncestryOp::Delete(prune),
    ];

    for order in permutation_orders(ops.len()) {
        let fixture = composition_fixture().await;
        admit_ancestry_ops(&fixture, &ops, &order, &thread_id).await;
        let child_state = state_cids(&fixture, &record_id(&ops_child(&ops))).await;
        assert!(
            child_state.is_empty(),
            "prune must settle the child absent (order {order:?})"
        );
        assert!(
            record_has_prune(TENANT, &thread_id, &fixture.message_store)
                .await
                .unwrap(),
            "prune must be retained (order {order:?})"
        );
    }
}

fn ops_child(ops: &[AncestryOp]) -> serde_json::Value {
    ops.iter()
        .find_map(|op| match op {
            AncestryOp::Write(message, _)
                if message["descriptor"]["modulePath"] == "thread/comment" =>
            {
                Some(message.clone())
            }
            _ => None,
        })
        .expect("scenario has a child write")
}

async fn owner_read(record_id: &str, timestamp: &str) -> serde_json::Value {
    let descriptor = RecordsReadDescriptor {
        message_timestamp: parse_time(timestamp),
        filter: RecordsFilter {
            record_id: Some(record_id.to_string()),
            ..Default::default()
        },
        permission_grant_id: None,
        date_sort: None,
        include_replication_support: None,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(&descriptor_json, json!({}), test_signer()).await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

async fn owner_scoped_query(
    module: &str,
    module_path: &str,
    context_id: Option<&str>,
    timestamp: &str,
) -> serde_json::Value {
    let descriptor = RecordsQueryDescriptor {
        message_timestamp: parse_time(timestamp),
        filter: RecordsFilter {
            module: Some(module.to_string()),
            module_path: Some(module_path.to_string()),
            context_id: context_id.map(str::to_string),
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
async fn cross_module_role_authorizes_read_and_co_delete() {
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
async fn cross_module_role_authorizes_query_and_co_update() {
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
async fn cross_module_role_holder_without_record_is_repairable() {
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
        Some("ModuleAuthorizationMatchingRoleRecordNotFound")
    );
    assert_eq!(
        classify_apply_reply(&reply.status, &parsed(&message), false),
        ReplicationApplyOutcome::Incomplete
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn cross_module_role_in_sibling_context_does_not_authorize() {
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
        Some("ModuleAuthorizationMatchingRoleRecordNotFound")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn cross_module_role_revocation_denies() {
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
        Some("ModuleAuthorizationMatchingRoleRecordNotFound")
    );
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn cross_module_role_removed_from_referenced_definition_denies() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    grant_participant(&fixture, (&thread.0, &thread.1), BOB, TS_ROLE).await;
    put_module_definition(
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
    // The consumer still references a role the stored provider no longer
    // declares; that composition cannot resolve, so admission fails before
    // role invocation is evaluated.
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert!(
        reply
            .status
            .detail
            .contains("ModulesConfigureRoleDoesNotExistAtGivenPath"),
        "{}",
        reply.status.detail
    );
}

// Covers: DWN-PROTO-005
#[tokio::test]
async fn unknown_cross_module_role_alias_denies() {
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
        Some("ModuleAuthorizationNotARole")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn cross_module_nested_role_query_without_context_denies() {
    let fixture = composition_fixture().await;
    let thread = seed_thread(&fixture, TS_THREAD).await;
    grant_participant(&fixture, (&thread.0, &thread.1), BOB, TS_ROLE).await;

    for context_id in [None, Some(""), Some("/")] {
        let query = bob_query(COMMENTS, "thread", context_id, PARTICIPANT, TS_COMMENT).await;
        let reply = fixture.query_handler.run(TENANT, &query, None).await;
        assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
        // A `$ref` root is a virtual attachment point, never a local record
        // with a rule set of its own.
        assert_eq!(
            reply.status.error_code.as_deref(),
            Some("ModuleAuthorizationMissingRuleSet")
        );
    }
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn deep_cross_module_role_query_with_short_context_denies() {
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
        Some("ModuleAuthorizationMissingContextId")
    );
}

// Covers: DWN-SYNC-003
#[tokio::test]
async fn referenced_definition_absent_is_repairable() {
    // Only the composing module is installed; the `$ref` target is missing.
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_module_definition(TENANT, &message_store, comments_definition(), INSTALL).await;
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
        Some("ModulesConfigureComposedModuleNotInstalled")
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
        module: COMMENTS.to_string(),
        module_path: "thread".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        ..WriteSpec::new(TS_COMMENT)
    })
    .await;
    // A `$ref` attachment point never admits a record, for any author.
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(bytes))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ModuleAuthorizationRefNodeWriteNotAllowed")
    );
}

// Covers: DWN-PROTO-005
#[tokio::test]
async fn multi_segment_ref_target_attaches_children_to_the_nested_target() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_module_definition(TENANT, &message_store, threads_definition(), INSTALL).await;
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
    put_module_definition(TENANT, &message_store, comments, INSTALL).await;
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
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

/// The threads fixture with an encrypted `thread` type and key agreement.
fn encrypted_threads_definition() -> Definition {
    let mut definition = threads_definition();
    definition
        .types
        .get_mut("thread")
        .expect("thread type")
        .encryption_required = Some(true);
    let thread = definition.structure.get_mut("thread").expect("thread rule");
    thread.key_agreement = Some(ModuleKeyAgreement {
        public_key_jwk: path_key_jwk(),
    });
    thread
        .rules
        .get_mut("participant")
        .expect("participant rule")
        .key_agreement = Some(ModuleKeyAgreement {
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
        .key_agreement = Some(ModuleKeyAgreement {
        public_key_jwk: path_key_jwk(),
    });
    definition
}

async fn encrypted_write(
    module: &str,
    module_path: &str,
    timestamp: &str,
    parent: Option<(&str, &str)>,
    data: &'static [u8],
) -> (serde_json::Value, Bytes) {
    let bytes = Bytes::from_static(data);
    let mut entries = vec![module_path_entry(&path_key_id())];
    if module == COMMENTS && module_path == "thread/comment" {
        entries.push(role_audience_entry_for(
            THREADS,
            "thread/participant",
            "participant-key",
        ));
    }
    let envelope = envelope_with_entries(entries);
    let (parent_id, parent_context_id) = match parent {
        Some((record_id, context_id)) => {
            (Some(record_id.to_string()), Some(context_id.to_string()))
        }
        None => (None, None),
    };
    let message = signed_write_message(WriteSpec {
        module: module.to_string(),
        module_path: module_path.to_string(),
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
    put_module_definition(
        TENANT,
        &message_store,
        encrypted_threads_definition(),
        INSTALL,
    )
    .await;
    put_module_definition(
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
    put_retained_audience(
        &message_store,
        THREADS,
        "thread/participant",
        &thread_id,
        "participant-key",
        TS_ROLE,
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
    put_module_definition(
        TENANT,
        &message_store,
        encrypted_threads_definition(),
        INSTALL,
    )
    .await;
    put_module_definition(
        TENANT,
        &message_store,
        encrypted_comments_definition(),
        INSTALL,
    )
    .await;
    put_retained_audience(
        &message_store,
        THREADS,
        "thread/participant",
        &thread_id,
        "participant-key",
        TS_ROLE,
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

async fn owner_query(module: &str, timestamp: &str) -> serde_json::Value {
    let descriptor = RecordsQueryDescriptor {
        message_timestamp: parse_time(timestamp),
        filter: crate::filters::Records {
            module: Some(module.to_string()),
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
async fn query_result_is_isolated_to_the_queried_module() {
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
            .module,
        COMMENTS,
        "comments query returned a foreign module record"
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
    put_module_definition(TENANT, &message_store, threads_definition(), INSTALL).await;
    put_module_definition(TENANT, &message_store, comments_v1, INSTALL).await;
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
    put_module_definition(
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

// ---------------------------------------------------------------------------
// Chained `$ref` inheritance across three modules.
// ---------------------------------------------------------------------------

const CHAIN_CORE: &str = "https://chain.example/core";
const CHAIN_COMMENTS: &str = "https://chain.example/comments";
const CHAIN_REACTIONS: &str = "https://chain.example/reactions";
const CHAIN_BOB: &str = "did:example:bob";

fn chain_core_definition(keyed_role: bool) -> Definition {
    let role_rule = RuleSet {
        role: Some(true),
        key_agreement: keyed_role.then(|| ModuleKeyAgreement {
            public_key_jwk: path_key_jwk(),
        }),
        actions: vec![Action::Who(ActionWho {
            who: Who::Author,
            of: Some("notebook/note".to_string()),
            can: vec![Can::Create],
        })],
        ..Default::default()
    };
    Definition {
        module: CHAIN_CORE.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([
            ("notebook".to_string(), text_type()),
            ("note".to_string(), text_type()),
            ("participant".to_string(), text_type()),
            ("member".to_string(), text_type()),
        ]),
        structure: BTreeMap::from([
            (
                "member".to_string(),
                RuleSet {
                    role: Some(true),
                    ..Default::default()
                },
            ),
            (
                "notebook".to_string(),
                RuleSet {
                    actions: vec![Action::Who(ActionWho {
                        who: Who::Anyone,
                        of: None,
                        can: vec![Can::Create, Can::Read],
                    })],
                    rules: BTreeMap::from([(
                        "note".to_string(),
                        RuleSet {
                            actions: vec![Action::Who(ActionWho {
                                who: Who::Anyone,
                                of: None,
                                can: vec![Can::Create, Can::Read],
                            })],
                            rules: BTreeMap::from([("participant".to_string(), role_rule)]),
                            ..Default::default()
                        },
                    )]),
                    ..Default::default()
                },
            ),
        ]),
    }
}

fn chain_comments_definition() -> Definition {
    Definition {
        module: CHAIN_COMMENTS.to_string(),
        published: true,
        uses: Some(BTreeMap::from([(
            "core".to_string(),
            CHAIN_CORE.to_string(),
        )])),
        key_agreement: None,
        types: BTreeMap::from([("comment".to_string(), text_type())]),
        structure: BTreeMap::from([(
            "note".to_string(),
            RuleSet {
                reference: Some("core:notebook/note".to_string()),
                rules: BTreeMap::from([(
                    "comment".to_string(),
                    RuleSet {
                        actions: vec![Action::Role(ActionRole {
                            role: "core:notebook/note/participant".to_string(),
                            can: vec![Can::Create, Can::Read],
                        })],
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
        )]),
    }
}

fn chain_reactions_definition() -> Definition {
    Definition {
        module: CHAIN_REACTIONS.to_string(),
        published: true,
        uses: Some(BTreeMap::from([(
            "comments".to_string(),
            CHAIN_COMMENTS.to_string(),
        )])),
        key_agreement: None,
        types: BTreeMap::from([("reaction".to_string(), text_type())]),
        structure: BTreeMap::from([(
            "comment".to_string(),
            RuleSet {
                reference: Some("comments:note/comment".to_string()),
                rules: BTreeMap::from([("reaction".to_string(), RuleSet::default())]),
                ..Default::default()
            },
        )]),
    }
}

async fn chain_fixture() -> CompositionFixture {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_module_definition(TENANT, &message_store, chain_core_definition(true), INSTALL).await;
    put_module_definition(TENANT, &message_store, chain_comments_definition(), INSTALL).await;
    put_module_definition(
        TENANT,
        &message_store,
        chain_reactions_definition(),
        INSTALL,
    )
    .await;
    CompositionFixture {
        write_handler: RecordsWriteHandler::<_, _>::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        delete_handler: RecordsDeleteHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        read_handler: RecordsReadHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        query_handler: RecordsQueryHandler::new(
            message_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        message_store,
    }
}

async fn seed_report(
    fixture: &CompositionFixture,
    timestamp: &str,
) -> ((String, String), (String, String)) {
    let (notebook, notebook_data) =
        write_record(CHAIN_CORE, "notebook", timestamp, None, b"notebook").await;
    let reply = fixture
        .write_handler
        .run(TENANT, &notebook, Some(notebook_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let notebook = (record_id(&notebook), context_id(&notebook));

    let (note, note_data) = write_record(
        CHAIN_CORE,
        "notebook/note",
        timestamp,
        Some((&notebook.0, &notebook.1)),
        b"note",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &note, Some(note_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let note = (record_id(&note), context_id(&note));
    (notebook, note)
}

// Covers: DWN-PROTO-001, DWN-PROTO-005
#[tokio::test]
async fn three_module_chain_writes_carry_physical_context() {
    let fixture = chain_fixture().await;
    let (_notebook, note) = seed_report(&fixture, TS_THREAD).await;

    let (comment, comment_data) = write_record(
        CHAIN_COMMENTS,
        "note/comment",
        TS_COMMENT,
        Some((&note.0, &note.1)),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &comment, Some(comment_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let comment = (record_id(&comment), context_id(&comment));

    let (reaction, reaction_data) = write_record(
        CHAIN_REACTIONS,
        "comment/reaction",
        TS_REACTION,
        Some((&comment.0, &comment.1)),
        b"reaction",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &reaction, Some(reaction_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // Declared paths are two segments everywhere; physical context is the
    // four-deep record chain.
    assert_eq!(
        context_id(&reaction),
        format!("{}/{}", comment.1, reaction["recordId"].as_str().unwrap())
    );
    assert_eq!(remark_context_depth(&context_id(&reaction)), 4);
}

fn remark_context_depth(context_id: &str) -> usize {
    context_id.split('/').count()
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn tenant_write_at_a_chained_ref_attachment_is_rejected() {
    let fixture = chain_fixture().await;
    let (_notebook, note) = seed_report(&fixture, TS_THREAD).await;

    let (message, data) = write_record(
        CHAIN_COMMENTS,
        "note",
        TS_COMMENT,
        Some((&note.0, &note.1)),
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ModuleAuthorizationRefNodeWriteNotAllowed")
    );
}

// Covers: DWN-REC-004
#[tokio::test]
async fn pruned_core_note_settles_a_late_composing_comment_as_superseded() {
    let fixture = chain_fixture().await;
    let (_notebook, note) = seed_report(&fixture, TS_THREAD).await;

    let prune = signed_delete_message(&note.0, true, TS_COMMENT).await;
    let reply = fixture.delete_handler.run(TENANT, &prune, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (comment, data) = write_record(
        CHAIN_COMMENTS,
        "note/comment",
        TS_REACTION,
        Some((&note.0, &note.1)),
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
        Some("ModuleAuthorizationParentRecordNotFound")
    );
    assert_eq!(
        classify_apply_reply_with_parent_state(
            &reply.status,
            &parsed(&comment),
            false,
            record_has_prune(TENANT, &note.0, &fixture.message_store)
                .await
                .unwrap(),
        ),
        ReplicationApplyOutcome::Superseded
    );
}

// ---------------------------------------------------------------------------
// Cross-module roles, root roles, and `of` actors.
// ---------------------------------------------------------------------------

async fn bob_create_no_role(
    module: &str,
    module_path: &str,
    parent: (&str, &str),
    timestamp: &str,
    data: &'static [u8],
) -> (serde_json::Value, Bytes) {
    let bytes = Bytes::from_static(data);
    let message = signed_write_message(WriteSpec {
        author: CHAIN_BOB.to_string(),
        signer: bob_signer(),
        module: module.to_string(),
        module_path: module_path.to_string(),
        parent_id: Some(parent.0.to_string()),
        parent_context_id: Some(parent.1.to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        ..WriteSpec::new(timestamp)
    })
    .await;
    (message, bytes)
}

async fn chain_hold_role(
    fixture: &CompositionFixture,
    note: (&str, &str),
    recipient: &str,
    timestamp: &str,
) -> String {
    let bytes = Bytes::from_static(b"role");
    let message = signed_write_message(WriteSpec {
        module: CHAIN_CORE.to_string(),
        module_path: "notebook/note/participant".to_string(),
        parent_id: Some(note.0.to_string()),
        parent_context_id: Some(note.1.to_string()),
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

// Covers: DWN-PROTO-002, DWN-PROTO-003
#[tokio::test]
async fn chain_context_role_authorizes_the_owning_context_only() {
    let fixture = chain_fixture().await;
    let (_notebook, note) = seed_report(&fixture, TS_THREAD).await;
    let (other_notebook, other_note) = seed_report(&fixture, "2025-01-01T00:00:10.000000Z").await;
    let _ = other_notebook;
    chain_hold_role(&fixture, (&note.0, &note.1), CHAIN_BOB, TS_ROLE).await;

    let role = "core:notebook/note/participant";
    let (message, data) = bob_create(
        CHAIN_COMMENTS,
        "note/comment",
        (&note.0, &note.1),
        role,
        TS_COMMENT,
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // The same role in a sibling context does not authorize.
    let (message, data) = bob_create(
        CHAIN_COMMENTS,
        "note/comment",
        (&other_note.0, &other_note.1),
        role,
        TS_REACTION,
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
        Some("ModuleAuthorizationMatchingRoleRecordNotFound")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn chain_root_role_authorizes_without_a_parent_context() {
    let mut definition = chain_comments_definition();
    definition.structure.get_mut("note").unwrap().rules.insert(
        "comment".to_string(),
        RuleSet {
            actions: vec![Action::Role(ActionRole {
                role: "core:member".to_string(),
                can: vec![Can::Create, Can::Read],
            })],
            ..Default::default()
        },
    );
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_module_definition(TENANT, &message_store, chain_core_definition(true), INSTALL).await;
    put_module_definition(TENANT, &message_store, definition, INSTALL).await;
    let fixture = CompositionFixture {
        write_handler: RecordsWriteHandler::<_, _>::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        delete_handler: RecordsDeleteHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        read_handler: RecordsReadHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        query_handler: RecordsQueryHandler::new(
            message_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        message_store,
    };
    let (_notebook, note) = seed_report(&fixture, TS_THREAD).await;

    // A root role record lives in the provider, has no parent, and grants
    // tenant-wide authority.
    let bytes = Bytes::from_static(b"role");
    let role_record = signed_write_message(WriteSpec {
        module: CHAIN_CORE.to_string(),
        module_path: "member".to_string(),
        recipient: Some(CHAIN_BOB.to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        ..WriteSpec::new(TS_ROLE)
    })
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &role_record, Some(bytes))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (message, data) = bob_create(
        CHAIN_COMMENTS,
        "note/comment",
        (&note.0, &note.1),
        "core:member",
        TS_COMMENT,
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-003, DWN-PROTO-005
#[tokio::test]
async fn chain_of_actor_resolves_the_owning_provider_record() {
    let mut definition = chain_comments_definition();
    definition.structure.get_mut("note").unwrap().rules.insert(
        "comment".to_string(),
        RuleSet {
            actions: vec![Action::Who(ActionWho {
                who: Who::Author,
                of: Some("core:notebook/note".to_string()),
                can: vec![Can::Create, Can::Read],
            })],
            ..Default::default()
        },
    );
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_module_definition(TENANT, &message_store, chain_core_definition(true), INSTALL).await;
    put_module_definition(TENANT, &message_store, definition, INSTALL).await;
    let fixture = CompositionFixture {
        write_handler: RecordsWriteHandler::<_, _>::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        delete_handler: RecordsDeleteHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        read_handler: RecordsReadHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        query_handler: RecordsQueryHandler::new(
            message_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        message_store,
    };

    // Bob authors the provider note, so the `of` author rule reaches him.
    let (notebook, notebook_data) =
        write_record(CHAIN_CORE, "notebook", TS_THREAD, None, b"notebook").await;
    assert_eq!(
        fixture
            .write_handler
            .run(TENANT, &notebook, Some(notebook_data))
            .await
            .status
            .code,
        202
    );
    let note_bytes = Bytes::from_static(b"note");
    let note = signed_write_message(WriteSpec {
        author: CHAIN_BOB.to_string(),
        signer: bob_signer(),
        module: CHAIN_CORE.to_string(),
        module_path: "notebook/note".to_string(),
        parent_id: Some(record_id(&notebook)),
        parent_context_id: Some(context_id(&notebook)),
        data_cid: generate_dag_pb_cid_from_bytes(&note_bytes).to_string(),
        data_size: note_bytes.len() as u64,
        ..WriteSpec::new(TS_THREAD)
    })
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &note, Some(note_bytes))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (message, data) = bob_create_no_role(
        CHAIN_COMMENTS,
        "note/comment",
        (&record_id(&note), &context_id(&note)),
        TS_COMMENT,
        b"comment",
    )
    .await;
    // No invoked role: the `of` author rule authorizes Bob directly.
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // A tenant-authored note does not authorize Bob through the same rule.
    let (_notebook, tenant_note) = seed_report(&fixture, "2025-01-01T00:00:20.000000Z").await;
    let (message, data) = bob_create_no_role(
        CHAIN_COMMENTS,
        "note/comment",
        (&tenant_note.0, &tenant_note.1),
        TS_REACTION,
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
}

// Covers: ENBOX-REC-003
#[tokio::test]
async fn composed_record_limit_groups_by_physical_parent_context() {
    let mut comments = chain_comments_definition();
    comments
        .structure
        .get_mut("note")
        .unwrap()
        .rules
        .get_mut("comment")
        .unwrap()
        .record_limit = Some(crate::modules::RecordLimit { max: 2 });
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_module_definition(TENANT, &message_store, chain_core_definition(true), INSTALL).await;
    put_module_definition(TENANT, &message_store, comments, INSTALL).await;
    let fixture = CompositionFixture {
        write_handler: RecordsWriteHandler::<_, _>::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        delete_handler: RecordsDeleteHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        read_handler: RecordsReadHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        query_handler: RecordsQueryHandler::new(
            message_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        message_store,
    };
    let (_notebook, note) = seed_report(&fixture, TS_THREAD).await;

    let mut comment_contexts = Vec::new();
    for (index, timestamp) in [TS_COMMENT, TS_REACTION, "2025-01-01T00:03:00.000000Z"]
        .into_iter()
        .enumerate()
    {
        let (comment, data) = write_record(
            CHAIN_COMMENTS,
            "note/comment",
            timestamp,
            Some((&note.0, &note.1)),
            b"comment",
        )
        .await;
        let reply = fixture
            .write_handler
            .run(TENANT, &comment, Some(data))
            .await;
        assert_eq!(
            reply.status.code, 202,
            "comment {index}: {}",
            reply.status.detail
        );
        comment_contexts.push(context_id(&comment));
    }

    // A filter at the comment's physical depth scopes its direct parent, so
    // all three siblings share one occupant group and only two are visible.
    let query = owner_scoped_query(
        CHAIN_COMMENTS,
        "note/comment",
        Some(&note.1),
        "2025-01-01T00:04:00.000000Z",
    )
    .await;
    let reply = fixture.query_handler.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
    assert_eq!(reply.reply.entries.unwrap_or_default().len(), 2);
}

// Covers: DWN-PROTO-006
#[tokio::test]
async fn encrypted_consumer_requires_the_provider_role_key_agreement() {
    let mut comments = chain_comments_definition();
    comments
        .types
        .get_mut("comment")
        .unwrap()
        .encryption_required = Some(true);
    comments
        .structure
        .get_mut("note")
        .unwrap()
        .rules
        .get_mut("comment")
        .unwrap()
        .key_agreement = Some(ModuleKeyAgreement {
        public_key_jwk: path_key_jwk(),
    });
    comments
        .structure
        .get_mut("note")
        .unwrap()
        .rules
        .get_mut("comment")
        .unwrap()
        .actions = vec![Action::Role(ActionRole {
        role: "core:notebook/note/participant".to_string(),
        can: vec![Can::Create, Can::Read],
    })];
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_module_definition(TENANT, &message_store, chain_core_definition(true), INSTALL).await;
    put_module_definition(TENANT, &message_store, comments, INSTALL).await;
    let fixture = CompositionFixture {
        write_handler: RecordsWriteHandler::<_, _>::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        delete_handler: RecordsDeleteHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        read_handler: RecordsReadHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        query_handler: RecordsQueryHandler::new(
            message_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        message_store,
    };
    let (_notebook, note) = seed_report(&fixture, TS_THREAD).await;

    let bytes = Bytes::from_static(b"comment");
    let envelope = envelope_with_entries(vec![
        module_path_entry(&path_key_id()),
        role_audience_entry_for(CHAIN_CORE, "notebook/note/participant", "role-key"),
    ]);
    let message = signed_write_message(WriteSpec {
        module: CHAIN_COMMENTS.to_string(),
        module_path: "note/comment".to_string(),
        parent_id: Some(note.0.clone()),
        parent_context_id: Some(note.1.clone()),
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        encryption: Some(envelope),
        ..WriteSpec::new(TS_COMMENT)
    })
    .await;
    let comment_context = context_id(&message);
    put_retained_audience(
        &fixture.message_store,
        CHAIN_CORE,
        "notebook/note/participant",
        &note.1,
        "role-key",
        TS_ROLE,
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(bytes))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // The same key material under a foreign role namespace is not an audience.
    let other_bytes = Bytes::from_static(b"comment");
    let wrong_namespace = envelope_with_entries(vec![
        module_path_entry(&path_key_id()),
        role_audience_entry_for(CHAIN_REACTIONS, "notebook/note/participant", "role-key"),
    ]);
    let message = signed_write_message(WriteSpec {
        module: CHAIN_COMMENTS.to_string(),
        module_path: "note/comment".to_string(),
        parent_id: Some(note.0),
        parent_context_id: Some(comment_context),
        data_cid: generate_dag_pb_cid_from_bytes(&other_bytes).to_string(),
        data_size: other_bytes.len() as u64,
        encryption: Some(wrong_namespace),
        ..WriteSpec::new(TS_REACTION)
    })
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(other_bytes))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ModuleAuthorizationEncryptionRoleAudienceEntryMissing")
    );
}

// Covers: DWN-PROTO-006, ENBOX-ERR-001
#[tokio::test]
async fn encrypted_consumer_rejects_a_provider_role_without_key_agreement() {
    let mut comments = chain_comments_definition();
    comments
        .types
        .get_mut("comment")
        .unwrap()
        .encryption_required = Some(true);
    comments
        .structure
        .get_mut("note")
        .unwrap()
        .rules
        .get_mut("comment")
        .unwrap()
        .key_agreement = Some(ModuleKeyAgreement {
        public_key_jwk: path_key_jwk(),
    });
    comments
        .structure
        .get_mut("note")
        .unwrap()
        .rules
        .get_mut("comment")
        .unwrap()
        .actions = vec![Action::Role(ActionRole {
        role: "core:notebook/note/participant".to_string(),
        can: vec![Can::Create, Can::Read],
    })];
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    // `keyed_role = false`: the provider role has no `$keyAgreement`.
    put_module_definition(
        TENANT,
        &message_store,
        chain_core_definition(false),
        INSTALL,
    )
    .await;
    put_module_definition(TENANT, &message_store, comments, INSTALL).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store,
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let bytes = Bytes::from_static(b"comment");
    let message = signed_write_message(WriteSpec {
        module: CHAIN_COMMENTS.to_string(),
        module_path: "note/comment".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&bytes).to_string(),
        data_size: bytes.len() as u64,
        ..WriteSpec::new(TS_COMMENT)
    })
    .await;
    let reply = handler.run(TENANT, &message, Some(bytes)).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert!(
        reply
            .status
            .detail
            .contains("ModulesConfigureInvalidEncryptedRoleMissingKeyAgreement"),
        "{}",
        reply.status.detail
    );
}

// Covers: DWN-PROTO-001, DWN-PROTO-005
#[tokio::test]
async fn chain_child_rejects_a_mismatched_parent_or_context() {
    let fixture = chain_fixture().await;
    let (_notebook, note) = seed_report(&fixture, TS_THREAD).await;

    let (comment, data) = write_record(
        CHAIN_COMMENTS,
        "note/comment",
        TS_COMMENT,
        Some(("missing-note", "missing-context")),
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
        Some("ModuleAuthorizationParentRecordNotFound")
    );

    let (comment, data) = write_record(
        CHAIN_COMMENTS,
        "note/comment",
        TS_COMMENT,
        Some((&note.0, "wrong/parent/context")),
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
        Some("ModuleAuthorizationIncorrectContextId")
    );
}

// Covers: DWN-PROTO-003, DWN-PROTO-005
#[tokio::test]
async fn chain_of_recipient_resolves_the_owning_provider_record() {
    let mut definition = chain_comments_definition();
    definition.structure.get_mut("note").unwrap().rules.insert(
        "comment".to_string(),
        RuleSet {
            actions: vec![Action::Who(ActionWho {
                who: Who::Recipient,
                of: Some("core:notebook/note".to_string()),
                can: vec![Can::Create, Can::Read],
            })],
            ..Default::default()
        },
    );
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_module_definition(TENANT, &message_store, chain_core_definition(true), INSTALL).await;
    put_module_definition(TENANT, &message_store, definition, INSTALL).await;
    let fixture = CompositionFixture {
        write_handler: RecordsWriteHandler::<_, _>::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        delete_handler: RecordsDeleteHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        read_handler: RecordsReadHandler::new(
            message_store.clone(),
            data_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        query_handler: RecordsQueryHandler::new(
            message_store.clone(),
            Some(Arc::new(test_resolver())),
        ),
        message_store,
    };

    let (notebook, notebook_data) =
        write_record(CHAIN_CORE, "notebook", TS_THREAD, None, b"notebook").await;
    assert_eq!(
        fixture
            .write_handler
            .run(TENANT, &notebook, Some(notebook_data))
            .await
            .status
            .code,
        202
    );
    let note_bytes = Bytes::from_static(b"note");
    let note = signed_write_message(WriteSpec {
        module: CHAIN_CORE.to_string(),
        module_path: "notebook/note".to_string(),
        parent_id: Some(record_id(&notebook)),
        parent_context_id: Some(context_id(&notebook)),
        recipient: Some(CHAIN_BOB.to_string()),
        data_cid: generate_dag_pb_cid_from_bytes(&note_bytes).to_string(),
        data_size: note_bytes.len() as u64,
        ..WriteSpec::new(TS_THREAD)
    })
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &note, Some(note_bytes))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (message, data) = bob_create_no_role(
        CHAIN_COMMENTS,
        "note/comment",
        (&record_id(&note), &context_id(&note)),
        TS_COMMENT,
        b"comment",
    )
    .await;
    let reply = fixture
        .write_handler
        .run(TENANT, &message, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}
