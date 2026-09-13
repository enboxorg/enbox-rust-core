//! Cross-protocol composition runtime: parent resolution and verification.
//!
//! A composing protocol references a base protocol through `$ref`. Runtime
//! admission must resolve every parent-bearing write in the protocol the
//! composing structure names, then require the declared path and context to
//! extend exactly that parent's (`DWN-PROTO-001`, `DWN-PROTO-005`).

use super::*;
use crate::protocols::{Action, ActionRole, ActionWho, Can, Who};

const TENANT: &str = "did:example:alice";
const THREADS: &str = "https://threads.example.com";
const COMMENTS: &str = "https://comments.example.com";
const INSTALL: &str = "2024-12-31T00:00:00.000000Z";

const TS_THREAD: &str = "2025-01-01T00:00:00.000000Z";
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
                            role: Some(true),
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
                                can: vec![Can::Read, Can::CoDelete],
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
        data_store,
        Some(Arc::new(test_resolver())),
    );
    CompositionFixture {
        message_store,
        write_handler,
        delete_handler,
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
