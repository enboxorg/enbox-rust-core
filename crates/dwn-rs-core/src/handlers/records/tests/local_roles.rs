//! Local protocol-role invocation for Write, Read, Delete, and Query.
//!
//! An invoked `protocolRole` must be a `$role` in the definition governing the
//! evaluation, its context source must carry the role's nesting, and the author
//! must actually hold an active role record (`DWN-PROTO-002`, `DWN-PROTO-004`).

use super::*;
use crate::descriptors::ReadDescriptor as RecordsReadDescriptor;
use crate::descriptors::{DeleteDescriptor as RecordsDeleteDescriptor, RecordsQueryDescriptor};
use crate::protocols::{Action, ActionRole, ActionWho, Can, Who};

const TENANT: &str = "did:example:alice";
const BOB: &str = "did:example:bob";
const THREADS: &str = "https://example.com/threads";
const INSTALL: &str = "2024-12-31T00:00:00.000000Z";
const T_THREAD: &str = "2025-01-01T00:00:00.000000Z";
const T_ROLE: &str = "2025-01-01T00:01:00.000000Z";
const T_MESSAGE: &str = "2025-01-01T00:02:00.000000Z";
const T_V2: &str = "2025-01-01T00:02:30.000000Z";
const T_LATE: &str = "2025-01-01T00:03:00.000000Z";

fn text_type() -> crate::protocols::Type {
    crate::protocols::Type {
        schema: None,
        data_formats: None,
        encryption_required: None,
    }
}

/// A local `threads` protocol. `participant_role` controls whether
/// `thread/participant` is a `$role`, and `thread/message` carries a role
/// action for create, read, and co-delete.
fn threads_definition(participant_role: bool) -> Definition {
    Definition {
        protocol: THREADS.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([
            ("thread".to_string(), text_type()),
            ("participant".to_string(), text_type()),
            ("message".to_string(), text_type()),
            ("moderator".to_string(), text_type()),
        ]),
        structure: BTreeMap::from([
            (
                "moderator".to_string(),
                RuleSet {
                    role: participant_role.then_some(true),
                    ..Default::default()
                },
            ),
            (
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
                                    can: vec![Can::Create, Can::Read, Can::CoDelete],
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
            ),
        ]),
    }
}

struct LocalFixture {
    message_store: TestMessageStore,
    write: RecordsWriteHandler<TestMessageStore, TestDataStore>,
    delete: RecordsDeleteHandler<TestMessageStore, TestDataStore>,
    read: RecordsReadHandler<TestMessageStore, TestDataStore>,
    query: RecordsQueryHandler<TestMessageStore>,
}

async fn fixture(definition: Definition) -> LocalFixture {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_protocol_definition(TENANT, &message_store, definition, INSTALL).await;
    let write = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let delete = RecordsDeleteHandler::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let read = RecordsReadHandler::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let query = RecordsQueryHandler::new(message_store.clone(), Some(Arc::new(test_resolver())));
    LocalFixture {
        message_store,
        write,
        delete,
        read,
        query,
    }
}

fn data(bytes: &'static [u8]) -> (String, u64, Bytes) {
    let data = Bytes::from_static(bytes);
    (
        generate_dag_pb_cid_from_bytes(&data).to_string(),
        data.len() as u64,
        data,
    )
}

/// Writes a root `thread` as the tenant and returns `(recordId, contextId)`.
async fn seed_thread(fixture: &LocalFixture, timestamp: &str) -> (String, String) {
    let (data_cid, data_size, payload) = data(b"thread");
    let message = signed_write_message(WriteSpec {
        protocol: THREADS.to_string(),
        protocol_path: "thread".to_string(),
        data_cid,
        data_size,
        ..WriteSpec::new(timestamp)
    })
    .await;
    let reply = fixture.write.run(TENANT, &message, Some(payload)).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    (
        message["recordId"].as_str().unwrap().to_string(),
        message["contextId"].as_str().unwrap().to_string(),
    )
}

/// Writes a `thread/participant` role record assigning `recipient` and
/// returns its record id.
async fn grant_role(
    fixture: &LocalFixture,
    parent: (&str, &str),
    recipient: &str,
    timestamp: &str,
) -> String {
    let (data_cid, data_size, payload) = data(b"role");
    let message = signed_write_message(WriteSpec {
        protocol: THREADS.to_string(),
        protocol_path: "thread/participant".to_string(),
        parent_id: Some(parent.0.to_string()),
        parent_context_id: Some(parent.1.to_string()),
        recipient: Some(recipient.to_string()),
        data_cid,
        data_size,
        ..WriteSpec::new(timestamp)
    })
    .await;
    let reply = fixture.write.run(TENANT, &message, Some(payload)).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    message["recordId"].as_str().unwrap().to_string()
}

/// A non-tenant `thread/message` write invoking `role`.
async fn role_write(
    parent: (&str, &str),
    role: &str,
    timestamp: &str,
    data_bytes: &'static [u8],
) -> (serde_json::Value, Bytes) {
    let (data_cid, data_size, payload) = data(data_bytes);
    let message = signed_write_message(WriteSpec {
        author: BOB.to_string(),
        signer: bob_signer(),
        protocol: THREADS.to_string(),
        protocol_path: "thread/message".to_string(),
        parent_id: Some(parent.0.to_string()),
        parent_context_id: Some(parent.1.to_string()),
        protocol_role: Some(role.to_string()),
        data_cid,
        data_size,
        ..WriteSpec::new(timestamp)
    })
    .await;
    (message, payload)
}

async fn signed_read(record_id: &str, role: &str, timestamp: &str) -> serde_json::Value {
    let descriptor = RecordsReadDescriptor {
        message_timestamp: parse_time(timestamp),
        filter: RecordsFilter {
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

async fn signed_delete(record_id: &str, role: &str, timestamp: &str) -> serde_json::Value {
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

async fn signed_query(
    protocol_path: Option<&str>,
    parent_id: Option<&str>,
    context_id: Option<&str>,
    role: &str,
    timestamp: &str,
) -> serde_json::Value {
    let descriptor = RecordsQueryDescriptor {
        message_timestamp: parse_time(timestamp),
        filter: RecordsFilter {
            protocol: Some(THREADS.to_string()),
            protocol_path: protocol_path.map(str::to_string),
            parent_id: parent_id.map(str::to_string),
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

fn parsed(message: &serde_json::Value) -> Message<Descriptor> {
    crate::validation::parse_message(message).unwrap()
}

/// Writes a root `moderator` role record assigning `recipient`.
async fn grant_root_role(fixture: &LocalFixture, recipient: &str, timestamp: &str) -> String {
    let (data_cid, data_size, payload) = data(b"role");
    let message = signed_write_message(WriteSpec {
        protocol: THREADS.to_string(),
        protocol_path: "moderator".to_string(),
        recipient: Some(recipient.to_string()),
        data_cid,
        data_size,
        ..WriteSpec::new(timestamp)
    })
    .await;
    let reply = fixture.write.run(TENANT, &message, Some(payload)).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    message["recordId"].as_str().unwrap().to_string()
}

/// Writes a `thread/message` as the tenant and returns its record id, so a
/// non-author role holder has a record to read or co-delete.
async fn seed_message(fixture: &LocalFixture, parent: (&str, &str), timestamp: &str) -> String {
    let (data_cid, data_size, payload) = data(b"message");
    let message = signed_write_message(WriteSpec {
        protocol: THREADS.to_string(),
        protocol_path: "thread/message".to_string(),
        parent_id: Some(parent.0.to_string()),
        parent_context_id: Some(parent.1.to_string()),
        data_cid,
        data_size,
        ..WriteSpec::new(timestamp)
    })
    .await;
    let reply = fixture.write.run(TENANT, &message, Some(payload)).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    message["recordId"].as_str().unwrap().to_string()
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn local_role_invocation_allows_write_read_and_co_delete() {
    let fixture = fixture(threads_definition(true)).await;
    let thread = seed_thread(&fixture, T_THREAD).await;
    grant_role(&fixture, (&thread.0, &thread.1), BOB, T_ROLE).await;

    // Write through the role.
    let (message, payload) = role_write(
        (&thread.0, &thread.1),
        "thread/participant",
        T_MESSAGE,
        b"message",
    )
    .await;
    let reply = fixture.write.run(TENANT, &message, Some(payload)).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // A tenant-authored record is neither authored nor received by Bob, so the
    // read and co-delete below exercise the role path, not an author shortcut.
    let message_id = seed_message(
        &fixture,
        (&thread.0, &thread.1),
        "2025-01-01T00:02:30.000000Z",
    )
    .await;

    // Read through the role.
    let read = signed_read(&message_id, "thread/participant", T_MESSAGE).await;
    let reply = fixture.read.run(TENANT, &read, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);

    // Co-delete through the role.
    let delete = signed_delete(&message_id, "thread/participant", T_MESSAGE).await;
    let reply = fixture.delete.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-002, DWN-SYNC-003
#[tokio::test]
async fn role_holder_without_role_record_is_repairable() {
    let fixture = fixture(threads_definition(true)).await;
    let thread = seed_thread(&fixture, T_THREAD).await;

    let (message, payload) = role_write(
        (&thread.0, &thread.1),
        "thread/participant",
        T_MESSAGE,
        b"message",
    )
    .await;
    let reply = fixture.write.run(TENANT, &message, Some(payload)).await;
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
async fn role_held_in_sibling_context_does_not_authorize() {
    let fixture = fixture(threads_definition(true)).await;
    let first = seed_thread(&fixture, T_THREAD).await;
    let second = seed_thread(&fixture, "2025-01-01T00:00:30.000000Z").await;
    grant_role(&fixture, (&first.0, &first.1), BOB, T_ROLE).await;

    let (message, payload) = role_write(
        (&second.0, &second.1),
        "thread/participant",
        T_MESSAGE,
        b"message",
    )
    .await;
    let reply = fixture.write.run(TENANT, &message, Some(payload)).await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationMatchingRoleRecordNotFound")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn revoked_role_no_longer_authorizes() {
    let fixture = fixture(threads_definition(true)).await;
    let thread = seed_thread(&fixture, T_THREAD).await;
    let role_id = grant_role(&fixture, (&thread.0, &thread.1), BOB, T_ROLE).await;

    // The tenant deletes the role record.
    let delete = signed_delete_message(&role_id, false, "2025-01-01T00:01:30.000000Z").await;
    let reply = fixture.delete.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let (message, payload) = role_write(
        (&thread.0, &thread.1),
        "thread/participant",
        T_MESSAGE,
        b"message",
    )
    .await;
    let reply = fixture.write.run(TENANT, &message, Some(payload)).await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationMatchingRoleRecordNotFound")
    );
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn role_removed_by_governing_definition_is_not_a_role() {
    let fixture = fixture(threads_definition(true)).await;
    let thread = seed_thread(&fixture, T_THREAD).await;
    grant_role(&fixture, (&thread.0, &thread.1), BOB, T_ROLE).await;
    // The next configuration removes the `$role` marker.
    put_protocol_definition(
        TENANT,
        &fixture.message_store,
        threads_definition(false),
        "2025-01-01T00:01:30.000000Z",
    )
    .await;

    let (message, payload) = role_write(
        (&thread.0, &thread.1),
        "thread/participant",
        T_MESSAGE,
        b"message",
    )
    .await;
    let reply = fixture.write.run(TENANT, &message, Some(payload)).await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationNotARole")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn nested_role_query_without_context_is_rejected() {
    let fixture = fixture(threads_definition(true)).await;
    let thread = seed_thread(&fixture, T_THREAD).await;

    let query = signed_query(
        Some("thread/message"),
        Some(&thread.0),
        None,
        "thread/participant",
        T_MESSAGE,
    )
    .await;
    let reply = fixture.query.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationMissingContextId")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn deep_role_query_with_short_context_is_rejected() {
    let fixture = fixture(threads_definition(true)).await;
    seed_thread(&fixture, T_THREAD).await;

    let query = signed_query(
        Some("thread/message"),
        None,
        Some("one-segment"),
        "thread/message/participant",
        T_MESSAGE,
    )
    .await;
    let reply = fixture.query.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationMissingContextId")
    );
}

// Covers: DWN-PROTO-002
#[tokio::test]
async fn anyone_rule_authorizes_a_role_invoking_query() {
    let fixture = fixture(threads_definition(true)).await;
    grant_root_role(&fixture, BOB, T_ROLE).await;

    // The `thread` read rule is `who: anyone`; a held root role still passes
    // role verification and the anyone rule authorizes the collection request.
    let query = signed_query(Some("thread"), None, None, "moderator", T_MESSAGE).await;
    let reply = fixture.query.run(TENANT, &query, None).await;
    assert_eq!(reply.status.code, 200, "{}", reply.status.detail);
}

/// Seeds a role-held message, then removes `$role` in a later configuration and
/// returns `(fixture, messageId)` so a Read or Delete can be evaluated after.
async fn seed_message_then_remove_role() -> (LocalFixture, String) {
    let fixture = fixture(threads_definition(true)).await;
    let thread = seed_thread(&fixture, T_THREAD).await;
    grant_role(&fixture, (&thread.0, &thread.1), BOB, T_ROLE).await;
    let message_id = seed_message(&fixture, (&thread.0, &thread.1), T_MESSAGE).await;

    put_protocol_definition(
        TENANT,
        &fixture.message_store,
        threads_definition(false),
        T_V2,
    )
    .await;

    (fixture, message_id)
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn role_removed_before_read_is_not_a_role_at_read_time() {
    let (fixture, message_id) = seed_message_then_remove_role().await;

    let read = signed_read(&message_id, "thread/participant", T_LATE).await;
    let reply = fixture.read.run(TENANT, &read, None).await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationNotARole")
    );
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn role_removed_before_delete_is_not_a_role_at_delete_time() {
    let (fixture, message_id) = seed_message_then_remove_role().await;

    let delete = signed_delete(&message_id, "thread/participant", T_LATE).await;
    let reply = fixture.delete.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationNotARole")
    );
}
