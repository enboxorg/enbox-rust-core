use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Bound;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use serde_json::json;

use crate::cid::generate_dag_pb_cid_from_bytes;
use crate::descriptors::{records::write_fields, Records};
use crate::dwn::Handler;
use crate::errors::{DataStoreError, MessageStoreError, StoreError};
use crate::filters::Records as RecordsFilter;
use crate::stores::durable_event_log::DurableEventLog;
use crate::stores::memory::MemoryMessageStore;
use crate::stores::occupancy::{is_occupant, occupant_ids_for_rows};
use crate::stores::replication_feed_reader::build_token;
use crate::stores::wake::{InProcessWakeBus, Wake, WakeError, WakePublisher};
use crate::stores::{
    DataStore, DataStoreGetResult, DataStorePutResult, EventLog, EventLogReadOptions, KeyValues,
    LatestStateTransition, LatestStateTransitionResult, MessageQueryResult, MessageStore,
    RecordLimitOccupancy, ReplicationFeedReader, SubscriptionErrorCode, SubscriptionMessage,
};
use crate::{
    permissions, Filter, FilterKey, Filters, MapValue, Message, MessageSort, Pagination,
    RangeFilter, SortDirection,
};
use crate::{Descriptor, Value};

use super::common::*;
use super::control::repair::{
    control_config_validity, verify_stored_create_action, ControlConfigValidity,
};
use super::subscribe::{
    authorize_records_delivery, DeliveryAuthorization, RecordsEventLogSubscribeHandler,
    RecordsSubscribeHandler,
};
use super::*;
use crate::handlers::configure::ProtocolsConfigureHandler;

mod control;

/// Drives a resumable delete the way a resume actually does: through the
/// controller that owns the stores, not a free function taking them.
async fn resume_delete(
    message_store: &TestMessageStore,
    data_store: &TestDataStore,
    message: &Message<Descriptor>,
) -> Result<(), String> {
    crate::tasks::controller::StorageController::new(message_store.clone(), data_store.clone())
        .perform_records_delete(crate::tasks::controller::ResumableRecordsDeleteData {
            tenant: "did:example:alice".to_string(),
            message: message.clone(),
        })
        .await
}

#[derive(Clone, Default)]
struct RecordingWakePublisher {
    wakes: Arc<Mutex<Vec<(String, u64)>>>,
}

impl RecordingWakePublisher {
    fn positions(&self) -> Vec<u64> {
        self.wakes
            .lock()
            .unwrap()
            .iter()
            .map(|(_, position)| *position)
            .collect()
    }
}

impl WakePublisher for RecordingWakePublisher {
    fn publish(&self, wake: Wake) -> Result<(), WakeError> {
        self.wakes
            .lock()
            .unwrap()
            .push((wake.tenant, wake.position));
        Ok(())
    }
}

#[tokio::test]
async fn records_write_read_query_and_count_published_inline_data() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;

    let write_handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let read_handler = RecordsReadHandler::new(message_store.clone(), data_store.clone(), None);
    let query_handler = RecordsQueryHandler::new(message_store.clone(), None);
    let count_handler = RecordsCountHandler::new(message_store.clone(), None);

    let data = Bytes::from_static(b"hello world");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let write = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let record_id = write["recordId"].as_str().unwrap().to_string();

    let reply = write_handler
        .run("did:example:alice", &write, Some(data.clone()))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let query = unsigned_query_message(json!({ "published": true }));
    let reply = query_handler.run("did:example:alice", &query, None).await;
    assert_eq!(reply.status.code, 200);
    let entries = reply.reply.entries.as_ref().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = serde_json::to_value(&entries[0]).unwrap();
    assert_eq!(
        entry["encodedData"].as_str(),
        Some(URL_SAFE_NO_PAD.encode(&data).as_str()),
    );

    let count = unsigned_count_message(json!({ "published": true }));
    let reply = count_handler.run("did:example:alice", &count, None).await;
    assert_eq!(reply.status.code, 200);
    assert_eq!(reply.reply.count, Some(1));

    let read = unsigned_read_message(json!({ "recordId": record_id }));
    let reply = read_handler.run("did:example:alice", &read, None).await;
    assert_eq!(reply.status.code, 200);
    assert_eq!(
        reply.reply.entry.as_ref().unwrap().encoded_data.as_deref(),
        Some(URL_SAFE_NO_PAD.encode(&data).as_str())
    );
}

#[tokio::test]
async fn records_write_update_without_data_copies_previous_inline_data_and_keeps_initial() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let data = Bytes::from_static(b"version one");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let initial = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    let context_id = initial["contextId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run("did:example:alice", &initial, Some(data.clone()))
            .await
            .status
            .code,
        202
    );

    let update = signed_write_message(WriteSpec {
        record_id: Some(record_id.clone()),
        context_id: Some(context_id),
        data_cid,
        data_size: data.len() as u64,
        date_created: "2025-01-01T00:00:00.000000Z".to_string(),
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    })
    .await;
    let reply = handler.run("did:example:alice", &update, None).await;
    assert_eq!(reply.status.code, 202);

    let stored = fetch_record_messages("did:example:alice", &record_id, &message_store)
        .await
        .unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(
        stored
            .iter()
            .filter(|message| write_fields(message)
                .ok()
                .and_then(|fields| fields.encoded_data.as_ref())
                .is_some())
            .count(),
        1
    );
}

#[tokio::test]
async fn records_write_missing_initial_is_repairable_after_dependency_arrives() {
    // Covers: DWN-SYNC-002
    // Covers: DWN-AUTH-006
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let initial = signed_write_message(WriteSpec::new("2025-01-01T00:00:00.000000Z")).await;
    let update = signed_write_message(WriteSpec {
        record_id: Some(initial["recordId"].as_str().unwrap().to_string()),
        context_id: Some(initial["contextId"].as_str().unwrap().to_string()),
        date_created: "2025-01-01T00:00:00.000000Z".to_string(),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    })
    .await;
    let reply = handler.run("did:example:alice", &update, None).await;

    assert_eq!(reply.status.code, 400);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("RecordsWriteGetInitialWriteNotFound")
    );

    let reply = handler
        .run("did:example:alice", &initial, Some(Bytes::new()))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    let reply = handler
        .run("did:example:alice", &update, Some(Bytes::new()))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
    assert_eq!(
        fetch_record_messages(
            "did:example:alice",
            initial["recordId"].as_str().unwrap(),
            &message_store
        )
        .await
        .unwrap()
        .len(),
        2
    );
}

#[tokio::test]
async fn records_write_preserves_structured_commit_validation_errors() {
    // Covers: DWN-REC-002, DWN-SYNC-002
    const TENANT: &str = "did:example:alice";

    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store,
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let data = Bytes::from_static(b"structured validation");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let initial = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    let context_id = initial["contextId"].as_str().unwrap().to_string();
    assert_eq!(
        handler.run(TENANT, &initial, Some(data)).await.status.code,
        202
    );

    let cases = [
        (
            WriteSpec {
                record_id: Some(record_id.clone()),
                context_id: Some(context_id.clone()),
                date_created: "2025-01-01T00:00:00.000000Z".to_string(),
                recipient: Some("did:example:bob".to_string()),
                data_cid: data_cid.clone(),
                data_size: b"structured validation".len() as u64,
                ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
            },
            "RecordsWriteImmutablePropertyChanged",
        ),
        (
            WriteSpec {
                record_id: Some(record_id.clone()),
                context_id: Some(context_id.clone()),
                date_created: "2025-01-01T00:00:00.000000Z".to_string(),
                data_cid: generate_dag_pb_cid_from_bytes(b"different").to_string(),
                data_size: b"structured validation".len() as u64,
                ..WriteSpec::new("2025-01-01T00:02:00.000000Z")
            },
            "RecordsWriteDataCidMismatch",
        ),
        (
            WriteSpec {
                record_id: Some(record_id.clone()),
                context_id: Some(context_id.clone()),
                date_created: "2025-01-01T00:00:00.000000Z".to_string(),
                data_cid: data_cid.clone(),
                data_size: b"structured validation".len() as u64 + 1,
                ..WriteSpec::new("2025-01-01T00:03:00.000000Z")
            },
            "RecordsWriteDataSizeMismatch",
        ),
    ];

    for (spec, expected_code) in cases {
        let update = signed_write_message(spec).await;
        let reply = handler.run(TENANT, &update, None).await;
        assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
        assert_eq!(reply.status.error_code.as_deref(), Some(expected_code));
    }
}

#[tokio::test]
async fn records_write_retains_initial_feed_position_without_extra_wake() {
    const TENANT: &str = "did:example:alice";

    let publisher = RecordingWakePublisher::default();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let data = Bytes::from_static(b"version one");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let initial = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let initial_message: Message<Descriptor> = serde_json::from_value(initial.clone()).unwrap();
    let initial_cid = message_cid(&initial_message).unwrap();
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    let context_id = initial["contextId"].as_str().unwrap().to_string();
    let reply = handler.run(TENANT, &initial, Some(data.clone())).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let update = signed_write_message(WriteSpec {
        record_id: Some(record_id),
        context_id: Some(context_id),
        data_cid,
        data_size: data.len() as u64,
        date_created: "2025-01-01T00:00:00.000000Z".to_string(),
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    })
    .await;
    let reply = handler.run(TENANT, &update, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let feed = message_store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .unwrap();
    let retained = feed
        .events
        .iter()
        .find(|entry| entry.message_cid.as_deref() == Some(initial_cid.as_str()))
        .expect("initial write remains in feed");
    assert_eq!(retained.seq, "2");
    assert_eq!(feed.cursor.unwrap().position, "3");
    assert_eq!(publisher.positions(), [1, 2, 3]);
}

#[tokio::test]
async fn records_write_data_bearing_exact_replay_is_non_mutating() {
    // Covers: DWN-REC-003
    // Covers: DWN-REC-005
    // Covers: DWN-REC-006
    const TENANT: &str = "did:example:alice";

    let publisher = RecordingWakePublisher::default();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let data = Bytes::from_static(b"data arriving after the signed operation");
    let write = signed_write_message(WriteSpec {
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let message: Message<Descriptor> = serde_json::from_value(write.clone()).unwrap();
    let cid = message_cid(&message).unwrap();

    let reply = handler.run(TENANT, &write, None).await;
    assert_eq!(reply.status.code, 204, "{}", reply.status.detail);

    let reply = handler.run(TENANT, &write, Some(data.clone())).await;
    assert_eq!(reply.status.code, 409, "{}", reply.status.detail);

    let feed = message_store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .unwrap();
    assert_eq!(feed.events.len(), 2);
    assert_eq!(feed.cursor.unwrap().position, "2");
    assert_eq!(publisher.positions(), [1, 2]);
    assert!(
        write_fields(&message_store.get(TENANT, &cid).await.unwrap().unwrap())
            .unwrap()
            .encoded_data
            .is_none()
    );
}

/// Resolver whose every lookup fails, standing in for a signer DID whose
/// document has become unreachable since the message was first admitted.
struct UnavailableResolver;

impl crate::auth::resolver::DidResolver for UnavailableResolver {
    fn resolve<'a>(
        &'a self,
        _did: &'a str,
    ) -> crate::auth::resolver::ResolverFuture<
        'a,
        Result<crate::auth::resolver::Resolution, crate::auth::resolver::ResolverError>,
    > {
        Box::pin(async { Err(crate::auth::resolver::ResolverError::NotFound) })
    }
}

#[tokio::test]
async fn exact_replay_returns_conflict_without_resolving_the_signer() {
    // Covers: DWN-REC-003
    // An identical retained CID is classified from the parsed message alone.
    // Re-resolving the signer of bytes the store already admitted proves
    // nothing, so an unreachable resolver must not turn a settled replay into
    // a 401, nor produce any storage or feed effect.
    const TENANT: &str = "did:example:alice";

    let publisher = RecordingWakePublisher::default();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;

    let write = signed_write_message(WriteSpec {
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;

    let admitted = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let reply = admitted.run(TENANT, &write, None).await;
    assert_eq!(reply.status.code, 204, "{}", reply.status.detail);

    let feed_after_admit = message_store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .unwrap();
    let wakes_after_admit = publisher.positions();

    // Same tenant and stores, but the signer's DID no longer resolves.
    let degraded = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(UnavailableResolver)),
    );
    let reply = degraded.run(TENANT, &write, None).await;
    assert_eq!(
        reply.status.code, 409,
        "replay must be settled before resolution: {}",
        reply.status.detail
    );

    let feed_after_replay = message_store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .unwrap();
    assert_eq!(
        feed_after_replay.events.len(),
        feed_after_admit.events.len(),
        "replay must not append a feed entry"
    );
    assert_eq!(
        feed_after_replay.cursor.map(|cursor| cursor.position),
        feed_after_admit.cursor.map(|cursor| cursor.position),
        "replay must not advance the feed cursor"
    );
    assert_eq!(
        publisher.positions(),
        wakes_after_admit,
        "replay must not publish a wake"
    );

    // A non-identical write from the same unresolvable signer still needs
    // authentication: the shortcut covers retained identical messages only.
    let different = signed_write_message(WriteSpec {
        published: Some(true),
        ..WriteSpec::new("2025-01-02T00:00:00.000000Z")
    })
    .await;
    let reply = degraded.run(TENANT, &different, None).await;
    assert_ne!(
        reply.status.code, 409,
        "only retained identical messages bypass authentication"
    );
}

// Covers: DWN-AUTH-001, DWN-PROTO-003
// An owner countersignature used to be carried along unexamined, so anyone
// could append one and claim the tenant had endorsed their write. It is now
// verified in the same place as the author signature, which is what keeps
// signer, author and owner distinct rather than merely declared.
//
// Both forgeries are signed by a DID the resolver actually knows, so neither
// can be turned away at resolution before the checks under test run, and each
// breaks exactly one commitment: the first is genuinely signed but endorses a
// different descriptor, the second endorses this descriptor but is not really
// signed. Either alone would still pass if the other check were the only one
// working.
#[tokio::test]
async fn a_forged_owner_countersignature_is_rejected() {
    const TENANT: &str = "did:example:alice";

    async fn admit(message: &serde_json::Value) -> crate::Response<crate::replies::records::Write> {
        let mut message_store = MemoryMessageStore::default();
        let mut data_store = TestDataStore::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        put_notes_protocol_without_actions(TENANT, &message_store).await;
        RecordsWriteHandler::<_, _>::new(message_store, data_store, Some(Arc::new(test_resolver())))
            .run(TENANT, message, None)
            .await
    }

    /// Countersigns `write` as Bob — a resolvable signer — over `descriptor_cid`.
    async fn counter_signed(write: &serde_json::Value, descriptor_cid: &str) -> serde_json::Value {
        let payload = serde_json::to_vec(&json!({ "descriptorCid": descriptor_cid })).unwrap();
        let signature = crate::auth::Jws::create(payload.as_slice(), &[bob_signer()])
            .await
            .unwrap();
        let mut counter_signed = write.clone();
        counter_signed["authorization"]["ownerSignature"] =
            serde_json::to_value(signature).unwrap();
        counter_signed
    }

    let write = signed_write_message(WriteSpec {
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;

    // The descriptor commitment the author already signed.
    let author_payload: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                write["authorization"]["signature"]["payload"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let descriptor_cid = author_payload["descriptorCid"].as_str().unwrap();

    // Genuinely signed, but endorsing some other descriptor.
    let wrong_commitment =
        counter_signed(&write, "bafkreiforgeddescriptorcidthatmatchesnothing").await;

    // Endorses this descriptor, but the signature bytes are not Bob's.
    let mut bad_signature = counter_signed(&write, descriptor_cid).await;
    bad_signature["authorization"]["ownerSignature"]["signatures"][0]["signature"] =
        json!(URL_SAFE_NO_PAD.encode([0u8; 64]));

    // Each submission runs against its own store, so none can be a replay of
    // another and the countersignature is the only difference from the baseline.
    let baseline = admit(&write).await;
    assert_eq!(
        baseline.status.code, 204,
        "the same write without a countersignature must be admissible: {}",
        baseline.status.detail
    );

    // The expected reason is asserted, not just the rejection: each forgery
    // must be caught by the check it actually defeats, so neither check can
    // silently stop working behind the other.
    for (label, message, expected_reason) in [
        (
            "endorses a different descriptor",
            wrong_commitment,
            "cid mismatch",
        ),
        (
            "is not really signed",
            bad_signature,
            "Signature verification failed",
        ),
    ] {
        let reply = admit(&message).await;
        assert!(
            reply.status.code >= 400,
            "owner countersignature that {label} must not be admitted, got {} {}",
            reply.status.code,
            reply.status.detail
        );
        assert!(
            reply.status.detail.contains(expected_reason),
            "{label} must be rejected with '{expected_reason}', got: {}",
            reply.status.detail
        );
    }

    // An owner-delegated grant with nothing countersigning it delegates
    // nothing. This is the owner side of the same binding the author side
    // enforces, so it also confirms the shared validator is reached with the
    // owner's signature rather than the author's.
    let mut dangling_grant = write.clone();
    dangling_grant["authorization"]["ownerDelegatedGrant"] = write.clone();
    let reply = admit(&dangling_grant).await;
    assert!(
        reply.status.code >= 400,
        "an ownerDelegatedGrant without an ownerSignature must not be admitted, got {} {}",
        reply.status.code,
        reply.status.detail
    );
}

#[tokio::test]
async fn stale_initial_data_replay_cannot_replace_an_update_or_resurrect_a_delete() {
    // Covers: DWN-REC-003
    // Covers: DWN-REC-005
    // Covers: ENBOX-REC-001
    const TENANT: &str = "did:example:alice";

    for tombstoned in [false, true] {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        put_notes_protocol_without_actions(TENANT, &message_store).await;
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

        let data = Bytes::from_static(b"late initial data");
        let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
        let initial = signed_write_message(WriteSpec {
            data_cid: data_cid.clone(),
            data_size: data.len() as u64,
            published: Some(true),
            ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
        })
        .await;
        let record_id = initial["recordId"].as_str().unwrap().to_string();
        let context_id = initial["contextId"].as_str().unwrap().to_string();
        let initial_message: Message<Descriptor> = serde_json::from_value(initial.clone()).unwrap();
        let initial_cid = message_cid(&initial_message).unwrap();
        assert_eq!(
            write_handler.run(TENANT, &initial, None).await.status.code,
            204
        );

        let winner = if tombstoned {
            let delete =
                signed_delete_message(&record_id, false, "2025-01-01T00:05:00.000000Z").await;
            assert_eq!(
                delete_handler.run(TENANT, &delete, None).await.status.code,
                202
            );
            serde_json::from_value::<Message<Descriptor>>(delete).unwrap()
        } else {
            let update = signed_write_message(WriteSpec {
                record_id: Some(record_id.clone()),
                context_id: Some(context_id),
                data_cid,
                data_size: data.len() as u64,
                date_created: "2025-01-01T00:00:00.000000Z".to_string(),
                published: Some(true),
                ..WriteSpec::new("2025-01-01T00:05:00.000000Z")
            })
            .await;
            assert_eq!(
                write_handler
                    .run(TENANT, &update, Some(data.clone()))
                    .await
                    .status
                    .code,
                202
            );
            serde_json::from_value::<Message<Descriptor>>(update).unwrap()
        };
        let winner_cid = message_cid(&winner).unwrap();

        let reply = write_handler
            .run(TENANT, &initial, Some(data.clone()))
            .await;
        assert_eq!(reply.status.code, 409, "{}", reply.status.detail);

        let rows = message_store.rows.read().unwrap();
        let record_rows = rows
            .iter()
            .filter(|row| message_record_id(&row.message).as_deref() == Some(record_id.as_str()))
            .collect::<Vec<_>>();
        let latest = record_rows
            .iter()
            .filter(|row| row.indexes.get("isLatestBaseState") == Some(&Value::Bool(true)))
            .collect::<Vec<_>>();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].cid, winner_cid);
        let retained_initial = record_rows
            .iter()
            .find(|row| row.cid == initial_cid)
            .unwrap();
        assert!(write_fields(&retained_initial.message)
            .unwrap()
            .encoded_data
            .is_none());
    }
}

#[tokio::test]
async fn records_delete_retains_initial_feed_position_without_extra_wake() {
    const TENANT: &str = "did:example:alice";

    let publisher = RecordingWakePublisher::default();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(publisher.clone());
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;
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

    let data = Bytes::from_static(b"version one");
    let initial = signed_write_message(WriteSpec {
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let initial_message: Message<Descriptor> = serde_json::from_value(initial.clone()).unwrap();
    let initial_cid = message_cid(&initial_message).unwrap();
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    let reply = write_handler.run(TENANT, &initial, Some(data)).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let delete = signed_delete_message(&record_id, false, "2025-01-01T00:01:00.000000Z").await;
    let reply = delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let feed = message_store
        .log_read(TENANT, EventLogReadOptions::default())
        .await
        .unwrap();
    let retained = feed
        .events
        .iter()
        .find(|entry| entry.message_cid.as_deref() == Some(initial_cid.as_str()))
        .expect("initial write remains in feed");
    assert_eq!(retained.seq, "2");
    assert_eq!(feed.cursor.unwrap().position, "3");
    assert_eq!(publisher.positions(), [1, 2, 3]);
}

#[tokio::test]
async fn records_delete_older_than_current_write_wins_in_both_arrival_orders() {
    // Covers: DWN-REC-004
    // Covers: DWN-REC-005
    // Covers: ENBOX-REC-001
    const TENANT: &str = "did:example:alice";

    let data = Bytes::from_static(b"delete-wins payload");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let initial = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    let context_id = initial["contextId"].as_str().unwrap().to_string();
    let newer_write = signed_write_message(WriteSpec {
        record_id: Some(record_id.clone()),
        context_id: Some(context_id),
        data_cid,
        data_size: data.len() as u64,
        date_created: "2025-01-01T00:00:00.000000Z".to_string(),
        published: Some(true),
        ..WriteSpec::new("2025-01-12T00:00:00.000000Z")
    })
    .await;
    let older_delete =
        signed_delete_message(&record_id, false, "2025-01-11T00:00:00.000000Z").await;
    let newer_write_cid =
        message_cid(&serde_json::from_value::<Message<Descriptor>>(newer_write.clone()).unwrap())
            .unwrap();
    let delete_cid =
        message_cid(&serde_json::from_value::<Message<Descriptor>>(older_delete.clone()).unwrap())
            .unwrap();

    for delete_first in [false, true] {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        put_notes_protocol_without_actions(TENANT, &message_store).await;
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
        assert_eq!(
            write_handler
                .run(TENANT, &initial, Some(data.clone()),)
                .await
                .status
                .code,
            202
        );

        let statuses = if delete_first {
            let delete = delete_handler
                .run(TENANT, &older_delete, None)
                .await
                .status
                .code;
            let write_reply = write_handler.run(TENANT, &newer_write, None).await;
            assert_eq!(
                write_reply.status.error_code.as_deref(),
                Some("RecordsWriteNotAllowedAfterDelete")
            );
            [delete, write_reply.status.code]
        } else {
            let write = write_handler
                .run(TENANT, &newer_write, None)
                .await
                .status
                .code;
            let delete = delete_handler
                .run(TENANT, &older_delete, None)
                .await
                .status
                .code;
            [write, delete]
        };
        assert_eq!(statuses, [202, if delete_first { 400 } else { 202 }]);

        let retained = fetch_record_messages(TENANT, &record_id, &message_store)
            .await
            .unwrap();
        let retained_cids = retained
            .iter()
            .map(message_cid)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(retained_cids.contains(&delete_cid));
        assert!(!retained_cids.contains(&newer_write_cid));
    }
}

#[tokio::test]
async fn records_prune_wins_over_newer_plain_delete_in_both_arrival_orders() {
    // Covers: DWN-REC-004
    // Covers: ENBOX-REC-001
    const TENANT: &str = "did:example:alice";

    let data = Bytes::from_static(b"prune-wins payload");
    let initial = signed_write_message(WriteSpec {
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    let older_prune = signed_delete_message(&record_id, true, "2025-01-11T00:00:00.000000Z").await;
    let newer_delete =
        signed_delete_message(&record_id, false, "2025-01-12T00:00:00.000000Z").await;
    let prune_cid =
        message_cid(&serde_json::from_value::<Message<Descriptor>>(older_prune.clone()).unwrap())
            .unwrap();
    let plain_cid =
        message_cid(&serde_json::from_value::<Message<Descriptor>>(newer_delete.clone()).unwrap())
            .unwrap();

    for prune_first in [false, true] {
        let mut message_store = TestMessageStore::default();
        let mut data_store = TestDataStore::default();
        message_store.open().await.unwrap();
        data_store.open().await.unwrap();
        put_notes_protocol_without_actions(TENANT, &message_store).await;
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
        assert_eq!(
            write_handler
                .run(TENANT, &initial, Some(data.clone()),)
                .await
                .status
                .code,
            202
        );

        let statuses = if prune_first {
            let prune = delete_handler
                .run(TENANT, &older_prune, None)
                .await
                .status
                .code;
            let plain = delete_handler
                .run(TENANT, &newer_delete, None)
                .await
                .status
                .code;
            [prune, plain]
        } else {
            let plain = delete_handler
                .run(TENANT, &newer_delete, None)
                .await
                .status
                .code;
            let prune = delete_handler
                .run(TENANT, &older_prune, None)
                .await
                .status
                .code;
            [plain, prune]
        };
        assert_eq!(statuses, [202, if prune_first { 409 } else { 202 }]);

        let retained_cids = fetch_record_messages(TENANT, &record_id, &message_store)
            .await
            .unwrap()
            .iter()
            .map(message_cid)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(retained_cids.contains(&prune_cid));
        assert!(!retained_cids.contains(&plain_cid));
    }
}

#[tokio::test]
async fn records_write_rejects_older_conflicting_write() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let data = Bytes::from_static(b"newest");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let initial = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:10:00.000000Z")
    })
    .await;
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    let context_id = initial["contextId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run("did:example:alice", &initial, Some(data.clone()))
            .await
            .status
            .code,
        202
    );

    let older = signed_write_message(WriteSpec {
        record_id: Some(record_id),
        context_id: Some(context_id),
        data_cid,
        data_size: data.len() as u64,
        date_created: "2025-01-01T00:10:00.000000Z".to_string(),
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:09:00.000000Z")
    })
    .await;
    let reply = handler.run("did:example:alice", &older, Some(data)).await;
    assert_eq!(reply.status.code, 409);
}

#[tokio::test]
async fn records_write_exact_replay_is_classified_before_mutable_protocol_validation() {
    // Covers: DWN-REC-003
    // Covers: DWN-AUTH-006
    const TENANT: &str = "did:example:alice";

    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let data = Bytes::from_static(b"admitted before protocol removal");
    let write = signed_write_message(WriteSpec {
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let reply = handler.run(TENANT, &write, Some(data.clone())).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let protocol_cids = message_store
        .rows
        .read()
        .unwrap()
        .iter()
        .filter(|row| matches!(row.message.descriptor, Descriptor::Protocols(_)))
        .map(|row| row.cid.clone())
        .collect::<Vec<_>>();
    for cid in protocol_cids {
        message_store.delete(TENANT, &cid).await.unwrap();
    }

    let reply = handler.run(TENANT, &write, Some(data)).await;
    assert_eq!(reply.status.code, 409, "{}", reply.status.detail);
    assert_eq!(
        message_store
            .rows
            .read()
            .unwrap()
            .iter()
            .filter(|row| matches!(row.message.descriptor, Descriptor::Records(_)))
            .count(),
        1
    );
}

#[tokio::test]
async fn records_delete_exact_replay_is_classified_before_mutable_protocol_validation() {
    // Covers: DWN-REC-003
    // Covers: DWN-AUTH-006
    // Covers: DWN-SYNC-002
    const TENANT: &str = "did:example:alice";

    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;
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

    let data = Bytes::from_static(b"delete admitted before protocol removal");
    let initial = signed_write_message(WriteSpec {
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let record_id = initial["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .run(TENANT, &initial, Some(data))
            .await
            .status
            .code,
        202
    );

    let delete = signed_delete_message(&record_id, false, "2025-01-01T00:01:00.000000Z").await;
    assert_eq!(
        delete_handler.run(TENANT, &delete, None).await.status.code,
        202
    );
    let records_before = message_store
        .rows
        .read()
        .unwrap()
        .iter()
        .filter(|row| matches!(row.message.descriptor, Descriptor::Records(_)))
        .count();

    let protocol_cids = message_store
        .rows
        .read()
        .unwrap()
        .iter()
        .filter(|row| matches!(row.message.descriptor, Descriptor::Protocols(_)))
        .map(|row| row.cid.clone())
        .collect::<Vec<_>>();
    for cid in protocol_cids {
        message_store.delete(TENANT, &cid).await.unwrap();
    }

    let reply = delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 409, "{}", reply.status.detail);
    let delete_message: Message<Descriptor> = serde_json::from_value(delete).unwrap();
    assert_eq!(
        crate::sync::endpoint::classify_apply_reply(&reply.status, &delete_message, true),
        crate::sync::endpoint::ReplicationApplyOutcome::Duplicate
    );
    assert_eq!(
        message_store
            .rows
            .read()
            .unwrap()
            .iter()
            .filter(|row| matches!(row.message.descriptor, Descriptor::Records(_)))
            .count(),
        records_before
    );
}

#[tokio::test]
async fn records_read_returns_gone_when_external_data_is_missing() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );
    let read_handler = RecordsReadHandler::new(message_store.clone(), data_store.clone(), None);

    let data = Bytes::from(vec![7u8; (MAX_ENCODED_DATA_SIZE + 1) as usize]);
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let write = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let record_id = write["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run("did:example:alice", &write, Some(data))
            .await
            .status
            .code,
        202
    );
    data_store
        .delete("did:example:alice", &record_id, &data_cid)
        .await
        .unwrap();

    let reply = read_handler
        .run(
            "did:example:alice",
            &unsigned_read_message(json!({ "recordId": record_id })),
            None,
        )
        .await;
    assert_eq!(reply.status.code, 410);
}

#[tokio::test]
async fn records_delete_prune_purges_descendant_records() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;
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

    let data = Bytes::from_static(b"parent");
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let parent = signed_write_message(WriteSpec {
        data_cid,
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let parent_record_id = parent["recordId"].as_str().unwrap().to_string();
    let parent_context_id = parent["contextId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .run("did:example:alice", &parent, Some(data))
            .await
            .status
            .code,
        202
    );

    let child_data = Bytes::from_static(b"child");
    let child_data_cid = generate_dag_pb_cid_from_bytes(&child_data).to_string();
    let child = signed_write_message(WriteSpec {
        parent_id: Some(parent_record_id.clone()),
        parent_context_id: Some(parent_context_id),
        data_cid: child_data_cid,
        data_size: child_data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    })
    .await;
    let child_record_id = child["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .run("did:example:alice", &child, Some(child_data))
            .await
            .status
            .code,
        202
    );

    let delete =
        signed_delete_message(&parent_record_id, true, "2025-01-01T00:02:00.000000Z").await;
    let reply = delete_handler.run("did:example:alice", &delete, None).await;
    assert_eq!(reply.status.code, 202);

    let child_messages =
        fetch_record_messages("did:example:alice", &child_record_id, &message_store)
            .await
            .unwrap();
    assert!(child_messages.is_empty());
}

#[tokio::test]
async fn records_delete_cleanup_failure_is_safe_and_resumable() {
    // Covers: DWN-REC-006
    const TENANT: &str = "did:example:alice";

    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;
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

    let data = Bytes::from(vec![7u8; (MAX_ENCODED_DATA_SIZE + 1) as usize]);
    let data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
    let write = signed_write_message(WriteSpec {
        data_cid: data_cid.clone(),
        data_size: data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let record_id = write["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .run(TENANT, &write, Some(data))
            .await
            .status
            .code,
        202
    );

    let delete = signed_delete_message(&record_id, false, "2025-01-01T00:01:00.000000Z").await;
    let delete_message: Message<Descriptor> = serde_json::from_value(delete.clone()).unwrap();
    data_store.fail_delete.store(true, Ordering::SeqCst);
    let reply = delete_handler.run(TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 500, "{}", reply.status.detail);

    let retained = fetch_record_messages(TENANT, &record_id, &message_store)
        .await
        .unwrap();
    assert_eq!(newest_message(&retained), Some(delete_message.clone()));
    assert!(data_store
        .get(TENANT, &record_id, &data_cid)
        .await
        .unwrap()
        .is_some());

    data_store.fail_delete.store(false, Ordering::SeqCst);
    resume_delete(&message_store, &data_store, &delete_message)
        .await
        .unwrap();
    assert!(data_store
        .get(TENANT, &record_id, &data_cid)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        newest_message(
            &fetch_record_messages(TENANT, &record_id, &message_store)
                .await
                .unwrap()
        ),
        Some(delete_message)
    );
}

#[tokio::test]
async fn superseded_prune_task_rechecks_winner_and_does_not_purge_descendants() {
    // Covers: DWN-REC-004
    // Covers: DWN-REC-006
    // Covers: ENBOX-REC-001
    const TENANT: &str = "did:example:alice";

    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;
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

    let parent_data = Bytes::from_static(b"parent");
    let parent = signed_write_message(WriteSpec {
        data_cid: generate_dag_pb_cid_from_bytes(&parent_data).to_string(),
        data_size: parent_data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let parent_record_id = parent["recordId"].as_str().unwrap().to_string();
    let parent_context_id = parent["contextId"].as_str().unwrap().to_string();
    assert_eq!(
        write_handler
            .run(TENANT, &parent, Some(parent_data))
            .await
            .status
            .code,
        202
    );

    let losing_prune =
        signed_delete_message(&parent_record_id, true, "2025-01-01T00:01:00.000000Z").await;
    let winning_prune =
        signed_delete_message(&parent_record_id, true, "2025-01-01T00:02:00.000000Z").await;
    assert_eq!(
        delete_handler
            .run(TENANT, &winning_prune, None)
            .await
            .status
            .code,
        202
    );

    // Model descendant work appearing after the winning task completed. A stale task must
    // not repeat destructive work merely because its message was once runnable.
    let child = signed_write_message(WriteSpec {
        parent_id: Some(parent_record_id.clone()),
        parent_context_id: Some(parent_context_id),
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:03:00.000000Z")
    })
    .await;
    let child_record_id = child["recordId"].as_str().unwrap().to_string();
    let child_message: Message<Descriptor> = serde_json::from_value(child).unwrap();
    let child_author = extract_author(&child_message).unwrap();
    let child_indexes = records_write_indexes(&child_message, &child_author, true).unwrap();
    message_store
        .put(TENANT, child_message, child_indexes)
        .await
        .unwrap();

    let losing_prune: Message<Descriptor> = serde_json::from_value(losing_prune).unwrap();
    resume_delete(&message_store, &data_store, &losing_prune)
        .await
        .unwrap();
    assert!(
        !fetch_record_messages(TENANT, &child_record_id, &message_store)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn records_write_squash_purges_older_sibling_records_and_sets_backstop() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_squash_protocol("did:example:alice", &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );

    let old_data = Bytes::from_static(b"old note");
    let old = signed_write_message(WriteSpec {
        protocol: "http://example.com/notes".to_string(),
        protocol_path: "note".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&old_data).to_string(),
        data_size: old_data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let old_record_id = old["recordId"].as_str().unwrap().to_string();
    let resp = handler.run("did:example:alice", &old, Some(old_data)).await;

    assert_eq!(resp.status.code, 202, "{}", resp.status.detail);

    let squash_data = Bytes::from_static(b"snapshot");
    let squash = signed_write_message(WriteSpec {
        protocol: "http://example.com/notes".to_string(),
        protocol_path: "note".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&squash_data).to_string(),
        data_size: squash_data.len() as u64,
        published: Some(true),
        squash: Some(true),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    })
    .await;
    assert_eq!(
        handler
            .run("did:example:alice", &squash, Some(squash_data))
            .await
            .status
            .code,
        202
    );
    assert!(
        fetch_record_messages("did:example:alice", &old_record_id, &message_store)
            .await
            .unwrap()
            .is_empty()
    );

    let late_old_data = Bytes::from_static(b"late old");
    let late_old = signed_write_message(WriteSpec {
        protocol: "http://example.com/notes".to_string(),
        protocol_path: "note".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&late_old_data).to_string(),
        data_size: late_old_data.len() as u64,
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:30.000000Z")
    })
    .await;
    let reply = handler
        .run("did:example:alice", &late_old, Some(late_old_data))
        .await;
    assert_eq!(reply.status.code, 409);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationSquashBackstop")
    );
    assert_eq!(
        reply
            .status
            .info
            .as_ref()
            .and_then(|info| info.get("squashFloorTimestamp")),
        Some(&json!("2025-01-01T00:01:00.000000Z"))
    );
}

#[tokio::test]
async fn records_write_accepts_permission_grant_id_and_enforces_publication_condition() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;

    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"},"conditions":{"publication":"Required"}}"#);
    let grant = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some("did:example:bob".to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        published: Some(true),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run("did:example:alice", &grant, Some(grant_data.clone()))
            .await
            .status
            .code,
        202
    );
    let unpublished_data = Bytes::from_static(b"unpublished note");
    let unpublished = signed_write_message(WriteSpec {
        author: "did:example:bob".to_string(),
        signer: bob_signer(),
        protocol: "http://example.com/notes".to_string(),
        protocol_path: "note".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&unpublished_data).to_string(),
        data_size: unpublished_data.len() as u64,
        permission_grant_id: Some(grant_id.clone()),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    })
    .await;
    let reply = handler
        .run("did:example:alice", &unpublished, Some(unpublished_data))
        .await;
    assert_eq!(reply.status.code, 401, "{}", reply.status.detail);
    assert!(
        reply.status.detail.contains("grant is not published"),
        "{}",
        reply.status.detail
    );

    let published_data = Bytes::from_static(b"published note");
    let published = signed_write_message(WriteSpec {
        author: "did:example:bob".to_string(),
        signer: bob_signer(),
        protocol: "http://example.com/notes".to_string(),
        protocol_path: "note".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&published_data).to_string(),
        data_size: published_data.len() as u64,
        published: Some(true),
        permission_grant_id: Some(grant_id),
        ..WriteSpec::new("2025-01-01T00:02:00.000000Z")
    })
    .await;
    let reply = handler
        .run("did:example:alice", &published, Some(published_data))
        .await;
    assert_eq!(reply.status.code, 202);
}

#[tokio::test]
async fn permissions_request_grant_and_revocation_reject_updates() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();

    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );
    let scope = r#"{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"}"#;
    let tags = Some(MapValue::from([(
        "protocol".to_string(),
        Value::String("http://example.com/notes".to_string()),
    )]));
    let grant_data = Bytes::from(format!(
        r#"{{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{scope}}}"#
    ));
    let grant = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some("did:example:bob".to_string()),
        tags: tags.clone(),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run("did:example:alice", &grant, Some(grant_data.clone()))
            .await
            .status
            .code,
        202
    );

    let request_data = Bytes::from(format!(r#"{{"delegated":false,"scope":{scope}}}"#));
    let request = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_REQUEST_PATH.to_string(),
        tags: tags.clone(),
        data_cid: generate_dag_pb_cid_from_bytes(&request_data).to_string(),
        data_size: request_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    })
    .await;
    assert_eq!(
        handler
            .run("did:example:alice", &request, Some(request_data.clone()))
            .await
            .status
            .code,
        202
    );

    let revocation_data = Bytes::from_static(br#"{"description":"revoke"}"#);
    let revocation = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_REVOCATION_PATH.to_string(),
        parent_id: Some(grant_id.clone()),
        parent_context_id: Some(grant_id),
        tags,
        data_cid: generate_dag_pb_cid_from_bytes(&revocation_data).to_string(),
        data_size: revocation_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:02:00.000000Z")
    })
    .await;
    assert_eq!(
        handler
            .run(
                "did:example:alice",
                &revocation,
                Some(revocation_data.clone())
            )
            .await
            .status
            .code,
        202
    );

    // Covers: DWN-REC-002, DWN-AUTH-006
    for (path, initial, data) in [
        (permissions::PERMISSIONS_REQUEST_PATH, request, request_data),
        (permissions::PERMISSIONS_GRANT_PATH, grant, grant_data),
        (
            permissions::PERMISSIONS_REVOCATION_PATH,
            revocation,
            revocation_data,
        ),
    ] {
        let mut update_spec = WriteSpec::new("2025-01-01T00:03:00.000000Z");
        update_spec.date_created = initial["descriptor"]["dateCreated"]
            .as_str()
            .unwrap()
            .to_string();
        update_spec.record_id = Some(initial["recordId"].as_str().unwrap().to_string());
        update_spec.context_id = Some(initial["contextId"].as_str().unwrap().to_string());
        update_spec.parent_id = initial["descriptor"]["parentId"]
            .as_str()
            .map(str::to_string);
        update_spec.protocol = permissions::PERMISSIONS_PROTOCOL_URI.to_string();
        update_spec.protocol_path = path.to_string();
        update_spec.recipient = initial["descriptor"]["recipient"]
            .as_str()
            .map(str::to_string);
        update_spec.tags = initial["descriptor"]["tags"]
            .as_object()
            .map(|tags| serde_json::from_value(tags.clone().into()).unwrap());
        update_spec.data_cid = generate_dag_pb_cid_from_bytes(&data).to_string();
        update_spec.data_size = data.len() as u64;
        update_spec.data_format = "application/json".to_string();
        let update = signed_write_message(update_spec).await;

        let reply = handler.run("did:example:alice", &update, Some(data)).await;
        assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
        assert_eq!(
            reply.status.error_code.as_deref(),
            Some("ProtocolAuthorizationImmutableRecord")
        );
        assert_eq!(
            reply.status.detail,
            format!(
                "ProtocolAuthorizationImmutableRecord: record at protocol path '{path}' is immutable: updates are not allowed."
            )
        );
    }
}

#[tokio::test]
async fn records_write_accepts_embedded_author_delegated_grant() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;

    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"},"delegated":true}"#);
    let grant = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some("did:example:bob".to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;

    let resp = handler
        .run("did:example:alice", &grant, Some(grant_data.clone()))
        .await;

    assert_eq!(resp.status.code, 202);
    let mut delegated_grant = grant.clone();
    delegated_grant["encodedData"] = serde_json::Value::String(URL_SAFE_NO_PAD.encode(&grant_data));

    let note_data = Bytes::from_static(b"delegated note");
    let note = signed_write_message(WriteSpec {
        author: "did:example:alice".to_string(),
        signer: bob_signer(),
        protocol: "http://example.com/notes".to_string(),
        protocol_path: "note".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&note_data).to_string(),
        data_size: note_data.len() as u64,
        ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
    })
    .await;
    let note = with_author_delegated_grant(note, &delegated_grant, bob_signer()).await;
    let reply = handler
        .run("did:example:alice", &note, Some(note_data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-AUTH-001, DWN-AUTH-004
// A signature over a delegated grant commits to *that* grant's CID. Without
// binding the embedded grant back to the signed id, a perfectly valid
// signature can be paired with an unsigned choice of grant — the signer
// approved some delegation, never this one. The later lifetime, scope and
// grantee checks all run against whichever grant was substituted in, so none
// of them can recover the missing commitment.
#[tokio::test]
async fn an_embedded_delegated_grant_must_be_the_one_that_was_signed() {
    const TENANT: &str = "did:example:alice";

    async fn grant_with(
        handler: &RecordsWriteHandler<TestMessageStore, TestDataStore>,
        data: &'static [u8],
        timestamp: &str,
    ) -> serde_json::Value {
        let data = Bytes::from_static(data);
        let grant = signed_write_message(WriteSpec {
            protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
            protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
            recipient: Some("did:example:bob".to_string()),
            tags: Some(MapValue::from([(
                "protocol".to_string(),
                Value::String("http://example.com/notes".to_string()),
            )])),
            data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
            data_size: data.len() as u64,
            data_format: "application/json".to_string(),
            ..WriteSpec::new(timestamp)
        })
        .await;
        assert_eq!(
            handler
                .run(TENANT, &grant, Some(data.clone()))
                .await
                .status
                .code,
            202
        );
        let mut embedded = grant;
        embedded["encodedData"] = serde_json::Value::String(URL_SAFE_NO_PAD.encode(&data));
        embedded
    }

    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;
    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );

    let signed_grant = grant_with(
        &handler,
        br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"},"delegated":true}"#,
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    // A second, equally valid grant to the same grantee — the one a writer
    // would rather have been given.
    let substituted = grant_with(
        &handler,
        br#"{"dateExpires":"2025-03-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"},"delegated":true}"#,
        "2025-01-01T00:00:30.000000Z",
    )
    .await;
    let undelegated = grant_with(
        &handler,
        br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"},"delegated":false}"#,
        "2025-01-01T00:00:45.000000Z",
    )
    .await;

    let note_data = Bytes::from_static(b"delegated note");
    let note = || async {
        signed_write_message(WriteSpec {
            author: TENANT.to_string(),
            signer: bob_signer(),
            protocol: "http://example.com/notes".to_string(),
            protocol_path: "note".to_string(),
            data_cid: generate_dag_pb_cid_from_bytes(&note_data).to_string(),
            data_size: note_data.len() as u64,
            ..WriteSpec::new("2025-01-01T00:01:00.000000Z")
        })
        .await
    };

    // Baseline: signed over the grant that is actually attached.
    let honest = with_author_delegated_grant(note().await, &signed_grant, bob_signer()).await;
    assert_eq!(
        handler
            .run(TENANT, &honest, Some(note_data.clone()))
            .await
            .status
            .code,
        202,
        "the grant that was signed must be accepted"
    );

    // Signature still commits to `signed_grant`; a different grant is attached.
    let mut swapped = with_author_delegated_grant(note().await, &signed_grant, bob_signer()).await;
    swapped["authorization"]["authorDelegatedGrant"] = substituted;
    let reply = handler.run(TENANT, &swapped, Some(note_data.clone())).await;
    assert!(
        reply.status.code >= 400,
        "an unsigned choice of grant must not be honoured, got {} {}",
        reply.status.code,
        reply.status.detail
    );

    // A grant that was never delegable cannot be delegated with, even when it
    // is the grant that was signed.
    let not_delegated = with_author_delegated_grant(note().await, &undelegated, bob_signer()).await;
    let reply = handler
        .run(TENANT, &not_delegated, Some(note_data.clone()))
        .await;
    assert!(
        reply.status.code >= 400,
        "a non-delegated grant must not authorize a delegate, got {} {}",
        reply.status.code,
        reply.status.detail
    );
}

#[tokio::test]
async fn permissions_revocation_cleans_grant_authorized_messages() {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;

    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );

    let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-02-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Write","protocol":"http://example.com/notes","protocolPath":"note"}}"#);
    let grant = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some("did:example:bob".to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run("did:example:alice", &grant, Some(grant_data))
            .await
            .status
            .code,
        202
    );

    let note_data = Bytes::from_static(b"revoked note");
    let note = signed_write_message(WriteSpec {
        author: "did:example:bob".to_string(),
        signer: bob_signer(),
        protocol: "http://example.com/notes".to_string(),
        protocol_path: "note".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&note_data).to_string(),
        data_size: note_data.len() as u64,
        permission_grant_id: Some(grant_id.clone()),
        ..WriteSpec::new("2025-01-01T00:05:00.000000Z")
    })
    .await;
    let note_record_id = note["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run("did:example:alice", &note, Some(note_data))
            .await
            .status
            .code,
        202
    );

    let revoke_data = Bytes::from_static(br#"{"description":"revoke"}"#);
    let revocation = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_REVOCATION_PATH.to_string(),
        parent_id: Some(grant_id.clone()),
        parent_context_id: Some(grant_id.clone()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&revoke_data).to_string(),
        data_size: revoke_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:04:00.000000Z")
    })
    .await;
    assert_eq!(
        handler
            .run("did:example:alice", &revocation, Some(revoke_data))
            .await
            .status
            .code,
        202
    );

    assert!(
        fetch_record_messages("did:example:alice", &note_record_id, &message_store)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn records_event_log_subscribe_replays_from_cursor_and_sends_eose() {
    const TENANT: &str = "did:example:alice";

    let wake_bus = InProcessWakeBus::new();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    message_store.open().await.unwrap();

    let first_note = stored_note_message("2025-01-01T00:01:00.000000Z").await;
    let second_note = stored_note_message("2025-01-01T00:02:00.000000Z").await;
    let second_cid = message_cid(&second_note).unwrap();
    for note in [&first_note, &second_note] {
        let indexes = records_write_indexes(note, TENANT, true).unwrap();
        message_store
            .put(TENANT, note.clone(), indexes)
            .await
            .unwrap();
    }

    let event_log = DurableEventLog::new(message_store.clone(), wake_bus, None, None);

    let read = EventLog::read(
        &event_log,
        TENANT,
        Some(EventLogReadOptions {
            limit: Some(1),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(read.events.len(), 1);
    let first = read
        .cursor
        .expect("scan cursor after the first committed entry");

    let delivered = Arc::new(RwLock::new(Vec::new()));
    let delivered_for_listener = delivered.clone();
    let handler = RecordsEventLogSubscribeHandler::new(
        message_store,
        event_log,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_records_subscribe_message(
        RecordsFilter {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        },
        Some(first),
        "2025-01-01T00:10:00.000000Z",
    )
    .await;

    let result = handler
        .handle_subscribe(
            "did:example:alice",
            &request,
            Box::new(move |message| delivered_for_listener.write().unwrap().push(message)),
        )
        .await;
    assert_eq!(
        result.reply.status.code, 200,
        "{}",
        result.reply.status.detail
    );
    assert!(result.reply.reply.entries.is_none());
    assert_eq!(
        result.reply.reply.subscription_id.as_deref(),
        Some(result.subscription.as_ref().unwrap().id.as_str())
    );
    let delivered = delivered.read().unwrap();
    assert_eq!(delivered.len(), 2);
    match &delivered[0] {
        SubscriptionMessage::Event { cursor, .. } => {
            assert_eq!(cursor.position, "2");
            assert_eq!(cursor.message_cid.as_deref(), Some(second_cid.as_str()));
        }
        other => panic!("expected event, got {other:?}"),
    }
    match &delivered[1] {
        SubscriptionMessage::Eose { cursor } => {
            assert_eq!(cursor.position, "2");
            assert_eq!(cursor.message_cid.as_deref(), Some(second_cid.as_str()));
        }
        other => panic!("expected eose, got {other:?}"),
    }
}

/// The native/WebSocket subscribe entry point admits messages through the shared ingress
/// rather than a private fork of it, so it rejects exactly what `Dwn::process_message` rejects,
/// with the same reply, and admits exactly what it admits.
#[tokio::test]
async fn records_event_log_subscribe_rejects_through_the_shared_ingress() {
    const TENANT: &str = "did:example:alice";

    let wake_bus = InProcessWakeBus::new();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    message_store.open().await.unwrap();
    let event_log = DurableEventLog::new(message_store.clone(), wake_bus, None, None);
    let handler = RecordsEventLogSubscribeHandler::new(
        message_store,
        event_log,
        Some(Arc::new(test_resolver())),
    );
    let dwn = crate::Dwn::default();

    for raw in [
        serde_json::json!({ "descriptor": { "interface": "Records" } }),
        serde_json::json!({ "descriptor": { "interface": "Records", "method": "Bogus" } }),
        serde_json::json!({ "descriptor": { "interface": "Records", "method": "Subscribe" } }),
    ] {
        let subscribed = handler
            .handle_subscribe(TENANT, &raw, Box::new(|_| {}))
            .await;
        let dispatched = dwn.process_message(TENANT, raw.clone()).await;

        assert_eq!(
            subscribed.reply.status, dispatched.status,
            "subscribe vs dispatch for {raw}"
        );
    }

    // And the accepted side: a message both entry points admit is admitted by both. Dispatch's
    // reply is the lookup-miss 501 (nothing is registered on `Dwn::default()`), so the
    // comparable fact is the ingress verdict, not the status — subscribe gets past ingress
    // and reaches authorization.
    let admitted = signed_records_subscribe_message(
        RecordsFilter {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        },
        None,
        "2025-01-01T00:10:00.000000Z",
    )
    .await;

    assert!(crate::validation::admit_message(&admitted).is_ok());
    let subscribed = handler
        .handle_subscribe(TENANT, &admitted, Box::new(|_| {}))
        .await;
    assert_ne!(
        subscribed.reply.status.code, 400,
        "shared ingress rejected a message it admits: {}",
        subscribed.reply.status.detail
    );
}

#[tokio::test]
async fn records_event_log_subscribe_maps_progress_gap_to_410() {
    const TENANT: &str = "did:example:alice";

    let wake_bus = InProcessWakeBus::new();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    message_store.open().await.unwrap();

    let note = stored_note_message("2025-01-01T00:01:00.000000Z").await;
    let indexes = records_write_indexes(&note, TENANT, true).unwrap();
    message_store
        .put(TENANT, note.clone(), indexes)
        .await
        .unwrap();

    // A token from a superseded feed epoch can never resume; the reader must
    // surface it as a structured progress gap.
    let stale_cursor = build_token(TENANT, "00000000-superseded-epoch", 1, None);

    let event_log = DurableEventLog::new(message_store.clone(), wake_bus, None, None);
    let handler = RecordsEventLogSubscribeHandler::new(
        message_store,
        event_log,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_records_subscribe_message(
        RecordsFilter {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        },
        Some(stale_cursor),
        "2025-01-01T00:10:00.000000Z",
    )
    .await;

    let result = handler
        .handle_subscribe("did:example:alice", &request, Box::new(|_| {}))
        .await;
    assert_eq!(result.reply.status.code, 410);
    let error = result.reply.reply.error.as_ref().unwrap();
    assert_eq!(error.code, crate::stores::ProgressGapCode::ProgressGap);
    assert_eq!(
        error.reason,
        crate::stores::ProgressGapReason::EpochMismatch
    );
    assert!(result.subscription.is_none());
}

#[tokio::test]
async fn records_event_log_subscribe_without_cursor_returns_snapshot_and_live_subscription() {
    const TENANT: &str = "did:example:alice";

    let wake_bus = InProcessWakeBus::new();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    message_store.open().await.unwrap();

    let note = stored_note_message("2025-01-01T00:01:00.000000Z").await;
    let indexes = records_write_indexes(&note, TENANT, true).unwrap();
    message_store
        .put(TENANT, note.clone(), indexes)
        .await
        .unwrap();

    let event_log = DurableEventLog::new(message_store.clone(), wake_bus, None, None);
    let delivered = Arc::new(RwLock::new(Vec::new()));
    let delivered_for_listener = delivered.clone();
    let handler = RecordsEventLogSubscribeHandler::new(
        message_store.clone(),
        event_log,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_records_subscribe_message(
        RecordsFilter {
            protocol: Some("http://example.com/notes".to_string()),
            ..Default::default()
        },
        None,
        "2025-01-01T00:10:00.000000Z",
    )
    .await;

    let result = handler
        .handle_subscribe(
            "did:example:alice",
            &request,
            Box::new(move |message| delivered_for_listener.write().unwrap().push(message)),
        )
        .await;
    assert_eq!(
        result.reply.status.code, 200,
        "{}",
        result.reply.status.detail
    );
    assert_eq!(result.reply.reply.entries.as_ref().unwrap().len(), 1);
    assert!(result.subscription.is_some());

    // Commit after the subscription opened; the wake must trigger a live drain
    // that delivers the new event without an EOSE.
    let live_note = stored_note_message("2025-01-01T00:02:00.000000Z").await;
    let live_indexes = records_write_indexes(&live_note, TENANT, true).unwrap();
    message_store
        .put(TENANT, live_note, live_indexes)
        .await
        .unwrap();

    for _ in 0..500 {
        if !delivered.read().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let delivered = delivered.read().unwrap();
    assert_eq!(delivered.len(), 1);
    assert!(matches!(delivered[0], SubscriptionMessage::Event { .. }));
}

#[test]
fn generic_records_descriptor_deserializes_by_method() {
    let count = json!({
        "interface": "Records",
        "method": "Count",
        "messageTimestamp": "2025-01-01T00:00:00.000000Z",
        "filter": { "published": true }
    });
    let descriptor: Descriptor = serde_json::from_value(count).unwrap();
    assert!(matches!(
        descriptor,
        Descriptor::Records(records) if matches!(records.as_ref(), Records::Count(_))
    ));

    let query = json!({
        "interface": "Records",
        "method": "Query",
        "messageTimestamp": "2025-01-01T00:00:00.000000Z",
        "filter": { "published": true }
    });
    let descriptor: Descriptor = serde_json::from_value(query).unwrap();
    assert!(matches!(
        descriptor,
        Descriptor::Records(records) if matches!(records.as_ref(), Records::Query(_))
    ));
}

use crate::testing::*;

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
    async fn open(&mut self) -> Result<(), MessageStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    fn put<D: crate::descriptors::MessageDescriptor + Send>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
        let rows = self.rows.clone();
        let tenant = tenant.to_string();
        async move {
            let value = serde_json::to_value(&message)?;
            let message: Message<Descriptor> = serde_json::from_value(value)?;
            let cid = message_cid(&message).map_err(test_store_error)?;
            rows.write()
                .unwrap()
                .retain(|row| row.tenant != tenant || row.cid != cid);
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
    ) -> impl Future<Output = Result<Option<Message<Descriptor>>, MessageStoreError>> + Send {
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

    async fn commit_latest_state(
        &self,
        tenant: &str,
        transition: LatestStateTransition,
    ) -> Result<LatestStateTransitionResult, MessageStoreError> {
        transition.validate()?;
        let mut rows = self.rows.write().unwrap();
        for retained in &transition.retains {
            let cid = message_cid(&retained.message).map_err(test_store_error)?;
            if !rows
                .iter()
                .any(|row| row.tenant == tenant && row.cid == cid)
            {
                return Err(test_store_error(format!(
                    "retained message '{cid}' does not exist"
                )));
            }
        }

        for mutation in std::iter::once(transition.put).chain(transition.retains) {
            let cid = message_cid(&mutation.message).map_err(test_store_error)?;
            rows.retain(|row| row.tenant != tenant || row.cid != cid);
            rows.push(TestMessageRow {
                tenant: tenant.to_string(),
                cid,
                message: mutation.message,
                indexes: mutation.indexes,
            });
        }
        rows.retain(|row| row.tenant != tenant || !transition.deletes.contains(&row.cid));
        Ok(LatestStateTransitionResult { position: None })
    }

    fn query(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
        pagination: Option<Pagination>,
        record_limit: Option<RecordLimitOccupancy>,
    ) -> impl Future<Output = Result<MessageQueryResult, MessageStoreError>> + Send {
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
                        .cmp(&value_string(right.indexes.get(property)))
                        .then_with(|| left.cid.cmp(&right.cid));
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
    ) -> Result<u64, MessageStoreError> {
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
    ) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
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

    fn clear(&self) -> impl Future<Output = Result<(), MessageStoreError>> + Send {
        let rows = self.rows.clone();
        async move {
            rows.write().unwrap().clear();
            Ok(())
        }
    }
}

type TestDataKey = (String, String, String);
type TestDataValues = Arc<RwLock<BTreeMap<TestDataKey, Bytes>>>;

#[derive(Clone, Default)]
struct TestDataStore {
    values: TestDataValues,
    fail_delete: Arc<AtomicBool>,
}

impl DataStore for TestDataStore {
    async fn open(&mut self) -> Result<(), DataStoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    fn put<T: Stream<Item = Bytes> + Send + Unpin>(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
        mut data_stream: T,
    ) -> impl Future<Output = Result<DataStorePutResult, DataStoreError>> + Send {
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
            let bytes = Bytes::from(bytes);
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
    ) -> impl Future<Output = Result<Option<DataStoreGetResult>, DataStoreError>> + Send {
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
                    data_stream: Box::pin(stream::iter(vec![Ok(bytes)])),
                }
            }))
        }
    }

    fn delete(
        &self,
        tenant: &str,
        record_id: &str,
        data_cid: &str,
    ) -> impl Future<Output = Result<(), DataStoreError>> + Send {
        let values = self.values.clone();
        let fail_delete = self.fail_delete.clone();
        let key = (
            tenant.to_string(),
            record_id.to_string(),
            data_cid.to_string(),
        );
        async move {
            if fail_delete.load(Ordering::SeqCst) {
                return Err(DataStoreError::StoreError(StoreError::InternalException(
                    "injected data delete failure".to_string(),
                )));
            }
            values.write().unwrap().remove(&key);
            Ok(())
        }
    }

    fn clear(&self) -> impl Future<Output = Result<(), DataStoreError>> + Send {
        let values = self.values.clone();
        async move {
            values.write().unwrap().clear();
            Ok(())
        }
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

fn test_store_error(error: String) -> MessageStoreError {
    MessageStoreError::StoreError(StoreError::InternalException(error))
}

// Covers: DWN-AUTH-005
#[tokio::test]
async fn subscribe_delivery_grant_revoked_is_terminal() {
    const TENANT: &str = "did:example:alice";
    const BOB: &str = "did:example:bob";

    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;

    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );

    // Records.Read grant to bob with far-future expiry: open validates at
    // request time while delivery validates at now, so the grant must cover
    // both for the baseline to establish.
    let grant_data = Bytes::from_static(br#"{"dateExpires":"2030-01-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Read","protocol":"http://example.com/notes","protocolPath":"note"}}"#);
    let grant = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some(BOB.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run(TENANT, &grant, Some(grant_data))
            .await
            .status
            .code,
        202
    );

    let filter = RecordsFilter {
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        ..Default::default()
    };
    let request =
        signed_records_subscribe_message(filter.clone(), None, "2025-01-01T00:10:00.000000Z").await;
    let message: Message<Descriptor> =
        serde_json::from_value(request).expect("subscribe request must deserialize");
    let auth_ctx = crate::permissions::AuthorizationContext {
        signer: BOB.to_string(),
        author: BOB.to_string(),
        payload: crate::permissions::VerifiedAuthorizationPayload::Generic(
            crate::auth::jws::AuthorizationPayloadData {
                descriptor_cid: String::new(),
                delegated_grant_id: None,
                permission_grant_id: Some(grant_id.clone()),
                permission_grant_ids: None,
                protocol_role: None,
            },
        ),
        permission_grant_invocation: crate::auth::jws::PermissionGrantInvocation::Single(
            grant_id.clone(),
        ),
        author_delegated_grant: None,
        owner: None,
    };
    let auth = DeliveryAuthorization {
        message,
        filter,
        auth_ctx,
        grant_valid_at_open: true,
        role_invoked: false,
        request_timestamp: "2025-01-01T00:10:00.000000Z".to_string(),
        control_only: false,
    };

    authorize_records_delivery(TENANT, &auth, &message_store)
        .await
        .expect("live grant must authorize delivery");

    let revoke_data = Bytes::from_static(br#"{"description":"revoke"}"#);
    let revocation = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_REVOCATION_PATH.to_string(),
        parent_id: Some(grant_id.clone()),
        parent_context_id: Some(grant_id.clone()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&revoke_data).to_string(),
        data_size: revoke_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:04:00.000000Z")
    })
    .await;
    assert_eq!(
        handler
            .run(TENANT, &revocation, Some(revoke_data))
            .await
            .status
            .code,
        202
    );

    let error = authorize_records_delivery(TENANT, &auth, &message_store)
        .await
        .expect_err("revoked grant must fail delivery");
    assert_eq!(
        error.code,
        SubscriptionErrorCode::RecordsDeliveryAuthorizationFailed
    );
}

// Covers: DWN-AUTH-005
#[tokio::test]
async fn subscribe_delivery_expired_grant_is_terminal() {
    const TENANT: &str = "did:example:alice";
    const BOB: &str = "did:example:bob";

    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &message_store).await;

    let handler = RecordsWriteHandler::<_, _>::new(
        message_store.clone(),
        data_store.clone(),
        Some(Arc::new(test_resolver())),
    );

    // Expired after the request but before delivery: valid at open (request
    // time), terminal at now. Fixed past dates keep this deterministic.
    let grant_data = Bytes::from_static(br#"{"dateExpires":"2025-06-01T00:00:00.000000Z","scope":{"interface":"Records","method":"Read","protocol":"http://example.com/notes","protocolPath":"note"}}"#);
    let grant = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some(BOB.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String("http://example.com/notes".to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&grant_data).to_string(),
        data_size: grant_data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new("2025-01-01T00:00:00.000000Z")
    })
    .await;
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        handler
            .run(TENANT, &grant, Some(grant_data))
            .await
            .status
            .code,
        202
    );

    let filter = RecordsFilter {
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        ..Default::default()
    };
    let request =
        signed_records_subscribe_message(filter.clone(), None, "2025-01-01T00:10:00.000000Z").await;
    let message: Message<Descriptor> =
        serde_json::from_value(request).expect("subscribe request must deserialize");
    let auth = DeliveryAuthorization {
        message,
        filter,
        auth_ctx: crate::permissions::AuthorizationContext {
            signer: BOB.to_string(),
            author: BOB.to_string(),
            payload: crate::permissions::VerifiedAuthorizationPayload::Generic(
                crate::auth::jws::AuthorizationPayloadData {
                    descriptor_cid: String::new(),
                    delegated_grant_id: None,
                    permission_grant_id: Some(grant_id.clone()),
                    permission_grant_ids: None,
                    protocol_role: None,
                },
            ),
            permission_grant_invocation: crate::auth::jws::PermissionGrantInvocation::Single(
                grant_id,
            ),
            author_delegated_grant: None,
            owner: None,
        },
        grant_valid_at_open: true,
        role_invoked: false,
        request_timestamp: "2025-01-01T00:10:00.000000Z".to_string(),
        control_only: false,
    };

    let error = authorize_records_delivery(TENANT, &auth, &message_store)
        .await
        .expect_err("expired grant must fail delivery");
    assert_eq!(
        error.code,
        SubscriptionErrorCode::RecordsDeliveryAuthorizationFailed
    );
}

// Covers: DWN-AUTH-005, DWN-REC-004
#[tokio::test]
async fn subscribe_delivery_suppresses_non_occupant_but_stays_live() {
    const TENANT: &str = "did:example:alice";
    const LIMITED: &str = "http://example.com/limited";

    let wake_bus = InProcessWakeBus::new();
    let mut message_store = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    message_store.open().await.unwrap();
    let mut data_store = TestDataStore::default();
    data_store.open().await.unwrap();
    crate::testing::put_limited_threads_protocol(TENANT, &message_store).await;

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

    async fn write_post(
        handler: &RecordsWriteHandler<MemoryMessageStore, TestDataStore>,
        day: &str,
    ) -> String {
        let timestamp = format!("2025-01-{day}T00:00:00.000000Z");
        let data = Bytes::from(format!("limited-post-{day}").into_bytes());
        let message = signed_write_message(WriteSpec {
            protocol: "http://example.com/limited".to_string(),
            protocol_path: "post".to_string(),
            data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
            data_size: data.len() as u64,
            published: Some(true),
            timestamp: timestamp.clone(),
            date_created: timestamp.clone(),
            ..WriteSpec::new(&timestamp)
        })
        .await;
        let record_id = message["recordId"].as_str().unwrap().to_string();
        assert_eq!(
            handler.run(TENANT, &message, Some(data)).await.status.code,
            202
        );
        record_id
    }

    let first = write_post(&write_handler, "01").await;
    write_post(&write_handler, "02").await;
    write_post(&write_handler, "03").await;

    let event_log = DurableEventLog::new(message_store.clone(), wake_bus, None, None);
    let delivered = Arc::new(RwLock::new(Vec::new()));
    let delivered_for_listener = delivered.clone();
    let handler = RecordsEventLogSubscribeHandler::new(
        message_store.clone(),
        event_log,
        Some(Arc::new(test_resolver())),
    );
    let request = signed_records_subscribe_message(
        RecordsFilter {
            protocol: Some(LIMITED.to_string()),
            protocol_path: Some("post".to_string()),
            ..Default::default()
        },
        None,
        "2025-01-01T00:10:00.000000Z",
    )
    .await;
    let result = handler
        .handle_subscribe(
            TENANT,
            &request,
            Box::new(move |message| delivered_for_listener.write().unwrap().push(message)),
        )
        .await;
    assert_eq!(result.reply.status.code, 200);
    assert_eq!(result.reply.reply.entries.as_ref().unwrap().len(), 2);

    // A live non-occupant must be suppressed without closing the stream.
    let fourth_data = Bytes::from_static(b"limited-post-04");
    let fourth = signed_write_message(WriteSpec {
        protocol: LIMITED.to_string(),
        protocol_path: "post".to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&fourth_data).to_string(),
        data_size: fourth_data.len() as u64,
        published: Some(true),
        timestamp: "2025-01-04T00:00:00.000000Z".to_string(),
        date_created: "2025-01-04T00:00:00.000000Z".to_string(),
        ..WriteSpec::new("2025-01-04T00:00:00.000000Z")
    })
    .await;
    let fourth_message: Message<Descriptor> =
        serde_json::from_value(fourth).expect("live write must deserialize");
    let fourth_indexes =
        records_write_indexes(&fourth_message, TENANT, true).expect("live indexes must build");
    message_store
        .put(TENANT, fourth_message, fourth_indexes)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        delivered.read().unwrap().is_empty(),
        "non-occupant live write must be suppressed"
    );

    // Deleting the oldest occupant changes nothing about suppression, but the
    // tombstone event itself must still be delivered: the stream is alive.
    let delete = signed_delete_message(&first, false, "2025-01-05T00:00:00.000000Z").await;
    assert_eq!(
        delete_handler.run(TENANT, &delete, None).await.status.code,
        202
    );
    for _ in 0..500 {
        if !delivered.read().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let delivered = delivered.read().unwrap();
    assert_eq!(delivered.len(), 1, "tombstone event must be delivered");
    assert!(matches!(delivered[0], SubscriptionMessage::Event { .. }));
}

// Covers: DWN-PROTO-001, DWN-PROTO-002
#[tokio::test]
async fn subscribe_nested_without_scope_rejected_unless_bounded() {
    const TENANT: &str = "did:example:alice";
    const NESTED: &str = "thread/message";

    async fn status(
        handler: &RecordsSubscribeHandler<TestMessageStore>,
        filter: RecordsFilter,
        pagination: Option<Pagination>,
    ) -> i32 {
        let request = signed_records_subscribe_with_pagination(
            filter,
            None,
            pagination,
            "2025-01-01T00:10:00.000000Z",
        )
        .await;
        handler.run(TENANT, &request, None).await.status.code
    }

    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();
    let handler = RecordsSubscribeHandler::new(message_store, Some(Arc::new(test_resolver())));

    let unscoped = RecordsFilter {
        protocol: Some("https://example.com/protocol/chat".to_string()),
        protocol_path: Some(NESTED.to_string()),
        ..Default::default()
    };
    assert_eq!(
        status(&handler, unscoped.clone(), None).await,
        400,
        "unbounded nested subscribe without scope must fail"
    );
    assert_eq!(
        status(&handler, unscoped, Some(Pagination::with_limit(2))).await,
        200,
        "bounded path-wide subscribe may omit scope"
    );

    let scoped = RecordsFilter {
        protocol: Some("https://example.com/protocol/chat".to_string()),
        protocol_path: Some(NESTED.to_string()),
        parent_id: Some("thread-1".to_string()),
        ..Default::default()
    };
    assert_eq!(
        status(&handler, scoped, None).await,
        200,
        "parent-scoped nested subscribe needs no exception"
    );
}

// Covers: DWN-PROTO-001, DWN-PROTO-002
#[tokio::test]
async fn event_log_subscribe_nested_without_scope_rejected_unless_bounded() {
    const TENANT: &str = "did:example:alice";

    let wake_bus = InProcessWakeBus::new();
    let mut message_store = MemoryMessageStore::default();
    message_store.open().await.unwrap();
    let event_log = DurableEventLog::new(message_store.clone(), wake_bus, None, None);
    let handler = RecordsEventLogSubscribeHandler::new(
        message_store,
        event_log,
        Some(Arc::new(test_resolver())),
    );

    let unscoped = RecordsFilter {
        protocol: Some("https://example.com/protocol/chat".to_string()),
        protocol_path: Some("thread/message".to_string()),
        ..Default::default()
    };
    let unbounded = signed_records_subscribe_with_pagination(
        unscoped.clone(),
        None,
        None,
        "2025-01-01T00:10:00.000000Z",
    )
    .await;
    assert_eq!(
        handler
            .handle_subscribe(TENANT, &unbounded, Box::new(|_| {}))
            .await
            .reply
            .status
            .code,
        400,
        "unbounded nested subscribe without scope must fail"
    );
    let bounded = signed_records_subscribe_with_pagination(
        unscoped,
        None,
        Some(Pagination::with_limit(2)),
        "2025-01-01T00:10:00.000000Z",
    )
    .await;
    assert_eq!(
        handler
            .handle_subscribe(TENANT, &bounded, Box::new(|_| {}))
            .await
            .reply
            .status
            .code,
        200,
        "bounded path-wide subscribe may omit scope"
    );
}

// Covers: DWN-REC-005
#[tokio::test]
async fn subscribe_snapshot_cannot_miss_write_landing_mid_setup() {
    const TENANT: &str = "did:example:alice";

    /// Blocks snapshot queries behind a gate so a write can land
    /// deterministically between subscription registration and the snapshot
    /// read. Puts pass straight through.
    #[derive(Clone)]
    struct GatedMessageStore {
        inner: MemoryMessageStore,
        entered: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    }

    impl MessageStore for GatedMessageStore {
        async fn open(&mut self) -> Result<(), MessageStoreError> {
            self.inner.open().await
        }

        async fn close(&mut self) {}

        async fn put<D>(
            &self,
            tenant: &str,
            message: Message<D>,
            indexes: KeyValues,
        ) -> Result<(), MessageStoreError>
        where
            D: crate::descriptors::MessageDescriptor + Send,
            Message<Descriptor>: From<Message<D>>,
        {
            self.inner.put(tenant, message, indexes).await
        }

        async fn get(
            &self,
            tenant: &str,
            cid: &str,
        ) -> Result<Option<Message<Descriptor>>, MessageStoreError> {
            self.inner.get(tenant, cid).await
        }

        async fn query(
            &self,
            tenant: &str,
            filters: Filters,
            sort: Option<MessageSort>,
            pagination: Option<Pagination>,
            record_limit: Option<RecordLimitOccupancy>,
        ) -> Result<MessageQueryResult, MessageStoreError> {
            self.entered.store(true, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            self.inner
                .query(tenant, filters, sort, pagination, record_limit)
                .await
        }

        async fn count(
            &self,
            tenant: &str,
            filters: Filters,
            sort: Option<MessageSort>,
            record_limit: Option<RecordLimitOccupancy>,
        ) -> Result<u64, MessageStoreError> {
            self.inner.count(tenant, filters, sort, record_limit).await
        }

        async fn delete(&self, tenant: &str, cid: &str) -> Result<(), MessageStoreError> {
            self.inner.delete(tenant, cid).await
        }

        async fn clear(&self) -> Result<(), MessageStoreError> {
            self.inner.clear().await
        }
    }

    impl crate::stores::ReplicationFeedReader for GatedMessageStore {
        async fn log_read(
            &self,
            tenant: &str,
            options: EventLogReadOptions,
        ) -> Result<crate::stores::EventLogReadResult, crate::errors::EventLogError> {
            self.inner.log_read(tenant, options).await
        }

        async fn log_bounds(
            &self,
            tenant: &str,
        ) -> Result<
            Option<crate::stores::replication_feed_reader::ReplicationBounds>,
            crate::errors::EventLogError,
        > {
            self.inner.log_bounds(tenant).await
        }

        async fn fingerprint(
            &self,
            tenant: &str,
            scopes: &[String],
        ) -> Result<crate::stores::replication_feed_reader::Fingerprint, crate::errors::EventLogError>
        {
            self.inner.fingerprint(tenant, scopes).await
        }

        async fn epoch(&self) -> Result<String, crate::errors::EventLogError> {
            self.inner.epoch().await
        }
    }

    async fn put_note(store: &MemoryMessageStore, record_id: &str, timestamp: &str) {
        let data = Bytes::from(format!("gated-{record_id}").into_bytes());
        let message: Message<Descriptor> = serde_json::from_value(
            signed_write_message(WriteSpec {
                protocol: "http://example.com/notes".to_string(),
                protocol_path: "note".to_string(),
                record_id: Some(record_id.to_string()),
                data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
                data_size: data.len() as u64,
                published: Some(true),
                timestamp: timestamp.to_string(),
                date_created: timestamp.to_string(),
                ..WriteSpec::new(timestamp)
            })
            .await,
        )
        .expect("seed note must deserialize");
        let indexes = records_write_indexes(&message, TENANT, true).expect("indexes must build");
        store.put(TENANT, message, indexes).await.unwrap();
    }

    let wake_bus = InProcessWakeBus::new();
    let inner = MemoryMessageStore::default().with_waker_publisher(wake_bus.clone());
    let mut gated = GatedMessageStore {
        inner,
        entered: Arc::new(AtomicBool::new(false)),
        release: Arc::new(AtomicBool::new(true)),
    };
    gated.open().await.unwrap();
    put_notes_protocol_without_actions(TENANT, &gated).await;
    put_note(&gated.inner, "gated-a", "2025-01-01T00:01:00.000000Z").await;

    // Freeze snapshot queries, then open the subscription: its listener is
    // registered before any snapshot can run.
    gated.release.store(false, Ordering::SeqCst);
    let event_log = DurableEventLog::new(gated.clone(), wake_bus, None, None);
    let handler = RecordsEventLogSubscribeHandler::new(
        gated.clone(),
        event_log,
        Some(Arc::new(test_resolver())),
    );
    let request = Arc::new(
        signed_records_subscribe_message(
            RecordsFilter {
                protocol: Some("http://example.com/notes".to_string()),
                ..Default::default()
            },
            None,
            "2025-01-01T00:10:00.000000Z",
        )
        .await,
    );
    let task_request = request.clone();
    let task = tokio::spawn(async move {
        handler
            .handle_subscribe(TENANT, &task_request, Box::new(|_| {}))
            .await
    });
    for _ in 0..500 {
        if gated.entered.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        gated.entered.load(Ordering::SeqCst),
        "snapshot query must block on the gate"
    );

    // Land record B while the snapshot is frozen, then release it.
    put_note(&gated.inner, "gated-b", "2025-01-01T00:02:00.000000Z").await;
    gated.release.store(true, Ordering::SeqCst);
    let result = task.await.expect("subscribe task must complete");
    assert_eq!(result.reply.status.code, 200);
    let entries = result.reply.reply.entries.expect("snapshot entries");
    let ids: Vec<String> = entries
        .iter()
        .filter_map(|entry| {
            serde_json::to_value(entry).unwrap()["recordId"]
                .as_str()
                .map(str::to_string)
        })
        .collect();
    assert!(
        ids.contains(&"gated-b".to_string()),
        "write landing mid-setup must appear in the snapshot (duplicates allowed, misses forbidden): {ids:?}"
    );
}

// Covers: DWN-AUTH-002, DWN-AUTH-005
#[tokio::test]
async fn subscribe_delivery_expired_delegated_grant_is_terminal() {
    const TENANT: &str = "did:example:alice";
    const BOB: &str = "did:example:bob";

    let mut message_store = TestMessageStore::default();
    message_store.open().await.unwrap();

    // Delegated grant covering notes reads, expired after the request but
    // before delivery: valid at open (request time), terminal at now.
    // Fixed past dates keep this deterministic.
    let grant = crate::permissions::PermissionGrant {
        id: "delegated-grant-1".to_string(),
        grantor: TENANT.to_string(),
        grantee: BOB.to_string(),
        date_granted: parse_time("2025-01-01T00:00:00.000000Z"),
        date_expires: parse_time("2025-06-01T00:00:00.000000Z"),
        delegated: Some(true),
        scope: crate::permissions::PermissionScope::Records(crate::permissions::RecordsScope {
            method: crate::permissions::RecordsMethod::Read,
            protocol: "http://example.com/notes".to_string(),
            selector: None,
        }),
        conditions: None,
        connect_session: None,
    };
    let filter = RecordsFilter {
        protocol: Some("http://example.com/notes".to_string()),
        protocol_path: Some("note".to_string()),
        ..Default::default()
    };
    let request =
        signed_records_subscribe_message(filter.clone(), None, "2025-01-01T00:10:00.000000Z").await;
    let message: Message<Descriptor> =
        serde_json::from_value(request).expect("subscribe request must deserialize");
    let auth = DeliveryAuthorization {
        message,
        filter,
        auth_ctx: crate::permissions::AuthorizationContext {
            signer: BOB.to_string(),
            author: TENANT.to_string(),
            payload: crate::permissions::VerifiedAuthorizationPayload::Generic(
                crate::auth::jws::AuthorizationPayloadData {
                    descriptor_cid: String::new(),
                    delegated_grant_id: Some("delegated-grant-1".to_string()),
                    permission_grant_id: None,
                    permission_grant_ids: None,
                    protocol_role: None,
                },
            ),
            permission_grant_invocation: crate::auth::jws::PermissionGrantInvocation::None,
            author_delegated_grant: Some(grant),
            owner: None,
        },
        grant_valid_at_open: true,
        role_invoked: false,
        request_timestamp: "2025-01-01T00:10:00.000000Z".to_string(),
        control_only: false,
    };

    let error = authorize_records_delivery(TENANT, &auth, &message_store)
        .await
        .expect_err("expired delegated grant must fail delivery");
    assert_eq!(
        error.code,
        SubscriptionErrorCode::RecordsDeliveryAuthorizationFailed
    );
}

use crate::encryption::{
    ContentEncryptionAlgorithm, EncryptionEnvelope, KeyAgreementAlgorithm, KeyEncryption,
    ENCRYPTION_PROTOCOL_GRANT_KEY_PATH, ENCRYPTION_PROTOCOL_URI,
};
use crate::protocols::{Definition, ProtocolKeyAgreement, RuleSet, Type};
use ssi_jwk::JWK;

const ENC_NOTES_PROTOCOL: &str = "http://example.com/enc-notes";
const ENC_T1: &str = "2024-12-01T00:00:00.000000Z";
const ENC_MID: &str = "2024-12-15T00:00:00.000000Z";
const ENC_T2: &str = "2025-01-01T00:00:00.000000Z";
const ENC_LATE: &str = "2025-01-02T00:00:00.000000Z";
const ENC_WRITE_TIME: &str = "2025-01-03T00:00:00.000000Z";
const SECRET_DATA: &[u8] = b"encrypted note";

fn path_key_jwk() -> JWK {
    serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "X25519",
        "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
    }))
    .unwrap()
}

fn path_key_id() -> String {
    path_key_jwk().thumbprint().unwrap()
}

fn keyed_rule_set() -> RuleSet {
    RuleSet {
        key_agreement: Some(ProtocolKeyAgreement {
            public_key_jwk: path_key_jwk(),
        }),
        ..Default::default()
    }
}

fn enc_notes_definition(encrypted: bool, keyed: bool) -> Definition {
    Definition {
        protocol: ENC_NOTES_PROTOCOL.to_string(),
        published: true,
        uses: None,
        key_agreement: if keyed {
            Some(ProtocolKeyAgreement {
                public_key_jwk: path_key_jwk(),
            })
        } else {
            None
        },
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
            if keyed {
                keyed_rule_set()
            } else {
                RuleSet::default()
            },
        )]),
    }
}

fn protocol_path_entry(key_id: &str) -> KeyEncryption {
    KeyEncryption::ProtocolPath {
        algorithm: KeyAgreementAlgorithm::X25519HkdfSha256A256Kw,
        key_id: key_id.to_string(),
        ephemeral_public_key: path_key_jwk(),
        encrypted_key: "a2V5".to_string(),
    }
}

fn role_audience_entry() -> KeyEncryption {
    KeyEncryption::RoleAudience {
        algorithm: KeyAgreementAlgorithm::X25519HkdfSha256A256Kw,
        key_id: "role-kid".to_string(),
        ephemeral_public_key: path_key_jwk(),
        encrypted_key: "a2V5".to_string(),
        protocol: ENC_NOTES_PROTOCOL.to_string(),
        role_path: "note/role".to_string(),
    }
}

fn envelope_with_entries(entries: Vec<KeyEncryption>) -> EncryptionEnvelope {
    EncryptionEnvelope {
        algorithm: ContentEncryptionAlgorithm::A256Ctr,
        initialization_vector: "oKGio6SlpqeoqaqrrK2urw".to_string(),
        key_encryption: entries,
    }
}

async fn enc_protocol_write(
    protocol: &str,
    protocol_path: &str,
    timestamp: &str,
    envelope: Option<EncryptionEnvelope>,
) -> serde_json::Value {
    let data = Bytes::from_static(SECRET_DATA);
    signed_write_message(WriteSpec {
        protocol: protocol.to_string(),
        protocol_path: protocol_path.to_string(),
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        encryption: envelope,
        ..WriteSpec::new(timestamp)
    })
    .await
}

async fn enc_test_handler(
    message_store: TestMessageStore,
    data_store: TestDataStore,
) -> RecordsWriteHandler<TestMessageStore, TestDataStore> {
    RecordsWriteHandler::<_, _>::new(message_store, data_store, Some(Arc::new(test_resolver())))
}

async fn open_stores() -> (TestMessageStore, TestDataStore) {
    let mut message_store = TestMessageStore::default();
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    (message_store, data_store)
}

fn write_data() -> Option<Bytes> {
    Some(Bytes::from_static(SECRET_DATA))
}

// Covers: DWN-PROTO-001, DWN-ENC-001
#[tokio::test]
async fn records_write_encrypted_path_with_matching_entry_is_accepted() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        enc_notes_definition(true, true),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let envelope = envelope_with_entries(vec![protocol_path_entry(&path_key_id())]);
    let write =
        enc_protocol_write(ENC_NOTES_PROTOCOL, "note", ENC_WRITE_TIME, Some(envelope)).await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn records_write_encrypted_path_without_envelope_is_rejected() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        enc_notes_definition(true, true),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let write = enc_protocol_write(ENC_NOTES_PROTOCOL, "note", ENC_WRITE_TIME, None).await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionRequired")
    );
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn records_write_plaintext_path_with_envelope_is_rejected() {
    let (message_store, data_store) = open_stores().await;
    put_notes_protocol_without_actions("did:example:alice", &message_store).await;
    let handler = enc_test_handler(message_store, data_store).await;

    let envelope = envelope_with_entries(vec![protocol_path_entry(&path_key_id())]);
    let write = enc_protocol_write(
        "http://example.com/notes",
        "note",
        ENC_WRITE_TIME,
        Some(envelope),
    )
    .await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionNotAllowed")
    );
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn records_write_encrypted_path_without_path_key_is_rejected() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        enc_notes_definition(true, false),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let envelope = envelope_with_entries(vec![protocol_path_entry(&path_key_id())]);
    let write =
        enc_protocol_write(ENC_NOTES_PROTOCOL, "note", ENC_WRITE_TIME, Some(envelope)).await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionKeyAgreementMissing")
    );
}

// Covers: DWN-PROTO-001, DWN-PROTO-006
#[tokio::test]
async fn records_write_encrypted_path_with_wrong_entry_is_rejected() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        enc_notes_definition(true, true),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let wrong_key = envelope_with_entries(vec![protocol_path_entry("other-kid")]);
    let write =
        enc_protocol_write(ENC_NOTES_PROTOCOL, "note", ENC_WRITE_TIME, Some(wrong_key)).await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionProtocolPathEntryMissing")
    );

    let role_only = envelope_with_entries(vec![role_audience_entry()]);
    let write = enc_protocol_write(
        ENC_NOTES_PROTOCOL,
        "note",
        "2025-01-03T00:01:00.000000Z",
        Some(role_only),
    )
    .await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionProtocolPathEntryMissing")
    );
}

// Covers: DWN-PROTO-006, DWN-ENC-001
#[tokio::test]
async fn records_write_encrypted_path_with_extra_entries_is_accepted() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        enc_notes_definition(true, true),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let envelope = envelope_with_entries(vec![
        protocol_path_entry("other-kid"),
        role_audience_entry(),
        protocol_path_entry(&path_key_id()),
    ]);
    let write =
        enc_protocol_write(ENC_NOTES_PROTOCOL, "note", ENC_WRITE_TIME, Some(envelope)).await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-001
#[tokio::test]
async fn records_write_grant_key_path_bypasses_path_key_lookup() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        Definition {
            protocol: ENCRYPTION_PROTOCOL_URI.to_string(),
            published: true,
            uses: None,
            key_agreement: None,
            types: BTreeMap::from([(
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH.to_string(),
                Type {
                    schema: None,
                    data_formats: None,
                    encryption_required: Some(true),
                },
            )]),
            structure: BTreeMap::from([(
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH.to_string(),
                RuleSet::default(),
            )]),
        },
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let envelope = envelope_with_entries(vec![protocol_path_entry("recipient-kid")]);
    let write = enc_protocol_write(
        ENCRYPTION_PROTOCOL_URI,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        ENC_WRITE_TIME,
        Some(envelope),
    )
    .await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let bare = enc_protocol_write(
        ENCRYPTION_PROTOCOL_URI,
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
        "2025-01-03T00:01:00.000000Z",
        None,
    )
    .await;
    let reply = handler.run("did:example:alice", &bare, write_data()).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionRequired")
    );
}

const REF_BLOG_PROTOCOL: &str = "http://example.com/blog";
const COMPOSED_PROTOCOL: &str = "http://example.com/composed";

fn referenced_blog_definition(encrypted: bool) -> Definition {
    Definition {
        protocol: REF_BLOG_PROTOCOL.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([(
            "post".to_string(),
            Type {
                schema: None,
                data_formats: None,
                encryption_required: if encrypted { Some(true) } else { None },
            },
        )]),
        structure: BTreeMap::from([("post".to_string(), RuleSet::default())]),
    }
}

fn composed_definition() -> Definition {
    Definition {
        protocol: COMPOSED_PROTOCOL.to_string(),
        published: true,
        uses: Some(BTreeMap::from([(
            "blog".to_string(),
            REF_BLOG_PROTOCOL.to_string(),
        )])),
        key_agreement: None,
        types: BTreeMap::from([(
            "comment".to_string(),
            Type {
                schema: None,
                data_formats: None,
                encryption_required: Some(true),
            },
        )]),
        structure: BTreeMap::from([
            (
                "post".to_string(),
                RuleSet {
                    reference: Some("blog:post".to_string()),
                    rules: BTreeMap::from([("comment".to_string(), keyed_rule_set())]),
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
    }
}

fn keyed_blog_definition() -> Definition {
    Definition {
        protocol: REF_BLOG_PROTOCOL.to_string(),
        published: true,
        uses: None,
        key_agreement: Some(ProtocolKeyAgreement {
            public_key_jwk: path_key_jwk(),
        }),
        types: BTreeMap::from([(
            "post".to_string(),
            Type {
                schema: None,
                data_formats: None,
                encryption_required: Some(true),
            },
        )]),
        structure: BTreeMap::from([("post".to_string(), keyed_rule_set())]),
    }
}

// Covers: DWN-PROTO-004, DWN-PROTO-005
#[tokio::test]
async fn records_write_ref_position_follows_referenced_type_policy() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        referenced_blog_definition(true),
        ENC_T1,
    )
    .await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        composed_definition(),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let write = enc_protocol_write(COMPOSED_PROTOCOL, "post", ENC_WRITE_TIME, None).await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionRequired")
    );

    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        referenced_blog_definition(false),
        ENC_T1,
    )
    .await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        composed_definition(),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let envelope = envelope_with_entries(vec![protocol_path_entry(&path_key_id())]);
    let write = enc_protocol_write(COMPOSED_PROTOCOL, "post", ENC_WRITE_TIME, Some(envelope)).await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionNotAllowed")
    );
}

// Covers: DWN-PROTO-001, DWN-PROTO-005
#[tokio::test]
async fn records_write_ref_roots_use_referenced_key_namespace() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        keyed_blog_definition(),
        ENC_T1,
    )
    .await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        composed_definition(),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    for path in ["post", "article"] {
        let envelope = envelope_with_entries(vec![protocol_path_entry(&path_key_id())]);
        let write =
            enc_protocol_write(COMPOSED_PROTOCOL, path, ENC_WRITE_TIME, Some(envelope)).await;
        let reply = handler.run("did:example:alice", &write, write_data()).await;
        assert_eq!(reply.status.code, 202, "{} at {path}", reply.status.detail);
    }

    let write = enc_protocol_write(COMPOSED_PROTOCOL, "article", ENC_WRITE_TIME, None).await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionRequired")
    );
}

// Covers: DWN-PROTO-005
#[tokio::test]
async fn records_write_local_child_below_ref_uses_composing_key_namespace() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        referenced_blog_definition(false),
        ENC_T1,
    )
    .await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        composed_definition(),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let envelope = envelope_with_entries(vec![protocol_path_entry(&path_key_id())]);
    let write = enc_protocol_write(
        COMPOSED_PROTOCOL,
        "post/comment",
        ENC_WRITE_TIME,
        Some(envelope),
    )
    .await;
    let reply = handler.run("did:example:alice", &write, write_data()).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: DWN-PROTO-004
#[tokio::test]
async fn records_write_policy_follows_governing_definition_over_time() {
    let (message_store, data_store) = open_stores().await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        enc_notes_definition(true, true),
        ENC_T2,
    )
    .await;
    put_protocol_definition(
        "did:example:alice",
        &message_store,
        enc_notes_definition(false, false),
        ENC_T1,
    )
    .await;
    let handler = enc_test_handler(message_store, data_store).await;

    let mid = enc_protocol_write(ENC_NOTES_PROTOCOL, "note", ENC_MID, None).await;
    let reply = handler.run("did:example:alice", &mid, write_data()).await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    let late_bare = enc_protocol_write(ENC_NOTES_PROTOCOL, "note", ENC_LATE, None).await;
    let reply = handler
        .run("did:example:alice", &late_bare, write_data())
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("ProtocolAuthorizationEncryptionRequired")
    );

    let envelope = envelope_with_entries(vec![protocol_path_entry(&path_key_id())]);
    let late_keyed = enc_protocol_write(
        ENC_NOTES_PROTOCOL,
        "note",
        "2025-01-02T00:01:00.000000Z",
        Some(envelope),
    )
    .await;
    let reply = handler
        .run("did:example:alice", &late_keyed, write_data())
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}
