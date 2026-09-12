//! Judging retained controls against a configuration, and destroying only the
//! ones it contradicts.

use std::fmt::Debug;
use std::sync::atomic::AtomicI64;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::descriptors::messages::record_id;
use crate::descriptors::{ConfigureDescriptor, MessageDescriptor};
use crate::errors::{ResumableTaskStoreError, StoreError};
use crate::handlers::records::control::ControlValidationError;
use crate::permissions::message_author;
use crate::protocols::{Action, ActionWho, Can, Who};
use crate::stores::memory::MemoryResumableTaskStore;
use crate::stores::{ManagedResumableTask, ResumableTaskStore};
use crate::tasks::controller::{
    ResumableControlPurgeData, ResumableControlRepairData, StorageController,
};
use crate::tasks::manager::{ResumableTask, ResumableTaskManager, ResumableTaskName};

use super::*;

async fn stored_audience(fixture: &ControlFixture) -> Message<Descriptor> {
    let filter = filter_map([
        ("interface", string_filter("Records")),
        ("protocolPath", string_filter(AUDIENCE_PATH)),
    ]);
    fixture
        .message_store
        .query(CONTROL_TENANT, Filters::from(filter), None, None, None)
        .await
        .unwrap()
        .messages
        .into_iter()
        .next()
        .expect("an audience must be stored")
}

// Covers: DWN-PROTO-004
// Configuration repair destroys custody material, so it fires only on a
// contradiction the configuration itself owns. Each case changes exactly one
// thing about the configuration and asserts the verdict that follows.
#[tokio::test]
async fn repair_removes_only_records_the_configuration_contradicts() {
    let fixture = control_fixture().await;
    admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:01:00.000000Z",
        None,
    )
    .await;
    let audience = stored_audience(&fixture).await;

    // Unchanged configuration: nothing to answer for.
    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &fixture.message_store).await,
        Ok(ControlConfigValidity::Valid),
        "an unchanged configuration invalidates nothing"
    );

    // The role keeps its identity but loses its key agreement. New material
    // cannot be minted, but what was already sealed under it stays valid —
    // destroying it would be unrecoverable.
    let mut unkeyed = control_definition();
    unkeyed.structure.get_mut("member").unwrap().key_agreement = None;
    reconfigure(&fixture, unkeyed, "2025-01-02T00:00:00.000000Z").await;
    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &fixture.message_store).await,
        Ok(ControlConfigValidity::Valid),
        "a role that loses its key agreement must not cost custody of what it already sealed"
    );

    // The role stops being a role at all: the record now names something the
    // protocol does not have.
    let mut demoted = control_definition();
    demoted.structure.get_mut("member").unwrap().role = None;
    reconfigure(&fixture, demoted, "2025-01-03T00:00:00.000000Z").await;
    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &fixture.message_store).await,
        Ok(ControlConfigValidity::Invalid),
        "a role that is no longer a role leaves the record contradicted"
    );
}

// Covers: DWN-PROTO-004
// Anything undetermined is kept. A record whose protocol cannot be found is not
// a record proven wrong — the configuration may simply not have arrived — and
// repair must not treat the two alike.
#[tokio::test]
async fn repair_retains_records_it_cannot_judge() {
    let fixture = control_fixture().await;
    admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:01:00.000000Z",
        None,
    )
    .await;
    let audience = stored_audience(&fixture).await;

    // A record whose protocol is absent entirely.
    let empty_store = MemoryMessageStore::default();
    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &empty_store).await,
        Ok(ControlConfigValidity::Unknown),
        "a missing configuration is undetermined, never proof the record is wrong"
    );
}

// Covers: DWN-PROTO-004, DWN-AUTH-001
// The create-authority replay uses only what the record and the configuration
// already say. A record whose authority came from the writer's own standing is
// preserved without re-fetching grants or re-resolving DIDs, because their
// absence today says nothing about what was authorized then. A record that
// leaned on a protocol rule is judged by whether that rule still permits it.
#[tokio::test]
async fn stored_create_replay_uses_only_the_record_and_the_configuration() {
    let fixture = control_fixture().await;
    admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:01:00.000000Z",
        None,
    )
    .await;
    let tenant_written = stored_audience(&fixture).await;

    // The base role declares no actions at all. A record leaning on a rule
    // would be contradicted by that; the tenant's own is not.
    let bare_role = control_definition()
        .structure
        .get("member")
        .unwrap()
        .clone();
    assert!(
        verify_stored_create_action(CONTROL_TENANT, &tenant_written, &bare_role).is_ok(),
        "a tenant-authored record stands on its own authority, not on a rule"
    );

    // A record written by someone else, invoking nothing. Under a role that
    // once let anyone create, it was admissible.
    let permissive = RuleSet {
        actions: vec![Action::Who(ActionWho {
            who: Who::Anyone,
            of: None,
            can: vec![Can::Create],
        })],
        ..control_definition()
            .structure
            .get("member")
            .unwrap()
            .clone()
    };
    let bob_signed = signed_write_message(WriteSpec {
        author: "did:example:bob".to_string(),
        signer: bob_signer(),
        protocol: CONTROL_PROTOCOL.to_string(),
        protocol_path: AUDIENCE_PATH.to_string(),
        tags: Some(audience_tags("member", "", &fixture.audience_key_id)),
        ..WriteSpec::new("2025-01-01T00:02:00.000000Z")
    })
    .await;
    let delegate_written: Message<Descriptor> =
        serde_json::from_value(bob_signed).expect("bob's write must deserialize");
    assert_ne!(
        message_author(&delegate_written),
        Some(CONTROL_TENANT.to_string()),
        "the record under test must not be tenant-authored, or it proves nothing"
    );

    assert!(
        verify_stored_create_action(CONTROL_TENANT, &delegate_written, &permissive).is_ok(),
        "the rule that admitted it still permits it"
    );

    // The same record once that rule is gone: now the configuration
    // contradicts it, and the error is one repair is allowed to act on.
    let error = verify_stored_create_action(CONTROL_TENANT, &delegate_written, &bare_role)
        .expect_err("a record with no permitting rule is contradicted");
    let ControlValidationError::Dwn(error) = error else {
        panic!("expected a coded failure");
    };
    assert!(
        error.code.is_control_invalidity(),
        "a removed create rule is a configuration-owned contradiction, got {:?}",
        error.code
    );
}

/// A second role key, so a configuration can change which key governs `member`.
fn later_role_key_jwk() -> JWK {
    serde_json::from_value(json!({
        "kty": "OKP", "crv": "X25519",
        "x": "B6r_Pp_BZydVRPTDpqF82Dfy7G54zYpXsePfs8wDWnY"
    }))
    .unwrap()
}

fn control_definition_keyed_with(role_key: &JWK) -> Definition {
    let mut definition = control_definition();
    definition
        .structure
        .get_mut("member")
        .unwrap()
        .key_agreement = Some(ProtocolKeyAgreement {
        public_key_jwk: role_key.clone(),
    });
    definition
}

// Covers: DWN-PROTO-004
// A configuration learned *late* still governs the records whose timestamps it
// covers. A record written on the 3rd was sealed under the key the 1st
// configuration named; learning on the 4th that a different configuration took
// effect on the 2nd means the record was never sealed under its governing key,
// and the configuration itself says so.
#[tokio::test]
async fn a_late_historical_configuration_invalidates_a_record_it_governs() {
    let fixture = control_fixture().await;

    // Mar 1: `member` keyed with key A. Mar 3: an audience sealed under it.
    reconfigure(
        &fixture,
        control_definition_keyed_with(&role_key_jwk()),
        "2025-03-01T00:00:00.000000Z",
    )
    .await;
    admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-03-03T00:00:00.000000Z",
        None,
    )
    .await;
    let audience = stored_audience(&fixture).await;
    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &fixture.message_store).await,
        Ok(ControlConfigValidity::Valid),
        "under the history as first known, the record is sound"
    );

    // Mar 2 arrives late, keying `member` with a different key. The record's
    // governing configuration is now that one, and its seal does not match.
    reconfigure(
        &fixture,
        control_definition_keyed_with(&later_role_key_jwk()),
        "2025-03-02T00:00:00.000000Z",
    )
    .await;
    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &fixture.message_store).await,
        Ok(ControlConfigValidity::Invalid),
        "a late historical configuration governs the record written after it"
    );
}

// Covers: DWN-PROTO-004
// The scan and the hook are each covered; this is their composition, which is
// the path that actually destroys anything.
#[tokio::test]
async fn configuring_a_protocol_purges_the_controls_it_invalidates() {
    let fixture = control_fixture().await;
    admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:01:00.000000Z",
        None,
    )
    .await;
    assert!(
        !stored_control_records(&fixture).await.is_empty(),
        "the audience must be stored before the configuration changes"
    );

    let mut data_store = TestDataStore::default();
    data_store.open().await.unwrap();
    let mut tasks = MemoryResumableTaskStore::default();
    ResumableTaskStore::open(&mut tasks).await.unwrap();
    let repairer = ResumableTaskManager::new(
        tasks,
        StorageController::new(fixture.message_store.clone(), data_store.clone()),
    );

    // A configuration in which `member` is no longer a role at all.
    let mut demoted = control_definition();
    demoted.structure.get_mut("member").unwrap().role = None;
    let configure_handler = ProtocolsConfigureHandler::new(
        fixture.message_store.clone(),
        Some(Arc::new(test_resolver())),
    )
    .with_repairer(Arc::new(repairer));

    let configure = signed_configure_with_definition(demoted, "2025-01-02T00:00:00.000000Z").await;
    let reply = configure_handler
        .run(CONTROL_TENANT, &configure, None)
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    assert!(
        stored_control_records(&fixture).await.is_empty(),
        "accepting the configuration must remove the control it contradicts"
    );
}

async fn stored_control_records(fixture: &ControlFixture) -> Vec<Message<Descriptor>> {
    let filter = filter_map([
        ("interface", string_filter("Records")),
        ("protocolPath", string_filter(AUDIENCE_PATH)),
    ]);
    fixture
        .message_store
        .query(CONTROL_TENANT, Filters::from(filter), None, None, None)
        .await
        .unwrap()
        .messages
}

async fn signed_configure_with_definition(
    definition: Definition,
    timestamp: &str,
) -> serde_json::Value {
    let descriptor = ConfigureDescriptor {
        message_timestamp: timestamp.parse().unwrap(),
        definition,
        permission_grant_id: None,
    };
    let descriptor_json = serde_json::to_value(&descriptor).unwrap();
    let signature = signature_for_descriptor(&descriptor_json, json!({}), test_signer()).await;
    json!({
        "descriptor": descriptor_json,
        "authorization": { "signature": signature }
    })
}

/// A message store whose queries can be made to fail, standing in for a store
/// that is unavailable rather than one that answers "no".
#[derive(Clone)]
struct FlakyMessageStore {
    inner: MemoryMessageStore,
    fail_query: Arc<AtomicBool>,
    /// Queries to answer before the store starts failing, so a failure can be
    /// placed *after* a scan has listed its candidates. Negative leaves the
    /// count out of play.
    healthy_queries: Arc<AtomicI64>,
}

impl Default for FlakyMessageStore {
    fn default() -> Self {
        Self {
            inner: MemoryMessageStore::default(),
            fail_query: Arc::new(AtomicBool::new(false)),
            healthy_queries: Arc::new(AtomicI64::new(-1)),
        }
    }
}

impl MessageStore for FlakyMessageStore {
    async fn open(&mut self) -> Result<(), MessageStoreError> {
        self.inner.open().await
    }
    async fn close(&mut self) {
        self.inner.close().await
    }
    async fn put<D>(
        &self,
        tenant: &str,
        message: Message<D>,
        indexes: KeyValues,
    ) -> Result<(), MessageStoreError>
    where
        D: MessageDescriptor + Send,
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
    async fn commit_latest_state(
        &self,
        tenant: &str,
        transition: LatestStateTransition,
    ) -> Result<LatestStateTransitionResult, MessageStoreError> {
        self.inner.commit_latest_state(tenant, transition).await
    }
    async fn query(
        &self,
        tenant: &str,
        filters: Filters,
        sort: Option<MessageSort>,
        pagination: Option<Pagination>,
        record_limit: Option<RecordLimitOccupancy>,
    ) -> Result<MessageQueryResult, MessageStoreError> {
        let counted_out = self.healthy_queries.load(Ordering::SeqCst) >= 0
            && self.healthy_queries.fetch_sub(1, Ordering::SeqCst) <= 0;
        if self.fail_query.load(Ordering::SeqCst) || counted_out {
            return Err(MessageStoreError::StoreError(
                StoreError::InternalException("store unavailable".to_string()),
            ));
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

// Covers: DWN-PROTO-004
// A store that cannot answer is not a record proven wrong. Repair must treat an
// unavailable store as undetermined and keep the record, because destroying
// custody material on a transient failure is unrecoverable while retaining it
// costs only another pass.
#[tokio::test]
async fn a_transient_store_failure_never_reads_as_proof_the_record_is_invalid() {
    let fixture = control_fixture().await;
    admit_audience_signed(
        &fixture,
        &audience_key_jwk(),
        CONTROL_TENANT,
        test_signer(),
        "2025-01-01T00:01:00.000000Z",
        None,
    )
    .await;
    let audience = stored_audience(&fixture).await;

    // The same record, judged through a store that has gone away.
    let mut flaky = FlakyMessageStore::default();
    flaky.open().await.unwrap();
    put_protocol_definition(
        CONTROL_TENANT,
        &flaky,
        control_definition(),
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    flaky.fail_query.store(true, Ordering::SeqCst);

    assert!(
        control_config_validity(CONTROL_TENANT, &audience, &flaky)
            .await
            .is_err(),
        "an unavailable store leaves the record unexamined — never grounds to \
         destroy it, and never a verdict a repair can retire on"
    );

    // And once it recovers, the same record is judged on its merits.
    flaky.fail_query.store(false, Ordering::SeqCst);
    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &flaky).await,
        Ok(ControlConfigValidity::Valid),
        "the record was always sound; only the store was not"
    );
}

/// A task store that keeps a log of what was enlisted, and can be made unable
/// to enlist anything.
///
/// Enlisting is the step both of these tests turn on — one that it happened
/// before the work it describes, one that a node which cannot do it refuses to
/// proceed — and neither is observable through the store's own API: a freshly
/// enlisted task holds a live lease, so `grab` will not return it, and `read`
/// needs an id the caller never sees.
#[derive(Clone, Default)]
struct ProbeTaskStore {
    inner: MemoryResumableTaskStore,
    fail_register: Arc<AtomicBool>,
    enlisted: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl ResumableTaskStore for ProbeTaskStore {
    async fn open(&mut self) -> Result<(), ResumableTaskStoreError> {
        ResumableTaskStore::open(&mut self.inner).await
    }

    async fn close(&mut self) {
        ResumableTaskStore::close(&mut self.inner).await
    }

    async fn register<T: Serialize + Send + Sync + DeserializeOwned + Debug + 'static>(
        &self,
        task: T,
        timeout_in_seconds: u64,
    ) -> Result<ManagedResumableTask<T>, ResumableTaskStoreError> {
        if self.fail_register.load(Ordering::SeqCst) {
            return Err(ResumableTaskStoreError::StoreError(
                StoreError::InternalException("task store unavailable".to_string()),
            ));
        }
        self.enlisted
            .lock()
            .unwrap()
            .push(serde_json::to_value(&task).expect("an enlisted task must serialize"));
        self.inner.register(task, timeout_in_seconds).await
    }

    async fn grab<T: Serialize + Send + Sync + DeserializeOwned + Debug + Unpin>(
        &self,
        count: u64,
    ) -> Result<Vec<ManagedResumableTask<T>>, ResumableTaskStoreError> {
        self.inner.grab(count).await
    }

    async fn read<T: Serialize + Send + Sync + DeserializeOwned + Debug>(
        &self,
        task_id: &str,
    ) -> Result<Option<ManagedResumableTask<T>>, ResumableTaskStoreError> {
        self.inner.read(task_id).await
    }

    async fn extend(
        &self,
        task_id: &str,
        timeout_in_seconds: u64,
    ) -> Result<(), ResumableTaskStoreError> {
        self.inner.extend(task_id, timeout_in_seconds).await
    }

    async fn delete(&self, task_id: &str) -> Result<(), ResumableTaskStoreError> {
        self.inner.delete(task_id).await
    }

    async fn clear(&self) -> Result<(), ResumableTaskStoreError> {
        self.inner.clear().await
    }
}

// Covers: DWN-PROTO-004, DWN-REC-006
// The obligation to re-examine records is recorded before the configuration it
// answers for is committed. A node that cannot record the obligation must
// refuse the configuration rather than accept one it could never repair
// against: nothing is durable yet, so refusing leaves a retry that still
// changes something, while accepting would leave an accepted history
// permanently contradicted by records nothing remembers to check.
#[tokio::test]
async fn a_configuration_is_refused_when_its_repair_cannot_be_enlisted() {
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    admit_audience(&fixture, &key_id, "2025-01-01T00:01:00.000000Z").await;

    let mut data_store = TestDataStore::default();
    data_store.open().await.unwrap();
    let mut tasks = ProbeTaskStore::default();
    ResumableTaskStore::open(&mut tasks).await.unwrap();
    tasks.fail_register.store(true, Ordering::SeqCst);
    let repairer = ResumableTaskManager::new(
        tasks,
        StorageController::new(fixture.message_store.clone(), data_store.clone()),
    );

    let mut demoted = control_definition();
    demoted.structure.get_mut("member").unwrap().role = None;
    let configure_handler = ProtocolsConfigureHandler::new(
        fixture.message_store.clone(),
        Some(Arc::new(test_resolver())),
    )
    .with_repairer(Arc::new(repairer));

    let configure = signed_configure_with_definition(demoted, "2025-01-02T00:00:00.000000Z").await;
    let reply = configure_handler
        .run(CONTROL_TENANT, &configure, None)
        .await;
    assert!(
        reply.status.code >= 500,
        "a configuration whose repair cannot be enlisted must be refused, got {} {}",
        reply.status.code,
        reply.status.detail
    );

    // And it left nothing behind: neither the configuration nor a half-judged
    // control record.
    assert_eq!(
        fixture
            .message_store
            .query(
                CONTROL_TENANT,
                Filters::from(filter_map([
                    ("interface", string_filter("Protocols")),
                    ("method", string_filter("Configure")),
                    (
                        "messageTimestamp",
                        string_filter("2025-01-02T00:00:00.000000Z")
                    ),
                ])),
                None,
                None,
                None,
            )
            .await
            .unwrap()
            .messages
            .len(),
        0,
        "the refused configuration must not have been committed"
    );
    assert!(
        !stored_control_records(&fixture).await.is_empty(),
        "and the control record it would have contradicted must still be there"
    );
}

// Covers: DWN-PROTO-004, DWN-REC-006
// A repair that could not examine every record has not finished, and must not
// retire as though it had. The store answers the scan's listing queries and
// then goes away, so the records are found but never judged — the shape a
// passing outage takes. Skipping them and reporting success would discharge the
// obligation while leaving the accepted configuration unchecked against them.
#[tokio::test]
async fn a_repair_that_could_not_judge_a_record_keeps_its_obligation() {
    let flaky = FlakyMessageStore::default();
    put_protocol_definition(
        CONTROL_TENANT,
        &flaky,
        control_definition(),
        "2025-01-01T00:00:00.000000Z",
    )
    .await;

    let mut write_data_store = TestDataStore::default();
    write_data_store.open().await.unwrap();
    let key_id = audience_key_jwk().thumbprint().unwrap();
    let data = audience_payload("member", "", &key_id, &role_key_jwk().thumbprint().unwrap());
    let write = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", &key_id),
        &data,
        "2025-01-01T00:01:00.000000Z",
        |_| {},
    )
    .await;
    assert_eq!(
        RecordsWriteHandler::new(
            flaky.clone(),
            write_data_store,
            Some(Arc::new(test_resolver()))
        )
        .run(CONTROL_TENANT, &write, Some(data))
        .await
        .status
        .code,
        202,
        "the audience must be stored, or the scan has nothing to fail on"
    );

    let mut data_store = TestDataStore::default();
    data_store.open().await.unwrap();
    let mut tasks = MemoryResumableTaskStore::default();
    ResumableTaskStore::open(&mut tasks).await.unwrap();
    let manager = ResumableTaskManager::new(
        tasks.clone(),
        StorageController::new(flaky.clone(), data_store),
    );
    // Registered with a lapsed lease, the way a crashed process leaves one:
    // recovery only reclaims work nobody is still holding.
    let enlisted = tasks
        .register(
            ResumableTask {
                name: ResumableTaskName::ControlRepair,
                data: serde_json::to_value(ResumableControlRepairData {
                    tenant: CONTROL_TENANT.to_string(),
                    protocol: CONTROL_PROTOCOL.to_string(),
                })
                .unwrap(),
            },
            0,
        )
        .await
        .unwrap();

    // Two queries: one per control path the listing walks. Nothing left for
    // judging what it found.
    flaky.healthy_queries.store(2, Ordering::SeqCst);
    assert!(
        manager
            .resume_tasks_and_wait_for_completion()
            .await
            .is_err(),
        "a repair that could not judge its records must report failure"
    );

    // And the obligation outlived the pass that could not discharge it: still
    // enlisted, waiting for its lease to lapse again rather than retired.
    let still_enlisted = tasks
        .read::<ResumableTask>(&enlisted.id)
        .await
        .expect("reading the task store must succeed");
    assert_eq!(
        still_enlisted.map(|managed| managed.task.name),
        Some(ResumableTaskName::ControlRepair),
        "the repair obligation must survive a pass that could not complete it"
    );
}

// Covers: DWN-PROTO-004, DWN-REC-006
// Each removal is enlisted before it starts, because the first thing it does is
// delete the messages that say which data belonged to the record. Once those
// are gone no scan can rediscover the cleanup — the scan derives its victims
// from retained messages — so the intent has to outlive them.
//
// Data cleanup is made to fail here, which is the observable stand-in for
// crashing between the two halves: the messages are gone, the data is not, and
// what remains is the enlisted intent that can still finish it.
#[tokio::test]
async fn each_removal_is_enlisted_before_the_messages_that_describe_it_are_gone() {
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    admit_audience(&fixture, &key_id, "2025-01-01T00:01:00.000000Z").await;
    let condemned = stored_control_records(&fixture)
        .await
        .first()
        .and_then(record_id)
        .expect("the audience must be stored");

    let mut data_store = TestDataStore::default();
    data_store.open().await.unwrap();
    data_store.fail_delete.store(true, Ordering::SeqCst);
    let mut tasks = ProbeTaskStore::default();
    ResumableTaskStore::open(&mut tasks).await.unwrap();
    let manager = ResumableTaskManager::new(
        tasks.clone(),
        StorageController::new(fixture.message_store.clone(), data_store),
    );

    // A configuration in which `member` is no longer a role, so the stored
    // audience is contradicted and the scan condemns it.
    let mut demoted = control_definition();
    demoted.structure.get_mut("member").unwrap().role = None;
    reconfigure(&fixture, demoted, "2025-01-02T00:00:00.000000Z").await;

    let enlisted = tasks
        .register(
            ResumableTask {
                name: ResumableTaskName::ControlRepair,
                data: serde_json::to_value(ResumableControlRepairData {
                    tenant: CONTROL_TENANT.to_string(),
                    protocol: CONTROL_PROTOCOL.to_string(),
                })
                .unwrap(),
            },
            0,
        )
        .await
        .unwrap();
    assert!(
        manager
            .resume_tasks_and_wait_for_completion()
            .await
            .is_err(),
        "a repair whose cleanup failed has not finished"
    );

    // The messages are gone, so nothing can be re-derived from them.
    assert!(
        stored_control_records(&fixture).await.is_empty(),
        "the condemned record's messages must have been removed"
    );

    // What survives is the cleanup intent, naming the record and its data.
    let enlisted_purge = tasks
        .enlisted
        .lock()
        .unwrap()
        .iter()
        .filter_map(|task| serde_json::from_value::<ResumableTask>(task.clone()).ok())
        .find(|task| task.name == ResumableTaskName::ControlPurge)
        .expect("the removal must have been enlisted before it started");
    let data: ResumableControlPurgeData =
        serde_json::from_value(enlisted_purge.data.clone()).unwrap();
    assert_eq!(data.record_id, condemned);
    assert_eq!(data.data_cids.len(), 1, "the data to reclaim is named");

    // And the scan's own obligation is still there too, undischarged.
    assert!(
        tasks
            .read::<ResumableTask>(&enlisted.id)
            .await
            .unwrap()
            .is_some(),
        "the scan obligation must outlive a pass that could not complete it"
    );
}
