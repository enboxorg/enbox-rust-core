//! Judging retained controls against a configuration, and destroying only the
//! ones it contradicts.

use crate::handlers::protocols::TaskControlRepairer;
use crate::stores::memory::MemoryResumableTaskStore;
use crate::tasks::controller::StorageController;
use crate::tasks::manager::ResumableTaskManager;

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
        ControlConfigValidity::Valid,
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
        ControlConfigValidity::Valid,
        "a role that loses its key agreement must not cost custody of what it already sealed"
    );

    // The role stops being a role at all: the record now names something the
    // protocol does not have.
    let mut demoted = control_definition();
    demoted.structure.get_mut("member").unwrap().role = None;
    reconfigure(&fixture, demoted, "2025-01-03T00:00:00.000000Z").await;
    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &fixture.message_store).await,
        ControlConfigValidity::Invalid,
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
        ControlConfigValidity::Unknown,
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
        actions: vec![crate::protocols::Action::Who(crate::protocols::ActionWho {
            who: crate::protocols::Who::Anyone,
            of: None,
            can: vec![crate::protocols::Can::Create],
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
        crate::permissions::message_author(&delegate_written),
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
    let crate::handlers::records::control::ControlValidationError::Dwn(error) = error else {
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
        ControlConfigValidity::Valid,
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
        ControlConfigValidity::Invalid,
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
    crate::stores::ResumableTaskStore::open(&mut tasks)
        .await
        .unwrap();
    let repairer = TaskControlRepairer::new(ResumableTaskManager::new(
        tasks,
        StorageController::new(fixture.message_store.clone(), data_store.clone()),
    ));

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
    let descriptor = crate::descriptors::ConfigureDescriptor {
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
#[derive(Clone, Default)]
struct FlakyMessageStore {
    inner: MemoryMessageStore,
    fail_query: Arc<AtomicBool>,
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
        if self.fail_query.load(Ordering::SeqCst) {
            return Err(MessageStoreError::StoreError(
                crate::errors::StoreError::InternalException("store unavailable".to_string()),
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

    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &flaky).await,
        ControlConfigValidity::Unknown,
        "an unavailable store is undetermined, never grounds to destroy the record"
    );

    // And once it recovers, the same record is judged on its merits.
    flaky.fail_query.store(false, Ordering::SeqCst);
    assert_eq!(
        control_config_validity(CONTROL_TENANT, &audience, &flaky).await,
        ControlConfigValidity::Valid,
        "the record was always sound; only the store was not"
    );
}

/// A task store that cannot record anything, standing in for one that is
/// unavailable at exactly the wrong moment.
#[derive(Clone, Default)]
struct UnwritableTaskStore {
    inner: MemoryResumableTaskStore,
}

impl crate::stores::ResumableTaskStore for UnwritableTaskStore {
    async fn open(&mut self) -> Result<(), crate::errors::ResumableTaskStoreError> {
        crate::stores::ResumableTaskStore::open(&mut self.inner).await
    }

    async fn close(&mut self) {
        crate::stores::ResumableTaskStore::close(&mut self.inner).await
    }

    async fn register<
        T: serde::Serialize + Send + Sync + serde::de::DeserializeOwned + std::fmt::Debug + 'static,
    >(
        &self,
        _task: T,
        _timeout_in_seconds: u64,
    ) -> Result<crate::stores::ManagedResumableTask<T>, crate::errors::ResumableTaskStoreError>
    {
        Err(crate::errors::ResumableTaskStoreError::StoreError(
            crate::errors::StoreError::InternalException("task store unavailable".to_string()),
        ))
    }

    async fn grab<
        T: serde::Serialize + Send + Sync + serde::de::DeserializeOwned + std::fmt::Debug + Unpin,
    >(
        &self,
        count: u64,
    ) -> Result<Vec<crate::stores::ManagedResumableTask<T>>, crate::errors::ResumableTaskStoreError>
    {
        self.inner.grab(count).await
    }

    async fn read<
        T: serde::Serialize + Send + Sync + serde::de::DeserializeOwned + std::fmt::Debug,
    >(
        &self,
        task_id: &str,
    ) -> Result<
        Option<crate::stores::ManagedResumableTask<T>>,
        crate::errors::ResumableTaskStoreError,
    > {
        self.inner.read(task_id).await
    }

    async fn extend(
        &self,
        task_id: &str,
        timeout_in_seconds: u64,
    ) -> Result<(), crate::errors::ResumableTaskStoreError> {
        self.inner.extend(task_id, timeout_in_seconds).await
    }

    async fn delete(&self, task_id: &str) -> Result<(), crate::errors::ResumableTaskStoreError> {
        self.inner.delete(task_id).await
    }

    async fn clear(&self) -> Result<(), crate::errors::ResumableTaskStoreError> {
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
    let mut tasks = UnwritableTaskStore::default();
    crate::stores::ResumableTaskStore::open(&mut tasks)
        .await
        .unwrap();
    let repairer = TaskControlRepairer::new(ResumableTaskManager::new(
        tasks,
        StorageController::new(fixture.message_store.clone(), data_store.clone()),
    ));

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
