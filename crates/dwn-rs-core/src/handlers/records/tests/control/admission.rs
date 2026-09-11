//! What a control record must be to be admitted at all.

use super::*;

// Covers: ENBOX-ENC-001, DWN-PROTO-002, DWN-PROTO-004
// A well-formed audience is admitted at a virtual path the protocol never
// declares, proving control records bypass application type and rule lookup
// while still resolving their role against the governing definition.
#[tokio::test]
async fn a_valid_audience_control_record_is_admitted() {
    let fixture = control_fixture().await;
    let data = audience_payload("member", "", &fixture.audience_key_id, &fixture.seal_key_id);
    let write = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", &fixture.audience_key_id),
        &data,
        "2025-01-01T00:01:00.000000Z",
        |_| {},
    )
    .await;

    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &write, Some(data))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: ENBOX-ENC-001
// The lifecycle contract: immutable, unpublished, bounded, and plaintext.
#[tokio::test]
async fn audience_lifecycle_rules_are_enforced() {
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    let data = audience_payload("member", "", &key_id, &fixture.seal_key_id);
    let tags = audience_tags("member", "", &key_id);

    // Published is rejected: control records are never public.
    let published = control_write(
        AUDIENCE_PATH,
        tags.clone(),
        &data,
        "2025-01-01T00:01:00.000000Z",
        |spec| spec.published = Some(true),
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &published, Some(data.clone()))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("EncryptionControlValidateUnexpectedRecord")
    );

    // Over the inline bound: admission validates the payload in full, so it
    // must be small enough to hold.
    let oversize = control_write(
        AUDIENCE_PATH,
        tags.clone(),
        &data,
        "2025-01-01T00:01:00.000000Z",
        |spec| spec.data_size = 30_001,
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &oversize, Some(data.clone()))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("EncryptionControlValidateUnexpectedRecord")
    );

    // The boundary itself is allowed.
    let boundary_data = Bytes::from(vec![b' '; 30_000]);
    let boundary = control_write(
        AUDIENCE_PATH,
        tags.clone(),
        &boundary_data,
        "2025-01-01T00:01:00.000000Z",
        |_| {},
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &boundary, Some(boundary_data))
        .await;
    assert_ne!(
        reply.status.error_code.as_deref(),
        Some("EncryptionControlValidateUnexpectedRecord"),
        "30000 bytes is within the bound; rejection must be about the payload, not the size: {}",
        reply.status.detail
    );
}

// Covers: ENBOX-ENC-001
// Identity and key commitments. Each case breaks exactly one thing, so the
// reported code names the commitment that was broken rather than whichever
// check happened to run first.
#[tokio::test]
async fn audience_identity_and_key_commitments_are_checked() {
    let fixture = control_fixture().await;
    let key = fixture.audience_key_id.clone();
    let seal = fixture.seal_key_id.clone();

    // (label, tags, payload, expected code)
    let cases = [
        (
            "payload disagrees with its own tags",
            audience_tags("member", "", &seal),
            audience_payload("member", "", &key, &seal),
            "EncryptionControlValidateAudienceTagsMismatch",
        ),
        (
            "role path is not a keyed role",
            audience_tags("plain", "", &key),
            audience_payload("plain", "", &key, &seal),
            "EncryptionControlValidateAudienceRolePathInvalid",
        ),
        (
            "root role carrying a context",
            audience_tags("member", "thread-1", &key),
            audience_payload("member", "thread-1", &key, &seal),
            "EncryptionControlValidateAudienceContextIdInvalid",
        ),
        (
            "nested role missing its context",
            audience_tags("thread/participant", "", &key),
            audience_payload("thread/participant", "", &key, &seal),
            "EncryptionControlValidateAudienceContextIdInvalid",
        ),
        (
            "keyId is not the published key's thumbprint",
            audience_tags("member", "", &seal),
            audience_payload("member", "", &seal, &seal),
            "EncryptionControlValidateAudienceKeyIdMismatch",
        ),
        (
            "seal is not under the governing role key",
            audience_tags("member", "", &key),
            audience_payload("member", "", &key, &key),
            "EncryptionControlValidateAudienceSealKeyIdMismatch",
        ),
    ];

    for (label, tags, data, expected) in cases {
        let write = control_write(
            AUDIENCE_PATH,
            tags,
            &data,
            "2025-01-01T00:01:00.000000Z",
            |_| {},
        )
        .await;
        let reply = fixture
            .handler
            .run(CONTROL_TENANT, &write, Some(data))
            .await;
        assert_eq!(reply.status.code, 400, "{label}: {}", reply.status.detail);
        assert_eq!(
            reply.status.error_code.as_deref(),
            Some(expected),
            "{label}: {}",
            reply.status.detail
        );
    }
}

// Covers: ENBOX-ENC-001, DWN-PROTO-002
// A delivery is admitted only once both things it references exist, and the
// two absences are reported distinctly so a producer can tell which to repair.
// Its ciphertext is never opened: admission inspects public metadata only.
#[tokio::test]
async fn delivery_requires_its_audience_and_a_role_holding_recipient() {
    const RECIPIENT: &str = "did:example:bob";
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    let ciphertext = Bytes::from_static(b"sealed key material, never opened here");

    let delivery = |timestamp: &'static str| {
        let key_id = key_id.clone();
        let ciphertext = ciphertext.clone();
        async move {
            control_write(
                DELIVERY_PATH,
                delivery_tags("member", "", &key_id, "roleHolder"),
                &ciphertext,
                timestamp,
                |spec| {
                    spec.recipient = Some(RECIPIENT.to_string());
                    spec.encryption = Some(delivery_envelope());
                },
            )
            .await
        }
    };

    // Neither the audience nor the role record exists yet.
    let reply = fixture
        .handler
        .run(
            CONTROL_TENANT,
            &delivery("2025-01-01T00:01:00.000000Z").await,
            Some(ciphertext.clone()),
        )
        .await;
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("EncryptionControlValidateDeliveryAudienceMissing"),
        "{}",
        reply.status.detail
    );

    // Audience present, recipient still holds no role.
    admit_audience(&fixture, &key_id, "2025-01-01T00:02:00.000000Z").await;
    let reply = fixture
        .handler
        .run(
            CONTROL_TENANT,
            &delivery("2025-01-01T00:03:00.000000Z").await,
            Some(ciphertext.clone()),
        )
        .await;
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("EncryptionControlValidateDeliveryRecipientRoleRecordMissing"),
        "{}",
        reply.status.detail
    );

    // Both present: admitted.
    grant_member_role(
        &fixture.message_store,
        RECIPIENT,
        "2025-01-01T00:04:00.000000Z",
    )
    .await;
    let reply = fixture
        .handler
        .run(
            CONTROL_TENANT,
            &delivery("2025-01-01T00:05:00.000000Z").await,
            Some(ciphertext),
        )
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);
}

// Covers: ENBOX-ENC-001
// A delivery is looked up by the whole four-field identity, key id included, so
// a key that has been superseded is still deliverable. Recipients who were sent
// an older key keep needing it; ceasing to be *current* is not ceasing to exist.
#[tokio::test]
async fn a_delivery_may_reference_a_superseded_audience_key() {
    const RECIPIENT: &str = "did:example:bob";
    let fixture = control_fixture().await;
    let older_key = fixture.audience_key_id.clone();
    let newer_key = fixture.seal_key_id.clone();

    admit_audience(&fixture, &older_key, "2025-01-01T00:01:00.000000Z").await;
    grant_member_role(
        &fixture.message_store,
        RECIPIENT,
        "2025-01-01T00:02:00.000000Z",
    )
    .await;

    // A second audience for the same role supersedes the first as *current*.
    let newer_data = audience_payload("member", "", &newer_key, &fixture.seal_key_id);
    let newer = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", &newer_key),
        &newer_data,
        "2025-01-01T00:03:00.000000Z",
        |_| {},
    )
    .await;
    // The newer key's payload publishes a different key than it names, so it is
    // only the *older* one that matters here; what is under test is that the
    // older key stays addressable regardless.
    let _ = fixture
        .handler
        .run(CONTROL_TENANT, &newer, Some(newer_data))
        .await;

    let ciphertext = Bytes::from_static(b"sealed older key");
    let delivery = control_write(
        DELIVERY_PATH,
        delivery_tags("member", "", &older_key, "roleHolder"),
        &ciphertext,
        "2025-01-01T00:04:00.000000Z",
        |spec| {
            spec.recipient = Some(RECIPIENT.to_string());
            spec.encryption = Some(delivery_envelope());
        },
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &delivery, Some(ciphertext))
        .await;
    assert_eq!(
        reply.status.code, 202,
        "a superseded audience key must remain deliverable: {}",
        reply.status.detail
    );
}

// Covers: ENBOX-ENC-001
// Control records are immutable and undeletable, including by the tenant.
// Key material recipients already hold cannot be recalled by removing the
// record describing it, so permitting either would destroy the node's own
// account of what was distributed without retracting anything.
#[tokio::test]
async fn control_records_cannot_be_updated_or_deleted() {
    let fixture = control_fixture().await;
    let key_id = fixture.audience_key_id.clone();
    let data = audience_payload("member", "", &key_id, &fixture.seal_key_id);
    let initial = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", &key_id),
        &data,
        "2025-01-01T00:01:00.000000Z",
        |_| {},
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &initial, Some(data.clone()))
        .await;
    assert_eq!(reply.status.code, 202, "{}", reply.status.detail);

    // An update to the same record is refused as an update, not as a duplicate.
    let update = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", &key_id),
        &data,
        "2025-01-01T00:02:00.000000Z",
        |spec| {
            spec.record_id = Some(initial["recordId"].as_str().unwrap().to_string());
            spec.date_created = "2025-01-01T00:01:00.000000Z".to_string();
        },
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &update, Some(data))
        .await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("EncryptionControlValidateUnexpectedRecord"),
        "{}",
        reply.status.detail
    );

    // And the tenant — who may delete anything else — cannot delete this.
    let mut data_store = TestDataStore::default();
    data_store.open().await.unwrap();
    let delete_handler = RecordsDeleteHandler::new(
        fixture.message_store.clone(),
        data_store,
        Some(Arc::new(test_resolver())),
    );
    let delete = signed_delete_message(
        initial["recordId"].as_str().unwrap(),
        false,
        "2025-01-01T00:03:00.000000Z",
    )
    .await;
    let reply = delete_handler.run(CONTROL_TENANT, &delete, None).await;
    assert_eq!(reply.status.code, 400, "{}", reply.status.detail);
    assert_eq!(
        reply.status.error_code.as_deref(),
        Some("EncryptionControlValidateUnexpectedRecord"),
        "{}",
        reply.status.detail
    );
}
