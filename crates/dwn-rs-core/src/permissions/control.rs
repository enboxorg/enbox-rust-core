//! Who a control write acts as.
//!
//! A control record is admitted on behalf of exactly one actor, and which DID
//! that is does not follow from any single field. A message can be signed by a
//! delegate, countersigned by the owner, countersigned by an *owner's*
//! delegate, or simply signed by its author — and each of those establishes a
//! different actor, sometimes backed by a grant that must hold on its own.
//!
//! Delegation never launders identity. A delegate acting for the tenant is
//! still the delegate: it acts with whatever its grant covers, and does not
//! inherit the tenant's standing by having the tenant as semantic author.

use super::{
    fetch_grant, perform_base_validation, verify_records_write_conditions, AuthorizationContext,
    AuthorizationValidationError, PermissionError, PermissionGrant,
};
use crate::{Descriptor, Message};

/// The DID a control write acts as, with the grant that established it.
///
/// `grant` is `None` when the actor stands on its own identity (a verified
/// owner, or a plain author); it is `Some` when authority was delegated, and
/// then the grant bounds what the actor may do.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlActor {
    pub did: String,
    pub grant: Option<PermissionGrant>,
}

impl ControlActor {
    fn new(did: impl Into<String>, grant: Option<PermissionGrant>) -> Self {
        Self {
            did: did.into(),
            grant,
        }
    }
}

/// Resolves the actor for a control write, verifying every grant it leans on.
///
/// Precedence, highest first:
///
/// 1. **author-delegate** — signed by a delegate of the semantic author;
/// 2. **owner-delegate** — countersigned by a delegate of the owner;
/// 3. **verified owner** — countersigned by the owner directly;
/// 4. **author** — plain, optionally invoking a tenant-issued grant.
///
/// A grant reached along the way is validated before it is allowed to confer
/// anything. An *absent* grant leaves the actor standing on its own identity;
/// an *invalid* one fails the write rather than quietly demoting it, so a
/// writer cannot improve its position by invoking a grant that does not hold.
pub async fn resolve_control_actor<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    signature: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<ControlActor, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    // Requirement 8: an asserted owner must be the tenant. Checked *before* the
    // precedence branches, not inside the owner branch — otherwise a message
    // countersigned by some other DWN's owner would be silently ignored
    // whenever author delegation happened to win, admitting a write that
    // asserts an owner nobody verified against this tenant.
    if let Some(owner) = &signature.owner {
        if owner.owner != tenant {
            return Err(AuthorizationValidationError::Unauthorized(format!(
                "owner '{}' is not the tenant '{tenant}'",
                owner.owner
            ))
            .into());
        }
    }

    if let Some(grant) = &signature.author_delegated_grant {
        // The author delegated to whoever signed.
        validate_control_grant(
            message,
            &signature.author,
            &signature.signer,
            grant,
            message_store,
        )
        .await?;
        return Ok(ControlActor::new(&signature.signer, Some(grant.clone())));
    }

    if let Some(owner) = &signature.owner {
        if let Some(grant) = &owner.delegated_grant {
            // The owner delegated to whoever countersigned.
            validate_control_grant(message, &owner.owner, &owner.signer, grant, message_store)
                .await?;
            return Ok(ControlActor::new(&owner.signer, Some(grant.clone())));
        }
        return Ok(ControlActor::new(&owner.owner, None));
    }

    // A plain author may still invoke a grant the tenant issued it directly.
    let Some(grant_id) = signature.permission_grant_id() else {
        return Ok(ControlActor::new(&signature.author, None));
    };
    let grant = fetch_grant(tenant, message_store, grant_id).await?;
    validate_control_grant(message, tenant, &signature.author, &grant, message_store).await?;
    Ok(ControlActor::new(&signature.author, Some(grant)))
}

/// Validates a grant a control write leans on.
///
/// Pairs the ordinary grant gate — grantor and grantee, the
/// `dateGranted <= messageTimestamp < dateExpires` window, revocation at or
/// before that timestamp, and interface/method scope — with the publication
/// conditions, which are separate upstream and easy to invoke one without the
/// other. Control records are never published, so a grant requiring
/// publication cannot authorize one.
pub(crate) async fn validate_control_grant<MessageStore>(
    message: &Message<Descriptor>,
    expected_grantor: &str,
    expected_grantee: &str,
    grant: &PermissionGrant,
    message_store: &MessageStore,
) -> Result<(), PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    perform_base_validation(
        message,
        expected_grantor,
        expected_grantee,
        grant,
        message_store,
    )
    .await?;
    verify_records_write_conditions(message, grant.conditions.as_ref())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jws::{AuthorizationPayloadData, PermissionGrantInvocation};
    use crate::permissions::{
        OwnerAuthorization, PermissionConditionPublication, PermissionConditions, PermissionScope,
        RecordsMethod, RecordsScope, VerifiedAuthorizationPayload,
    };
    use crate::stores::memory::MemoryMessageStore;

    const TENANT: &str = "did:example:alice";
    const AUTHOR: &str = "did:example:bob";
    const DELEGATE: &str = "did:example:carol";
    const PROTOCOL: &str = "https://example.com/protocol/threads";

    fn parse_time(value: &str) -> chrono::DateTime<chrono::Utc> {
        value.parse().expect("valid timestamp")
    }

    fn grant(id: &str, grantor: &str, grantee: &str) -> PermissionGrant {
        PermissionGrant {
            id: id.to_string(),
            grantor: grantor.to_string(),
            grantee: grantee.to_string(),
            date_granted: parse_time("2025-01-01T00:00:00.000000Z"),
            date_expires: parse_time("2025-02-01T00:00:00.000000Z"),
            delegated: Some(true),
            scope: PermissionScope::Records(RecordsScope {
                protocol: PROTOCOL.to_string(),
                method: RecordsMethod::Write,
                selector: None,
            }),
            conditions: None,
            connect_session: None,
        }
    }

    fn control_write() -> Message<Descriptor> {
        serde_json::from_value(serde_json::json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "protocol": PROTOCOL,
                "protocolPath": "$encryption/audience",
                "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
                "dataSize": 0,
                "dataFormat": "application/json",
                "dateCreated": "2025-01-10T00:00:00.000000Z",
                "messageTimestamp": "2025-01-10T00:00:00.000000Z"
            },
            "recordId": "control-record"
        }))
        .expect("control write fixture")
    }

    fn context(signer: &str, author: &str) -> AuthorizationContext {
        AuthorizationContext {
            signer: signer.to_string(),
            author: author.to_string(),
            payload: VerifiedAuthorizationPayload::Generic(AuthorizationPayloadData {
                descriptor_cid: String::new(),
                delegated_grant_id: None,
                permission_grant_id: None,
                permission_grant_ids: None,
                protocol_role: None,
            }),
            permission_grant_invocation: PermissionGrantInvocation::None,
            author_delegated_grant: None,
            owner: None,
        }
    }

    // Covers: DWN-AUTH-001, DWN-PROTO-003
    // Signer, semantic author and owner stay distinct. Each branch resolves to
    // the DID that actually acted, never to whoever the message names.
    #[tokio::test]
    async fn actor_precedence_resolves_who_actually_acted() {
        let store = MemoryMessageStore::default();
        let message = control_write();

        // 1. Author-delegate: the delegate acted, bounded by the author's grant.
        let mut delegated = context(DELEGATE, AUTHOR);
        delegated.author_delegated_grant = Some(grant("g1", AUTHOR, DELEGATE));
        let actor = resolve_control_actor(TENANT, &message, &delegated, &store)
            .await
            .expect("author delegation resolves");
        assert_eq!(actor.did, DELEGATE, "the delegate acted, not the author");
        assert!(actor.grant.is_some(), "delegation is bounded by its grant");

        // 2. Owner-delegate outranks a plain owner countersignature.
        let mut owner_delegated = context(AUTHOR, AUTHOR);
        owner_delegated.owner = Some(OwnerAuthorization {
            owner: TENANT.to_string(),
            signer: DELEGATE.to_string(),
            delegated_grant: Some(grant("g2", TENANT, DELEGATE)),
        });
        let actor = resolve_control_actor(TENANT, &message, &owner_delegated, &store)
            .await
            .expect("owner delegation resolves");
        assert_eq!(actor.did, DELEGATE);
        assert!(actor.grant.is_some());

        // 3. Verified owner stands on its own identity, with no grant.
        let mut owned = context(AUTHOR, AUTHOR);
        owned.owner = Some(OwnerAuthorization {
            owner: TENANT.to_string(),
            signer: TENANT.to_string(),
            delegated_grant: None,
        });
        let actor = resolve_control_actor(TENANT, &message, &owned, &store)
            .await
            .expect("verified owner resolves");
        assert_eq!(actor.did, TENANT);
        assert!(actor.grant.is_none());

        // 4. Plain author, nothing invoked.
        let actor = resolve_control_actor(TENANT, &message, &context(AUTHOR, AUTHOR), &store)
            .await
            .expect("plain author resolves");
        assert_eq!(actor.did, AUTHOR);
        assert!(actor.grant.is_none());
    }

    // Covers: DWN-AUTH-001
    // Delegation must not launder identity: a delegate acting for the tenant is
    // still the delegate, and does not inherit the tenant's standing.
    #[tokio::test]
    async fn delegation_does_not_confer_the_tenants_identity() {
        let store = MemoryMessageStore::default();
        let message = control_write();

        let mut tenant_delegated = context(DELEGATE, TENANT);
        tenant_delegated.author_delegated_grant = Some(grant("g3", TENANT, DELEGATE));
        let actor = resolve_control_actor(TENANT, &message, &tenant_delegated, &store)
            .await
            .expect("tenant delegation resolves");
        assert_eq!(
            actor.did, DELEGATE,
            "a delegate of the tenant acts as itself, not as the tenant"
        );
    }

    // Covers: DWN-AUTH-001, DWN-PROTO-003
    // Requirement 8: an asserted owner must be the tenant. The author-delegate
    // branch outranks the owner branch, so without an up-front check a write
    // asserting a foreign owner would be admitted with that assertion never
    // examined.
    #[tokio::test]
    async fn an_owner_that_is_not_the_tenant_is_rejected_whichever_branch_would_win() {
        let store = MemoryMessageStore::default();
        let message = control_write();
        let foreign = |signature: &mut AuthorizationContext| {
            signature.owner = Some(OwnerAuthorization {
                owner: "did:example:other-dwn".to_string(),
                signer: "did:example:other-dwn".to_string(),
                delegated_grant: None,
            });
        };

        // Owner branch: nothing else could have admitted this.
        let mut owned = context(AUTHOR, AUTHOR);
        foreign(&mut owned);
        assert!(
            resolve_control_actor(TENANT, &message, &owned, &store)
                .await
                .is_err(),
            "an owner from another tenant must not authorize a control write"
        );

        // Author-delegate branch, which outranks it: the foreign owner must
        // still be rejected rather than shadowed by a valid delegation.
        let mut shadowed = context(DELEGATE, AUTHOR);
        shadowed.author_delegated_grant = Some(grant("g7", AUTHOR, DELEGATE));
        foreign(&mut shadowed);
        assert!(
            resolve_control_actor(TENANT, &message, &shadowed, &store)
                .await
                .is_err(),
            "a foreign owner assertion must not be ignored because another branch wins"
        );

        // The same delegation without the foreign assertion is fine, so the
        // rejection above is the owner check and not the delegation.
        let mut clean = context(DELEGATE, AUTHOR);
        clean.author_delegated_grant = Some(grant("g7", AUTHOR, DELEGATE));
        assert!(
            resolve_control_actor(TENANT, &message, &clean, &store)
                .await
                .is_ok(),
            "the delegation itself is valid"
        );
    }

    // Covers: DWN-AUTH-004
    #[tokio::test]
    async fn an_invalid_grant_fails_the_write_rather_than_being_ignored() {
        let store = MemoryMessageStore::default();
        let message = control_write();

        // Grantee mismatch: the grant names someone other than the signer.
        let mut wrong_grantee = context(DELEGATE, AUTHOR);
        wrong_grantee.author_delegated_grant = Some(grant("g4", AUTHOR, "did:example:mallory"));
        assert!(
            resolve_control_actor(TENANT, &message, &wrong_grantee, &store)
                .await
                .is_err(),
            "a grant issued to someone else must not authorize this signer"
        );

        // Expired before the message timestamp.
        let mut expired_grant = grant("g5", AUTHOR, DELEGATE);
        expired_grant.date_expires = parse_time("2025-01-02T00:00:00.000000Z");
        let mut expired = context(DELEGATE, AUTHOR);
        expired.author_delegated_grant = Some(expired_grant);
        assert!(
            resolve_control_actor(TENANT, &message, &expired, &store)
                .await
                .is_err(),
            "an expired grant confers nothing"
        );

        // Publication-required cannot authorize a control record, which is
        // never published.
        let mut publish_required = grant("g6", AUTHOR, DELEGATE);
        publish_required.conditions = Some(PermissionConditions {
            publication: Some(PermissionConditionPublication::Required),
        });
        let mut conditioned = context(DELEGATE, AUTHOR);
        conditioned.author_delegated_grant = Some(publish_required);
        assert!(
            resolve_control_actor(TENANT, &message, &conditioned, &store)
                .await
                .is_err(),
            "a grant requiring publication cannot authorize an unpublished control"
        );
    }
}
