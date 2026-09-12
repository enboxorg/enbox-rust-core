use crate::canonical_rfc3339;
use crate::permissions::errors::PermissionError;

use super::*;

mod audience;
pub(crate) mod delivery;

pub(crate) use audience::filter_pins_an_audience_scope;
use audience::{can_enumerate_audience, exact_audience_request_matches};
pub(in crate::handlers::records::control) use audience::{names_record, pins_audience_key};
use delivery::delivery_reachable_by_grant;

/// Who a read request acts as.
///
/// For an author-delegated request that is the delegate who actually signed,
/// not the author it signs for. A delegate reading on someone's behalf is still
/// the delegate: letting it borrow the author's identity would let a tenant's
/// delegate read every recipient's deliveries merely because the tenant is the
/// semantic author.
pub(crate) fn read_requester(signature: &AuthorizationContext) -> &str {
    if signature.author_delegated_grant.is_some() {
        &signature.signer
    } else {
        &signature.author
    }
}

/// The grant a read request invokes, validated before it is allowed to confer
/// visibility.
///
/// Validation happens here rather than at the point of use so that an invalid
/// grant fails the request instead of silently falling through to whatever
/// access the requester would have had anyway.
pub(crate) async fn authorize_control_read_request<MessageStore>(
    tenant: &str,
    read_message: &Message<Descriptor>,
    signature: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<(), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if read_requester(signature) == tenant {
        return Ok(());
    }
    invoked_read_grant(tenant, read_message, signature, message_store).await?;
    Ok(())
}

/// At most one: a request either embeds an author-delegated grant or names a
/// single grant id, and the two are alternatives rather than a set.
async fn invoked_read_grant<MessageStore>(
    tenant: &str,
    read_message: &Message<Descriptor>,
    signature: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<Option<PermissionGrant>, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let requester = read_requester(signature);
    let unauthorized = |error: PermissionError| {
        control_error(
            DwnErrorCode::EncryptionControlReadUnauthorized,
            error.to_string(),
        )
    };

    if let Some(grant) = &signature.author_delegated_grant {
        perform_base_validation(
            read_message,
            &grant.grantor,
            requester,
            grant,
            message_store,
        )
        .await
        .map_err(unauthorized)?;
        return Ok(Some(grant.clone()));
    }

    let Some(grant_id) = signature.permission_grant_id() else {
        return Ok(None);
    };
    let grant = fetch_grant(tenant, message_store, grant_id)
        .await
        .map_err(unauthorized)?;
    perform_base_validation(read_message, tenant, requester, &grant, message_store)
        .await
        .map_err(unauthorized)?;
    Ok(Some(grant))
}

/// The timestamp a read request's authority is evaluated at. Role policy and
/// grant validity are resolved as of the request, never blindly the newest
/// configuration.
fn request_timestamp(read_message: &Message<Descriptor>) -> Result<String, ControlValidationError> {
    Ok(canonical_rfc3339(read_message.message_timestamp()))
}

/// Whether a request targets control records exclusively.
///
/// Such a request cannot match anything else, which is what makes it safe to
/// let control authorization decide it instead of the ordinary protocol ladder
/// — a ladder that would reject it outright, since these paths are not
/// declared by any protocol.
pub(crate) fn filter_targets_only_controls(filter: &RecordsFilter) -> bool {
    filter
        .protocol_path
        .as_deref()
        .is_some_and(|path| ControlKind::from_protocol_path(path).is_some())
}

/// Whether a request's candidate population could contain control records.
///
/// Only a filter pinned to some other protocol path provably excludes them. A
/// protocol-wide or unpinned request may sweep up audiences and deliveries, and
/// must therefore be projected and visibility-checked like any other control
/// request — counting such a population through the store would report
/// superseded audiences and records the requester cannot read.
pub(crate) fn filter_may_match_controls(filter: &RecordsFilter) -> bool {
    match filter.protocol_path.as_deref() {
        Some(path) => ControlKind::from_protocol_path(path).is_some(),
        None => true,
    }
}

/// Whether `signature` may read this control record.
///
/// Control records are unpublished, so there is no anonymous path to any of
/// them. Beyond the tenant, an audience and a delivery are reached by entirely
/// different routes: an audience is a directory entry, addressable by anyone
/// who can already name it exactly; a delivery is addressed key material, and
/// only its parties or a grant connecting them reaches it.
pub(crate) async fn can_read<MessageStore>(
    tenant: &str,
    read_message: &Message<Descriptor>,
    signature: Option<&AuthorizationContext>,
    control: &Message<Descriptor>,
    filter: Option<&RecordsFilter>,
    message_store: &MessageStore,
) -> Result<bool, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(kind) = ControlKind::of(control) else {
        return Ok(true);
    };
    // Unpublished by construction, so an unauthenticated reader has no route.
    let Some(signature) = signature else {
        return Ok(false);
    };
    let requester = read_requester(signature).to_string();
    if requester == tenant {
        return Ok(true);
    }

    // An invoked grant is validated up front, including on requests that would
    // otherwise be answered without it.
    let grant = invoked_read_grant(tenant, read_message, signature, message_store).await?;
    let id = AudienceId::from_message(control, kind)?;

    match kind {
        ControlKind::Delivery => {
            let descriptor =
                records_write_descriptor(control).map_err(|error| unexpected(error.to_string()))?;
            if descriptor.recipient.as_deref() == Some(requester.as_str())
                || extract_author(control).as_deref() == Some(requester.as_str())
            {
                return Ok(true);
            }
            delivery_reachable_by_grant(
                tenant,
                read_message,
                control,
                &id,
                grant.as_ref(),
                message_store,
            )
            .await
        }
        ControlKind::Audience => {
            if filter.is_some_and(|filter| exact_audience_request_matches(filter, &id, control)) {
                return Ok(true);
            }
            can_enumerate_audience(
                tenant,
                read_message,
                signature,
                &requester,
                &id,
                grant.as_ref(),
                message_store,
            )
            .await
        }
    }
}

/// Removes control records the requester may not see from a collection page.
///
/// Collections share this one filter rather than each handler re-deriving
/// visibility, so a record hidden from Query cannot surface through Count or a
/// Subscribe snapshot. Non-control records pass straight through: this decides
/// only what ordinary record authorization has no vocabulary for.
pub(crate) async fn filter_visible_controls<MessageStore>(
    tenant: &str,
    request: &Message<Descriptor>,
    signature: Option<&AuthorizationContext>,
    filter: Option<&RecordsFilter>,
    records: Vec<Message<Descriptor>>,
    message_store: &MessageStore,
) -> Result<Vec<Message<Descriptor>>, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    // Nothing to decide unless the page actually contains a control record.
    if !records
        .iter()
        .any(|record| ControlKind::of(record).is_some())
    {
        return Ok(records);
    }

    let mut visible = Vec::with_capacity(records.len());
    for record in records {
        if can_read(tenant, request, signature, &record, filter, message_store).await? {
            visible.push(record);
        }
    }
    Ok(visible)
}

/// Whether a Records grant of `method` covers this role path, by exact protocol
/// and path-boundary subtree.
pub(super) fn grant_covers_role(
    scope: &PermissionScope,
    id: &AudienceId,
    method: RecordsMethod,
) -> bool {
    let PermissionScope::Records(records) = scope else {
        return false;
    };
    if records.method != method {
        return false;
    }
    scope.matches_protocol_target(&ProtocolScopeTarget {
        protocol: Some(&id.scope.protocol),
        protocol_path: Some(&id.scope.role_path),
        context_id: None,
    })
}
