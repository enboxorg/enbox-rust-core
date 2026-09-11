//! Whether a reader may reach an audience record.
//!
//! An audience is a directory entry. Anyone who can already name one
//! exactly may read it, because naming a specific stored key is not the
//! same as enumerating a role's keys — and enumerating needs authority over
//! the role itself.

use super::super::authorization::actor_can_create_role;
use super::super::*;
use super::{grant_covers_role, request_timestamp};

/// Whether a request names this audience exactly, rather than sweeping for it.
///
/// Naming a specific stored key is not the same as enumerating a role's keys,
/// which is why an exact request needs no further authority while a broad one
/// does. The tuple must be fully pinned by equality: a range or list predicate
/// describes a region, not a record, and supplies no component.
pub(super) fn exact_audience_request_matches(
    filter: &RecordsFilter,
    id: &AudienceId,
    control: &Message<Descriptor>,
) -> bool {
    // Reaching a directory entry needs only the role pinned; the key id is
    // optional, because a three-field tuple still names one role's directory.
    names_record(filter, control) || pins_audience_scope(filter, id)
}

/// Whether the caller pinned this record by id.
pub(in crate::handlers::records::control) fn names_record(
    filter: &RecordsFilter,
    control: &Message<Descriptor>,
) -> bool {
    filter.record_id.is_some() && filter.record_id == record_id(control)
}

/// Reads a tag the caller pinned by equality.
///
/// A range or list predicate describes a region rather than a record and
/// supplies nothing, which is what stops a caller reaching a specific key by
/// gesturing near it.
pub(super) fn pinned_tag<'a>(filter: &'a RecordsFilter, tag: &str) -> Option<&'a str> {
    match filter.tags.as_ref()?.get(tag)? {
        crate::Filter::Equal(crate::Value::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Whether the caller pinned *some* audience scope exactly, without reference
/// to any stored record.
///
/// Candidate selection needs this form: it decides which records a collection
/// may consider before any of them has been read, so it cannot ask whether the
/// tuple matches a particular one. Naming a record by id is deliberately not
/// enough — that reaches a directory entry through direct Read, and widening a
/// collection on it would let anyone enumerate an audience they happen to know
/// the id of.
pub(crate) fn filter_pins_an_audience_scope(filter: &RecordsFilter) -> bool {
    audience_scope_pinned_by(filter).is_some()
}

/// The three-field scope the caller pinned, if it pinned one.
fn audience_scope_pinned_by(filter: &RecordsFilter) -> Option<(&str, &str, &str)> {
    if filter.protocol_path.as_deref() != Some(ControlKind::Audience.protocol_path()) {
        return None;
    }
    let protocol = pinned_tag(filter, "protocol")?;
    if filter.protocol.as_deref() != Some(protocol) {
        return None;
    }
    Some((
        protocol,
        pinned_tag(filter, "rolePath")?,
        pinned_tag(filter, "contextId")?,
    ))
}

/// Whether the caller pinned the three-field scope this audience belongs to.
pub(super) fn pins_audience_scope(filter: &RecordsFilter, id: &AudienceId) -> bool {
    audience_scope_pinned_by(filter)
        == Some((
            id.scope.protocol.as_str(),
            id.scope.role_path.as_str(),
            id.scope.context_id.as_str(),
        ))
}

/// Whether the caller pinned this audience's whole four-field identity.
///
/// Only that names one stored record, which is why only that bypasses
/// projection: the caller asked for a particular key, not for whichever key is
/// current.
pub(in crate::handlers::records::control) fn pins_audience_key(
    filter: &RecordsFilter,
    id: &AudienceId,
) -> bool {
    pins_audience_scope(filter, id) && pinned_tag(filter, "keyId") == Some(id.key_id.as_str())
}

/// Broad audience visibility: a read grant covering the role, or the authority
/// to create that role in the first place.
///
/// Someone who could mint the role's keys can hardly be kept from reading them,
/// which is why create authority is sufficient here.
pub(super) async fn can_enumerate_audience<MessageStore>(
    tenant: &str,
    read_message: &Message<Descriptor>,
    signature: &AuthorizationContext,
    requester: &str,
    id: &AudienceId,
    grants: &[PermissionGrant],
    message_store: &MessageStore,
) -> Result<bool, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if grants
        .iter()
        .any(|grant| grant_covers_role(&grant.scope, id, RecordsMethod::Read))
    {
        return Ok(true);
    }

    let timestamp = request_timestamp(read_message)?;
    let role = resolve_role_audience_definition(tenant, id, &timestamp, message_store).await?;
    let actor = ControlActor {
        did: requester.to_string(),
        grant: None,
    };
    actor_can_create_role(tenant, &actor, id, &role, signature, message_store).await
}
