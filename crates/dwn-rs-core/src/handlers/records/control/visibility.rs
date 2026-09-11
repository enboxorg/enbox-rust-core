use super::authorization::actor_can_create_role;
use super::*;

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

/// The grants a read request invokes, validated before any of them is allowed
/// to confer visibility.
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
    invoked_read_grants(tenant, read_message, signature, message_store).await?;
    Ok(())
}

async fn invoked_read_grants<MessageStore>(
    tenant: &str,
    read_message: &Message<Descriptor>,
    signature: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<Vec<PermissionGrant>, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let requester = read_requester(signature);
    let unauthorized = |error: crate::permissions::errors::PermissionError| {
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
        return Ok(vec![grant.clone()]);
    }

    let Some(grant_id) = signature.permission_grant_id() else {
        return Ok(Vec::new());
    };
    let grant = fetch_grant(tenant, message_store, grant_id)
        .await
        .map_err(unauthorized)?;
    perform_base_validation(read_message, tenant, requester, &grant, message_store)
        .await
        .map_err(unauthorized)?;
    Ok(vec![grant])
}

/// The timestamp a read request's authority is evaluated at. Role policy and
/// grant validity are resolved as of the request, never blindly the newest
/// configuration.
fn request_timestamp(read_message: &Message<Descriptor>) -> Result<String, ControlValidationError> {
    message_timestamp(read_message)
        .map(crate::canonical_rfc3339)
        .map_err(&unexpected)
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

    // Invoked grants are validated up front, including on requests that would
    // otherwise be answered without them.
    let grants = invoked_read_grants(tenant, read_message, signature, message_store).await?;
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
            delivery_reachable_by_grant(tenant, read_message, control, &id, &grants, message_store)
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
                &grants,
                message_store,
            )
            .await
        }
    }
}

/// Whether a request names this audience exactly, rather than sweeping for it.
///
/// Naming a specific stored key is not the same as enumerating a role's keys,
/// which is why an exact request needs no further authority while a broad one
/// does. The tuple must be fully pinned by equality: a range or list predicate
/// describes a region, not a record, and supplies no component.
fn exact_audience_request_matches(
    filter: &RecordsFilter,
    id: &AudienceId,
    control: &Message<Descriptor>,
) -> bool {
    // Reaching a directory entry needs only the role pinned; the key id is
    // optional, because a three-field tuple still names one role's directory.
    names_record(filter, control) || pins_audience_scope(filter, id)
}

/// Whether the caller pinned this record by id.
pub(super) fn names_record(filter: &RecordsFilter, control: &Message<Descriptor>) -> bool {
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

/// Whether the caller pinned the three-field scope this audience belongs to.
pub(super) fn pins_audience_scope(filter: &RecordsFilter, id: &AudienceId) -> bool {
    filter.protocol.as_deref() == Some(id.scope.protocol.as_str())
        && filter.protocol_path.as_deref() == Some(ControlKind::Audience.protocol_path())
        && pinned_tag(filter, "protocol") == Some(id.scope.protocol.as_str())
        && pinned_tag(filter, "rolePath") == Some(id.scope.role_path.as_str())
        && pinned_tag(filter, "contextId") == Some(id.scope.context_id.as_str())
}

/// Whether the caller pinned this audience's whole four-field identity.
///
/// Only that names one stored record, which is why only that bypasses
/// projection: the caller asked for a particular key, not for whichever key is
/// current.
pub(super) fn pins_audience_key(filter: &RecordsFilter, id: &AudienceId) -> bool {
    pins_audience_scope(filter, id) && pinned_tag(filter, "keyId") == Some(id.key_id.as_str())
}

/// Broad audience visibility: a read grant covering the role, or the authority
/// to create that role in the first place.
///
/// Someone who could mint the role's keys can hardly be kept from reading them,
/// which is why create authority is sufficient here.
async fn can_enumerate_audience<MessageStore>(
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

/// Whether a grant connects the delivery's recipient to the reader and covers
/// the delivered role.
///
/// The grant must join the recipient — as either party — to the requester, so a
/// tenant-issued delegate grant does not expose unrelated recipients' key
/// material merely because the tenant authored it. Context-scoped grants are
/// excluded: a delivery is addressed by role, not by context, so a context
/// scope would be matching on a dimension the target does not have.
async fn delivery_reachable_by_grant<MessageStore>(
    tenant: &str,
    read_message: &Message<Descriptor>,
    control: &Message<Descriptor>,
    id: &AudienceId,
    grants: &[PermissionGrant],
    message_store: &MessageStore,
) -> Result<bool, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let recipient = records_write_descriptor(control)
        .map_err(|error| unexpected(error.to_string()))?
        .recipient
        .clone();
    let Some(recipient) = recipient else {
        return Ok(false);
    };

    let mut definition = None;
    for grant in grants {
        if recipient != grant.grantor && recipient != grant.grantee {
            continue;
        }
        let PermissionScope::Records(scope) = &grant.scope else {
            continue;
        };
        if scope.method != RecordsMethod::Read || scope.protocol != id.scope.protocol {
            continue;
        }
        let scope_path = match &scope.selector {
            Some(RecordsSelector::ProtocolPath(path)) => Some(path.0.as_str()),
            // A context-scoped grant has no bearing on a role-addressed delivery.
            Some(RecordsSelector::ContextId(_)) => continue,
            None => None,
        };

        // No path at all covers the whole protocol.
        let Some(scope_path) = scope_path else {
            return Ok(true);
        };
        // The delivered role inside the granted subtree.
        if grant_covers_role(&grant.scope, id, RecordsMethod::Read) {
            return Ok(true);
        }
        // Or a keyed role the granted subtree itself grants read on: a reader
        // given a subtree implicitly reaches the roles that subtree reads
        // through, wherever in the protocol those roles are declared.
        let timestamp = request_timestamp(read_message)?;
        if definition.is_none() {
            definition = match fetch_protocol_definition(
                tenant,
                &id.scope.protocol,
                message_store,
                Some(&timestamp),
            )
            .await
            {
                Ok(definition) => Some(definition),
                Err(ProtocolDefinitionLookupError::Store(detail)) => {
                    return Err(ControlValidationError::Internal(detail))
                }
                Err(_) => return Ok(false),
            };
        }
        if let Some(definition) = &definition {
            if read_roles_under(definition, scope_path).contains(&id.scope.role_path) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Whether a Records grant of `method` covers this role path, by exact protocol
/// and path-boundary subtree.
fn grant_covers_role(scope: &PermissionScope, id: &AudienceId, method: RecordsMethod) -> bool {
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

/// Local role paths that the rule set at `scope_path`, or anything beneath it,
/// grants read through. Cross-protocol role references are excluded: they name
/// membership this protocol does not define.
pub(crate) fn read_roles_under(definition: &Definition, scope_path: &str) -> BTreeSet<String> {
    fn collect(definition: &Definition, rule_set: &RuleSet, found: &mut BTreeSet<String>) {
        for action in &rule_set.actions {
            if let Action::Role(role_action) = action {
                if role_action.can.contains(&Can::Read)
                    && crate::protocols::parse_cross_protocol_ref(&role_action.role).is_none()
                    // The role must still be keyed at the request timestamp.
                    // A configuration that keeps a role but drops its
                    // `$keyAgreement` stops it conveying key material, and a
                    // subtree delegate must lose that reach with it — otherwise
                    // removing the key agreement would silently leave retained
                    // deliveries reachable through a role that no longer keys
                    // anything.
                    && definition.rule_at(&role_action.role).is_some_and(|rule_set| {
                        rule_set.role == Some(true) && rule_set.key_agreement.is_some()
                    })
                {
                    found.insert(role_action.role.clone());
                }
            }
        }
        for child in rule_set.rules.values() {
            collect(definition, child, found);
        }
    }

    let mut found = BTreeSet::new();
    if let Some(rule_set) = definition.rule_at(scope_path) {
        collect(definition, rule_set, &mut found);
    }
    found
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
