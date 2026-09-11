use crate::canonical_rfc3339;
use crate::permissions::{message_author, stored_signature_payload};

use super::*;

// ---------------------------------------------------------------------------
// Configuration repair
// ---------------------------------------------------------------------------

/// What a newly learned configuration says about a control record already held.
///
/// The three outcomes are not degrees of confidence but different obligations.
/// `Invalid` is the only one that licenses destroying custody material, and it
/// means the configuration itself contradicts the record. `Unknown` covers
/// everything we could not determine — a lookup that failed, a store that was
/// unavailable, a shape we could not parse — and retains the record, because a
/// record wrongly kept can be removed later while one wrongly destroyed cannot
/// be recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlConfigValidity {
    Valid,
    Invalid,
    Unknown,
}

/// Re-validates a stored control record against the configuration history as it
/// now stands.
///
/// Two definitions matter and they are asked different questions. The one
/// governing the record's *own* timestamp decides whether the record was ever
/// admissible — a configuration learned later cannot retroactively change what
/// the record meant when written. The *newest* definition is asked only whether
/// the role still exists, and deliberately not whether it still carries
/// `$keyAgreement`: a configuration that drops a key agreement stops new
/// material being minted, but sealed material already delivered remains valid
/// and destroying it would be unrecoverable.
pub(crate) async fn validate_stored_control_record<MessageStore>(
    tenant: &str,
    control: &Message<Descriptor>,
    kind: ControlKind,
    message_store: &MessageStore,
) -> Result<RuleSet, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor =
        records_write_descriptor(control).map_err(|error| unexpected(error.to_string()))?;
    let id = AudienceId::from_message(control, kind)?;
    let timestamp = canonical_rfc3339(descriptor.message_timestamp);
    let governing =
        resolve_role_audience_definition(tenant, &id, &timestamp, message_store).await?;

    // An audience carries its payload inline, so its key commitments can be
    // re-checked against the role key that governed it.
    if kind == ControlKind::Audience {
        if let Some(encoded) = write_fields(control)
            .map_err(|error| unexpected(error.to_string()))?
            .encoded_data
            .as_deref()
        {
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|error| unexpected(error.to_string()))?;
            let payload = AudiencePayload::parse(&bytes)?;
            let role_key = governing
                .rule_set
                .key_agreement
                .as_ref()
                .map(|agreement| &agreement.public_key_jwk)
                .ok_or_else(|| {
                    control_error(
                        DwnErrorCode::EncryptionControlValidateAudienceRolePathInvalid,
                        "governing role has no $keyAgreement",
                    )
                })?;
            payload.verify_seal_key_id(role_key)?;
        }
    }

    // The role must still be a role. Its key agreement need not survive.
    let newest = fetch_protocol_definition(tenant, &id.scope.protocol, message_store, None)
        .await
        .map_err(|error| match error {
            ProtocolDefinitionLookupError::NotFound(uri) => {
                ControlValidationError::Dwn(DwnError::new(
                    DwnErrorCode::ProtocolAuthorizationProtocolNotFound,
                    format!("unable to find protocol definition for {uri}"),
                ))
            }
            ProtocolDefinitionLookupError::Store(detail) => {
                ControlValidationError::Internal(detail)
            }
            ProtocolDefinitionLookupError::InvalidMessage(detail) => {
                ControlValidationError::Detail(detail)
            }
        })?;
    if newest
        .rule_at(&id.scope.role_path)
        .is_none_or(|rule_set| rule_set.role != Some(true))
    {
        return Err(control_error(
            DwnErrorCode::EncryptionControlValidateAudienceRolePathInvalid,
            format!(
                "role audience path '{}' no longer exists as a role in protocol '{}'",
                id.scope.role_path, id.scope.protocol
            ),
        ));
    }

    Ok(governing.rule_set)
}

/// Replays the create authority a stored control record was admitted under,
/// using only what the record and the configuration already say.
///
/// Deliberately decides nothing that depends on mutable state. A record whose
/// authority came from the writer's own standing — countersigned by the owner,
/// authored by the tenant, signed by a delegate, or invoking a grant — is
/// preserved without re-fetching that grant or re-resolving that DID, because
/// its absence today says nothing about whether the write was authorized then.
/// Author and recipient selectors resolve against a parent chain, so they are
/// preserved rather than resolved for the same reason.
///
/// What remains is the configuration contradicting itself: a path with no
/// action rules at all, or none that would have permitted this write.
pub(crate) fn verify_stored_create_action(
    tenant: &str,
    control: &Message<Descriptor>,
    rule_set: &RuleSet,
) -> Result<(), ControlValidationError> {
    if stored_write_is_directly_authorized(tenant, control) {
        return Ok(());
    }

    if rule_set.actions.is_empty() {
        return Err(control_error(
            DwnErrorCode::ProtocolAuthorizationStoredInitialWriteActionRulesNotFound,
            "no create action rule defined for the stored control record",
        ));
    }

    let sought = actions_sought_by_stored_write(control, rule_set);
    let invoked_role = stored_signature_payload(control).and_then(|payload| payload.protocol_role);

    for action in &rule_set.actions {
        match action {
            Action::Role(role_action) => {
                if !role_action.can.iter().any(|can| sought.contains(can)) {
                    continue;
                }
                // A record that invoked a role is preserved when that role's
                // rule still exists; whether the writer still holds it is
                // mutable state this replay must not consult.
                if invoked_role.as_deref() == Some(role_action.role.as_str()) {
                    return Ok(());
                }
            }
            Action::Who(who) => {
                if !who.can.iter().any(|can| sought.contains(can)) {
                    continue;
                }
                // An invoked role is answered only by a role rule.
                if invoked_role.is_some() {
                    continue;
                }
                match who.who {
                    Who::Anyone => return Ok(()),
                    // Parent-dependent, so conservatively preserved.
                    Who::Author | Who::Recipient => return Ok(()),
                }
            }
        }
    }

    Err(control_error(
        DwnErrorCode::ProtocolAuthorizationStoredInitialWriteActionNotAllowed,
        "the stored control record is not allowed by the resolved protocol configuration",
    ))
}

/// Whether the record's authority came from who wrote it rather than from a
/// protocol rule, in which case the configuration has nothing to say about it.
fn stored_write_is_directly_authorized(tenant: &str, control: &Message<Descriptor>) -> bool {
    let authorization = control.fields.authorization();
    authorization.owner_signature.is_some()
        || authorization.owner_delegated_grant.is_some()
        || message_author(control).as_deref() == Some(tenant)
        || authorization.author_delegated_grant.is_some()
        || stored_signature_payload(control)
            .is_some_and(|payload| payload.permission_grant_id.is_some())
}

/// Which actions a stored write's rule match may be sought under.
///
/// An ordinary write seeks `create`. A squash seeks `squash` where the path
/// declares one, and otherwise either — a protocol that never mentions squash
/// treats it as an ordinary create rather than forbidding it.
fn actions_sought_by_stored_write(control: &Message<Descriptor>, rule_set: &RuleSet) -> Vec<Can> {
    let is_squash = records_write_descriptor(control)
        .ok()
        .and_then(|descriptor| descriptor.squash)
        == Some(true);
    if !is_squash {
        return vec![Can::Create];
    }
    let declares_squash = rule_set
        .actions
        .iter()
        .any(|action| action_can(action).contains(&Can::Squash));
    if declares_squash {
        vec![Can::Squash]
    } else {
        vec![Can::Squash, Can::Create]
    }
}

fn action_can(action: &Action) -> &[Can] {
    match action {
        Action::Role(role_action) => &role_action.can,
        Action::Who(who) => &who.can,
    }
}

/// Classifies a stored control record against the configuration now in force.
pub(crate) async fn control_config_validity<MessageStore>(
    tenant: &str,
    control: &Message<Descriptor>,
    message_store: &MessageStore,
) -> ControlConfigValidity
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(kind) = ControlKind::of(control) else {
        return ControlConfigValidity::Valid;
    };

    let outcome = match validate_stored_control_record(tenant, control, kind, message_store).await {
        Ok(rule_set) => verify_stored_create_action(tenant, control, &rule_set),
        Err(error) => Err(error),
    };

    match outcome {
        Ok(()) => ControlConfigValidity::Valid,
        // Only a configuration-owned contradiction licenses removal. Anything
        // else — a store that was unavailable, a payload that would not parse,
        // a dependency that has moved — is something we could not determine,
        // and an undetermined record is kept.
        Err(ControlValidationError::Dwn(error)) if error.code.is_control_invalidity() => {
            ControlConfigValidity::Invalid
        }
        Err(_) => ControlConfigValidity::Unknown,
    }
}
