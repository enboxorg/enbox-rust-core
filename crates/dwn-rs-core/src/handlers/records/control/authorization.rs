use crate::canonical_rfc3339;
use crate::protocols::parse_cross_protocol_ref;

use super::*;

/// Writer authorization: may this actor mint this role's key material?
///
/// Separate from referential admission because the answer depends on who is
/// asking, and because the two failures mean different things to a caller.
pub(crate) async fn authorize_write<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    kind: ControlKind,
    signature: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<(), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor =
        records_write_descriptor(message).map_err(|error| unexpected(error.to_string()))?;
    let id = AudienceId::from_message(message, kind)?;
    let timestamp = canonical_rfc3339(descriptor.message_timestamp);
    let role = resolve_role_audience_definition(tenant, &id, &timestamp, message_store).await?;

    let actor = resolve_control_actor(tenant, message, signature, message_store)
        .await
        .map_err(|error| {
            control_error(
                DwnErrorCode::EncryptionControlValidateAudienceWriterUnauthorized,
                error.to_string(),
            )
        })?;

    if actor_can_create_role(tenant, &actor, &id, &role, signature, message_store).await? {
        return Ok(());
    }
    Err(control_error(
        DwnErrorCode::EncryptionControlValidateAudienceWriterUnauthorized,
        "control records must be written by a DID authorized to create the referenced role",
    ))
}

/// Whether an actor could create the role itself, which is the authority a
/// control record's key material stands on.
///
/// A grant that does not cover the role does not *deny* the write: the actor
/// may still hold independent create authority through the protocol, and
/// falling back is what lets a role holder mint keys without a grant. An
/// invalid grant is different and has already failed in `resolve_control_actor`.
pub(super) async fn actor_can_create_role<MessageStore>(
    tenant: &str,
    actor: &ControlActor,
    id: &AudienceId,
    role: &RoleAudienceDefinition,
    signature: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if actor.did == tenant {
        return Ok(true);
    }

    if let Some(grant) = &actor.grant {
        if grant_covers_role_create(&grant.scope, id) {
            return Ok(true);
        }
    }

    let record_chain = role_parent_chain(tenant, id, message_store).await?;
    let invoked_role = signature.protocol_role();

    for action in &role.rule_set.actions {
        match action {
            Action::Who(who) => {
                if !who.can.contains(&Can::Create) {
                    continue;
                }
                if who.who == Who::Anyone {
                    return Ok(true);
                }
                // Author/recipient selectors resolve against the role's parent
                // chain. Upstream leaves these conservative rather than
                // resolving parents that may not be reachable.
                if check_actor(
                    &actor.did,
                    &who.who,
                    who.of.as_deref(),
                    &record_chain,
                    Some(&role.definition),
                ) {
                    return Ok(true);
                }
            }
            Action::Role(role_action) => {
                if !role_action.can.contains(&Can::Create) {
                    continue;
                }
                // An explicitly invoked role only counts when the writer
                // actually holds it: naming a role is not holding it.
                if invoked_role == Some(role_action.role.as_str())
                    && invoked_role_is_held(
                        tenant,
                        &actor.did,
                        &role_action.role,
                        id,
                        &role.definition,
                        message_store,
                    )
                    .await?
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Whether a Records Write grant covers creating this role.
///
/// Scope comparison is exact protocol plus a path-boundary subtree, so a grant
/// over `message` never reaches `member`. A context-scoped grant matches
/// nothing here: the target has no context dimension to compare against.
fn grant_covers_role_create(scope: &PermissionScope, id: &AudienceId) -> bool {
    let PermissionScope::Records(records) = scope else {
        return false;
    };
    if records.method != RecordsMethod::Write {
        return false;
    }
    scope.matches_protocol_target(&ProtocolScopeTarget {
        protocol: Some(&id.scope.protocol),
        protocol_path: Some(&id.scope.role_path),
        context_id: None,
    })
}

async fn invoked_role_is_held<MessageStore>(
    tenant: &str,
    actor: &str,
    role_reference: &str,
    id: &AudienceId,
    definition: &Definition,
    message_store: &MessageStore,
) -> Result<bool, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let (protocol, role_path) = match parse_cross_protocol_ref(role_reference) {
        Some(parsed) => {
            let Some(protocol) = definition
                .uses
                .as_ref()
                .and_then(|uses| uses.get(parsed.alias))
            else {
                return Ok(false);
            };
            (protocol.clone(), parsed.protocol_path.to_string())
        }
        None => (id.scope.protocol.clone(), role_reference.to_string()),
    };

    role_record_exists(
        tenant,
        actor,
        &protocol,
        &role_path,
        Some(id.scope.context_id.as_str()),
        message_store,
    )
    .await
    .map_err(&unexpected)
}

/// The record chain the role's parent context names, for author/recipient
/// selectors. A root role has no parent, and therefore no chain.
async fn role_parent_chain<MessageStore>(
    tenant: &str,
    id: &AudienceId,
    message_store: &MessageStore,
) -> Result<Vec<Message<Descriptor>>, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(parent_record_id) = id
        .scope
        .context_id
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
    else {
        return Ok(Vec::new());
    };
    // The chain is addressed by the parent record itself. A parent that is not
    // retained yields no chain rather than an error: requirement 22 keeps
    // parent-dependent selectors conservative instead of resolving parents.
    let Ok(parent) = fetch_newest_write(tenant, parent_record_id, message_store).await else {
        return Ok(Vec::new());
    };
    construct_record_chain(tenant, &parent, message_store)
        .await
        .map_err(&unexpected)
}
