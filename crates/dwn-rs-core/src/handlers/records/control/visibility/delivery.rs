//! Whether a reader may reach a delivery record.
//!
//! A delivery is addressed key material, so it is not reachable by naming
//! it. Beyond its own parties, only a grant that joins the reader to this
//! recipient and covers the delivered role opens it.

use crate::protocols::parse_cross_protocol_ref;

use super::super::*;
use super::{grant_covers_role, request_timestamp};

/// Whether a grant connects the delivery's recipient to the reader and covers
/// the delivered role.
///
/// The grant must join the recipient — as either party — to the requester, so a
/// tenant-issued delegate grant does not expose unrelated recipients' key
/// material merely because the tenant authored it. Context-scoped grants are
/// excluded: a delivery is addressed by role, not by context, so a context
/// scope would be matching on a dimension the target does not have.
pub(super) async fn delivery_reachable_by_grant<MessageStore>(
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

/// Local role paths that the rule set at `scope_path`, or anything beneath it,
/// grants read through. Cross-protocol role references are excluded: they name
/// membership this protocol does not define.
pub(crate) fn read_roles_under(definition: &Definition, scope_path: &str) -> BTreeSet<String> {
    fn collect(definition: &Definition, rule_set: &RuleSet, found: &mut BTreeSet<String>) {
        for action in &rule_set.actions {
            if let Action::Role(role_action) = action {
                if role_action.can.contains(&Can::Read)
                    && parse_cross_protocol_ref(&role_action.role).is_none()
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
