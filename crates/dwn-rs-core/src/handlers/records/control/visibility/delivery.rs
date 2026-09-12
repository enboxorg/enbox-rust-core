//! Whether a reader may reach a delivery record.
//!
//! A delivery is addressed key material, so it is not reachable by naming
//! it. Beyond its own parties, only a grant that joins the reader to this
//! recipient and covers the delivered role opens it.

use crate::encryption::grant_key::{
    eligible_grant_scope, read_grant_covers_delivered_scope, DeliveredScope,
};

use super::super::*;
use super::request_timestamp;

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
    grant: Option<&PermissionGrant>,
    message_store: &MessageStore,
) -> Result<bool, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(grant) = grant else {
        return Ok(false);
    };
    let recipient = records_write_descriptor(control)
        .map_err(|error| unexpected(error.to_string()))?
        .recipient
        .clone();
    let Some(recipient) = recipient else {
        return Ok(false);
    };
    // The grant must join the recipient — as either party — to the requester.
    if recipient != grant.grantor && recipient != grant.grantee {
        return Ok(false);
    }
    let Some(scope) = eligible_grant_scope(&grant.scope) else {
        return Ok(false);
    };
    if scope.method != RecordsMethod::Read {
        return Ok(false);
    }

    let delivered = DeliveredScope {
        protocol: &id.scope.protocol,
        protocol_path: Some(&id.scope.role_path),
    };
    // Whole-protocol and direct-subtree coverage are decidable without a
    // definition, so they are answered before paying for a lookup.
    if read_grant_covers_delivered_scope(&scope, &delivered, None) {
        return Ok(true);
    }

    // What remains is the keyed-role exception, which needs the configuration
    // governing this request.
    let timestamp = request_timestamp(read_message)?;
    let definition = match fetch_protocol_definition(
        tenant,
        &id.scope.protocol,
        message_store,
        Some(&timestamp),
    )
    .await
    {
        Ok(definition) => definition,
        Err(ProtocolDefinitionLookupError::Store(detail)) => {
            return Err(ControlValidationError::Internal(detail))
        }
        // Without a definition the exception is undecidable, and undecidable
        // is not reachable.
        Err(_) => return Ok(false),
    };
    Ok(read_grant_covers_delivered_scope(
        &scope,
        &delivered,
        Some(&definition),
    ))
}
