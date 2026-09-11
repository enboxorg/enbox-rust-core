//! Admission and writer authorization for encryption-control records.
//!
//! Control records sit at reserved virtual paths inside the source protocol,
//! where no application rule set exists. They are therefore admitted against a
//! fixed contract rather than a protocol definition's type and rule map: they
//! are immutable, unpublished, small enough to validate inline, and carry
//! their identity in tags.
//!
//! What a control record *does* still borrow from the protocol is the role it
//! names. That role is resolved against the definition governing the record's
//! own timestamp, not the newest one, so a configuration learned later cannot
//! retroactively change what a record meant when it was written.

use crate::descriptors::records::{is_initial_write, records_write_descriptor, write_fields};
use crate::encryption::control::{required_string_tag, AudienceId, AudiencePayload, ControlKind};
use crate::errors::{DwnError, DwnErrorCode};
use crate::interfaces::messages::protocols::{Action, Can, Definition, RuleSet, Who};
use crate::permissions::control::{resolve_control_actor, ControlActor};
use crate::permissions::{AuthorizationContext, PermissionScope};
use crate::{Descriptor, Message};

use super::common::{check_actor, construct_record_chain, fetch_newest_write, role_record_exists};
use crate::handlers::protocols::configure::{
    fetch_protocol_definition, ProtocolDefinitionLookupError,
};

/// Upper bound on control record data, matching the inline-encodable limit:
/// admission validates an audience payload in full, so it must be small enough
/// to hold rather than stream.
pub(crate) const MAX_CONTROL_DATA_SIZE: u64 = 30_000;

/// The only recipient authority a delivery may assert.
const RECIPIENT_AUTHORITY_ROLE_HOLDER: &str = "roleHolder";

fn control_error(code: DwnErrorCode, detail: impl Into<String>) -> ControlValidationError {
    ControlValidationError::Dwn(DwnError::new(code, detail))
}

fn unexpected(detail: impl Into<String>) -> ControlValidationError {
    control_error(
        DwnErrorCode::EncryptionControlValidateUnexpectedRecord,
        detail,
    )
}

/// Why a control record could not be admitted, preserving the distinction
/// between "this record is wrong" and "we could not tell".
///
/// The write handler already separates these three outcomes; control admission
/// reuses that vocabulary so an unavailable store cannot be reported as a
/// record defect.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlValidationError {
    #[error(transparent)]
    Dwn(#[from] DwnError),
    #[error("{0}")]
    Detail(String),
    #[error("{0}")]
    Internal(String),
}

/// The role a control record names, as it stood when the record was written.
pub(crate) struct RoleAudienceDefinition {
    pub definition: Definition,
    pub rule_set: RuleSet,
}

/// Resolves the role a control record names against the definition governing
/// its own timestamp.
///
/// The path must be a role *and* carry `$keyAgreement`: a control record exists
/// to distribute that role's key, so a role without one has no key to
/// distribute and a non-role path has no membership to key.
pub(crate) async fn resolve_role_audience_definition<MessageStore>(
    tenant: &str,
    id: &AudienceId,
    message_timestamp: &str,
    message_store: &MessageStore,
) -> Result<RoleAudienceDefinition, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    id.scope.validate_context_depth()?;

    // Why the definition could not be used matters as much as that it could
    // not. `AudienceRolePathInvalid` is on the repair allowlist and so licenses
    // destroying the record later; it must mean "the configuration resolved,
    // and contradicts this record", never "the configuration was missing" or
    // "the store was unavailable". Both of those are repairable and keep their
    // own classification.
    let definition = fetch_protocol_definition(
        tenant,
        &id.scope.protocol,
        message_store,
        Some(message_timestamp),
    )
    .await
    .map_err(|error| match error {
        ProtocolDefinitionLookupError::NotFound(uri) => ControlValidationError::Dwn(DwnError::new(
            DwnErrorCode::ProtocolAuthorizationProtocolNotFound,
            format!("unable to find protocol definition for {uri}"),
        )),
        ProtocolDefinitionLookupError::Store(detail) => ControlValidationError::Internal(detail),
        ProtocolDefinitionLookupError::InvalidMessage(detail) => {
            ControlValidationError::Detail(detail)
        }
    })?;

    // Only now, with a definition actually in hand, can the record be called
    // invalid against it.
    let rule_set = definition
        .rule_at(&id.scope.role_path)
        .filter(|rule_set| rule_set.role == Some(true) && rule_set.key_agreement.is_some())
        .ok_or_else(|| {
            control_error(
                DwnErrorCode::EncryptionControlValidateAudienceRolePathInvalid,
                format!(
                    "role audience path '{}' must be a role path with $keyAgreement",
                    id.scope.role_path
                ),
            )
        })?
        .clone();

    Ok(RoleAudienceDefinition {
        definition,
        rule_set,
    })
}

/// Lifecycle rules shared by both control kinds.
///
/// Immutability is checked as "is this an initial write" rather than "does a
/// previous version exist": an update that arrives before its initial write
/// must be refused on its own terms.
fn validate_lifecycle(
    message: &Message<Descriptor>,
    author: &str,
) -> Result<(), ControlValidationError> {
    let descriptor =
        records_write_descriptor(message).map_err(|error| unexpected(error.to_string()))?;

    if !is_initial_write(message, author).map_err(&unexpected)? {
        return Err(unexpected("encryption control records are immutable"));
    }
    if descriptor.published == Some(true) {
        return Err(unexpected(
            "encryption control records must not be published",
        ));
    }
    if descriptor.data_size > MAX_CONTROL_DATA_SIZE {
        return Err(unexpected(format!(
            "encryption control records must be at most {MAX_CONTROL_DATA_SIZE} bytes, got {}",
            descriptor.data_size
        )));
    }
    Ok(())
}

/// Referential admission: everything decidable before the record's data is in
/// hand, and before the writer's authority is considered.
///
/// Failures here are referential — the record points at something that is not
/// there, or is not what it claims — and are reported as bad requests.
/// Authorization failures are a separate stage precisely so a writer cannot
/// learn what exists by watching which error it gets.
pub(crate) async fn validate_referential_integrity<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    kind: ControlKind,
    author: &str,
    message_store: &MessageStore,
) -> Result<(), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    validate_lifecycle(message, author)?;

    let descriptor =
        records_write_descriptor(message).map_err(|error| unexpected(error.to_string()))?;
    let id = AudienceId::from_message(message, kind)?;
    let timestamp = crate::canonical_rfc3339(descriptor.message_timestamp);
    resolve_role_audience_definition(tenant, &id, &timestamp, message_store).await?;

    let fields = write_fields(message).map_err(|error| unexpected(error.to_string()))?;
    match kind {
        ControlKind::Audience => {
            // An audience publishes a public key and an owner seal. Both are
            // meant to be readable by the node, so an envelope would only hide
            // what admission has to check.
            if fields.encryption.is_some() {
                return Err(unexpected("audience control records must be plaintext"));
            }
        }
        ControlKind::Delivery => {
            // A delivery hands a private key to one recipient, so it is always
            // encrypted and always addressed. Its ciphertext is never opened
            // here: admission inspects the public metadata only.
            if fields.encryption.is_none() {
                return Err(unexpected("delivery control records must be encrypted"));
            }
            let Some(recipient) = descriptor.recipient.as_deref() else {
                return Err(control_error(
                    DwnErrorCode::EncryptionControlValidateDeliveryRecipientMissing,
                    "delivery control records must have a recipient",
                ));
            };
            validate_delivery_references(tenant, message, &id, recipient, message_store).await?;
        }
    }
    Ok(())
}

/// A delivery must reference a stored audience and go to a current role holder.
///
/// The audience lookup is by the whole four-field identity, key id included, so
/// a delivery of a superseded key still resolves: the key stops being *current*
/// without ceasing to exist, and recipients who were sent it keep needing it.
async fn validate_delivery_references<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    id: &AudienceId,
    recipient: &str,
    message_store: &MessageStore,
) -> Result<(), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let authority = required_string_tag(message, "recipientAuthority", ControlKind::Delivery)?;
    if authority != RECIPIENT_AUTHORITY_ROLE_HOLDER {
        return Err(control_error(
            DwnErrorCode::EncryptionControlValidateDeliveryRecipientAuthorityInvalid,
            format!("unsupported delivery recipient authority '{authority}'"),
        ));
    }

    if !stored_audience_exists(tenant, id, message_store).await? {
        return Err(control_error(
            DwnErrorCode::EncryptionControlValidateDeliveryAudienceMissing,
            "delivery control record references a missing audience",
        ));
    }

    let holds_role = role_record_exists(
        tenant,
        recipient,
        &id.scope.protocol,
        &id.scope.role_path,
        Some(id.scope.context_id.as_str()),
        message_store,
    )
    .await
    .map_err(&unexpected)?;
    if !holds_role {
        return Err(control_error(
            DwnErrorCode::EncryptionControlValidateDeliveryRecipientRoleRecordMissing,
            "delivery recipient does not hold the referenced role",
        ));
    }
    Ok(())
}

/// Whether an audience with this exact identity is retained.
pub(crate) async fn stored_audience_exists<MessageStore>(
    tenant: &str,
    id: &AudienceId,
    message_store: &MessageStore,
) -> Result<bool, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    use super::common::{bool_filter, filter_map, string_filter};
    use crate::filters::{FilterKey, Filters};
    use crate::Pagination;

    let mut filter = filter_map([
        ("interface", string_filter(super::RECORDS_INTERFACE)),
        ("method", string_filter(super::WRITE_METHOD)),
        ("protocol", string_filter(&id.scope.protocol)),
        (
            "protocolPath",
            string_filter(ControlKind::Audience.protocol_path()),
        ),
        ("isLatestBaseState", bool_filter(true)),
    ]);
    for (tag, value) in [
        ("protocol", id.scope.protocol.as_str()),
        ("rolePath", id.scope.role_path.as_str()),
        ("contextId", id.scope.context_id.as_str()),
        ("keyId", id.key_id.as_str()),
    ] {
        // Tags index as `tag.<name>`, the same shape
        // `records_filter_to_filter_map` builds for caller tag filters.
        filter.insert(FilterKey::Index(format!("tag.{tag}")), string_filter(value));
    }
    let result = message_store
        .query(
            tenant,
            Filters::from(filter),
            None,
            Some(Pagination::with_limit(1)),
            None,
        )
        .await
        .map_err(|error| unexpected(error.to_string()))?;
    Ok(!result.messages.is_empty())
}

/// Payload validation, once the record's data is available.
///
/// A delivery's ciphertext is deliberately not decrypted or parsed: node
/// admission has no private key and must not need one, so the producer's
/// payload format imposes nothing here.
pub(crate) async fn validate_payload<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    kind: ControlKind,
    data: &[u8],
    message_store: &MessageStore,
) -> Result<(), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if kind == ControlKind::Delivery {
        return Ok(());
    }

    let descriptor =
        records_write_descriptor(message).map_err(|error| unexpected(error.to_string()))?;
    let id = AudienceId::from_message(message, kind)?;
    let payload = AudiencePayload::parse(data)?;

    if payload.claimed_id() != id {
        return Err(control_error(
            DwnErrorCode::EncryptionControlValidateAudienceTagsMismatch,
            "audience tags must match payload fields",
        ));
    }
    payload.verify_key_id()?;

    let timestamp = crate::canonical_rfc3339(descriptor.message_timestamp);
    let role = resolve_role_audience_definition(tenant, &id, &timestamp, message_store).await?;
    let role_key = role
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
    Ok(())
}

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
    let timestamp = crate::canonical_rfc3339(descriptor.message_timestamp);
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
async fn actor_can_create_role<MessageStore>(
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
    use crate::permissions::scopes::ProtocolScopeTarget;
    use crate::permissions::RecordsMethod;

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
    let (protocol, role_path) = match crate::protocols::parse_cross_protocol_ref(role_reference) {
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
