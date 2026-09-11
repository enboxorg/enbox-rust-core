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
pub(crate) use crate::encryption::control::ControlKind;
use crate::encryption::control::{required_string_tag, AudienceId, AudiencePayload};
use crate::errors::{DwnError, DwnErrorCode};
use crate::filters::message_filters::Records as RecordsFilter;
use crate::interfaces::messages::protocols::{Action, Can, Definition, RuleSet, Who};
use crate::permissions::control::{resolve_control_actor, ControlActor};
use crate::permissions::{
    fetch_grant, perform_base_validation, AuthorizationContext, PermissionGrant, PermissionScope,
    RecordsMethod, RecordsSelector,
};
use crate::{Descriptor, Message};

use std::collections::BTreeSet;

use crate::descriptors::messages::record_id;

use super::common::{
    check_actor, construct_record_chain, extract_author, fetch_newest_write, message_timestamp,
    role_record_exists,
};
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
    if filter.record_id.is_some() && filter.record_id == record_id(control) {
        return true;
    }
    if filter.protocol.as_deref() != Some(id.scope.protocol.as_str())
        || filter.protocol_path.as_deref() != Some(ControlKind::Audience.protocol_path())
    {
        return false;
    }
    let exact_tag = |tag: &str| -> Option<&str> {
        match filter.tags.as_ref()?.get(tag)? {
            crate::Filter::Equal(crate::Value::String(value)) => Some(value.as_str()),
            _ => None,
        }
    };
    // The three-field scope must be pinned; the key id is optional, and a tuple
    // without it still names one role's directory rather than one record.
    if exact_tag("protocol") != Some(id.scope.protocol.as_str())
        || exact_tag("rolePath") != Some(id.scope.role_path.as_str())
        || exact_tag("contextId") != Some(id.scope.context_id.as_str())
    {
        return false;
    }
    match exact_tag("keyId") {
        Some(key_id) => key_id == id.key_id,
        None => true,
    }
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
    use crate::permissions::scopes::ProtocolScopeTarget;

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
fn read_roles_under(definition: &Definition, scope_path: &str) -> BTreeSet<String> {
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

#[cfg(test)]
pub(crate) fn read_roles_under_for_test(
    definition: &Definition,
    scope_path: &str,
) -> BTreeSet<String> {
    read_roles_under(definition, scope_path)
}
