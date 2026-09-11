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

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::descriptors::messages::record_id;
use crate::descriptors::records::{is_initial_write, records_write_descriptor, write_fields};
pub(crate) use crate::encryption::control::ControlKind;
use crate::encryption::control::{required_string_tag, AudienceId, AudiencePayload, AudienceScope};
use crate::errors::{DwnError, DwnErrorCode};
use crate::filters::message_filters::Records as RecordsFilter;
use crate::filters::query::Cursor;
use crate::filters::{FilterKey, Filters};
use crate::interfaces::messages::protocols::{Action, Can, Definition, RuleSet, Who};
use crate::permissions::control::{resolve_control_actor, ControlActor};
use crate::permissions::{
    fetch_grant, perform_base_validation, AuthorizationContext, PermissionGrant, PermissionScope,
    RecordsMethod, RecordsSelector,
};
use crate::{Descriptor, Message};

use super::common::{
    bool_filter, check_actor, construct_record_chain, extract_author, fetch_newest_write,
    filter_map, message_timestamp, role_record_exists, string_filter,
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
fn names_record(filter: &RecordsFilter, control: &Message<Descriptor>) -> bool {
    filter.record_id.is_some() && filter.record_id == record_id(control)
}

/// Reads a tag the caller pinned by equality.
///
/// A range or list predicate describes a region rather than a record and
/// supplies nothing, which is what stops a caller reaching a specific key by
/// gesturing near it.
fn pinned_tag<'a>(filter: &'a RecordsFilter, tag: &str) -> Option<&'a str> {
    match filter.tags.as_ref()?.get(tag)? {
        crate::Filter::Equal(crate::Value::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Whether the caller pinned the three-field scope this audience belongs to.
fn pins_audience_scope(filter: &RecordsFilter, id: &AudienceId) -> bool {
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
fn pins_audience_key(filter: &RecordsFilter, id: &AudienceId) -> bool {
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

/// Where a candidate ranks as the current audience for its scope.
///
/// A real tenant signature outranks everything, then the oldest creation, then
/// the lowest record id. Tenant priority is by *actual signer*: a delegated
/// mint and an owner countersignature do not borrow it, which is what stops a
/// delegate from installing a current key the tenant never signed for. Oldest
/// rather than newest is deliberate — it makes a later flood of non-tenant
/// audiences inert instead of letting the most recent writer take over a role.
pub(crate) fn projection_rank(
    tenant: &str,
    record: &Message<Descriptor>,
) -> Option<(bool, String, String)> {
    let descriptor = records_write_descriptor(record).ok()?;
    Some((
        crate::permissions::message_signer(record)? != tenant,
        crate::canonical_rfc3339(descriptor.date_created),
        record_id(record)?,
    ))
}

/// The record id of the audience currently representing `scope`.
///
/// Ranks over every stored audience in the scope rather than the page in hand,
/// so the winner does not depend on the caller's filters, sort or pagination.
async fn current_audience_record_id<MessageStore>(
    tenant: &str,
    scope: &AudienceScope,
    message_store: &MessageStore,
) -> Result<Option<String>, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let mut filter = filter_map([
        ("interface", string_filter(super::RECORDS_INTERFACE)),
        ("method", string_filter(super::WRITE_METHOD)),
        ("protocol", string_filter(&scope.protocol)),
        (
            "protocolPath",
            string_filter(ControlKind::Audience.protocol_path()),
        ),
        ("isLatestBaseState", bool_filter(true)),
    ]);
    for (tag, value) in [
        ("protocol", scope.protocol.as_str()),
        ("rolePath", scope.role_path.as_str()),
        ("contextId", scope.context_id.as_str()),
    ] {
        filter.insert(FilterKey::Index(format!("tag.{tag}")), string_filter(value));
    }

    let stored = message_store
        .query(tenant, Filters::from(filter), None, None, None)
        .await
        .map_err(|error| ControlValidationError::Internal(error.to_string()))?;

    Ok(stored
        .messages
        .iter()
        .filter_map(|record| projection_rank(tenant, record).map(|rank| (rank, record)))
        .min_by(|(left, _), (right, _)| left.cmp(right))
        .and_then(|(_, record)| record_id(record)))
}

/// Narrows a page of records to one current audience per scope.
///
/// Only audiences are projected; deliveries are addressed key material and each
/// one stands alone. A caller that named a record by id, or pinned its whole
/// four-field identity, bypasses projection entirely — that caller asked for a
/// specific stored key, and answering with a different one would be wrong. A
/// three-field tuple names a role's directory, not a record, so it does not
/// bypass.
///
/// Selection never injects: a winner that fails the caller's own filters was
/// not in the page and does not join it here.
pub(crate) async fn project_current_audiences<MessageStore>(
    tenant: &str,
    filter: Option<&RecordsFilter>,
    records: Vec<Message<Descriptor>>,
    message_store: &MessageStore,
) -> Result<Vec<Message<Descriptor>>, ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    // Identify which records are subject to projection at all, keeping each
    // one's decision beside it so the second pass re-derives nothing.
    let mut projected_scopes = BTreeSet::new();
    let subject: Vec<Option<AudienceScope>> = records
        .iter()
        .map(|record| {
            if ControlKind::of(record) != Some(ControlKind::Audience) {
                return None;
            }
            let id = AudienceId::from_message(record, ControlKind::Audience).ok()?;
            let bypassed = filter.is_some_and(|filter| {
                names_record(filter, record) || pins_audience_key(filter, &id)
            });
            if bypassed {
                return None;
            }
            projected_scopes.insert(id.scope.clone());
            Some(id.scope)
        })
        .collect();

    if projected_scopes.is_empty() {
        return Ok(records);
    }

    let mut current = BTreeMap::new();
    for scope in projected_scopes {
        let winner = current_audience_record_id(tenant, &scope, message_store).await?;
        current.insert(scope, winner);
    }

    Ok(records
        .into_iter()
        .zip(subject)
        .filter(|(record, scope)| match scope {
            // Not an audience, or exempt from projection.
            None => true,
            Some(scope) => {
                current.get(scope).and_then(Option::as_ref) == record_id(record).as_ref()
            }
        })
        .map(|(record, _)| record)
        .collect())
}

/// Fetches storage pages until the caller's visible limit is met or the store
/// is exhausted, applying projection and control visibility to each.
///
/// A storage page is not a reply page. Projection drops superseded audiences
/// and visibility drops control records the requester may not see, so filtering
/// one storage page and returning would hand back a short page — or an empty
/// one — while the records that belong in it sit on the next page. A caller
/// asking for one record, newest first, would see nothing at all when the
/// newest candidate happens to be superseded.
///
/// The returned cursor is the last storage page's, so a caller resumes after
/// everything actually examined rather than re-reading what was filtered out.
pub(crate) async fn collect_visible_page<MessageStore, Fetch, Fut>(
    tenant: &str,
    request: &Message<Descriptor>,
    signature: Option<&AuthorizationContext>,
    filter: &RecordsFilter,
    limit: Option<u64>,
    message_store: &MessageStore,
    mut fetch: Fetch,
) -> Result<(Vec<Message<Descriptor>>, Option<Cursor>), ControlValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
    Fetch: FnMut(Option<Cursor>) -> Fut,
    Fut: std::future::Future<Output = Result<(Vec<Message<Descriptor>>, Option<Cursor>), String>>,
{
    let mut visible: Vec<Message<Descriptor>> = Vec::new();
    let mut cursor = None;

    loop {
        let (page, next) = fetch(cursor.clone())
            .await
            .map_err(ControlValidationError::Internal)?;
        let exhausted = page.is_empty() || next.is_none();
        cursor = next;

        let projected =
            project_current_audiences(tenant, Some(filter), page, message_store).await?;
        visible.extend(
            filter_visible_controls(
                tenant,
                request,
                signature,
                Some(filter),
                projected,
                message_store,
            )
            .await?,
        );

        match limit {
            Some(limit) if (visible.len() as u64) < limit && !exhausted => continue,
            Some(limit) => {
                // A refill can overshoot; the caller asked for a bounded page.
                visible.truncate(limit as usize);
                return Ok((visible, cursor));
            }
            None if exhausted => return Ok((visible, cursor)),
            None => continue,
        }
    }
}

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
    let timestamp = crate::canonical_rfc3339(descriptor.message_timestamp);
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
    let invoked_role = crate::permissions::stored_signature_payload(control)
        .and_then(|payload| payload.protocol_role);

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
        || crate::permissions::message_author(control).as_deref() == Some(tenant)
        || authorization.author_delegated_grant.is_some()
        || crate::permissions::stored_signature_payload(control)
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
