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

pub(crate) mod admission;
pub(crate) mod authorization;
pub(crate) mod projection;
pub(crate) mod repair;
pub(crate) mod visibility;

// The handlers reach these by concept — `control::can_read`,
// `control::project_current_audiences` — rather than through the file that
// happens to hold them: the split is for readers of this module, not for its
// callers. Anything used from one place only stays behind its own module.
pub(crate) use admission::{validate_payload, validate_referential_integrity};
pub(crate) use authorization::authorize_write;
pub(crate) use projection::{collect_visible_page, project_current_audiences};
pub(crate) use visibility::{
    authorize_control_read_request, can_read, filter_may_match_controls,
    filter_targets_only_controls, filter_visible_controls,
};

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
use crate::permissions::scopes::ProtocolScopeTarget;
use crate::permissions::{
    fetch_grant, perform_base_validation, AuthorizationContext, PermissionGrant, PermissionScope,
    RecordsMethod, RecordsSelector,
};
use crate::{Descriptor, Message, Pagination};

use super::common::{
    bool_filter, check_actor, construct_record_chain, extract_author, fetch_newest_write,
    filter_map, message_timestamp, role_record_exists, string_filter,
};
use super::{RECORDS_INTERFACE, WRITE_METHOD};
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
