pub mod errors;
pub mod scopes;

use crate::auth::jws::{
    permission_grant_invocation, AuthorizationPayloadData, PermissionGrantInvocation,
    RecordsWriteAuthorizationPayloadData,
};
pub use crate::permissions::errors::AuthorizationValidationError;
use crate::permissions::errors::{
    AuthorizationRequestError, GrantError, GrantMessageTypeError, PermissionError,
    ProtocolValidationError,
};
pub use crate::permissions::scopes::{
    ContextId, MessagesScope, MessagesSelector, PermissionScope, ProtocolPath, ProtocolsMethod,
    ProtocolsScope, RecordsMethod, RecordsScope, RecordsSelector,
};
use crate::permissions::scopes::{OwnedProtocolScopeTarget, ProtocolScopeTarget};
use crate::stores::MessageStore;

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::auth::resolver::DidResolver;
use crate::auth::{Authorization, Jws, JwsError};
use crate::cid::{generate_cid_from_serialized, generate_message_cid_from_json};
use crate::descriptors::{
    messages::record_id,
    records::{records_write_descriptor, write_fields},
    ConfigureDescriptor, Descriptor, MessageDescriptor, ProtocolQueryDescriptor, Protocols,
    Records, RecordsWriteDescriptor, QUERY,
};
use crate::fields::Fields;
use crate::filters::{
    message_filters::Messages as MessagesFilter, message_filters::Records as RecordsFilter,
};
use crate::filters::{Filter, FilterKey, Filters};
use crate::interfaces::messages::protocols::{
    Action, ActionWho, Can, Definition, RuleSet, Size, Type, Who,
};
use crate::ser::serialize_datetime;
use crate::{Message, MessageSort, Pagination, SortDirection, Value};

pub const PERMISSIONS_PROTOCOL_URI: &str = "https://identity.foundation/dwn/permissions";
pub const PERMISSIONS_REQUEST_PATH: &str = "request";
pub const PERMISSIONS_GRANT_PATH: &str = "grant";
pub const PERMISSIONS_REVOCATION_PATH: &str = "grant/revocation";

const RECORDS_INTERFACE: &str = "Records";
const PROTOCOLS_INTERFACE: &str = "Protocols";
const MESSAGES_INTERFACE: &str = "Messages";
const READ_METHOD: &str = "Read";
const SUBSCRIBE_METHOD: &str = "Subscribe";
const MAX_ENCODED_DATA_SIZE: u64 = 30_000;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum VerifiedAuthorizationPayload {
    Generic(AuthorizationPayloadData),
    RecordsWrite(RecordsWriteAuthorizationPayloadData),
}

impl VerifiedAuthorizationPayload {
    pub(crate) fn descriptor_cid(&self) -> &str {
        match self {
            VerifiedAuthorizationPayload::Generic(payload) => payload.descriptor_cid.as_str(),
            VerifiedAuthorizationPayload::RecordsWrite(payload) => payload.descriptor_cid.as_str(),
        }
    }

    pub(crate) fn delegated_grant_id(&self) -> Option<&str> {
        match self {
            VerifiedAuthorizationPayload::Generic(payload) => payload.delegated_grant_id.as_deref(),
            VerifiedAuthorizationPayload::RecordsWrite(payload) => {
                payload.delegated_grant_id.as_deref()
            }
        }
    }

    pub(crate) fn permission_grant_invocation(
        &self,
    ) -> Result<PermissionGrantInvocation, GrantError> {
        match self {
            VerifiedAuthorizationPayload::Generic(payload) => permission_grant_invocation(
                payload.permission_grant_id.as_deref(),
                payload.permission_grant_ids.as_deref(),
            )
            .map_err(GrantError::InvalidGrant),
            VerifiedAuthorizationPayload::RecordsWrite(payload) => {
                permission_grant_invocation(payload.permission_grant_id.as_deref(), None)
                    .map_err(GrantError::InvalidGrant)
            }
        }
    }

    pub(crate) fn protocol_role(&self) -> Option<&str> {
        match self {
            VerifiedAuthorizationPayload::Generic(payload) => payload.protocol_role.as_deref(),
            VerifiedAuthorizationPayload::RecordsWrite(payload) => payload.protocol_role.as_deref(),
        }
    }

    pub(crate) fn as_records_write(&self) -> Option<&RecordsWriteAuthorizationPayloadData> {
        match self {
            VerifiedAuthorizationPayload::RecordsWrite(payload) => Some(payload),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationContext {
    pub signer: String,
    pub author: String,
    pub(crate) payload: VerifiedAuthorizationPayload,
    pub permission_grant_invocation: PermissionGrantInvocation,
    pub author_delegated_grant: Option<PermissionGrant>,
}

impl AuthorizationContext {
    pub fn permission_grant_id(&self) -> Option<&str> {
        match &self.permission_grant_invocation {
            PermissionGrantInvocation::Single(id) => Some(id.as_str()),
            _ => None,
        }
    }

    pub fn permission_grant_ids(&self) -> Option<&[String]> {
        match &self.permission_grant_invocation {
            PermissionGrantInvocation::Multi(ids) => Some(ids),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PermissionGrant {
    pub id: String,
    pub grantor: String,
    pub grantee: String,
    pub date_granted: chrono::DateTime<chrono::Utc>,
    pub date_expires: chrono::DateTime<chrono::Utc>,
    pub delegated: Option<bool>,
    pub scope: PermissionScope,
    pub conditions: Option<PermissionConditions>,
    pub connect_session: Option<ConnectSessionMetadata>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PermissionConditions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication: Option<PermissionConditionPublication>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum PermissionConditionPublication {
    Required,
    Prohibited,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct PermissionRequestData {
    delegated: bool,
    scope: PermissionScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conditions: Option<PermissionConditions>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ConnectSessionTransport {
    Relay,
    PostMessage,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectSessionMetadata {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub languages: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<ConnectSessionTransport>,
    #[serde(serialize_with = "serialize_datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(serialize_with = "serialize_datetime")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct PermissionGrantData {
    #[serde(rename = "dateExpires")]
    date_expires: chrono::DateTime<chrono::Utc>,
    scope: PermissionScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conditions: Option<PermissionConditions>,
    #[serde(rename = "connectSession", skip_serializing_if = "Option::is_none")]
    connect_session: Option<ConnectSessionMetadata>,
}

pub struct ValidatedMessagesGrantSet {
    grants: Vec<PermissionGrant>,
}

impl ValidatedMessagesGrantSet {
    fn has_unscoped_grants(&self) -> bool {
        self.grants.iter().any(|grant| grant.scope.is_unscoped())
    }

    async fn covers_message<MS: MessageStore + Sync>(
        &self,
        tenant: &str,
        message: &Message<Descriptor>,
        message_store: &MS,
    ) -> Result<bool, PermissionError> {
        let target = resolve_messages_scope_target(tenant, message, message_store).await?;

        Ok(self
            .grants
            .iter()
            .any(|grant| grant.scope.matches_protocol_target(&target.as_ref())))
    }

    async fn covers_filter(&self, filter: &MessagesFilter) -> bool {
        let target = filter.into();

        self.grants
            .iter()
            .any(|grant| grant.scope.matches_protocol_target(&target))
    }
}

async fn resolve_messages_scope_target<MS: MessageStore + Sync>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MS,
) -> Result<OwnedProtocolScopeTarget, PermissionError> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Write(write) => {
                let context_id = context_id(message);

                let (protocol, protocol_path) = if write.protocol == PERMISSIONS_PROTOCOL_URI {
                    let embedded_scope =
                        get_scope_from_permission_record(tenant, message_store, message).await?;
                    (
                        embedded_scope.protocol().map(str::to_owned),
                        embedded_scope.protocol_path().map(str::to_owned),
                    )
                } else {
                    (
                        Some(write.protocol.clone()),
                        Some(write.protocol_path.clone()),
                    )
                };

                Ok(OwnedProtocolScopeTarget {
                    protocol,
                    protocol_path,
                    context_id,
                })
            }
            Records::Delete(delete) => {
                let newest_write =
                    fetch_newest_write(tenant, &delete.record_id, message_store).await?;
                Box::pin(resolve_messages_scope_target(
                    tenant,
                    &newest_write,
                    message_store,
                ))
                .await
            }
            _ => Err(GrantError::InvalidRecordsDescriptorType.into()),
        },
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            Protocols::Configure(configure) => Ok(OwnedProtocolScopeTarget {
                protocol: Some(configure.definition.protocol.clone()),
                protocol_path: None,
                context_id: None,
            }),
            _ => Err(GrantError::InvalidProtocolDescriptorType.into()),
        },
        _ => Err(GrantError::InvalidDescriptorType.into()),
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct PermissionRevocationData {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordsGrantAuthorizationKind {
    Write,
    Read,
    Query,
    Count,
    Delete,
    Subscribe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagesGrantAuthorizationKind {
    Read,
    Subscribe,
    Sync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagesReadGrantAccess {
    Full,
    MetadataOnly,
}

pub fn permissions_protocol_definition() -> Definition {
    Definition {
        protocol: PERMISSIONS_PROTOCOL_URI.to_string(),
        published: true,
        uses: None,
        types: BTreeMap::from([
            (
                "request".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["application/json".to_string()]),
                    encryption_required: None,
                },
            ),
            (
                "grant".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["application/json".to_string()]),
                    encryption_required: None,
                },
            ),
            (
                "revocation".to_string(),
                Type {
                    schema: None,
                    data_formats: Some(vec!["application/json".to_string()]),
                    encryption_required: None,
                },
            ),
        ]),
        structure: BTreeMap::from([
            (
                "request".to_string(),
                RuleSet {
                    size: Some(Size {
                        min: None,
                        max: Some(10_000),
                    }),
                    actions: vec![Action::Who(ActionWho {
                        who: Who::Anyone,
                        of: None,
                        can: vec![Can::Create],
                    })],
                    ..Default::default()
                },
            ),
            (
                "grant".to_string(),
                RuleSet {
                    size: Some(Size {
                        min: None,
                        max: Some(10_000),
                    }),
                    actions: vec![Action::Who(ActionWho {
                        who: Who::Recipient,
                        of: Some("grant".to_string()),
                        can: vec![Can::Read],
                    })],
                    rules: BTreeMap::from([(
                        "revocation".to_string(),
                        RuleSet {
                            size: Some(Size {
                                min: None,
                                max: Some(10_000),
                            }),
                            actions: vec![Action::Who(ActionWho {
                                who: Who::Anyone,
                                of: None,
                                can: vec![Can::Read],
                            })],
                            ..Default::default()
                        },
                    )]),
                    ..Default::default()
                },
            ),
        ]),
    }
}

pub enum AuthorizationPayloadKind {
    RecordsWrite,
    Direct,
    MessageGrantSet,
    NoGrant,
}

fn descriptor_permission_grant_invocation(
    message: &Message<Descriptor>,
) -> PermissionGrantInvocation {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Read(read) => read
                .permission_grant_id
                .clone()
                .map(PermissionGrantInvocation::Single)
                .unwrap_or(PermissionGrantInvocation::None),
            Records::Write(write) => write
                .permission_grant_id
                .clone()
                .map(PermissionGrantInvocation::Single)
                .unwrap_or(PermissionGrantInvocation::None),
            Records::Count(_) | Records::Delete(_) | Records::Query(_) | Records::Subscribe(_) => {
                PermissionGrantInvocation::None
            }
        },
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            Protocols::Configure(configure) => configure
                .permission_grant_id
                .clone()
                .map(PermissionGrantInvocation::Single)
                .unwrap_or(PermissionGrantInvocation::None),
            Protocols::Query(query) => query
                .permission_grant_id
                .clone()
                .map(PermissionGrantInvocation::Single)
                .unwrap_or(PermissionGrantInvocation::None),
        },
        Descriptor::Messages(messages) => match messages.as_ref() {
            crate::descriptors::Messages::Read(read) => read
                .permission_grant_ids
                .clone()
                .map(PermissionGrantInvocation::Multi)
                .unwrap_or(PermissionGrantInvocation::None),
            crate::descriptors::Messages::Query(query) => query
                .permission_grant_ids
                .clone()
                .map(PermissionGrantInvocation::Multi)
                .unwrap_or(PermissionGrantInvocation::None),
            crate::descriptors::Messages::Subscribe(subscribe) => subscribe
                .permission_grant_ids
                .clone()
                .map(PermissionGrantInvocation::Multi)
                .unwrap_or(PermissionGrantInvocation::None),
            crate::descriptors::Messages::Sync(_) => PermissionGrantInvocation::None,
        },
    }
}

fn authorization_payload_kind(message: &Message<Descriptor>) -> AuthorizationPayloadKind {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Write(_) => AuthorizationPayloadKind::RecordsWrite,
            _ => AuthorizationPayloadKind::Direct,
        },
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            Protocols::Configure(_) | Protocols::Query(_) => AuthorizationPayloadKind::Direct,
        },
        Descriptor::Messages(messages) => match messages.as_ref() {
            crate::descriptors::Messages::Read(_)
            | crate::descriptors::Messages::Query(_)
            | crate::descriptors::Messages::Subscribe(_) => {
                AuthorizationPayloadKind::MessageGrantSet
            }
            crate::descriptors::Messages::Sync(_) => AuthorizationPayloadKind::NoGrant,
        },
    }
}

fn validate_invocation_and_kind(
    message: &Message<Descriptor>,
    payload: &VerifiedAuthorizationPayload,
) -> Result<PermissionGrantInvocation, GrantError> {
    let descriptor_invocation = descriptor_permission_grant_invocation(message);
    let payload_invocation = payload.permission_grant_invocation()?;

    if descriptor_invocation != payload_invocation {
        return Err(GrantError::InvalidGrant(
            AuthorizationRequestError::SignatureMismatch.into(),
        ));
    }

    match (authorization_payload_kind(message), &payload_invocation) {
        (
            AuthorizationPayloadKind::RecordsWrite,
            PermissionGrantInvocation::None | PermissionGrantInvocation::Single(_),
        )
        | (
            AuthorizationPayloadKind::Direct,
            PermissionGrantInvocation::None | PermissionGrantInvocation::Single(_),
        )
        | (
            AuthorizationPayloadKind::MessageGrantSet,
            PermissionGrantInvocation::None | PermissionGrantInvocation::Multi(_),
        )
        | (AuthorizationPayloadKind::NoGrant, PermissionGrantInvocation::None) => {
            Ok(payload_invocation)
        }
        _ => Err(GrantError::InvalidDescriptorType),
    }
}

pub async fn validate_authorization_signature(
    message: &Message<Descriptor>,
    did_resolver: Option<&dyn DidResolver>,
    required: bool,
) -> Result<Option<AuthorizationContext>, AuthorizationValidationError> {
    validate_authorization_signature_inner(message, did_resolver, required, true)
        .await
        .map_err(|error| match error {
            // Authorization parsing/validation errors remain distinguishable to
            // request handlers, preserving their 400 response behavior.
            GrantError::InvalidGrant(error) => error,
            // Grant parsing failures encountered while validating an embedded
            // delegated grant are malformed authorization requests as well.
            error => AuthorizationValidationError::BadRequest(
                AuthorizationRequestError::ValidationError(error.to_string()),
            ),
        })
}

fn validate_records_write_payload(
    message: &Message<Descriptor>,
    payload: &VerifiedAuthorizationPayload,
) -> Result<(), GrantError> {
    let payload = payload.as_records_write().ok_or(GrantError::InvalidGrant(
        AuthorizationRequestError::ValidationError("RecordsWrite payload expected".to_string())
            .into(),
    ))?;

    let context_id = context_id(message).ok_or(GrantError::InvalidGrant(
        AuthorizationRequestError::SignatureMismatch.into(),
    ))?;
    let record_id = record_id(message).ok_or(GrantError::InvalidGrant(
        AuthorizationRequestError::SignatureMismatch.into(),
    ))?;

    if payload.context_id != context_id {
        return Err(GrantError::InvalidGrant(
            AuthorizationRequestError::SignatureMismatch.into(),
        ));
    }

    if payload.record_id != record_id {
        return Err(GrantError::InvalidGrant(
            AuthorizationRequestError::SignatureMismatch.into(),
        ));
    }

    let attestation_cid = write_fields(message)
        .map_err(ProtocolValidationError::from)?
        .attestation
        .as_ref()
        .map(|attestation| {
            generate_cid_from_serialized(attestation).map_err(|err| {
                GrantError::InvalidGrant(
                    AuthorizationRequestError::ValidationError(err.to_string()).into(),
                )
            })
        })
        .transpose()?;

    let encryption_cid = write_fields(message)
        .map_err(ProtocolValidationError::from)?
        .encryption
        .as_ref()
        .map(|encryption| {
            generate_cid_from_serialized(encryption).map_err(|err| {
                GrantError::InvalidGrant(
                    AuthorizationRequestError::ValidationError(err.to_string()).into(),
                )
            })
        })
        .transpose()?;

    payload
        .attestation_cid
        .as_ref()
        .map(|payload_attestation_cid| {
            attestation_cid
                .ok_or(GrantError::InvalidGrant(
                    AuthorizationRequestError::SignatureMismatch.into(),
                ))
                .and_then(|attestation| {
                    if attestation.to_string() != *payload_attestation_cid {
                        return Err(GrantError::InvalidGrant(
                            AuthorizationRequestError::SignatureMismatch.into(),
                        ));
                    }
                    Ok(())
                })
        })
        .transpose()?;

    match payload.encryption_cid.as_ref() {
        Some(payload_encryption_cid) => {
            let encryption_cid = encryption_cid.ok_or(GrantError::InvalidGrant(
                AuthorizationRequestError::SignatureMismatch.into(),
            ))?;
            if encryption_cid.to_string() != *payload_encryption_cid {
                return Err(GrantError::InvalidGrant(
                    AuthorizationRequestError::SignatureMismatch.into(),
                ));
            }
        }
        None => {
            if encryption_cid.is_some() {
                return Err(GrantError::InvalidGrant(
                    AuthorizationRequestError::SignatureMismatch.into(),
                ));
            }
        }
    }

    // compute delegated grant Cid
    let delegated_grant_cid = write_fields(message)
        .map_err(ProtocolValidationError::from)?
        .authorization
        .author_delegated_grant
        .as_ref()
        .map(|grant| {
            grant.message_cid().map_err(|err| {
                GrantError::InvalidGrant(
                    AuthorizationRequestError::ValidationError(err.to_string()).into(),
                )
            })
        })
        .map(|c| c.map(|cid| cid.to_string()))
        .transpose()?;

    if payload.delegated_grant_id != delegated_grant_cid {
        return Err(GrantError::InvalidGrant(
            AuthorizationRequestError::SignatureMismatch.into(),
        ));
    }

    Ok(())
}

async fn validate_authorization_signature_inner(
    message: &Message<Descriptor>,
    did_resolver: Option<&dyn DidResolver>,
    required: bool,
    validate_delegated_grant: bool,
) -> Result<Option<AuthorizationContext>, GrantError> {
    let authorization = match &message.fields {
        Fields::Write(fields) => &fields.authorization,
        Fields::InitialWriteField(fields) => &fields.write_fields.authorization,
        Fields::Authorization(auth) => auth,
    };

    if authorization.is_empty() && required {
        return Err(AuthorizationValidationError::BadRequest(
            AuthorizationRequestError::SignatureRequired,
        )
        .into());
    } else if authorization.is_empty() {
        return Ok(None);
    }

    let jws = &authorization.signature;
    let signature_count = jws.signatures.as_ref().map(Vec::len).unwrap_or(0);
    if signature_count != 1 {
        return Err(AuthorizationValidationError::BadRequest(
            AuthorizationRequestError::ExpectedOneSignature,
        )
        .into());
    }

    let payload = match authorization_payload_kind(message) {
        AuthorizationPayloadKind::RecordsWrite => {
            let payload = VerifiedAuthorizationPayload::RecordsWrite(decode_jws_payload(jws)?);
            validate_descriptor_cid(message, payload.descriptor_cid().to_string())?;
            validate_invocation_and_kind(message, &payload)?;
            validate_records_write_payload(message, &payload)?;
            payload
        }
        _ => {
            let payload = VerifiedAuthorizationPayload::Generic(decode_jws_payload(jws)?);
            validate_descriptor_cid(message, payload.descriptor_cid().to_string())?;
            validate_invocation_and_kind(message, &payload)?;
            payload
        }
    };

    validate_descriptor_cid(message, payload.descriptor_cid().to_string())?;

    let permission_grants = validate_permission_grant(message, &payload)?;
    let unverified_signer =
        signer_did_from_jws(jws).map_err(AuthorizationValidationError::BadRequest)?;
    let signer = match did_resolver {
        Some(resolver) => jws
            .verify_signatures(resolver)
            .await
            .map_err(|err| AuthorizationValidationError::BadRequest(err.into()))?
            .into_iter()
            .next()
            .ok_or(AuthorizationValidationError::BadRequest(
                AuthorizationRequestError::NoSignerFound,
            ))?,
        None => unverified_signer,
    };

    let mut author = signer.clone();
    let mut author_delegated_grant = None;
    if validate_delegated_grant {
        author_delegated_grant =
            validate_embedded_author_delegated_grant(authorization, &payload, did_resolver).await?;
        if let Some(grant) = &author_delegated_grant {
            author = grant.grantor.clone();
        }
    }

    Ok(Some(AuthorizationContext {
        signer,
        author,
        payload,
        permission_grant_invocation: permission_grants,
        author_delegated_grant,
    }))
}

async fn validate_embedded_author_delegated_grant(
    authorization: &Authorization,
    payload: &VerifiedAuthorizationPayload,
    did_resolver: Option<&dyn DidResolver>,
) -> Result<Option<PermissionGrant>, GrantError> {
    let Some(ref grant_message) = authorization.author_delegated_grant else {
        if payload.delegated_grant_id().is_some() {
            return Err(AuthorizationValidationError::BadRequest(
                AuthorizationRequestError::MissingAuthorDelegateGrant,
            )
            .into());
        }
        return Ok(None);
    };

    let grant_cid = grant_message.message_cid().map_err(|err| {
        GrantError::InvalidGrant(AuthorizationRequestError::ValidationError(err.to_string()).into())
    })?;
    let delegated_grant_id =
        payload
            .delegated_grant_id()
            .ok_or(AuthorizationValidationError::BadRequest(
                AuthorizationRequestError::DelegateGrantIDRequired,
            ))?;
    if delegated_grant_id != grant_cid.to_string() {
        return Err(AuthorizationValidationError::BadRequest(
            AuthorizationRequestError::DelegateAuthorMismatch,
        )
        .into());
    }

    let grant_message_general: Message<Descriptor> = (**grant_message).clone().into();

    let grant_authorization = Box::pin(validate_authorization_signature_inner(
        &grant_message_general,
        did_resolver,
        true,
        false,
    ))
    .await?
    .ok_or(AuthorizationValidationError::BadRequest(
        AuthorizationRequestError::SignatureRequired,
    ))?;

    parse_permission_grant(&grant_message_general, &grant_authorization.author).map(Some)
}

fn decode_jws_payload<T: DeserializeOwned>(jws: &Jws) -> Result<T, AuthorizationValidationError> {
    let payload = jws
        .payload
        .as_deref()
        .ok_or_else(|| AuthorizationValidationError::BadRequest(JwsError::MissingPayload.into()))?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|err| AuthorizationValidationError::BadRequest(err.into()))?;
    serde_json::from_slice(&payload)
        .map_err(|err| AuthorizationValidationError::BadRequest(err.into()))
}

fn validate_permission_grant(
    message: &Message<Descriptor>,
    payload: &VerifiedAuthorizationPayload,
) -> Result<PermissionGrantInvocation, AuthorizationValidationError> {
    let payload_invocation = payload.permission_grant_invocation().map_err(|err| {
        AuthorizationValidationError::BadRequest(AuthorizationRequestError::ValidationError(
            err.to_string(),
        ))
    })?;

    let descriptor_invocation = descriptor_permission_grant_invocation(message);

    if payload_invocation != descriptor_invocation {
        return Err(AuthorizationValidationError::BadRequest(
            AuthorizationRequestError::SignatureMismatch,
        ));
    }

    Ok(payload_invocation)
}

fn validate_descriptor_cid(
    message: &Message<Descriptor>,
    payload_descriptor_cid: String,
) -> Result<(), AuthorizationValidationError> {
    if payload_descriptor_cid != message.descriptor.cid().to_string() {
        return Err(AuthorizationValidationError::BadRequest(
            AuthorizationRequestError::CidMismatch,
        ));
    }

    Ok(())
}

fn signer_did_from_jws(jws: &Jws) -> Result<String, AuthorizationRequestError> {
    let signatures = jws
        .signatures
        .as_deref()
        .ok_or(AuthorizationRequestError::SignatureRequired)?;
    let protected = signatures
        .first()
        .and_then(|sig| sig.protected.as_deref())
        .ok_or(AuthorizationRequestError::SignatureRequired)?;
    let protected = URL_SAFE_NO_PAD.decode(protected)?;
    let protected: JsonValue = serde_json::from_slice(&protected)?;
    let kid = protected
        .get("kid")
        .and_then(JsonValue::as_str)
        .ok_or(AuthorizationRequestError::KidRequired)?;
    kid.split('#')
        .next()
        .filter(|did| !did.is_empty())
        .map(str::to_string)
        .ok_or(AuthorizationRequestError::KidRequired)
}

pub fn message_author(message: &Message<Descriptor>) -> Option<String> {
    authorization_from_message(message)
        .and_then(|authorization| authorization.get("authorDelegatedGrant").cloned())
        .and_then(|grant_value| serde_json::from_value::<Message<Descriptor>>(grant_value).ok())
        .and_then(|grant| message_signer(&grant))
        .or_else(|| message_signer(message))
}

pub fn message_signer(message: &Message<Descriptor>) -> Option<String> {
    let authorization = authorization_from_message(message)?;
    let signature = authorization.get("signature")?;
    let jws: Jws = serde_json::from_value(signature.clone()).ok()?;
    signer_did_from_jws(&jws).ok()
}

fn authorization_from_message(message: &Message<Descriptor>) -> Option<JsonValue> {
    serde_json::to_value(message)
        .ok()?
        .get("authorization")
        .cloned()
}

pub fn validate_permissions_record_schema(message: &Message<Descriptor>) -> Result<(), GrantError> {
    let descriptor = records_write_descriptor(message)?;
    if descriptor.protocol.as_str() != PERMISSIONS_PROTOCOL_URI {
        return Ok(());
    }
    let data = permission_record_data_bytes(message)?;
    match descriptor.protocol_path.as_str() {
        PERMISSIONS_REQUEST_PATH => {
            let data: PermissionRequestData = serde_json::from_slice(&data)
                .map_err(|err| GrantError::InvalidGrant(err.into()))?;

            Ok(validate_scope_and_tags(&data.scope, descriptor)?)
        }
        PERMISSIONS_GRANT_PATH => {
            let data: PermissionGrantData = serde_json::from_slice(&data)
                .map_err(|err| GrantError::InvalidGrant(err.into()))?;
            Ok(validate_scope_and_tags(&data.scope, descriptor)?)
        }
        PERMISSIONS_REVOCATION_PATH => {
            let _: PermissionRevocationData = serde_json::from_slice(&data)
                .map_err(|err| GrantError::InvalidGrant(err.into()))?;
            Ok(())
        }
        protocol_path => Err(AuthorizationValidationError::UnexpectedPermissionRecord(
            protocol_path.to_string(),
        )
        .into()),
    }
}

pub async fn pre_process_permissions_write<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
) -> Result<(), PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor =
        records_write_descriptor(message).map_err(|e| PermissionError::InvalidGrant(e.into()))?;
    if descriptor.protocol.as_str() != PERMISSIONS_PROTOCOL_URI
        || descriptor.protocol_path != PERMISSIONS_REVOCATION_PATH
    {
        return Ok(());
    }
    let parent_id = descriptor
        .parent_id
        .as_deref()
        .ok_or(GrantError::ProtocolValidationError(
            ProtocolValidationError::MissingRevocationParentId,
        ))?;
    let grant = fetch_grant(tenant, message_store, parent_id).await?;
    let revocation_protocol_tag = descriptor
        .tags
        .as_ref()
        .and_then(|tags| tags.get("protocol"))
        .and_then(index_value_as_str);
    if grant.scope.protocol() != revocation_protocol_tag {
        return Err(GrantError::ProtocolValidationError(
            ProtocolValidationError::MissingRevocationParentId,
        )
        .into());
    }
    Ok(())
}

pub async fn post_process_permissions_write<MessageStore, DataStore, StateIndex>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
    data_store: &DataStore,
    state_index: &StateIndex,
) -> Result<(), PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
    DataStore: crate::stores::DataStore + Sync,
    StateIndex: crate::stores::StateIndex + Sync,
{
    let descriptor =
        records_write_descriptor(message).map_err(|e| PermissionError::InvalidGrant(e.into()))?;
    if descriptor.protocol.as_str() != PERMISSIONS_PROTOCOL_URI
        || descriptor.protocol_path != PERMISSIONS_REVOCATION_PATH
    {
        return Ok(());
    }
    let Some(permission_grant_id) = descriptor.parent_id.as_deref() else {
        return Ok(());
    };
    let revoke_timestamp = descriptor.message_timestamp;
    let result = message_store
        .query(
            tenant,
            Filters::from(filter_map([(
                "permissionGrantId",
                string_filter(permission_grant_id),
            )])),
            None,
            None,
        )
        .await?;
    let mut cids = Vec::new();
    for authorized_message in result.messages {
        if message_timestamp(&authorized_message) < revoke_timestamp {
            continue;
        }

        if let Ok(write) = records_write_descriptor(&authorized_message) {
            if write.data_size > MAX_ENCODED_DATA_SIZE {
                if let Some(record_id) = record_id(&authorized_message) {
                    data_store
                        .delete(tenant, &record_id, &write.data_cid)
                        .await?;
                }
            }
        }
        let cid = message_cid(&authorized_message)?;
        message_store.delete(tenant, &cid).await?;
        cids.push(cid);
    }
    if !cids.is_empty() {
        state_index.delete(tenant, &cids).await?;
    }
    Ok(())
}

pub async fn fetch_grant<MessageStore>(
    tenant: &str,
    message_store: &MessageStore,
    permission_grant_id: &str,
) -> Result<PermissionGrant, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let result = message_store
        .query(
            tenant,
            Filters::from(filter_map([
                ("recordId", string_filter(permission_grant_id)),
                ("isLatestBaseState", bool_filter(true)),
            ])),
            None,
            Some(Pagination::with_limit(1)),
        )
        .await?;
    let Some(message) = result.messages.first() else {
        return Err(GrantError::NotFound(permission_grant_id.to_string()).into());
    };
    let grantor = message_author(message).ok_or(GrantError::UnableToExtractGrantor)?;
    Ok(parse_permission_grant(message, &grantor)?)
}

pub async fn authorize_delegated_records_write<MessageStore>(
    records_write_message: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(permission_grant) = auth.author_delegated_grant.as_ref() else {
        return Ok(false);
    };
    authorize_records_write_with_grant(
        records_write_message,
        &auth.author,
        &auth.signer,
        permission_grant,
        message_store,
    )
    .await?;
    Ok(true)
}

pub async fn authorize_records_write_with_grant_id<MessageStore>(
    tenant: &str,
    records_write_message: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(permission_grant_id) = auth.permission_grant_id() else {
        return Ok(false);
    };
    let permission_grant = fetch_grant(tenant, message_store, permission_grant_id).await?;
    authorize_records_write_with_grant(
        records_write_message,
        tenant,
        &auth.author,
        &permission_grant,
        message_store,
    )
    .await?;
    Ok(true)
}

pub async fn authorize_records_read_with_grant<MessageStore>(
    tenant: &str,
    records_read_message: &Message<Descriptor>,
    records_write_message_to_read: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let grant = if let Some(grant) = auth.author_delegated_grant.as_ref() {
        Some((grant.clone(), auth.author.as_str(), auth.signer.as_str()))
    } else if let Some(permission_grant_id) = auth.permission_grant_id() {
        Some((
            fetch_grant(tenant, message_store, permission_grant_id).await?,
            tenant,
            auth.author.as_str(),
        ))
    } else {
        None
    };
    let Some((permission_grant, expected_grantor, expected_grantee)) = grant else {
        return Ok(false);
    };
    perform_base_validation(
        records_read_message,
        expected_grantor,
        expected_grantee,
        &permission_grant,
        message_store,
    )
    .await?;
    verify_records_scope(records_write_message_to_read, &permission_grant.scope)?;
    Ok(true)
}

pub async fn authorize_records_query_or_subscribe_with_grant<MessageStore>(
    tenant: &str,
    incoming_message: &Message<Descriptor>,
    filter: &RecordsFilter,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let grant = if let Some(grant) = auth.author_delegated_grant.as_ref() {
        Some((grant.clone(), auth.author.as_str(), auth.signer.as_str()))
    } else if let Some(permission_grant_id) = auth.permission_grant_id() {
        Some((
            fetch_grant(tenant, message_store, permission_grant_id).await?,
            tenant,
            auth.author.as_str(),
        ))
    } else {
        None
    };
    let Some((permission_grant, expected_grantor, expected_grantee)) = grant else {
        return Ok(false);
    };
    perform_base_validation(
        incoming_message,
        expected_grantor,
        expected_grantee,
        &permission_grant,
        message_store,
    )
    .await?;

    let target = ProtocolScopeTarget {
        protocol: filter.protocol.as_deref(),
        protocol_path: filter.protocol_path.as_deref(),
        context_id: filter.context_id.as_deref(),
    };

    if !permission_grant.scope.matches_protocol_target(&target) {
        return Err(GrantError::OutsideScope.into());
    }

    Ok(true)
}

pub async fn authorize_records_delete_with_grant<MessageStore>(
    tenant: &str,
    records_delete_message: &Message<Descriptor>,
    records_write_to_delete: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let grant = if let Some(grant) = auth.author_delegated_grant.as_ref() {
        Some((grant.clone(), auth.author.as_str(), auth.signer.as_str()))
    } else if let Some(permission_grant_id) = auth.permission_grant_id() {
        Some((
            fetch_grant(tenant, message_store, permission_grant_id).await?,
            tenant,
            auth.author.as_str(),
        ))
    } else {
        None
    };
    let Some((permission_grant, expected_grantor, expected_grantee)) = grant else {
        return Ok(false);
    };
    perform_base_validation(
        records_delete_message,
        expected_grantor,
        expected_grantee,
        &permission_grant,
        message_store,
    )
    .await?;

    verify_records_scope(records_write_to_delete, &permission_grant.scope)?;

    Ok(true)
}

pub async fn authorize_protocols_configure<MessageStore>(
    tenant: &str,
    protocols_configure_message: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<(), PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if let Some(permission_grant) = auth.author_delegated_grant.as_ref() {
        authorize_protocols_configure_with_grant(
            protocols_configure_message,
            &auth.author,
            &auth.signer,
            permission_grant,
            message_store,
        )
        .await?;
        return Ok(());
    }
    if auth.author == tenant {
        return Ok(());
    }
    if let Some(permission_grant_id) = auth.permission_grant_id() {
        let permission_grant = fetch_grant(tenant, message_store, permission_grant_id).await?;
        authorize_protocols_configure_with_grant(
            protocols_configure_message,
            tenant,
            &auth.author,
            &permission_grant,
            message_store,
        )
        .await?;
        return Ok(());
    }

    Err(GrantError::Unauthorized.into())
}

pub async fn authorize_protocols_query<MessageStore>(
    tenant: &str,
    protocols_query_message: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if auth.author == tenant {
        return Ok(true);
    }
    let Some(permission_grant_id) = auth.permission_grant_id() else {
        return Ok(false);
    };
    let permission_grant = fetch_grant(tenant, message_store, permission_grant_id).await?;
    perform_base_validation(
        protocols_query_message,
        tenant,
        &auth.author,
        &permission_grant,
        message_store,
    )
    .await?;
    let protocol_in_grant = permission_grant.scope.protocol();
    let protocol_in_message = protocols_query_descriptor(protocols_query_message)
        .map_err(GrantError::InvalidMessageType)?
        .filter
        .as_ref()
        .and_then(|filter| filter.protocol.as_deref());
    if protocol_in_grant.is_some() && protocol_in_message != protocol_in_grant {
        return Err(GrantError::OutsideScope.into());
    }
    Ok(true)
}

pub async fn authorize_messages_read<MessageStore>(
    tenant: &str,
    messages_read_message: &Message<Descriptor>,
    message_to_read: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<MessagesReadGrantAccess, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let permission_grants =
        fetch_and_validate_messages_grants(tenant, messages_read_message, auth, message_store)
            .await?;

    if !permission_grants
        .covers_message(tenant, message_to_read, message_store)
        .await?
    {
        return Err(GrantError::OutsideScope.into());
    }

    if permission_grants.has_unscoped_grants() {
        Ok(MessagesReadGrantAccess::Full)
    } else {
        Ok(MessagesReadGrantAccess::MetadataOnly)
    }
}

pub async fn authorize_messages_subscribe_and_query<MessageStore>(
    tenant: &str,
    incoming_message: &Message<Descriptor>,
    filters: &[MessagesFilter],
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<(), PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let permission_grants =
        fetch_and_validate_messages_grants(tenant, incoming_message, auth, message_store).await?;

    if filters.is_empty() {
        return permission_grants
            .has_unscoped_grants()
            .then_some(())
            .ok_or(GrantError::OutsideScope.into());
    }

    for filter in filters {
        if !permission_grants.covers_filter(filter).await {
            return Err(GrantError::OutsideScope.into());
        }
    }

    Ok(())
}

async fn fetch_and_validate_messages_grants<MessageStore>(
    tenant: &str,
    incoming_message: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<ValidatedMessagesGrantSet, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(permission_grant_ids) = auth.permission_grant_ids() else {
        return Err(AuthorizationValidationError::BadRequest(
            AuthorizationRequestError::PermissionGrantIDsRequired,
        )
        .into());
    };

    let mut grants = Vec::with_capacity(permission_grant_ids.len());
    for permission_grant_id in permission_grant_ids {
        let permission_grant = fetch_grant(tenant, message_store, permission_grant_id).await?;
        perform_base_validation(
            incoming_message,
            tenant,
            &auth.author,
            &permission_grant,
            message_store,
        )
        .await?;
        grants.push(permission_grant);
    }

    Ok(ValidatedMessagesGrantSet { grants })
}

async fn authorize_records_write_with_grant<MessageStore>(
    records_write_message: &Message<Descriptor>,
    expected_grantor: &str,
    expected_grantee: &str,
    permission_grant: &PermissionGrant,
    message_store: &MessageStore,
) -> Result<(), PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    perform_base_validation(
        records_write_message,
        expected_grantor,
        expected_grantee,
        permission_grant,
        message_store,
    )
    .await?;
    verify_records_scope(records_write_message, &permission_grant.scope)?;
    Ok(verify_records_write_conditions(
        records_write_message,
        permission_grant.conditions.as_ref(),
    )?)
}

async fn authorize_protocols_configure_with_grant<MessageStore>(
    protocols_configure_message: &Message<Descriptor>,
    expected_grantor: &str,
    expected_grantee: &str,
    permission_grant: &PermissionGrant,
    message_store: &MessageStore,
) -> Result<(), PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    perform_base_validation(
        protocols_configure_message,
        expected_grantor,
        expected_grantee,
        permission_grant,
        message_store,
    )
    .await?;
    let grant_protocol = permission_grant.scope.protocol();
    if let Some(grant_protocol) = grant_protocol {
        let configured_protocol = protocols_configure_descriptor(protocols_configure_message)
            .map_err(GrantError::InvalidMessageType)?
            .definition
            .protocol
            .as_str();
        if configured_protocol != grant_protocol {
            return Err(GrantError::OutsideScope.into());
        }
    }
    Ok(())
}

async fn perform_base_validation<MessageStore>(
    incoming_message: &Message<Descriptor>,
    expected_grantor: &str,
    expected_grantee: &str,
    permission_grant: &PermissionGrant,
    message_store: &MessageStore,
) -> Result<(), PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if expected_grantee != permission_grant.grantee {
        return Err(AuthorizationValidationError::UnexpectedGrantee(
            expected_grantee.to_string(),
            permission_grant.grantee.clone(),
        )
        .into());
    }
    if expected_grantor != permission_grant.grantor {
        return Err(AuthorizationValidationError::UnexpectedGrantor(
            expected_grantor.to_string(),
            permission_grant.grantor.clone(),
        )
        .into());
    }
    let incoming_timestamp = message_timestamp(incoming_message);
    if incoming_timestamp < permission_grant.date_granted {
        return Err(GrantError::NotActive.into());
    }
    if incoming_timestamp >= permission_grant.date_expires {
        return Err(GrantError::Expired.into());
    }
    verify_grant_not_revoked(
        expected_grantor,
        incoming_timestamp,
        permission_grant,
        message_store,
    )
    .await?;
    let (interface, method) = message_interface_and_method(incoming_message);
    if interface != permission_grant.scope.interface() {
        return Err(GrantError::OutsideScope.into());
    }
    if interface == MESSAGES_INTERFACE {
        if permission_grant.scope.method() != READ_METHOD {
            return Err(AuthorizationValidationError::BadRequest(
                AuthorizationRequestError::MismatchedGrant(
                    permission_grant.scope.method().to_string(),
                ),
            )
            .into());
        }
        if !matches!(method.as_str(), READ_METHOD | QUERY | SUBSCRIBE_METHOD) {
            return Err(AuthorizationValidationError::BadRequest(
                AuthorizationRequestError::GrantScopeMismatch(
                    method.to_string(),
                    permission_grant.id.clone(),
                ),
            )
            .into());
        }
    } else if method != permission_grant.scope.method() {
        return Err(AuthorizationValidationError::BadRequest(
            AuthorizationRequestError::GrantScopeMismatch(
                method.to_string(),
                permission_grant.id.clone(),
            ),
        )
        .into());
    }
    Ok(())
}

async fn verify_grant_not_revoked<MessageStore>(
    tenant: &str,
    incoming_timestamp: chrono::DateTime<chrono::Utc>,
    permission_grant: &PermissionGrant,
    message_store: &MessageStore,
) -> Result<(), PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let result = message_store
        .query(
            tenant,
            Filters::from(filter_map([
                ("parentId", string_filter(&permission_grant.id)),
                ("protocolPath", string_filter(PERMISSIONS_REVOCATION_PATH)),
                ("isLatestBaseState", bool_filter(true)),
            ])),
            Some(MessageSort::Timestamp(SortDirection::Ascending)),
            None,
        )
        .await?;
    if result
        .messages
        .iter()
        .any(|message| message_timestamp(message) <= incoming_timestamp)
    {
        return Err(GrantError::Revoked.into());
    }
    Ok(())
}

fn verify_records_scope(
    records_write_message: &Message<Descriptor>,
    grant_scope: &PermissionScope,
) -> Result<(), GrantError> {
    let descriptor = records_write_descriptor(records_write_message)?;
    let context_id = context_id(records_write_message);
    let target = ProtocolScopeTarget {
        protocol: Some(descriptor.protocol.as_str()),
        protocol_path: Some(descriptor.protocol_path.as_str()),
        context_id: context_id.as_deref(),
    };

    if !grant_scope.matches_protocol_target(&target) {
        return Err(GrantError::InvalidScopeForTarget(
            format!("{:?}", grant_scope),
            format!("{:?}", target),
        ));
    }

    Ok(())
}

fn verify_records_write_conditions(
    records_write_message: &Message<Descriptor>,
    conditions: Option<&PermissionConditions>,
) -> Result<(), GrantError> {
    let descriptor = records_write_descriptor(records_write_message)?;
    match conditions.and_then(|conditions| conditions.publication.as_ref()) {
        Some(PermissionConditionPublication::Required) if descriptor.published != Some(true) => {
            Err(GrantError::UnpublishedGrant)
        }
        Some(PermissionConditionPublication::Prohibited) if descriptor.published == Some(true) => {
            Err(GrantError::PublishProhibited)
        }
        _ => Ok(()),
    }
}

async fn get_scope_from_permission_record<MessageStore>(
    tenant: &str,
    message_store: &MessageStore,
    incoming_message: &Message<Descriptor>,
) -> Result<PermissionScope, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let descriptor = records_write_descriptor(incoming_message)
        .map_err(|e| PermissionError::InvalidGrant(e.into()))?;
    if descriptor.protocol.as_str() != PERMISSIONS_PROTOCOL_URI {
        return Err(GrantError::UnexpectedProtocol(descriptor.protocol.clone()).into());
    }
    match descriptor.protocol_path.as_str() {
        PERMISSIONS_REVOCATION_PATH => {
            let parent_id = descriptor
                .parent_id
                .as_deref()
                .ok_or(GrantError::RevocationParentIdRequired)?;

            Ok(fetch_grant(tenant, message_store, parent_id)
                .await
                .map(|grant| grant.scope)?)
        }
        PERMISSIONS_GRANT_PATH => {
            let grantor =
                message_author(incoming_message).ok_or(GrantError::UnableToExtractGrantor)?;
            Ok(parse_permission_grant(incoming_message, &grantor).map(|grant| grant.scope)?)
        }
        _ => {
            let data: PermissionRequestData = serde_json::from_slice(
                &permission_record_data_bytes(incoming_message)
                    .map_err(GrantError::ProtocolValidationError)?,
            )
            .map_err(AuthorizationValidationError::ParseFailed)?;
            Ok(data.scope)
        }
    }
}

fn validate_scope_and_tags(
    scope: &PermissionScope,
    descriptor: &RecordsWriteDescriptor,
) -> Result<(), AuthorizationValidationError> {
    if let Some(protocol) = scope.protocol() {
        validate_permission_protocol_tag(descriptor, protocol)?;
    }
    if scope.interface() == RECORDS_INTERFACE && scope.protocol().is_none() {
        return Err(AuthorizationValidationError::RecordsGrantMissingProtocol);
    }
    Ok(())
}

fn validate_permission_protocol_tag(
    descriptor: &RecordsWriteDescriptor,
    scoped_protocol: &str,
) -> Result<(), AuthorizationValidationError> {
    let tagged_protocol = descriptor
        .tags
        .as_ref()
        .and_then(|tags| tags.get("protocol"))
        .and_then(index_value_as_str)
        .ok_or(AuthorizationValidationError::ProtocolInvalidTags)?;
    if tagged_protocol != scoped_protocol {
        return Err(AuthorizationValidationError::ProtocolInvalidTags);
    }
    Ok(())
}

fn parse_permission_grant(
    message: &Message<Descriptor>,
    grantor: &str,
) -> Result<PermissionGrant, GrantError> {
    let descriptor = records_write_descriptor(message)?;
    if descriptor.protocol.as_str() != PERMISSIONS_PROTOCOL_URI
        || descriptor.protocol_path != PERMISSIONS_GRANT_PATH
    {
        return Err(GrantMessageTypeError::InvalidMessageType.into());
    }
    let data: PermissionGrantData = serde_json::from_slice(&permission_record_data_bytes(message)?)
        .map_err(AuthorizationValidationError::ParseFailed)?;
    let id = record_id(message).ok_or(GrantError::RecordIdRequired)?;
    let grantee = descriptor
        .recipient
        .clone()
        .ok_or(GrantError::UnableToExtractGrantor)?;

    Ok(PermissionGrant {
        id,
        grantor: grantor.to_string(),
        grantee,
        date_granted: descriptor.date_created,
        date_expires: data.date_expires,
        delegated: data.delegated,
        scope: data.scope,
        conditions: data.conditions,
        connect_session: data.connect_session,
    })
}

fn permission_record_data_bytes(
    message: &Message<Descriptor>,
) -> Result<Vec<u8>, ProtocolValidationError> {
    let fields = write_fields(message)?;
    let encoded_data = fields
        .encoded_data
        .as_deref()
        .ok_or(ProtocolValidationError::MissingEncodedData)?;
    Ok(URL_SAFE_NO_PAD.decode(encoded_data)?)
}

fn protocols_configure_descriptor(
    message: &Message<Descriptor>,
) -> Result<&ConfigureDescriptor, GrantMessageTypeError> {
    match &message.descriptor {
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            crate::descriptors::Protocols::Configure(descriptor) => Ok(descriptor),
            _ => Err(GrantMessageTypeError::InvalidProtocolsConfigureMessageType),
        },
        _ => Err(GrantMessageTypeError::InvalidProtocolsConfigureMessageType),
    }
}

fn protocols_query_descriptor(
    message: &Message<Descriptor>,
) -> Result<&ProtocolQueryDescriptor, GrantMessageTypeError> {
    match &message.descriptor {
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            crate::descriptors::Protocols::Query(descriptor) => Ok(descriptor),
            _ => Err(GrantMessageTypeError::InvalidProtocolsQueryMessageType),
        },
        _ => Err(GrantMessageTypeError::InvalidProtocolsQueryMessageType),
    }
}

fn context_id(message: &Message<Descriptor>) -> Option<String> {
    write_fields(message).ok()?.context_id.clone()
}

async fn fetch_newest_write<MessageStore>(
    tenant: &str,
    record_id: &str,
    message_store: &MessageStore,
) -> Result<Message<Descriptor>, PermissionError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let result = message_store
        .query(
            tenant,
            Filters::from(filter_map([
                ("interface", string_filter(RECORDS_INTERFACE)),
                ("method", string_filter("Write")),
                ("recordId", string_filter(record_id)),
            ])),
            Some(MessageSort::Timestamp(SortDirection::Descending)),
            Some(Pagination::with_limit(1)),
        )
        .await?;

    result
        .messages
        .into_iter()
        .next()
        .ok_or_else(|| GrantError::NotFound(record_id.to_string()).into())
}

fn message_timestamp(message: &Message<Descriptor>) -> chrono::DateTime<chrono::Utc> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Read(descriptor) => descriptor.message_timestamp,
            Records::Count(descriptor) => descriptor.message_timestamp,
            Records::Query(descriptor) => descriptor.message_timestamp,
            Records::Write(descriptor) => descriptor.message_timestamp,
            Records::Delete(descriptor) => descriptor.message_timestamp,
            Records::Subscribe(descriptor) => descriptor.message_timestamp,
        },
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            crate::descriptors::Protocols::Configure(descriptor) => descriptor.message_timestamp,
            crate::descriptors::Protocols::Query(descriptor) => descriptor.message_timestamp,
        },
        Descriptor::Messages(messages) => match messages.as_ref() {
            crate::descriptors::Messages::Read(descriptor) => descriptor.message_timestamp,
            crate::descriptors::Messages::Query(descriptor) => descriptor.message_timestamp,
            crate::descriptors::Messages::Subscribe(descriptor) => descriptor.message_timestamp,
            crate::descriptors::Messages::Sync(descriptor) => descriptor.message_timestamp,
        },
    }
}

fn message_interface_and_method(message: &Message<Descriptor>) -> (String, String) {
    match &message.descriptor {
        Descriptor::Records(records) => (
            RECORDS_INTERFACE.to_string(),
            MessageDescriptor::method(records.as_ref()).to_string(),
        ),
        Descriptor::Protocols(protocols) => (
            PROTOCOLS_INTERFACE.to_string(),
            MessageDescriptor::method(protocols.as_ref()).to_string(),
        ),
        Descriptor::Messages(messages) => (
            MESSAGES_INTERFACE.to_string(),
            MessageDescriptor::method(messages.as_ref()).to_string(),
        ),
    }
}

fn message_cid(message: &Message<Descriptor>) -> Result<String, AuthorizationValidationError> {
    Ok(serde_json::to_value(message)?)
        .and_then(|value| Ok(generate_message_cid_from_json(&value)?))
        .map(|cid| cid.to_string())
}

fn index_value_as_str(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) => Some(value.as_str()),
        _ => None,
    }
}

fn string_filter(value: &str) -> Filter<Value> {
    Filter::Equal(Value::String(value.to_string()))
}

fn bool_filter(value: bool) -> Filter<Value> {
    Filter::Equal(Value::Bool(value))
}

fn filter_map<const N: usize>(
    items: [(&str, Filter<Value>); N],
) -> BTreeMap<FilterKey, Filter<Value>> {
    items
        .into_iter()
        .map(|(key, value)| (FilterKey::Index(key.to_string()), value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Authorization;
    use crate::descriptors::{Messages, MessagesSubscribeDescriptor};
    use crate::errors::MessageStoreError;
    use crate::filters::message_filters::Messages as MessagesFilter;
    use crate::stores::{MessageQueryResult, MessageStore};

    #[test]
    fn permission_grant_invocation_requires_canonical_matching_plural_fields() {
        let message: Message<Descriptor> = serde_json::from_value(serde_json::json!({
            "descriptor": {
                "interface": "Messages",
                "method": "Subscribe",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z",
                "filters": [],
                "permissionGrantIds": ["grant-a", "grant-b"],
            },
            "signature": {},
        }))
        .unwrap();
        let valid_payload = VerifiedAuthorizationPayload::Generic(AuthorizationPayloadData {
            descriptor_cid: String::new(),
            delegated_grant_id: None,
            permission_grant_id: None,
            permission_grant_ids: Some(vec!["grant-a".to_string(), "grant-b".to_string()]),
            protocol_role: None,
        });
        assert_eq!(
            validate_permission_grant(&message, &valid_payload).unwrap(),
            PermissionGrantInvocation::Multi(vec!["grant-a".to_string(), "grant-b".to_string()]),
        );

        for permission_grant_ids in [
            Some(vec![]),
            Some(vec!["grant-b".to_string(), "grant-a".to_string()]),
            Some(vec!["grant-a".to_string(), "grant-a".to_string()]),
            Some(vec!["grant-a".to_string(), "grant-c".to_string()]),
        ] {
            let payload = VerifiedAuthorizationPayload::Generic(AuthorizationPayloadData {
                descriptor_cid: String::new(),
                delegated_grant_id: None,
                permission_grant_id: None,
                permission_grant_ids,
                protocol_role: None,
            });
            assert!(validate_permission_grant(&message, &payload).is_err());
        }

        let conflicting_payload = VerifiedAuthorizationPayload::Generic(AuthorizationPayloadData {
            descriptor_cid: String::new(),
            delegated_grant_id: None,
            permission_grant_id: Some("grant-a".to_string()),
            permission_grant_ids: Some(vec!["grant-a".to_string(), "grant-b".to_string()]),
            protocol_role: None,
        });
        assert!(validate_permission_grant(&message, &conflicting_payload).is_err());
    }

    #[tokio::test]
    async fn messages_read_grant_authorizes_messages_subscribe() {
        let grant = PermissionGrant {
            id: "grant-1".to_string(),
            grantor: "did:example:alice".to_string(),
            grantee: "did:example:bob".to_string(),
            date_granted: parse_time("2025-01-01T00:00:00.000000Z"),
            date_expires: parse_time("2025-02-01T00:00:00.000000Z"),
            delegated: None,
            scope: PermissionScope::Messages(MessagesScope {
                protocol: Some("http://example.com/notes".to_string()),
                selector: None,
            }),
            conditions: None,
            connect_session: None,
        };
        let message = Message {
            descriptor: Descriptor::Messages(Box::new(Messages::Subscribe(
                MessagesSubscribeDescriptor {
                    message_timestamp: parse_time("2025-01-01T00:10:00.000000Z"),
                    filters: vec![MessagesFilter {
                        protocol: Some("http://example.com/notes".to_string()),
                        ..Default::default()
                    }],
                    permission_grant_ids: Some(vec!["grant-1".to_string()]),
                    cursor: None,
                },
            ))),
            fields: Fields::Authorization(Authorization::default()),
        };

        perform_base_validation(
            &message,
            "did:example:alice",
            "did:example:bob",
            &grant,
            &NoopMessageStore,
        )
        .await
        .unwrap();
    }

    fn parse_time(value: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[derive(Clone, Default)]
    struct NoopMessageStore;

    impl MessageStore for NoopMessageStore {
        async fn open(&mut self) -> Result<(), MessageStoreError> {
            Ok(())
        }

        async fn close(&mut self) {}

        async fn put<D: crate::descriptors::MessageDescriptor + Send>(
            &self,
            _tenant: &str,
            _message: Message<D>,
            _indexes: BTreeMap<String, Value>,
        ) -> Result<(), MessageStoreError> {
            Ok(())
        }

        async fn get(
            &self,
            _tenant: &str,
            _cid: &str,
        ) -> Result<Option<Message<Descriptor>>, MessageStoreError> {
            Ok(None)
        }

        async fn query(
            &self,
            _tenant: &str,
            _filters: Filters,
            _sort: Option<MessageSort>,
            _pagination: Option<Pagination>,
        ) -> Result<MessageQueryResult, MessageStoreError> {
            Ok(MessageQueryResult {
                messages: Vec::new(),
                cursor: None,
            })
        }

        async fn count(
            &self,
            _tenant: &str,
            _filters: Filters,
            _sort: Option<MessageSort>,
        ) -> Result<u64, MessageStoreError> {
            Ok(0)
        }

        async fn delete(&self, _tenant: &str, _cid: &str) -> Result<(), MessageStoreError> {
            Ok(())
        }

        async fn clear(&self) -> Result<(), MessageStoreError> {
            Ok(())
        }
    }
}
