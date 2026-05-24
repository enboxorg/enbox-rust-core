use std::collections::BTreeMap;
use std::ops::Bound;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::auth::{GeneralJws, GeneralJwsPublicKeyResolver};
use crate::cid::generate_cid_from_json;
use crate::descriptors::{
    ConfigureDescriptor, Descriptor, ProtocolQueryDescriptor, Records, RecordsWriteDescriptor,
};
use crate::fields::{Fields, WriteFields};
use crate::filters::message_filters::Records as RecordsFilter;
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::interfaces::messages::protocols::{
    Action, ActionWho, Can, Definition, RuleSet, Size, Type, Who,
};
use crate::stores::{EnboxDataStore, EnboxMessageStore, EnboxStateIndex};
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
const SYNC_METHOD: &str = "Sync";
const MAX_ENCODED_DATA_SIZE: u64 = 30_000;

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationContext {
    pub signer: String,
    pub author: String,
    pub payload: JsonValue,
    pub author_delegated_grant: Option<PermissionGrant>,
}

impl AuthorizationContext {
    pub fn permission_grant_id(&self) -> Option<&str> {
        self.payload
            .get("permissionGrantId")
            .and_then(JsonValue::as_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationValidationError {
    BadRequest(String),
    Unauthorized(String),
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
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PermissionScope {
    pub interface: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "contextId", skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(rename = "protocolPath", skip_serializing_if = "Option::is_none")]
    pub protocol_path: Option<String>,
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
    #[serde(
        rename = "delegateKeyDelivery",
        skip_serializing_if = "Option::is_none"
    )]
    delegate_key_delivery: Option<JsonValue>,
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

pub fn validate_authorization_signature(
    raw_message: &JsonValue,
    public_key_resolver: Option<&(dyn GeneralJwsPublicKeyResolver + Send + Sync)>,
    required: bool,
) -> Result<Option<AuthorizationContext>, AuthorizationValidationError> {
    validate_authorization_signature_inner(raw_message, public_key_resolver, required, true)
}

fn validate_authorization_signature_inner(
    raw_message: &JsonValue,
    public_key_resolver: Option<&(dyn GeneralJwsPublicKeyResolver + Send + Sync)>,
    required: bool,
    validate_delegated_grant: bool,
) -> Result<Option<AuthorizationContext>, AuthorizationValidationError> {
    let Some(authorization) = raw_message.get("authorization") else {
        return if required {
            Err(AuthorizationValidationError::Unauthorized(
                "AuthenticateJwsMissing: authorization signature is required".to_string(),
            ))
        } else {
            Ok(None)
        };
    };
    let signature = authorization.get("signature").ok_or_else(|| {
        AuthorizationValidationError::BadRequest(
            "AuthenticateJwsMissing: authorization signature is required".to_string(),
        )
    })?;
    let jws: GeneralJws = serde_json::from_value(signature.clone()).map_err(|err| {
        AuthorizationValidationError::BadRequest(format!("AuthenticationInvalidSignature: {err}"))
    })?;
    if jws.signatures.len() != 1 {
        return Err(AuthorizationValidationError::BadRequest(
            "AuthenticationMoreThanOneSignatureNotSupported: expected exactly one signature"
                .to_string(),
        ));
    }
    let payload = decode_jws_payload(&jws)?;
    validate_descriptor_cid(raw_message, &payload)?;
    let unverified_signer = signer_did_from_jws(&jws)?;
    let signer = public_key_resolver
        .map(|resolver| {
            jws.verify_signatures(resolver)
                .map_err(|err| {
                    AuthorizationValidationError::Unauthorized(format!("{}: {err}", err.code()))
                })
                .and_then(|signers| {
                    signers.into_iter().next().ok_or_else(|| {
                        AuthorizationValidationError::Unauthorized(
                            "AuthenticateJwsMissing: no signer found".to_string(),
                        )
                    })
                })
        })
        .transpose()?
        .unwrap_or(unverified_signer);

    let mut author = signer.clone();
    let mut author_delegated_grant = None;
    if validate_delegated_grant {
        author_delegated_grant =
            validate_embedded_author_delegated_grant(authorization, &payload, public_key_resolver)?;
        if let Some(grant) = &author_delegated_grant {
            author = grant.grantor.clone();
        }
    }

    Ok(Some(AuthorizationContext {
        signer,
        author,
        payload,
        author_delegated_grant,
    }))
}

fn validate_embedded_author_delegated_grant(
    authorization: &JsonValue,
    payload: &JsonValue,
    public_key_resolver: Option<&(dyn GeneralJwsPublicKeyResolver + Send + Sync)>,
) -> Result<Option<PermissionGrant>, AuthorizationValidationError> {
    let Some(grant_value) = authorization.get("authorDelegatedGrant") else {
        if payload.get("delegatedGrantId").is_some() {
            return Err(AuthorizationValidationError::BadRequest(
                "GrantAuthorizationGrantMissing: delegatedGrantId requires authorDelegatedGrant"
                    .to_string(),
            ));
        }
        return Ok(None);
    };

    let grant_message: Message<Descriptor> =
        serde_json::from_value(grant_value.clone()).map_err(|err| {
            AuthorizationValidationError::BadRequest(format!(
                "GrantAuthorizationGrantInvalid: {err}"
            ))
        })?;
    let grant_cid =
        message_cid(&grant_message).map_err(AuthorizationValidationError::BadRequest)?;
    let delegated_grant_id = payload
        .get("delegatedGrantId")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            AuthorizationValidationError::BadRequest(
                "GrantAuthorizationGrantMissing: delegatedGrantId is required".to_string(),
            )
        })?;
    if delegated_grant_id != grant_cid {
        return Err(AuthorizationValidationError::BadRequest(format!(
            "GrantAuthorizationGrantMismatch: delegatedGrantId {delegated_grant_id} does not match authorDelegatedGrant CID {grant_cid}"
        )));
    }

    let grant_authorization =
        validate_authorization_signature_inner(grant_value, public_key_resolver, true, false)?
            .ok_or_else(|| {
                AuthorizationValidationError::Unauthorized(
                    "AuthenticateJwsMissing: authorization signature is required".to_string(),
                )
            })?;
    parse_permission_grant(&grant_message, &grant_authorization.author)
        .map(Some)
        .map_err(AuthorizationValidationError::BadRequest)
}

fn decode_jws_payload(jws: &GeneralJws) -> Result<JsonValue, AuthorizationValidationError> {
    let payload = URL_SAFE_NO_PAD.decode(&jws.payload).map_err(|err| {
        AuthorizationValidationError::BadRequest(format!(
            "AuthenticationInvalidSignaturePayload: {err}"
        ))
    })?;
    serde_json::from_slice(&payload).map_err(|err| {
        AuthorizationValidationError::BadRequest(format!(
            "AuthenticationInvalidSignaturePayload: {err}"
        ))
    })
}

fn validate_descriptor_cid(
    raw_message: &JsonValue,
    payload: &JsonValue,
) -> Result<(), AuthorizationValidationError> {
    let descriptor_cid = payload
        .get("descriptorCid")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            AuthorizationValidationError::BadRequest(
                "AuthenticationInvalidSignaturePayload: descriptorCid is required".to_string(),
            )
        })?;
    let descriptor = raw_message.get("descriptor").ok_or_else(|| {
        AuthorizationValidationError::BadRequest(
            "AuthenticationInvalidSignaturePayload: descriptor is required".to_string(),
        )
    })?;
    let expected = generate_cid_from_json(descriptor)
        .map_err(|err| {
            AuthorizationValidationError::BadRequest(format!(
                "AuthenticationInvalidSignaturePayload: {err}"
            ))
        })?
        .to_string();
    if descriptor_cid != expected {
        return Err(AuthorizationValidationError::BadRequest(format!(
            "AuthenticateDescriptorCidMismatch: provided descriptorCid {descriptor_cid} does not match expected CID {expected}"
        )));
    }
    Ok(())
}

fn signer_did_from_jws(jws: &GeneralJws) -> Result<String, AuthorizationValidationError> {
    let protected = &jws
        .signatures
        .first()
        .ok_or_else(|| {
            AuthorizationValidationError::BadRequest(
                "AuthenticationInvalidSignatureProtectedHeader: signature is required".to_string(),
            )
        })?
        .protected;
    let protected = URL_SAFE_NO_PAD.decode(protected).map_err(|err| {
        AuthorizationValidationError::BadRequest(format!(
            "AuthenticationInvalidSignatureProtectedHeader: {err}"
        ))
    })?;
    let protected: JsonValue = serde_json::from_slice(&protected).map_err(|err| {
        AuthorizationValidationError::BadRequest(format!(
            "AuthenticationInvalidSignatureProtectedHeader: {err}"
        ))
    })?;
    let kid = protected
        .get("kid")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            AuthorizationValidationError::BadRequest(
                "AuthenticationInvalidSignatureProtectedHeader: kid is required".to_string(),
            )
        })?;
    kid.split('#')
        .next()
        .filter(|did| !did.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            AuthorizationValidationError::BadRequest(
                "AuthenticationInvalidSignatureProtectedHeader: kid is required".to_string(),
            )
        })
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
    let jws: GeneralJws = serde_json::from_value(signature.clone()).ok()?;
    signer_did_from_jws(&jws).ok()
}

fn authorization_from_message(message: &Message<Descriptor>) -> Option<JsonValue> {
    serde_json::to_value(message)
        .ok()?
        .get("authorization")
        .cloned()
}

pub fn validate_permissions_record_schema(message: &Message<Descriptor>) -> Result<(), String> {
    let descriptor = records_write_descriptor(message)?;
    if descriptor.protocol.as_deref() != Some(PERMISSIONS_PROTOCOL_URI) {
        return Ok(());
    }
    let data = permission_record_data_bytes(message)?;
    match descriptor.protocol_path.as_deref() {
        Some(PERMISSIONS_REQUEST_PATH) => {
            let data: PermissionRequestData = serde_json::from_slice(&data).map_err(|err| {
                format!("PermissionsProtocolValidateSchemaInvalidRequest: {err}")
            })?;
            validate_scope_and_tags(&data.scope, descriptor)
        }
        Some(PERMISSIONS_GRANT_PATH) => {
            let data: PermissionGrantData = serde_json::from_slice(&data)
                .map_err(|err| format!("PermissionsProtocolValidateSchemaInvalidGrant: {err}"))?;
            validate_scope_and_tags(&data.scope, descriptor)
        }
        Some(PERMISSIONS_REVOCATION_PATH) => {
            let _: PermissionRevocationData = serde_json::from_slice(&data).map_err(|err| {
                format!("PermissionsProtocolValidateSchemaInvalidRevocation: {err}")
            })?;
            Ok(())
        }
        Some(protocol_path) => Err(format!(
            "PermissionsProtocolValidateSchemaUnexpectedRecord: Unexpected permission record: {protocol_path}"
        )),
        None => Err("PermissionsProtocolValidateSchemaUnexpectedRecord: permission record missing protocolPath".to_string()),
    }
}

pub async fn pre_process_permissions_write<MessageStore>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
{
    let descriptor = records_write_descriptor(message)?;
    if descriptor.protocol.as_deref() != Some(PERMISSIONS_PROTOCOL_URI)
        || descriptor.protocol_path.as_deref() != Some(PERMISSIONS_REVOCATION_PATH)
    {
        return Ok(());
    }
    let parent_id = descriptor.parent_id.as_deref().ok_or_else(|| {
        "PermissionsProtocolValidateRevocationMissingGrant: revocation parentId is required"
            .to_string()
    })?;
    let grant = fetch_grant(tenant, message_store, parent_id).await?;
    let revocation_protocol_tag = descriptor
        .tags
        .as_ref()
        .and_then(|tags| tags.get("protocol"))
        .and_then(index_value_as_str);
    if grant.scope.protocol.as_deref() != revocation_protocol_tag {
        return Err(format!(
            "PermissionsProtocolValidateRevocationProtocolTagMismatch: Revocation protocol {:?} does not match grant protocol {:?}",
            revocation_protocol_tag, grant.scope.protocol
        ));
    }
    Ok(())
}

pub async fn post_process_permissions_write<MessageStore, DataStore, StateIndex>(
    tenant: &str,
    message: &Message<Descriptor>,
    message_store: &MessageStore,
    data_store: &DataStore,
    state_index: &StateIndex,
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
    DataStore: EnboxDataStore + Sync,
    StateIndex: EnboxStateIndex + Sync,
{
    let descriptor = records_write_descriptor(message)?;
    if descriptor.protocol.as_deref() != Some(PERMISSIONS_PROTOCOL_URI)
        || descriptor.protocol_path.as_deref() != Some(PERMISSIONS_REVOCATION_PATH)
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
        .await
        .map_err(|err| err.to_string())?;
    let mut cids = Vec::new();
    for authorized_message in result.messages {
        if message_timestamp(&authorized_message)
            .ok()
            .is_none_or(|timestamp| timestamp < revoke_timestamp)
        {
            continue;
        }
        if let Ok(write) = records_write_descriptor(&authorized_message) {
            if write.data_size > MAX_ENCODED_DATA_SIZE {
                if let Some(record_id) = record_id(&authorized_message) {
                    data_store
                        .delete(tenant, &record_id, &write.data_cid)
                        .await
                        .map_err(|err| err.to_string())?;
                }
            }
        }
        let cid = message_cid(&authorized_message)?;
        message_store
            .delete(tenant, &cid)
            .await
            .map_err(|err| err.to_string())?;
        cids.push(cid);
    }
    if !cids.is_empty() {
        state_index
            .delete(tenant, &cids)
            .await
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

pub async fn fetch_grant<MessageStore>(
    tenant: &str,
    message_store: &MessageStore,
    permission_grant_id: &str,
) -> Result<PermissionGrant, String>
where
    MessageStore: EnboxMessageStore + Sync,
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
        .await
        .map_err(|err| err.to_string())?;
    let Some(message) = result.messages.first() else {
        return Err(format!(
            "GrantAuthorizationGrantMissing: Could not find permission grant with record ID {permission_grant_id}."
        ));
    };
    let grantor = message_author(message).ok_or_else(|| {
        "PermissionGrantParseMissingAuthorization: unable to extract grantor".to_string()
    })?;
    parse_permission_grant(message, &grantor)
}

pub async fn authorize_delegated_records_write<MessageStore>(
    records_write_message: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, String>
where
    MessageStore: EnboxMessageStore + Sync,
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
) -> Result<bool, String>
where
    MessageStore: EnboxMessageStore + Sync,
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
) -> Result<bool, String>
where
    MessageStore: EnboxMessageStore + Sync,
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
) -> Result<bool, String>
where
    MessageStore: EnboxMessageStore + Sync,
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
    let protocol = filter.protocol.as_deref();
    if protocol != permission_grant.scope.protocol.as_deref() {
        return Err(format!(
            "RecordsGrantAuthorizationQueryOrSubscribeProtocolScopeMismatch: Grant protocol scope {:?} does not match protocol in message {:?}",
            permission_grant.scope.protocol, protocol
        ));
    }
    Ok(true)
}

pub async fn authorize_records_delete_with_grant<MessageStore>(
    tenant: &str,
    records_delete_message: &Message<Descriptor>,
    records_write_to_delete: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, String>
where
    MessageStore: EnboxMessageStore + Sync,
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
    let record_protocol = records_write_descriptor(records_write_to_delete)?
        .protocol
        .as_deref();
    if record_protocol != permission_grant.scope.protocol.as_deref() {
        return Err(format!(
            "RecordsGrantAuthorizationDeleteProtocolScopeMismatch: Grant protocol scope {:?} does not match protocol in record to delete {:?}",
            permission_grant.scope.protocol, record_protocol
        ));
    }
    Ok(true)
}

pub async fn authorize_protocols_configure<MessageStore>(
    tenant: &str,
    protocols_configure_message: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
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
    Err("ProtocolsConfigureAuthorizationFailed: message failed authorization".to_string())
}

pub async fn authorize_protocols_query<MessageStore>(
    tenant: &str,
    protocols_query_message: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<bool, String>
where
    MessageStore: EnboxMessageStore + Sync,
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
    let protocol_in_grant = permission_grant.scope.protocol.as_deref();
    let protocol_in_message = protocols_query_descriptor(protocols_query_message)?
        .filter
        .as_ref()
        .and_then(|filter| filter.protocol.as_deref());
    if protocol_in_grant.is_some() && protocol_in_message != protocol_in_grant {
        return Err(format!(
            "ProtocolsGrantAuthorizationQueryProtocolScopeMismatch: Grant protocol scope {:?} does not match protocol in message {:?}",
            protocol_in_grant, protocol_in_message
        ));
    }
    Ok(true)
}

pub async fn authorize_messages_read<MessageStore>(
    tenant: &str,
    messages_read_message: &Message<Descriptor>,
    message_to_read: &Message<Descriptor>,
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
{
    let Some(permission_grant_id) = auth.permission_grant_id() else {
        return Err("GrantAuthorizationGrantMissing: permissionGrantId is required".to_string());
    };
    let permission_grant = fetch_grant(tenant, message_store, permission_grant_id).await?;
    perform_base_validation(
        messages_read_message,
        tenant,
        &auth.author,
        &permission_grant,
        message_store,
    )
    .await?;
    verify_messages_protocol_scope(
        tenant,
        message_to_read,
        &permission_grant.scope,
        message_store,
    )
    .await
}

pub async fn authorize_messages_subscribe_or_sync<MessageStore>(
    tenant: &str,
    incoming_message: &Message<Descriptor>,
    protocols_in_message: &[String],
    auth: &AuthorizationContext,
    message_store: &MessageStore,
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
{
    let Some(permission_grant_id) = auth.permission_grant_id() else {
        return Err("GrantAuthorizationGrantMissing: permissionGrantId is required".to_string());
    };
    let permission_grant = fetch_grant(tenant, message_store, permission_grant_id).await?;
    perform_base_validation(
        incoming_message,
        tenant,
        &auth.author,
        &permission_grant,
        message_store,
    )
    .await?;
    if let Some(scoped_protocol) = permission_grant.scope.protocol.as_deref() {
        if protocols_in_message.is_empty() {
            return Err(format!(
                "MessagesGrantAuthorizationMismatchedProtocol: The scoped protocol {scoped_protocol} is not present in the incoming message"
            ));
        }
        for protocol in protocols_in_message {
            if protocol != scoped_protocol {
                return Err(format!(
                    "MessagesGrantAuthorizationMismatchedProtocol: The protocol {protocol} does not match the scoped protocol {scoped_protocol}"
                ));
            }
        }
    }
    Ok(())
}

async fn authorize_records_write_with_grant<MessageStore>(
    records_write_message: &Message<Descriptor>,
    expected_grantor: &str,
    expected_grantee: &str,
    permission_grant: &PermissionGrant,
    message_store: &MessageStore,
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
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
    verify_records_write_conditions(records_write_message, permission_grant.conditions.as_ref())
}

async fn authorize_protocols_configure_with_grant<MessageStore>(
    protocols_configure_message: &Message<Descriptor>,
    expected_grantor: &str,
    expected_grantee: &str,
    permission_grant: &PermissionGrant,
    message_store: &MessageStore,
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
{
    perform_base_validation(
        protocols_configure_message,
        expected_grantor,
        expected_grantee,
        permission_grant,
        message_store,
    )
    .await?;
    let grant_protocol = permission_grant.scope.protocol.as_deref();
    if let Some(grant_protocol) = grant_protocol {
        let configured_protocol = protocols_configure_descriptor(protocols_configure_message)?
            .definition
            .protocol
            .as_str();
        if configured_protocol != grant_protocol {
            return Err("ProtocolsGrantAuthorizationScopeProtocolMismatch: Grant scope specifies different protocol than what appears in the configure message.".to_string());
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
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
{
    if expected_grantee != permission_grant.grantee {
        return Err(format!(
            "GrantAuthorizationNotGrantedToAuthor: Permission grant is granted to {}, but need to be granted to {expected_grantee}",
            permission_grant.grantee
        ));
    }
    if expected_grantor != permission_grant.grantor {
        return Err(format!(
            "GrantAuthorizationNotGrantedForTenant: Permission grant is granted by {}, but need to be granted by {expected_grantor}",
            permission_grant.grantor
        ));
    }
    let incoming_timestamp = message_timestamp(incoming_message)?;
    if incoming_timestamp < permission_grant.date_granted {
        return Err("GrantAuthorizationGrantNotYetActive: The message has a timestamp before the associated permission grant becomes active".to_string());
    }
    if incoming_timestamp >= permission_grant.date_expires {
        return Err("GrantAuthorizationGrantExpired: The message has timestamp after the expiry of the associated permission grant".to_string());
    }
    verify_grant_not_revoked(
        expected_grantor,
        incoming_timestamp,
        permission_grant,
        message_store,
    )
    .await?;
    let (interface, method) = message_interface_and_method(incoming_message)?;
    if interface != permission_grant.scope.interface {
        return Err(format!(
            "GrantAuthorizationInterfaceMismatch: DWN Interface of incoming message is outside the scope of permission grant with ID {}",
            permission_grant.id
        ));
    }
    if interface == MESSAGES_INTERFACE {
        if permission_grant.scope.method != READ_METHOD {
            return Err(format!(
                "GrantAuthorizationMethodMismatch: messages permission grant must have method 'Read', got '{}' for grant {}",
                permission_grant.scope.method, permission_grant.id
            ));
        }
        if !matches!(
            method.as_str(),
            READ_METHOD | SUBSCRIBE_METHOD | SYNC_METHOD
        ) {
            return Err(format!(
                "GrantAuthorizationMethodMismatch: DWN Method of incoming message is outside the scope of permission grant with ID {}",
                permission_grant.id
            ));
        }
    } else if method != permission_grant.scope.method {
        return Err(format!(
            "GrantAuthorizationMethodMismatch: DWN Method of incoming message is outside the scope of permission grant with ID {}",
            permission_grant.id
        ));
    }
    Ok(())
}

async fn verify_grant_not_revoked<MessageStore>(
    tenant: &str,
    incoming_timestamp: chrono::DateTime<chrono::Utc>,
    permission_grant: &PermissionGrant,
    message_store: &MessageStore,
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
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
        .await
        .map_err(|err| err.to_string())?;
    if result.messages.iter().any(|message| {
        message_timestamp(message).is_ok_and(|timestamp| timestamp <= incoming_timestamp)
    }) {
        return Err(format!(
            "GrantAuthorizationGrantRevoked: Permission grant with CID {} has been revoked",
            permission_grant.id
        ));
    }
    Ok(())
}

fn verify_records_scope(
    records_write_message: &Message<Descriptor>,
    grant_scope: &PermissionScope,
) -> Result<(), String> {
    let descriptor = records_write_descriptor(records_write_message)?;
    if grant_scope.protocol.as_deref() != descriptor.protocol.as_deref() {
        return Err("RecordsGrantAuthorizationScopeProtocolMismatch: Grant scope specifies different protocol than what appears in the record".to_string());
    }
    if let Some(scope_context_id) = grant_scope.context_id.as_deref() {
        let record_context_id = context_id(records_write_message).ok_or_else(|| {
            "RecordsGrantAuthorizationScopeContextIdMismatch: record contextId is missing"
                .to_string()
        })?;
        if !record_context_id.starts_with(scope_context_id) {
            return Err("RecordsGrantAuthorizationScopeContextIdMismatch: Grant scope specifies different contextId than what appears in the record".to_string());
        }
    }
    if let Some(scope_protocol_path) = grant_scope.protocol_path.as_deref() {
        if descriptor.protocol_path.as_deref() != Some(scope_protocol_path) {
            return Err("RecordsGrantAuthorizationScopeProtocolPathMismatch: Grant scope specifies different protocolPath than what appears in the record".to_string());
        }
    }
    Ok(())
}

fn verify_records_write_conditions(
    records_write_message: &Message<Descriptor>,
    conditions: Option<&PermissionConditions>,
) -> Result<(), String> {
    let descriptor = records_write_descriptor(records_write_message)?;
    match conditions.and_then(|conditions| conditions.publication.as_ref()) {
        Some(PermissionConditionPublication::Required) if descriptor.published != Some(true) => {
            Err("RecordsGrantAuthorizationConditionPublicationRequired: Permission grant requires message to be published".to_string())
        }
        Some(PermissionConditionPublication::Prohibited) if descriptor.published == Some(true) => {
            Err("RecordsGrantAuthorizationConditionPublicationProhibited: Permission grant prohibits message from being published".to_string())
        }
        _ => Ok(()),
    }
}

async fn verify_messages_protocol_scope<MessageStore>(
    tenant: &str,
    message_to_read: &Message<Descriptor>,
    scope: &PermissionScope,
    message_store: &MessageStore,
) -> Result<(), String>
where
    MessageStore: EnboxMessageStore + Sync,
{
    let Some(scoped_protocol) = scope.protocol.as_deref() else {
        return Ok(());
    };
    match &message_to_read.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Write(write) => {
                if write.protocol.as_deref() == Some(scoped_protocol) {
                    return Ok(());
                }
                if write.protocol.as_deref() == Some(PERMISSIONS_PROTOCOL_URI) {
                    let permission_scope =
                        get_scope_from_permission_record(tenant, message_store, message_to_read)
                            .await?;
                    if permission_scope.protocol.as_deref() == Some(scoped_protocol) {
                        return Ok(());
                    }
                }
            }
            Records::Delete(delete) => {
                let newest_write =
                    fetch_newest_write(tenant, &delete.record_id, message_store).await?;
                return Box::pin(verify_messages_protocol_scope(
                    tenant,
                    &newest_write,
                    scope,
                    message_store,
                ))
                .await;
            }
            _ => {}
        },
        Descriptor::Protocols(protocols) => {
            if let crate::descriptors::Protocols::Configure(configure) = protocols.as_ref() {
                if configure.definition.protocol == scoped_protocol {
                    return Ok(());
                }
            }
        }
        _ => {}
    }
    Err("MessagesReadVerifyScopeFailed: record message failed scope authorization".to_string())
}

async fn get_scope_from_permission_record<MessageStore>(
    tenant: &str,
    message_store: &MessageStore,
    incoming_message: &Message<Descriptor>,
) -> Result<PermissionScope, String>
where
    MessageStore: EnboxMessageStore + Sync,
{
    let descriptor = records_write_descriptor(incoming_message)?;
    if descriptor.protocol.as_deref() != Some(PERMISSIONS_PROTOCOL_URI) {
        return Err(format!(
            "PermissionsProtocolGetScopeInvalidProtocol: Unexpected protocol for permission record: {:?}",
            descriptor.protocol
        ));
    }
    match descriptor.protocol_path.as_deref() {
        Some(PERMISSIONS_REVOCATION_PATH) => {
            let parent_id = descriptor.parent_id.as_deref().ok_or_else(|| {
                "PermissionsProtocolGetScopeInvalidRevocation: revocation parentId is required"
                    .to_string()
            })?;
            fetch_grant(tenant, message_store, parent_id)
                .await
                .map(|grant| grant.scope)
        }
        Some(PERMISSIONS_GRANT_PATH) => {
            let grantor = message_author(incoming_message).ok_or_else(|| {
                "PermissionGrantParseMissingAuthorization: unable to extract grantor".to_string()
            })?;
            parse_permission_grant(incoming_message, &grantor).map(|grant| grant.scope)
        }
        _ => {
            let data: PermissionRequestData =
                serde_json::from_slice(&permission_record_data_bytes(incoming_message)?)
                    .map_err(|err| format!("PermissionRequestParseMissingScope: {err}"))?;
            Ok(data.scope)
        }
    }
}

fn validate_scope_and_tags(
    scope: &PermissionScope,
    descriptor: &RecordsWriteDescriptor,
) -> Result<(), String> {
    if let Some(protocol) = scope.protocol.as_deref() {
        validate_permission_protocol_tag(descriptor, protocol)?;
    }
    if scope.interface == RECORDS_INTERFACE {
        if scope.protocol.is_none() {
            return Err("PermissionsProtocolValidateScopeMissingProtocol: Permission grants for Records must have a scope with a `protocol` property".to_string());
        }
        if scope.context_id.is_some() && scope.protocol_path.is_some() {
            return Err("PermissionsProtocolValidateScopeContextIdProhibitedProperties: Permission grants cannot have both `contextId` and `protocolPath` present".to_string());
        }
    }
    Ok(())
}

fn validate_permission_protocol_tag(
    descriptor: &RecordsWriteDescriptor,
    scoped_protocol: &str,
) -> Result<(), String> {
    let tagged_protocol = descriptor
        .tags
        .as_ref()
        .and_then(|tags| tags.get("protocol"))
        .and_then(index_value_as_str)
        .ok_or_else(|| {
            "PermissionsProtocolValidateScopeMissingProtocolTag: Permission grants must have a `tags` property that contains a protocol tag".to_string()
        })?;
    if tagged_protocol != scoped_protocol {
        return Err(format!(
            "PermissionsProtocolValidateScopeProtocolMismatch: Permission grants must have a scope with a protocol that matches the tagged protocol: {tagged_protocol}"
        ));
    }
    Ok(())
}

fn parse_permission_grant(
    message: &Message<Descriptor>,
    grantor: &str,
) -> Result<PermissionGrant, String> {
    let descriptor = records_write_descriptor(message)?;
    if descriptor.protocol.as_deref() != Some(PERMISSIONS_PROTOCOL_URI)
        || descriptor.protocol_path.as_deref() != Some(PERMISSIONS_GRANT_PATH)
    {
        return Err("GrantAuthorizationGrantMissing: permission grant must be a PermissionsProtocol grant RecordsWrite".to_string());
    }
    let data: PermissionGrantData = serde_json::from_slice(&permission_record_data_bytes(message)?)
        .map_err(|err| format!("PermissionGrantParseMissingScope: {err}"))?;
    let id = record_id(message)
        .ok_or_else(|| "PermissionGrantParseMissingRecordId: recordId is required".to_string())?;
    let grantee = descriptor
        .recipient
        .clone()
        .ok_or_else(|| "PermissionGrantParseMissingRecipient: recipient is required".to_string())?;
    Ok(PermissionGrant {
        id,
        grantor: grantor.to_string(),
        grantee,
        date_granted: descriptor.date_created,
        date_expires: data.date_expires,
        delegated: data.delegated,
        scope: data.scope,
        conditions: data.conditions,
    })
}

fn permission_record_data_bytes(message: &Message<Descriptor>) -> Result<Vec<u8>, String> {
    let fields = write_fields(message)?;
    let encoded_data = fields.encoded_data.as_deref().ok_or_else(|| {
        "PermissionsProtocolValidateSchemaMissingEncodedData: encodedData is required".to_string()
    })?;
    URL_SAFE_NO_PAD
        .decode(encoded_data)
        .map_err(|err| format!("PermissionsProtocolValidateSchemaInvalidEncodedData: {err}"))
}

fn records_write_descriptor(
    message: &Message<Descriptor>,
) -> Result<&RecordsWriteDescriptor, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Write(descriptor) => Ok(descriptor),
            _ => Err("expected RecordsWrite message".to_string()),
        },
        _ => Err("expected RecordsWrite message".to_string()),
    }
}

fn protocols_configure_descriptor(
    message: &Message<Descriptor>,
) -> Result<&ConfigureDescriptor, String> {
    match &message.descriptor {
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            crate::descriptors::Protocols::Configure(descriptor) => Ok(descriptor),
            _ => Err("expected ProtocolsConfigure message".to_string()),
        },
        _ => Err("expected ProtocolsConfigure message".to_string()),
    }
}

fn protocols_query_descriptor(
    message: &Message<Descriptor>,
) -> Result<&ProtocolQueryDescriptor, String> {
    match &message.descriptor {
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            crate::descriptors::Protocols::Query(descriptor) => Ok(descriptor),
            _ => Err("expected ProtocolsQuery message".to_string()),
        },
        _ => Err("expected ProtocolsQuery message".to_string()),
    }
}

fn write_fields(message: &Message<Descriptor>) -> Result<&WriteFields, String> {
    match &message.fields {
        Fields::Write(fields) => Ok(fields),
        Fields::InitialWriteField(fields) => Ok(&fields.write_fields),
        _ => Err("RecordsWriteFieldsExpected: write fields are required".to_string()),
    }
}

fn record_id(message: &Message<Descriptor>) -> Option<String> {
    write_fields(message).ok()?.record_id.clone()
}

fn context_id(message: &Message<Descriptor>) -> Option<String> {
    write_fields(message).ok()?.context_id.clone()
}

async fn fetch_newest_write<MessageStore>(
    tenant: &str,
    record_id: &str,
    message_store: &MessageStore,
) -> Result<Message<Descriptor>, String>
where
    MessageStore: EnboxMessageStore + Sync,
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
        .await
        .map_err(|err| err.to_string())?;
    result
        .messages
        .into_iter()
        .next()
        .ok_or_else(|| "RecordsWriteGetNewestWriteRecordNotFound: record not found".to_string())
}

fn message_timestamp(
    message: &Message<Descriptor>,
) -> Result<chrono::DateTime<chrono::Utc>, String> {
    match &message.descriptor {
        Descriptor::Records(records) => match records.as_ref() {
            Records::Read(descriptor) => Ok(descriptor.message_timestamp),
            Records::Count(descriptor) => Ok(descriptor.message_timestamp),
            Records::Query(descriptor) => Ok(descriptor.message_timestamp),
            Records::Write(descriptor) => Ok(descriptor.message_timestamp),
            Records::Delete(descriptor) => Ok(descriptor.message_timestamp),
            Records::Subscribe(descriptor) => Ok(descriptor.message_timestamp),
        },
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            crate::descriptors::Protocols::Configure(descriptor) => {
                Ok(descriptor.message_timestamp)
            }
            crate::descriptors::Protocols::Query(descriptor) => Ok(descriptor.message_timestamp),
        },
        Descriptor::Messages(messages) => match messages.as_ref() {
            crate::descriptors::Messages::Read(descriptor) => Ok(descriptor.message_timestamp),
            crate::descriptors::Messages::Query(descriptor) => Ok(descriptor.message_timestamp),
            crate::descriptors::Messages::Subscribe(descriptor) => Ok(descriptor.message_timestamp),
            crate::descriptors::Messages::Sync(descriptor) => Ok(descriptor.message_timestamp),
        },
    }
}

fn message_interface_and_method(message: &Message<Descriptor>) -> Result<(String, String), String> {
    match &message.descriptor {
        Descriptor::Records(records) => {
            Ok((RECORDS_INTERFACE.to_string(), records.method().to_string()))
        }
        Descriptor::Protocols(protocols) => Ok((
            PROTOCOLS_INTERFACE.to_string(),
            protocols.method().to_string(),
        )),
        Descriptor::Messages(messages) => Ok((
            MESSAGES_INTERFACE.to_string(),
            messages.method().to_string(),
        )),
    }
}

fn message_cid(message: &Message<Descriptor>) -> Result<String, String> {
    serde_json::to_value(message)
        .map_err(|err| err.to_string())
        .and_then(|value| generate_cid_from_json(&value).map_err(|err| err.to_string()))
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

#[allow(dead_code)]
fn range_string_filter(lower: Bound<Value>, upper: Bound<Value>) -> Filter<Value> {
    Filter::Range(RangeFilter::Numeric(lower, upper))
}

trait DescriptorMethod {
    fn method(&self) -> &'static str;
}

impl DescriptorMethod for Records {
    fn method(&self) -> &'static str {
        match self {
            Records::Read(_) => "Read",
            Records::Count(_) => "Count",
            Records::Query(_) => "Query",
            Records::Write(_) => "Write",
            Records::Delete(_) => "Delete",
            Records::Subscribe(_) => "Subscribe",
        }
    }
}

impl DescriptorMethod for crate::descriptors::Protocols {
    fn method(&self) -> &'static str {
        match self {
            crate::descriptors::Protocols::Configure(_) => "Configure",
            crate::descriptors::Protocols::Query(_) => "Query",
        }
    }
}

impl DescriptorMethod for crate::descriptors::Messages {
    fn method(&self) -> &'static str {
        match self {
            crate::descriptors::Messages::Read(_) => "Read",
            crate::descriptors::Messages::Query(_) => "Query",
            crate::descriptors::Messages::Subscribe(_) => "Subscribe",
            crate::descriptors::Messages::Sync(_) => "Sync",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Authorization;
    use crate::descriptors::{Messages, MessagesSubscribeDescriptor};
    use crate::errors::MessageStoreError;
    use crate::filters::message_filters::Messages as MessagesFilter;
    use crate::stores::EnboxMessageQueryResult;

    #[tokio::test]
    async fn messages_read_grant_authorizes_messages_subscribe() {
        let grant = PermissionGrant {
            id: "grant-1".to_string(),
            grantor: "did:example:alice".to_string(),
            grantee: "did:example:bob".to_string(),
            date_granted: parse_time("2025-01-01T00:00:00.000000Z"),
            date_expires: parse_time("2025-02-01T00:00:00.000000Z"),
            delegated: None,
            scope: PermissionScope {
                interface: "Messages".to_string(),
                method: "Read".to_string(),
                protocol: Some("http://example.com/notes".to_string()),
                context_id: None,
                protocol_path: None,
            },
            conditions: None,
        };
        let message = Message {
            descriptor: Descriptor::Messages(Box::new(Messages::Subscribe(
                MessagesSubscribeDescriptor {
                    message_timestamp: parse_time("2025-01-01T00:10:00.000000Z"),
                    filters: vec![MessagesFilter {
                        protocol: Some("http://example.com/notes".to_string()),
                        ..Default::default()
                    }],
                    permission_grant_id: Some("grant-1".to_string()),
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

    impl EnboxMessageStore for NoopMessageStore {
        async fn open(&mut self) -> Result<(), MessageStoreError> {
            Ok(())
        }

        async fn close(&mut self) {}

        async fn put(
            &self,
            _tenant: &str,
            _message: Message<Descriptor>,
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
        ) -> Result<EnboxMessageQueryResult, MessageStoreError> {
            Ok(EnboxMessageQueryResult {
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
