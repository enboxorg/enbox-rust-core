use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Bound;
use std::pin::Pin;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::SecondsFormat;
use serde_json::Value as JsonValue;

use crate::auth::{GeneralJws, GeneralJwsPublicKeyResolver};
use crate::cid::generate_cid_from_json;
use crate::descriptors::{ConfigureDescriptor, Descriptor, Protocols};
use crate::dwn::{DwnReply, MethodHandler, MethodHandlerRequest};
use crate::filters::{Filter, FilterKey, Filters, RangeFilter};
use crate::interfaces::messages::protocols::{self as protocol_types, Definition, RuleSet};
use crate::interfaces::replies::Status;
use crate::stores::{EnboxMessageStore, EnboxStateIndex, KeyValues};
use crate::{Message, MessageSort, Pagination, SortDirection, Value};

const PROTOCOLS_INTERFACE: &str = "Protocols";
const CONFIGURE_METHOD: &str = "Configure";

#[derive(Clone)]
pub struct ProtocolsConfigureHandler<MessageStore, StateIndex> {
    message_store: MessageStore,
    state_index: StateIndex,
    public_key_resolver: Option<Arc<dyn GeneralJwsPublicKeyResolver + Send + Sync>>,
}

#[derive(Clone)]
pub struct ProtocolsQueryHandler<MessageStore> {
    message_store: MessageStore,
    public_key_resolver: Option<Arc<dyn GeneralJwsPublicKeyResolver + Send + Sync>>,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolDefinitionLookupError {
    #[error("ProtocolAuthorizationProtocolNotFound: unable to find protocol definition for {0}")]
    NotFound(String),
    #[error("{0}")]
    Store(String),
    #[error("{0}")]
    InvalidMessage(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthorizationValidationError {
    BadRequest(String),
    Unauthorized(String),
}

impl<MessageStore, StateIndex> ProtocolsConfigureHandler<MessageStore, StateIndex> {
    pub fn new(message_store: MessageStore, state_index: StateIndex) -> Self {
        Self {
            message_store,
            state_index,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        state_index: StateIndex,
        public_key_resolver: impl GeneralJwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            state_index,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

impl<MessageStore> ProtocolsQueryHandler<MessageStore> {
    pub fn new(message_store: MessageStore) -> Self {
        Self {
            message_store,
            public_key_resolver: None,
        }
    }

    pub fn with_public_key_resolver(
        message_store: MessageStore,
        public_key_resolver: impl GeneralJwsPublicKeyResolver + Send + Sync + 'static,
    ) -> Self {
        Self {
            message_store,
            public_key_resolver: Some(Arc::new(public_key_resolver)),
        }
    }
}

pub async fn fetch_protocol_definition<MessageStore>(
    tenant: &str,
    protocol_uri: &str,
    message_store: &MessageStore,
    message_timestamp: Option<&str>,
) -> Result<Definition, ProtocolDefinitionLookupError>
where
    MessageStore: EnboxMessageStore + Sync,
{
    let filters = protocol_definition_lookup_filters(protocol_uri, message_timestamp);
    let result = message_store
        .query(
            tenant,
            filters,
            Some(MessageSort::Timestamp(SortDirection::Descending)),
            Some(Pagination::with_limit(1)),
        )
        .await
        .map_err(|err| ProtocolDefinitionLookupError::Store(err.to_string()))?;

    let Some(message) = result.messages.first() else {
        return Err(ProtocolDefinitionLookupError::NotFound(
            protocol_uri.to_string(),
        ));
    };

    protocols_configure_descriptor(message)
        .map(|descriptor| descriptor.definition.clone())
        .map_err(ProtocolDefinitionLookupError::InvalidMessage)
}

impl<MessageStore, StateIndex> MethodHandler for ProtocolsConfigureHandler<MessageStore, StateIndex>
where
    MessageStore: EnboxMessageStore + Clone + Send + Sync + 'static,
    StateIndex: EnboxStateIndex + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_configure(request.tenant, request.message).await })
    }
}

impl<MessageStore> MethodHandler for ProtocolsQueryHandler<MessageStore>
where
    MessageStore: EnboxMessageStore + Clone + Send + Sync + 'static,
{
    fn handle<'a>(
        &'a self,
        request: MethodHandlerRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move { self.handle_query(request.tenant, request.message).await })
    }
}

impl<MessageStore, StateIndex> ProtocolsConfigureHandler<MessageStore, StateIndex>
where
    MessageStore: EnboxMessageStore + Clone + Send + Sync + 'static,
    StateIndex: EnboxStateIndex + Clone + Send + Sync + 'static,
{
    async fn handle_configure(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match protocols_configure_descriptor(&message) {
            Ok(descriptor) => descriptor,
            Err(detail) => return DwnReply::bad_request(detail),
        };

        let author = match validate_authorization_signature(
            raw_message,
            self.public_key_resolver.as_deref(),
        ) {
            Ok(Some(author)) if author == tenant => author,
            Ok(Some(_)) | Ok(None) => {
                return DwnReply::unauthorized(
                    "ProtocolsConfigureAuthorizationFailed: message failed authorization",
                )
            }
            Err(AuthorizationValidationError::BadRequest(detail)) => {
                return DwnReply::bad_request(detail)
            }
            Err(AuthorizationValidationError::Unauthorized(detail)) => {
                return DwnReply::unauthorized(detail)
            }
        };

        if let Err(err) = protocol_types::validate_definition(&descriptor.definition) {
            return DwnReply::bad_request(err.to_string());
        }

        if let Err(detail) = self
            .validate_composition_dependencies(tenant, &descriptor.definition)
            .await
        {
            return DwnReply::bad_request(detail);
        }

        let incoming_cid = match message_cid(&message) {
            Ok(cid) => cid,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let existing_messages = match self
            .message_store
            .query(
                tenant,
                protocol_configure_filters(&descriptor.definition.protocol, false),
                Some(MessageSort::Timestamp(SortDirection::Ascending)),
                None,
            )
            .await
        {
            Ok(result) => result.messages,
            Err(err) => return store_error_reply(err.to_string()),
        };

        let mut comparable = Vec::new();
        for existing in &existing_messages {
            let cid = match message_cid(existing) {
                Ok(cid) => cid,
                Err(detail) => return DwnReply::bad_request(detail),
            };
            if cid == incoming_cid {
                return DwnReply::new(409, "Conflict");
            }
            comparable.push((cid, existing));
        }

        let incoming_is_latest = comparable.iter().all(|(cid, existing)| {
            compare_configure_messages(&incoming_cid, &message, cid, existing) == Ordering::Greater
        });
        let latest_existing_cid = comparable
            .iter()
            .max_by(|(left_cid, left), (right_cid, right)| {
                compare_configure_messages(left_cid, left, right_cid, right)
            })
            .map(|(cid, _)| cid.clone());

        let indexes = configure_indexes(descriptor, Some(&author), incoming_is_latest);
        if let Err(err) = self
            .message_store
            .put(tenant, message.clone(), indexes.clone())
            .await
        {
            return store_error_reply(err.to_string());
        }
        if let Err(err) = self
            .state_index
            .insert(tenant, &incoming_cid, indexes)
            .await
        {
            return store_error_reply(err.to_string());
        }

        for existing in existing_messages {
            let existing_cid = match message_cid(&existing) {
                Ok(cid) => cid,
                Err(detail) => return DwnReply::bad_request(detail),
            };
            let existing_descriptor = match protocols_configure_descriptor(&existing) {
                Ok(descriptor) => descriptor,
                Err(detail) => return DwnReply::bad_request(detail),
            };
            let existing_is_latest = !incoming_is_latest
                && latest_existing_cid
                    .as_ref()
                    .is_some_and(|latest| latest == &existing_cid);
            let existing_author = extract_author(&existing);
            let updated_indexes = configure_indexes(
                existing_descriptor,
                existing_author.as_deref(),
                existing_is_latest,
            );
            if let Err(err) = self.message_store.delete(tenant, &existing_cid).await {
                return store_error_reply(err.to_string());
            }
            if let Err(err) = self
                .message_store
                .put(tenant, existing, updated_indexes)
                .await
            {
                return store_error_reply(err.to_string());
            }
        }

        DwnReply::new(202, "Accepted")
    }

    async fn validate_composition_dependencies(
        &self,
        tenant: &str,
        definition: &Definition,
    ) -> Result<(), String> {
        let Some(uses) = &definition.uses else {
            return Ok(());
        };

        let mut referenced = BTreeMap::new();
        for (alias, protocol_uri) in uses {
            let Some(definition) = self
                .fetch_installed_protocol_definition(tenant, protocol_uri)
                .await?
            else {
                return Err(format!(
                    "ProtocolsConfigureComposedProtocolNotInstalled: composed protocol '{protocol_uri}' (alias '{alias}') is not installed for tenant '{tenant}'."
                ));
            };
            referenced.insert(alias.clone(), definition);
        }

        validate_refs_and_roles_recursively(&definition.structure, "", &referenced)
    }

    async fn fetch_installed_protocol_definition(
        &self,
        tenant: &str,
        protocol_uri: &str,
    ) -> Result<Option<Definition>, String> {
        match fetch_protocol_definition(tenant, protocol_uri, &self.message_store, None).await {
            Ok(definition) => Ok(Some(definition)),
            Err(ProtocolDefinitionLookupError::NotFound(_)) => Ok(None),
            Err(err) => Err(err.to_string()),
        }
    }
}

impl<MessageStore> ProtocolsQueryHandler<MessageStore>
where
    MessageStore: EnboxMessageStore + Clone + Send + Sync + 'static,
{
    async fn handle_query(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match protocols_query_descriptor(&message) {
            Ok(descriptor) => descriptor,
            Err(detail) => return DwnReply::bad_request(detail),
        };

        let include_private = if raw_message.get("authorization").is_some() {
            match validate_authorization_signature(raw_message, self.public_key_resolver.as_deref())
            {
                Ok(Some(author)) => author == tenant,
                Ok(None) => false,
                Err(AuthorizationValidationError::BadRequest(detail)) => {
                    return DwnReply::bad_request(detail)
                }
                Err(AuthorizationValidationError::Unauthorized(detail)) => {
                    return DwnReply::unauthorized(detail)
                }
            }
        } else {
            false
        };

        let mut filters = BTreeMap::new();
        filters.insert(
            FilterKey::Index("interface".to_string()),
            Filter::Equal(Value::String(PROTOCOLS_INTERFACE.to_string())),
        );
        filters.insert(
            FilterKey::Index("method".to_string()),
            Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
        );
        filters.insert(
            FilterKey::Index("isLatestBaseState".to_string()),
            Filter::Equal(Value::Bool(true)),
        );
        if !include_private {
            filters.insert(
                FilterKey::Index("published".to_string()),
                Filter::Equal(Value::Bool(true)),
            );
        }
        if let Some(filter) = &descriptor.filter {
            if let Some(protocol) = &filter.protocol {
                filters.insert(
                    FilterKey::Index("protocol".to_string()),
                    Filter::Equal(Value::String(protocol.clone())),
                );
            }
        }

        let result = match self
            .message_store
            .query(
                tenant,
                Filters::from(filters),
                Some(MessageSort::Timestamp(SortDirection::Ascending)),
                None,
            )
            .await
        {
            Ok(result) => result,
            Err(err) => return store_error_reply(err.to_string()),
        };

        let entries = match serde_json::to_value(result.messages) {
            Ok(entries) => entries,
            Err(err) => return DwnReply::bad_request(err.to_string()),
        };
        DwnReply::new(200, "OK").with_body("entries", entries)
    }
}

fn parse_message(raw_message: &JsonValue) -> Result<Message<Descriptor>, String> {
    serde_json::from_value(raw_message.clone()).map_err(|err| err.to_string())
}

fn protocols_configure_descriptor(
    message: &Message<Descriptor>,
) -> Result<&ConfigureDescriptor, String> {
    match &message.descriptor {
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            Protocols::Configure(descriptor) => Ok(descriptor),
            _ => Err("expected ProtocolsConfigure message".to_string()),
        },
        _ => Err("expected ProtocolsConfigure message".to_string()),
    }
}

fn protocols_query_descriptor(
    message: &Message<Descriptor>,
) -> Result<&crate::descriptors::ProtocolQueryDescriptor, String> {
    match &message.descriptor {
        Descriptor::Protocols(protocols) => match protocols.as_ref() {
            Protocols::Query(descriptor) => Ok(descriptor),
            _ => Err("expected ProtocolsQuery message".to_string()),
        },
        _ => Err("expected ProtocolsQuery message".to_string()),
    }
}

fn message_cid(message: &Message<Descriptor>) -> Result<String, String> {
    message
        .cid()
        .map(|cid| cid.to_string())
        .map_err(|err| err.to_string())
}

fn protocol_configure_filters(protocol: &str, latest_only: bool) -> Filters {
    let mut filters = BTreeMap::new();
    filters.insert(
        FilterKey::Index("interface".to_string()),
        Filter::Equal(Value::String(PROTOCOLS_INTERFACE.to_string())),
    );
    filters.insert(
        FilterKey::Index("method".to_string()),
        Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
    );
    filters.insert(
        FilterKey::Index("protocol".to_string()),
        Filter::Equal(Value::String(protocol.to_string())),
    );
    if latest_only {
        filters.insert(
            FilterKey::Index("isLatestBaseState".to_string()),
            Filter::Equal(Value::Bool(true)),
        );
    }
    Filters::from(filters)
}

fn protocol_definition_lookup_filters(protocol: &str, message_timestamp: Option<&str>) -> Filters {
    let mut filters = BTreeMap::new();
    filters.insert(
        FilterKey::Index("interface".to_string()),
        Filter::Equal(Value::String(PROTOCOLS_INTERFACE.to_string())),
    );
    filters.insert(
        FilterKey::Index("method".to_string()),
        Filter::Equal(Value::String(CONFIGURE_METHOD.to_string())),
    );
    filters.insert(
        FilterKey::Index("protocol".to_string()),
        Filter::Equal(Value::String(protocol.to_string())),
    );

    if let Some(timestamp) = message_timestamp {
        filters.insert(
            FilterKey::Index("messageTimestamp".to_string()),
            Filter::Range(RangeFilter::Numeric(
                Bound::Unbounded,
                Bound::Included(Value::String(timestamp.to_string())),
            )),
        );
    } else {
        filters.insert(
            FilterKey::Index("isLatestBaseState".to_string()),
            Filter::Equal(Value::Bool(true)),
        );
    }

    Filters::from(filters)
}

fn configure_indexes(
    descriptor: &ConfigureDescriptor,
    author: Option<&str>,
    is_latest_base_state: bool,
) -> KeyValues {
    let mut indexes = BTreeMap::new();
    indexes.insert(
        "interface".to_string(),
        Value::String(PROTOCOLS_INTERFACE.to_string()),
    );
    indexes.insert(
        "method".to_string(),
        Value::String(CONFIGURE_METHOD.to_string()),
    );
    indexes.insert(
        "messageTimestamp".to_string(),
        Value::String(
            descriptor
                .message_timestamp
                .to_rfc3339_opts(SecondsFormat::Micros, true),
        ),
    );
    indexes.insert(
        "protocol".to_string(),
        Value::String(descriptor.definition.protocol.clone()),
    );
    indexes.insert(
        "published".to_string(),
        Value::Bool(descriptor.definition.published),
    );
    indexes.insert(
        "isLatestBaseState".to_string(),
        Value::Bool(is_latest_base_state),
    );
    if let Some(author) = author {
        indexes.insert("author".to_string(), Value::String(author.to_string()));
    }
    if let Some(permission_grant_id) = &descriptor.permission_grant_id {
        indexes.insert(
            "permissionGrantId".to_string(),
            Value::String(permission_grant_id.clone()),
        );
    }
    indexes
}

fn compare_configure_messages(
    left_cid: &str,
    left: &Message<Descriptor>,
    right_cid: &str,
    right: &Message<Descriptor>,
) -> Ordering {
    let left_timestamp = protocols_configure_descriptor(left)
        .map(|descriptor| descriptor.message_timestamp)
        .ok();
    let right_timestamp = protocols_configure_descriptor(right)
        .map(|descriptor| descriptor.message_timestamp)
        .ok();
    left_timestamp
        .cmp(&right_timestamp)
        .then_with(|| left_cid.cmp(right_cid))
}

fn validate_authorization_signature(
    raw_message: &JsonValue,
    public_key_resolver: Option<&(dyn GeneralJwsPublicKeyResolver + Send + Sync)>,
) -> Result<Option<String>, AuthorizationValidationError> {
    let authorization = raw_message.get("authorization").ok_or_else(|| {
        AuthorizationValidationError::Unauthorized(
            "AuthenticateJwsMissing: authorization signature is required".to_string(),
        )
    })?;
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

    let payload = URL_SAFE_NO_PAD.decode(&jws.payload).map_err(|err| {
        AuthorizationValidationError::BadRequest(format!(
            "AuthenticationInvalidSignaturePayload: {err}"
        ))
    })?;
    let payload: JsonValue = serde_json::from_slice(&payload).map_err(|err| {
        AuthorizationValidationError::BadRequest(format!(
            "AuthenticationInvalidSignaturePayload: {err}"
        ))
    })?;
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
    let _unverified_author = signer_did_from_jws(&jws)?;

    public_key_resolver
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
        .transpose()
}

fn extract_author(message: &Message<Descriptor>) -> Option<String> {
    let raw_message = serde_json::to_value(message).ok()?;
    let signature = raw_message.get("authorization")?.get("signature")?;
    let jws: GeneralJws = serde_json::from_value(signature.clone()).ok()?;
    signer_did_from_jws(&jws).ok()
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

fn validate_refs_and_roles_recursively(
    rule_set: &BTreeMap<String, RuleSet>,
    protocol_path: &str,
    referenced: &BTreeMap<String, Definition>,
) -> Result<(), String> {
    for (key, child_rule_set) in rule_set {
        let child_protocol_path = if protocol_path.is_empty() {
            key.clone()
        } else {
            format!("{protocol_path}/{key}")
        };

        if let Some(reference) = &child_rule_set.reference {
            if let Some(parsed) = protocol_types::parse_cross_protocol_ref(reference) {
                let definition = referenced.get(parsed.alias).ok_or_else(|| {
                    format!(
                        "ProtocolsConfigureInvalidRefAlias: '$ref' alias '{}' at protocol path '{}' was not found.",
                        parsed.alias, child_protocol_path
                    )
                })?;
                validate_ref_target(
                    &definition.protocol,
                    &definition.structure,
                    parsed.protocol_path,
                    &child_protocol_path,
                )?;
            }
        }

        for action in &child_rule_set.actions {
            match action {
                protocol_types::Action::Role(action) => {
                    if let Some(parsed) = protocol_types::parse_cross_protocol_ref(&action.role) {
                        let definition = referenced.get(parsed.alias).ok_or_else(|| {
                            format!(
                                "ProtocolsConfigureInvalidCrossProtocolRole: alias '{}' at protocol path '{}' was not found.",
                                parsed.alias, child_protocol_path
                            )
                        })?;
                        let Some(role_rule_set) = protocol_types::get_rule_set_at_path(
                            parsed.protocol_path,
                            &definition.structure,
                        ) else {
                            return Err(format!(
                                "ProtocolsConfigureInvalidCrossProtocolRole: role '{}' at protocol path '{}' does not exist in protocol '{}'.",
                                action.role, child_protocol_path, definition.protocol
                            ));
                        };
                        if role_rule_set.role != Some(true) {
                            return Err(format!(
                                "ProtocolsConfigureInvalidCrossProtocolRole: role '{}' at protocol path '{}' does not point to a valid role in protocol '{}'.",
                                action.role, child_protocol_path, definition.protocol
                            ));
                        }
                    }
                }
                protocol_types::Action::Who(action) => {
                    if let Some(of) = &action.of {
                        if let Some(parsed) = protocol_types::parse_cross_protocol_ref(of) {
                            let definition = referenced.get(parsed.alias).ok_or_else(|| {
                                format!(
                                    "ProtocolsConfigureInvalidCrossProtocolOf: alias '{}' at protocol path '{}' was not found.",
                                    parsed.alias, child_protocol_path
                                )
                            })?;
                            if protocol_types::get_rule_set_at_path(
                                parsed.protocol_path,
                                &definition.structure,
                            )
                            .is_none()
                            {
                                return Err(format!(
                                    "ProtocolsConfigureInvalidCrossProtocolOf: reference '{}' at protocol path '{}' does not point to a valid type path in protocol '{}'.",
                                    of, child_protocol_path, definition.protocol
                                ));
                            }
                        }
                    }
                }
            }
        }

        validate_refs_and_roles_recursively(
            &child_rule_set.rules,
            &child_protocol_path,
            referenced,
        )?;
    }

    Ok(())
}

fn validate_ref_target(
    protocol: &str,
    structure: &BTreeMap<String, RuleSet>,
    target_path: &str,
    source_path: &str,
) -> Result<(), String> {
    let mut current = structure;
    let mut traversed = Vec::new();
    for segment in target_path.split('/') {
        traversed.push(segment);
        let Some(node) = current.get(segment) else {
            return Err(format!(
                "ProtocolsConfigureInvalidRefProtocolPath: '$ref' at protocol path '{source_path}' references type path '{target_path}' which does not exist in protocol '{protocol}'."
            ));
        };
        if node.reference.is_some() {
            return Err(format!(
                "ProtocolsConfigureInvalidRefTargetThroughRef: '$ref' at protocol path '{source_path}' references type path '{target_path}' in protocol '{protocol}', but node '{}' is itself a '$ref'.",
                traversed.join("/")
            ));
        }
        current = &node.rules;
    }
    Ok(())
}

fn store_error_reply(detail: String) -> DwnReply {
    DwnReply {
        status: Status { code: 500, detail },
        body: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, RwLock};

    use crate::auth::{
        GeneralJws, GeneralJwsPrivateJwk, GeneralJwsPublicJwk, PrivateJwkSigner,
        StaticPublicKeyResolver,
    };
    use crate::descriptors::{ConfigureDescriptor, Descriptor, ProtocolQueryDescriptor, Protocols};
    use crate::dwn::{Dwn, MessageKind};
    use crate::fields::WriteFields;
    use crate::interfaces::messages::protocols::{
        self as protocol_types, Action, ActionRole, ActionWho, Can, Definition, Type, Who,
    };
    use crate::state_index::MemoryStateIndex;
    use crate::stores::{EnboxMessageQueryResult, EnboxMessageStore};
    use crate::{Fields, Message, Pagination};

    use super::*;

    const QUERY_METHOD_FOR_TESTS: &str = "Query";

    #[tokio::test]
    async fn protocols_configure_stores_latest_base_state() {
        let mut message_store = TestMessageStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let handler = ProtocolsConfigureHandler::with_public_key_resolver(
            message_store.clone(),
            state_index,
            test_resolver(),
        );
        let older = signed_configure_message(
            "http://example.com/protocol",
            true,
            "2025-01-01T00:00:00.000000Z",
        );
        let newer = signed_configure_message(
            "http://example.com/protocol",
            false,
            "2025-01-01T00:00:01.000000Z",
        );

        assert_eq!(
            handler
                .handle_configure("did:example:alice", &older)
                .await
                .status
                .code,
            202
        );
        assert_eq!(
            handler
                .handle_configure("did:example:alice", &newer)
                .await
                .status
                .code,
            202
        );
        assert_eq!(
            handler
                .handle_configure("did:example:alice", &newer)
                .await
                .status
                .code,
            409
        );

        let latest = message_store
            .query(
                "did:example:alice",
                protocol_configure_filters("http://example.com/protocol", true),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(latest.messages.len(), 1);
        assert!(
            !protocols_configure_descriptor(&latest.messages[0])
                .unwrap()
                .definition
                .published
        );
    }

    #[tokio::test]
    async fn protocols_query_unsigned_returns_only_published_latest_configures() {
        let mut message_store = TestMessageStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let configure_handler = ProtocolsConfigureHandler::with_public_key_resolver(
            message_store.clone(),
            state_index,
            test_resolver(),
        );
        let query_handler = ProtocolsQueryHandler::new(message_store.clone());

        configure_handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_message(
                    "http://example.com/public",
                    true,
                    "2025-01-01T00:00:00.000000Z",
                ),
            )
            .await;
        configure_handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_message(
                    "http://example.com/private",
                    false,
                    "2025-01-01T00:00:01.000000Z",
                ),
            )
            .await;

        let reply = query_handler
            .handle_query("did:example:alice", &unsigned_query_message(None))
            .await;
        assert_eq!(reply.status.code, 200);
        let entries = reply.body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["descriptor"]["definition"]["protocol"].as_str(),
            Some("http://example.com/public")
        );
    }

    #[tokio::test]
    async fn protocols_query_signed_by_tenant_returns_private_configures() {
        let mut message_store = TestMessageStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let configure_handler = ProtocolsConfigureHandler::with_public_key_resolver(
            message_store.clone(),
            state_index,
            test_resolver(),
        );
        let query_handler =
            ProtocolsQueryHandler::with_public_key_resolver(message_store.clone(), test_resolver());

        configure_handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_message(
                    "http://example.com/private",
                    false,
                    "2025-01-01T00:00:00.000000Z",
                ),
            )
            .await;

        let reply = query_handler
            .handle_query(
                "did:example:alice",
                &signed_query_message(None, test_signer_with_key_id("did:example:alice#key1")),
            )
            .await;
        assert_eq!(reply.status.code, 200);
        let entries = reply.body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["descriptor"]["definition"]["published"].as_bool(),
            Some(false)
        );
    }

    #[tokio::test]
    async fn protocols_query_signed_by_non_tenant_falls_back_to_published_configures() {
        let mut message_store = TestMessageStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let configure_handler = ProtocolsConfigureHandler::with_public_key_resolver(
            message_store.clone(),
            state_index,
            test_resolver(),
        );
        let query_handler = ProtocolsQueryHandler::with_public_key_resolver(
            message_store.clone(),
            test_resolver_with_bob(),
        );

        configure_handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_message(
                    "http://example.com/public",
                    true,
                    "2025-01-01T00:00:00.000000Z",
                ),
            )
            .await;
        configure_handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_message(
                    "http://example.com/private",
                    false,
                    "2025-01-01T00:00:01.000000Z",
                ),
            )
            .await;

        let reply = query_handler
            .handle_query(
                "did:example:alice",
                &signed_query_message(None, test_signer_with_key_id("did:example:bob#key1")),
            )
            .await;
        assert_eq!(reply.status.code, 200);
        let entries = reply.body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["descriptor"]["definition"]["protocol"].as_str(),
            Some("http://example.com/public")
        );
    }

    #[tokio::test]
    async fn protocols_configure_rejects_tampered_descriptor_cid_as_bad_request() {
        let mut message_store = TestMessageStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let handler = ProtocolsConfigureHandler::with_public_key_resolver(
            message_store,
            state_index,
            test_resolver(),
        );
        let mut message = signed_configure_message(
            "http://example.com/original",
            true,
            "2025-01-01T00:00:00.000000Z",
        );
        message["descriptor"]["definition"]["protocol"] =
            JsonValue::String("http://example.com/tampered".to_string());

        let reply = handler
            .handle_configure("did:example:alice", &message)
            .await;
        assert_eq!(reply.status.code, 400);
    }

    #[tokio::test]
    async fn protocols_configure_rejects_non_tenant_signer() {
        let mut message_store = TestMessageStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let handler = ProtocolsConfigureHandler::with_public_key_resolver(
            message_store,
            state_index,
            test_resolver_with_bob(),
        );

        let reply = handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_message_with_signer(
                    "http://example.com/protocol",
                    true,
                    "2025-01-01T00:00:00.000000Z",
                    test_signer_with_key_id("did:example:bob#key1"),
                ),
            )
            .await;
        assert_eq!(reply.status.code, 401);
    }

    #[tokio::test]
    async fn fetch_protocol_definition_supports_latest_and_temporal_lookup() {
        let mut message_store = TestMessageStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let handler = ProtocolsConfigureHandler::with_public_key_resolver(
            message_store.clone(),
            state_index,
            test_resolver(),
        );

        handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_message(
                    "http://example.com/versioned",
                    true,
                    "2025-01-01T00:00:00.000000Z",
                ),
            )
            .await;
        handler
            .handle_configure(
                "did:example:alice",
                &signed_configure_message(
                    "http://example.com/versioned",
                    false,
                    "2025-01-01T00:10:00.000000Z",
                ),
            )
            .await;

        let historical = fetch_protocol_definition(
            "did:example:alice",
            "http://example.com/versioned",
            &message_store,
            Some("2025-01-01T00:05:00.000000Z"),
        )
        .await
        .unwrap();
        assert!(historical.published);

        let latest = fetch_protocol_definition(
            "did:example:alice",
            "http://example.com/versioned",
            &message_store,
            None,
        )
        .await
        .unwrap();
        assert!(!latest.published);
    }

    #[tokio::test]
    async fn protocols_configure_validates_composition_dependencies() {
        let mut message_store = TestMessageStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        state_index.open().await.unwrap();
        let handler = ProtocolsConfigureHandler::with_public_key_resolver(
            message_store,
            state_index,
            test_resolver(),
        );

        let missing_dependency = signed_configure_descriptor(composed_descriptor(
            "http://example.com/composed-missing",
            "threads:thread/participant",
        ));
        assert_eq!(
            handler
                .handle_configure("did:example:alice", &missing_dependency)
                .await
                .status
                .code,
            400
        );

        assert_eq!(
            handler
                .handle_configure(
                    "did:example:alice",
                    &signed_configure_descriptor(base_thread_descriptor()),
                )
                .await
                .status
                .code,
            202
        );
        assert_eq!(
            handler
                .handle_configure(
                    "did:example:alice",
                    &signed_configure_descriptor(composed_descriptor(
                        "http://example.com/composed",
                        "threads:thread/participant",
                    )),
                )
                .await
                .status
                .code,
            202
        );
        assert_eq!(
            handler
                .handle_configure(
                    "did:example:alice",
                    &signed_configure_descriptor(composed_descriptor(
                        "http://example.com/composed-invalid-role",
                        "threads:thread/missing",
                    )),
                )
                .await
                .status
                .code,
            400
        );
    }

    #[tokio::test]
    async fn protocol_handlers_integrate_with_dwn_dispatch() {
        let mut message_store = TestMessageStore::default();
        let mut state_index = MemoryStateIndex::default();
        message_store.open().await.unwrap();
        state_index.open().await.unwrap();

        let mut dwn = Dwn::default();
        dwn.register_handler(
            MessageKind::new(PROTOCOLS_INTERFACE, CONFIGURE_METHOD),
            ProtocolsConfigureHandler::with_public_key_resolver(
                message_store.clone(),
                state_index,
                test_resolver(),
            ),
        );
        dwn.register_handler(
            MessageKind::new(PROTOCOLS_INTERFACE, QUERY_METHOD_FOR_TESTS),
            ProtocolsQueryHandler::new(message_store),
        );

        let configure = signed_configure_message(
            "http://example.com/dispatch",
            true,
            "2025-01-01T00:00:00.000000Z",
        );
        let configure_reply = dwn.process_message("did:example:alice", configure).await;
        assert_eq!(configure_reply.status.code, 202);

        let query_reply = dwn
            .process_message("did:example:alice", unsigned_query_message(None))
            .await;
        assert_eq!(query_reply.status.code, 200);
        assert_eq!(query_reply.body["entries"].as_array().unwrap().len(), 1);
    }

    #[derive(Clone, Default)]
    struct TestMessageStore {
        rows: Arc<RwLock<Vec<TestMessageRow>>>,
    }

    #[derive(Clone)]
    struct TestMessageRow {
        tenant: String,
        cid: String,
        message: Message<Descriptor>,
        indexes: KeyValues,
    }

    impl EnboxMessageStore for TestMessageStore {
        async fn open(&mut self) -> Result<(), crate::errors::MessageStoreError> {
            Ok(())
        }

        async fn close(&mut self) {}

        fn put(
            &self,
            tenant: &str,
            message: Message<Descriptor>,
            indexes: KeyValues,
        ) -> impl Future<Output = Result<(), crate::errors::MessageStoreError>> + Send {
            let rows = self.rows.clone();
            let tenant = tenant.to_string();
            async move {
                let cid = message_cid(&message).map_err(test_store_error)?;
                rows.write().unwrap().push(TestMessageRow {
                    tenant,
                    cid,
                    message,
                    indexes,
                });
                Ok(())
            }
        }

        fn get(
            &self,
            tenant: &str,
            cid: &str,
        ) -> impl Future<
            Output = Result<Option<Message<Descriptor>>, crate::errors::MessageStoreError>,
        > + Send {
            let rows = self.rows.clone();
            let tenant = tenant.to_string();
            let cid = cid.to_string();
            async move {
                Ok(rows
                    .read()
                    .unwrap()
                    .iter()
                    .find(|row| row.tenant == tenant && row.cid == cid)
                    .map(|row| row.message.clone()))
            }
        }

        fn query(
            &self,
            tenant: &str,
            filters: Filters,
            sort: Option<MessageSort>,
            pagination: Option<Pagination>,
        ) -> impl Future<Output = Result<EnboxMessageQueryResult, crate::errors::MessageStoreError>> + Send
        {
            let rows = self.rows.clone();
            let tenant = tenant.to_string();
            async move {
                let mut rows = rows
                    .read()
                    .unwrap()
                    .iter()
                    .filter(|row| {
                        row.tenant == tenant && matches_filters(&row.indexes, filters.clone())
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if let Some(sort) = sort {
                    let (property, direction) = match sort {
                        MessageSort::DateCreated(direction) => ("dateCreated", direction),
                        MessageSort::DatePublished(direction) => ("datePublished", direction),
                        MessageSort::Timestamp(direction) => ("messageTimestamp", direction),
                    };
                    rows.sort_by(|left, right| {
                        let order = value_string(left.indexes.get(property))
                            .cmp(&value_string(right.indexes.get(property)));
                        match direction {
                            SortDirection::Ascending => order,
                            SortDirection::Descending => order.reverse(),
                        }
                    });
                }
                if let Some(limit) = pagination.and_then(|pagination| pagination.limit) {
                    rows.truncate(limit as usize);
                }
                Ok(EnboxMessageQueryResult {
                    messages: rows.into_iter().map(|row| row.message).collect(),
                    cursor: None,
                })
            }
        }

        async fn count(
            &self,
            tenant: &str,
            filters: Filters,
            sort: Option<MessageSort>,
        ) -> Result<u64, crate::errors::MessageStoreError> {
            Ok(self
                .query(tenant, filters, sort, None)
                .await?
                .messages
                .len() as u64)
        }

        fn delete(
            &self,
            tenant: &str,
            cid: &str,
        ) -> impl Future<Output = Result<(), crate::errors::MessageStoreError>> + Send {
            let rows = self.rows.clone();
            let tenant = tenant.to_string();
            let cid = cid.to_string();
            async move {
                rows.write()
                    .unwrap()
                    .retain(|row| row.tenant != tenant || row.cid != cid);
                Ok(())
            }
        }

        fn clear(
            &self,
        ) -> impl Future<Output = Result<(), crate::errors::MessageStoreError>> + Send {
            let rows = self.rows.clone();
            async move {
                rows.write().unwrap().clear();
                Ok(())
            }
        }
    }

    fn signed_configure_message(protocol: &str, published: bool, timestamp: &str) -> JsonValue {
        signed_configure_message_with_signer(protocol, published, timestamp, test_signer())
    }

    fn signed_configure_message_with_signer(
        protocol: &str,
        published: bool,
        timestamp: &str,
        signer: PrivateJwkSigner,
    ) -> JsonValue {
        signed_configure_descriptor_with_signer(
            configure_descriptor(protocol, published, timestamp),
            signer,
        )
    }

    fn signed_configure_descriptor(descriptor: ConfigureDescriptor) -> JsonValue {
        signed_configure_descriptor_with_signer(descriptor, test_signer())
    }

    fn signed_configure_descriptor_with_signer(
        descriptor: ConfigureDescriptor,
        signer: PrivateJwkSigner,
    ) -> JsonValue {
        let descriptor_json = serde_json::to_value(&descriptor).unwrap();
        let payload = serde_json::json!({
            "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
        });
        let signature =
            GeneralJws::create(serde_json::to_vec(&payload).unwrap().as_slice(), &[signer])
                .unwrap();
        serde_json::json!({
            "descriptor": descriptor_json,
            "authorization": { "signature": signature }
        })
    }

    fn signed_query_message(protocol: Option<&str>, signer: PrivateJwkSigner) -> JsonValue {
        let descriptor = query_descriptor(protocol);
        let descriptor_json = serde_json::to_value(&descriptor).unwrap();
        let payload = serde_json::json!({
            "descriptorCid": generate_cid_from_json(&descriptor_json).unwrap().to_string(),
        });
        let signature =
            GeneralJws::create(serde_json::to_vec(&payload).unwrap().as_slice(), &[signer])
                .unwrap();
        serde_json::json!({
            "descriptor": descriptor_json,
            "authorization": { "signature": signature }
        })
    }

    fn unsigned_query_message(protocol: Option<&str>) -> JsonValue {
        serde_json::json!({ "descriptor": query_descriptor(protocol) })
    }

    fn query_descriptor(protocol: Option<&str>) -> ProtocolQueryDescriptor {
        let filter = protocol.map(|protocol| serde_json::json!({ "protocol": protocol }));
        ProtocolQueryDescriptor {
            message_timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:10:00.000000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            filter: filter.map(|filter| serde_json::from_value(filter).unwrap()),
            permission_grant_id: None,
        }
    }

    fn configure_descriptor(
        protocol: &str,
        published: bool,
        timestamp: &str,
    ) -> ConfigureDescriptor {
        ConfigureDescriptor {
            message_timestamp: chrono::DateTime::parse_from_rfc3339(timestamp)
                .unwrap()
                .with_timezone(&chrono::Utc),
            definition: Definition {
                protocol: protocol.to_string(),
                published,
                uses: None,
                types: BTreeMap::from([(
                    "note".to_string(),
                    Type {
                        schema: Some("http://schema.example.com/note".to_string()),
                        data_formats: Some(vec!["text/plain".to_string()]),
                        encryption_required: None,
                    },
                )]),
                structure: BTreeMap::from([(
                    "note".to_string(),
                    RuleSet {
                        actions: vec![Action::Who(ActionWho {
                            who: Who::Anyone,
                            of: None,
                            can: vec![Can::Create, Can::Read],
                        })],
                        ..Default::default()
                    },
                )]),
            },
            permission_grant_id: None,
        }
    }

    fn base_thread_descriptor() -> ConfigureDescriptor {
        ConfigureDescriptor {
            message_timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00.000000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            definition: Definition {
                protocol: "http://example.com/thread-protocol".to_string(),
                published: true,
                uses: None,
                types: BTreeMap::from([
                    (
                        "thread".to_string(),
                        Type {
                            schema: Some("http://schema.example.com/thread".to_string()),
                            data_formats: Some(vec!["application/json".to_string()]),
                            encryption_required: None,
                        },
                    ),
                    (
                        "participant".to_string(),
                        Type {
                            schema: Some("http://schema.example.com/participant".to_string()),
                            data_formats: Some(vec!["application/json".to_string()]),
                            encryption_required: None,
                        },
                    ),
                ]),
                structure: BTreeMap::from([(
                    "thread".to_string(),
                    RuleSet {
                        actions: vec![Action::Who(ActionWho {
                            who: Who::Anyone,
                            of: None,
                            can: vec![Can::Create, Can::Read],
                        })],
                        rules: BTreeMap::from([(
                            "participant".to_string(),
                            RuleSet {
                                role: Some(true),
                                actions: vec![Action::Who(ActionWho {
                                    who: Who::Anyone,
                                    of: None,
                                    can: vec![Can::Create, Can::Read],
                                })],
                                ..Default::default()
                            },
                        )]),
                        ..Default::default()
                    },
                )]),
            },
            permission_grant_id: None,
        }
    }

    fn composed_descriptor(protocol: &str, role: &str) -> ConfigureDescriptor {
        ConfigureDescriptor {
            message_timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:01:00.000000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            definition: Definition {
                protocol: protocol.to_string(),
                published: true,
                uses: Some(BTreeMap::from([(
                    "threads".to_string(),
                    "http://example.com/thread-protocol".to_string(),
                )])),
                types: BTreeMap::from([(
                    "comment".to_string(),
                    Type {
                        schema: Some("http://schema.example.com/comment".to_string()),
                        data_formats: Some(vec!["text/plain".to_string()]),
                        encryption_required: None,
                    },
                )]),
                structure: BTreeMap::from([(
                    "thread".to_string(),
                    RuleSet {
                        reference: Some("threads:thread".to_string()),
                        rules: BTreeMap::from([(
                            "comment".to_string(),
                            RuleSet {
                                actions: vec![Action::Role(ActionRole {
                                    role: role.to_string(),
                                    can: vec![Can::Create, Can::Read],
                                })],
                                ..Default::default()
                            },
                        )]),
                        ..Default::default()
                    },
                )]),
            },
            permission_grant_id: None,
        }
    }

    fn test_signer() -> PrivateJwkSigner {
        test_signer_with_key_id("did:example:alice#key1")
    }

    fn test_signer_with_key_id(key_id: &str) -> PrivateJwkSigner {
        PrivateJwkSigner::new(
            key_id,
            "EdDSA",
            GeneralJwsPrivateJwk {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                d: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string(),
                x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
                y: None,
                kid: Some("did:example:alice#key1".to_string()),
                alg: Some("EdDSA".to_string()),
            },
        )
    }

    fn test_resolver() -> StaticPublicKeyResolver {
        StaticPublicKeyResolver::new(BTreeMap::from([(
            "did:example:alice#key1".to_string(),
            test_public_jwk("did:example:alice#key1"),
        )]))
    }

    fn test_resolver_with_bob() -> StaticPublicKeyResolver {
        StaticPublicKeyResolver::new(BTreeMap::from([
            (
                "did:example:alice#key1".to_string(),
                test_public_jwk("did:example:alice#key1"),
            ),
            (
                "did:example:bob#key1".to_string(),
                test_public_jwk("did:example:bob#key1"),
            ),
        ]))
    }

    fn test_public_jwk(key_id: &str) -> GeneralJwsPublicJwk {
        GeneralJwsPublicJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
            y: None,
            kid: Some(key_id.to_string()),
            alg: Some("EdDSA".to_string()),
        }
    }

    fn matches_filters(indexes: &KeyValues, filters: Filters) -> bool {
        let mut has_filter_set = false;
        for filter_set in filters {
            has_filter_set = true;
            if filter_set.into_iter().all(|(key, filter)| match key {
                FilterKey::Index(index) => indexes
                    .get(&index)
                    .is_some_and(|value| matches_filter(value, &filter)),
                FilterKey::Tag(_) => false,
            }) {
                return true;
            }
        }
        !has_filter_set
    }

    fn matches_filter(value: &Value, filter: &Filter<Value>) -> bool {
        match filter {
            Filter::Equal(expected) => value == expected,
            Filter::OneOf(values) => values.iter().any(|expected| value == expected),
            Filter::Prefix(prefix) => {
                value_string(Some(value)).starts_with(&value_string(Some(prefix)))
            }
            Filter::Range(RangeFilter::Numeric(lower, upper))
            | Filter::Range(RangeFilter::Criterion(lower, upper)) => {
                matches_lower_bound(value, lower) && matches_upper_bound(value, upper)
            }
        }
    }

    fn matches_lower_bound(value: &Value, bound: &Bound<Value>) -> bool {
        match bound {
            Bound::Included(bound) => value_string(Some(value)) >= value_string(Some(bound)),
            Bound::Excluded(bound) => value_string(Some(value)) > value_string(Some(bound)),
            Bound::Unbounded => true,
        }
    }

    fn matches_upper_bound(value: &Value, bound: &Bound<Value>) -> bool {
        match bound {
            Bound::Included(bound) => value_string(Some(value)) <= value_string(Some(bound)),
            Bound::Excluded(bound) => value_string(Some(value)) < value_string(Some(bound)),
            Bound::Unbounded => true,
        }
    }

    fn value_string(value: Option<&Value>) -> String {
        match value {
            Some(Value::String(value)) => value.clone(),
            Some(Value::Bool(value)) => value.to_string(),
            Some(value) => value.to_string(),
            None => String::new(),
        }
    }

    fn test_store_error(error: String) -> crate::errors::MessageStoreError {
        crate::errors::MessageStoreError::StoreError(crate::errors::StoreError::InternalException(
            error,
        ))
    }

    #[test]
    fn generic_message_deserializes_typescript_authorization_shape() {
        let raw = signed_configure_message(
            "http://example.com/protocol",
            true,
            "2025-01-01T00:00:00.000000Z",
        );
        let message: Message<Descriptor> = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(serde_json::to_value(message).unwrap(), raw);

        let unsigned = serde_json::json!({ "descriptor": configure_descriptor("http://example.com/protocol", true, "2025-01-01T00:00:00.000000Z") });
        let message: Message<Descriptor> = serde_json::from_value(unsigned.clone()).unwrap();
        assert_eq!(serde_json::to_value(message).unwrap(), unsigned);
    }

    #[test]
    fn validate_definition_rejects_invalid_protocol_rules() {
        let mut descriptor = configure_descriptor(
            "http://example.com/protocol",
            true,
            "2025-01-01T00:00:00.000000Z",
        );
        descriptor
            .definition
            .structure
            .get_mut("note")
            .unwrap()
            .size = Some(protocol_types::Size {
            min: Some(10),
            max: Some(1),
        });
        let error = protocol_types::validate_definition(&descriptor.definition).unwrap_err();
        assert_eq!(error.code, "ProtocolsConfigureInvalidSize");
    }

    #[allow(dead_code)]
    fn _message_from_descriptor(descriptor: ConfigureDescriptor) -> Message<Descriptor> {
        Message {
            descriptor: Descriptor::Protocols(Box::new(Protocols::Configure(descriptor))),
            fields: Fields::Write(WriteFields::default()),
        }
    }
}
