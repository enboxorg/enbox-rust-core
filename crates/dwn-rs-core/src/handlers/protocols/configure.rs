use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::auth::JwsPublicKeyResolver;
use crate::core_protocol::CoreProtocolRegistry;
use crate::descriptors::ConfigureDescriptor;
use crate::dwn::{DwnReply, HandlerContext};
use crate::interfaces::messages::protocols::{self as protocol_types, Definition};
use crate::{permissions, Handler, Pagination};
use crate::{MessageSort, SortDirection};

use super::common::*;

#[derive(Clone)]
pub struct ProtocolsConfigureHandler<MessageStore, StateIndex> {
    message_store: MessageStore,
    state_index: StateIndex,
    public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
}

impl<MessageStore, StateIndex> ProtocolsConfigureHandler<MessageStore, StateIndex> {
    pub fn new(
        message_store: MessageStore,
        state_index: StateIndex,
        public_key_resolver: Option<Arc<dyn JwsPublicKeyResolver + Send + Sync>>,
    ) -> Self {
        Self {
            message_store,
            state_index,
            public_key_resolver,
        }
    }
}

impl<MessageStore, StateIndex> Handler for ProtocolsConfigureHandler<MessageStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    type Descriptor = ConfigureDescriptor;

    fn handle<'a>(
        &'a self,
        ctx: HandlerContext<'a, Self::Descriptor>,
    ) -> Pin<Box<dyn Future<Output = DwnReply> + Send + 'a>> {
        Box::pin(async move {
            let HandlerContext {
                tenant,
                raw_message,
                message,
                descriptor,
                ..
            } = ctx;

            let authorization = match permissions::validate_authorization_signature(
                raw_message,
                self.public_key_resolver.as_deref(),
                true,
            ) {
                Ok(Some(authorization)) => authorization,
                Ok(None) => {
                    return DwnReply::unauthorized(
                        "ProtocolsConfigureAuthorizationFailed: message failed authorization",
                    )
                }
                Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                    return DwnReply::bad_request(detail)
                }
                Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                    return DwnReply::unauthorized(detail)
                }
            };

            if let Err(detail) = permissions::authorize_protocols_configure(
                tenant,
                &message,
                &authorization,
                &self.message_store,
            )
            .await
            {
                return DwnReply::unauthorized(detail);
            }
            let author = authorization.author.clone();

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
                compare_configure_messages(&incoming_cid, &message, cid, existing)
                    == Ordering::Greater
            });
            let latest_existing_cid = comparable
                .iter()
                .max_by(|(left_cid, left), (right_cid, right)| {
                    compare_configure_messages(left_cid, left, right_cid, right)
                })
                .map(|(cid, _)| cid.clone());

            let indexes = configure_indexes(&descriptor, Some(&author), incoming_is_latest);
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
        })
    }
}

impl<MessageStore, StateIndex> ProtocolsConfigureHandler<MessageStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
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

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolDefinitionLookupError {
    #[error("ProtocolAuthorizationProtocolNotFound: unable to find protocol definition for {0}")]
    NotFound(String),
    #[error("{0}")]
    Store(String),
    #[error("{0}")]
    InvalidMessage(String),
}

pub async fn fetch_protocol_definition<MessageStore>(
    tenant: &str,
    protocol_uri: &str,
    message_store: &MessageStore,
    message_timestamp: Option<&str>,
) -> Result<Definition, ProtocolDefinitionLookupError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if let Some(definition) = CoreProtocolRegistry::with_permissions().get_definition(protocol_uri)
    {
        return Ok(definition);
    }

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
