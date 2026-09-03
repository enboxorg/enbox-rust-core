use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::core_protocol::CoreProtocolRegistry;
use crate::descriptors::ConfigureDescriptor;
use crate::dwn::HandlerContext;
use crate::interfaces::messages::protocols::{self as protocol_types, Definition};
use crate::replies::protocols::Configure;
use crate::stores::{LatestStateMutation, LatestStateTransition};
use crate::{permissions, Handler, Message, Pagination, Response};
use crate::{MessageSort, SortDirection};

use super::common::*;

#[derive(Clone)]
pub struct ProtocolsConfigureHandler<MessageStore> {
    message_store: MessageStore,
    did_resolver: Option<Arc<dyn DidResolver>>,
}

impl<MessageStore> ProtocolsConfigureHandler<MessageStore> {
    pub fn new(message_store: MessageStore, did_resolver: Option<Arc<dyn DidResolver>>) -> Self {
        Self {
            message_store,
            did_resolver,
        }
    }
}

impl<MessageStore> Handler for ProtocolsConfigureHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    type Reply = Configure;
    type Descriptor = ConfigureDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = Response<Self::Reply>> + Send {
        async move {
            let HandlerContext {
                tenant,
                message,
                descriptor,
                ..
            } = ctx;

            let authorization = match permissions::validate_authorization_signature(
                &message,
                self.did_resolver.as_deref(),
                true,
            )
            .await
            {
                Ok(Some(authorization)) => authorization,
                Ok(None) => {
                    return Response::unauthorized(
                        "ProtocolsConfigureAuthorizationFailed: message failed authorization"
                            .to_string(),
                    )
                }
                Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                    return Response::bad_request(detail.to_string())
                }
                Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                    return Response::unauthorized(detail.to_string())
                }
                Err(error) => return Response::bad_request(error.to_string()),
            };

            let author = authorization.author.clone();
            let incoming_cid = match message_cid(&message) {
                Ok(cid) => cid,
                Err(detail) => return Response::bad_request(detail.to_string()),
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
            for existing in &existing_messages {
                match message_cid(existing) {
                    Ok(cid) if cid == incoming_cid => return Response::conflict(),
                    Ok(_) => {}
                    Err(detail) => return Response::bad_request(detail),
                }
            }

            // Covers: DWN-REC-003, DWN-AUTH-006
            // Exact replay is classified before mutable grant and composition state can
            // reinterpret an operation that was already admitted.
            if let Err(detail) = permissions::authorize_protocols_configure(
                tenant,
                &message,
                &authorization,
                &self.message_store,
            )
            .await
            {
                return Response::unauthorized(detail.to_string());
            }
            if let Err(err) = protocol_types::validate_definition(&descriptor.definition) {
                return Response::bad_request(err.to_string());
            }
            if let Err(detail) = self
                .validate_composition_dependencies(tenant, &descriptor.definition)
                .await
            {
                return Response::bad_request(detail.to_string());
            }

            let transition =
                match plan_configure_transition(message, &incoming_cid, &author, existing_messages)
                {
                    Ok(Some(transition)) => transition,
                    Ok(None) => return Response::conflict(),
                    Err(detail) => return Response::bad_request(detail),
                };
            if let Err(err) = self
                .message_store
                .commit_latest_state(tenant, transition)
                .await
            {
                return store_error_reply(err.to_string());
            }

            Response::accepted()
        }
    }
}

impl<MessageStore> ProtocolsConfigureHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
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

fn plan_configure_transition(
    incoming: Message<crate::Descriptor>,
    incoming_cid: &str,
    incoming_author: &str,
    existing: Vec<Message<crate::Descriptor>>,
) -> Result<Option<LatestStateTransition>, String> {
    let mut comparable = Vec::with_capacity(existing.len());
    for message in &existing {
        let cid = message_cid(message)?;
        if cid == incoming_cid {
            return Ok(None);
        }
        comparable.push(cid);
    }

    let incoming_is_latest = existing.iter().zip(&comparable).all(|(message, cid)| {
        compare_configure_messages(incoming_cid, &incoming, cid, message) == Ordering::Greater
    });
    let latest_existing_cid = existing
        .iter()
        .zip(&comparable)
        .max_by(|(left, left_cid), (right, right_cid)| {
            compare_configure_messages(left_cid, left, right_cid, right)
        })
        .map(|(_, cid)| cid.clone());

    let descriptor = protocols_configure_descriptor(&incoming)?;
    let put = LatestStateMutation {
        indexes: configure_indexes(descriptor, Some(incoming_author), incoming_is_latest),
        message: incoming,
    };
    let retains = existing
        .into_iter()
        .zip(comparable)
        .map(|(message, cid)| {
            let descriptor = protocols_configure_descriptor(&message)?;
            let author = extract_author(&message);
            Ok(LatestStateMutation {
                indexes: configure_indexes(
                    descriptor,
                    author.as_deref(),
                    !incoming_is_latest && latest_existing_cid.as_deref() == Some(cid.as_str()),
                ),
                message,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(Some(LatestStateTransition {
        put,
        retains,
        deletes: Vec::new(),
    }))
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
