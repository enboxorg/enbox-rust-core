use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::core_protocol::CoreProtocolRegistry;
use crate::descriptors::records::{records_write_descriptor, write_fields};
use crate::descriptors::ConfigureDescriptor;
use crate::dwn::HandlerContext;
use crate::encryption::is_encryption_control_path;
use crate::filters::Filters;
use crate::handlers::records::common::{filter_map, string_filter};
use crate::handlers::records::{RECORDS_INTERFACE, WRITE_METHOD};
use crate::interfaces::messages::protocols::{self as protocol_types, Definition};
use crate::replies::protocols::Configure;
use crate::stores::{LatestStateMutation, LatestStateTransition};
use crate::{canonical_rfc3339, permissions, Handler, Message, Pagination, Response};
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

            // Covers: DWN-PROTO-001, DWN-PROTO-004, DWN-PROTO-005
            // Representation policy is immutable once records exist under a
            // path. The scan runs before the configure commits.
            let incoming_timestamp = canonical_rfc3339(descriptor.message_timestamp);
            if let Err(reply) = self
                .validate_encryption_policy_immutable(
                    tenant,
                    &descriptor.definition,
                    &incoming_timestamp,
                    &existing_messages,
                )
                .await
            {
                return reply;
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

    #[allow(clippy::result_large_err)]
    async fn validate_encryption_policy_immutable(
        &self,
        tenant: &str,
        incoming: &Definition,
        incoming_timestamp: &str,
        existing: &[Message<crate::Descriptor>],
    ) -> Result<(), Response<Configure>> {
        let mut newest: Option<&Message<crate::Descriptor>> = None;
        let mut newest_cid = String::new();
        for message in existing {
            let cid = message_cid(message).map_err(Response::bad_request)?;
            let is_newer = match newest {
                None => true,
                Some(current) => {
                    compare_configure_messages(&cid, message, &newest_cid, current)
                        == Ordering::Greater
                }
            };
            if is_newer {
                newest = Some(message);
                newest_cid = cid;
            }
        }
        let Some(newest) = newest else {
            return Ok(());
        };
        let previous = protocols_configure_descriptor(newest)
            .map(|descriptor| descriptor.definition.clone())
            .map_err(Response::bad_request)?;
        if !protocol_types::has_encryption_policy_change(&previous, incoming) {
            return Ok(());
        }

        let filter = filter_map([
            ("interface", string_filter(RECORDS_INTERFACE)),
            ("method", string_filter(WRITE_METHOD)),
            ("protocol", string_filter(&incoming.protocol)),
        ]);
        let records = self
            .message_store
            .query(tenant, Filters::from(filter), None, None, None)
            .await
            .map(|result| result.messages)
            .map_err(|err| store_error_reply(err.to_string()))?;
        let mut policy_by_path: BTreeMap<String, bool> = BTreeMap::new();
        for record in &records {
            let descriptor = records_write_descriptor(record)
                .map_err(|err| store_error_reply(err.to_string()))?;
            let protocol_path = descriptor.protocol_path.clone();
            if is_encryption_control_path(&protocol_path) {
                continue;
            }
            if incoming.rule_at(&protocol_path).is_none() {
                continue;
            }
            let required = match policy_by_path.get(&protocol_path) {
                Some(required) => *required,
                None => {
                    let required = self
                        .effective_incoming_policy(
                            tenant,
                            incoming,
                            &protocol_path,
                            incoming_timestamp,
                        )
                        .await?;
                    policy_by_path.insert(protocol_path.clone(), required);
                    required
                }
            };
            let encrypted = write_fields(record)
                .map(|fields| fields.encryption.is_some())
                .map_err(|err| store_error_reply(err.to_string()))?;
            if encrypted == required {
                continue;
            }
            return Err(Response::bad_request(format!(
                "ProtocolsConfigureEncryptionPolicyImmutable: cannot change encryption policy for protocol path '{protocol_path}' after records exist; install the changed definition under a new protocol URI."
            )));
        }

        self.validate_composed_encryption_policy_immutable(tenant, incoming)
            .await
    }

    #[allow(clippy::result_large_err)]
    async fn effective_incoming_policy(
        &self,
        tenant: &str,
        incoming: &Definition,
        protocol_path: &str,
        incoming_timestamp: &str,
    ) -> Result<bool, Response<Configure>> {
        let type_name = protocol_path.split('/').next_back().unwrap_or_default();
        if let Some(parsed) = incoming.ref_position(protocol_path) {
            let ref_uri = incoming
                .uses
                .as_ref()
                .and_then(|uses| uses.get(parsed.alias))
                .ok_or_else(|| {
                    Response::bad_request(format!(
                        "ProtocolsConfigureInvalidRefAlias: '$ref' alias '{}' at protocol path '{protocol_path}' does not exist in the 'uses' map.",
                        parsed.alias
                    ))
                })?;
            let referenced =
                fetch_protocol_definition(tenant, ref_uri, &self.message_store, Some(incoming_timestamp))
                    .await
                    .map_err(|err| match err {
                        ProtocolDefinitionLookupError::NotFound(uri) => Response::bad_request(
                            format!("ProtocolAuthorizationProtocolNotFound: unable to find protocol definition for {uri}"),
                        ),
                        ProtocolDefinitionLookupError::Store(detail) => {
                            store_error_reply(detail)
                        }
                        ProtocolDefinitionLookupError::InvalidMessage(detail) => {
                            Response::bad_request(detail)
                        }
                    })?;
            return Ok(referenced
                .types
                .get(type_name)
                .and_then(|protocol_type| protocol_type.encryption_required)
                == Some(true));
        }
        Ok(incoming
            .types
            .get(type_name)
            .and_then(|protocol_type| protocol_type.encryption_required)
            == Some(true))
    }

    #[allow(clippy::result_large_err)]
    async fn validate_composed_encryption_policy_immutable(
        &self,
        tenant: &str,
        incoming: &Definition,
    ) -> Result<(), Response<Configure>> {
        let configurations = self
            .message_store
            .query(tenant, latest_configure_filters(), None, None, None)
            .await
            .map(|result| result.messages)
            .map_err(|err| store_error_reply(err.to_string()))?;
        let mut policies: BTreeMap<String, BTreeMap<String, bool>> = BTreeMap::new();
        for configuration in &configurations {
            let composing = protocols_configure_descriptor(configuration)
                .map(|descriptor| descriptor.definition.clone())
                .map_err(|err| store_error_reply(err.to_string()))?;
            let aliases: BTreeSet<&str> = composing
                .uses
                .as_ref()
                .map(|uses| {
                    uses.iter()
                        .filter(|(_, uri)| *uri == &incoming.protocol)
                        .map(|(alias, _)| alias.as_str())
                        .collect()
                })
                .unwrap_or_default();
            if aliases.is_empty() {
                continue;
            }
            for (root_path, rule_set) in &composing.structure {
                let Some(reference) = rule_set.reference.as_deref() else {
                    continue;
                };
                let Some(parsed) = protocol_types::parse_cross_protocol_ref(reference) else {
                    continue;
                };
                if !aliases.contains(parsed.alias) {
                    continue;
                }
                let required = incoming
                    .types
                    .get(root_path.as_str())
                    .and_then(|protocol_type| protocol_type.encryption_required)
                    == Some(true);
                policies
                    .entry(composing.protocol.clone())
                    .or_default()
                    .insert(root_path.clone(), required);
            }
        }
        if policies.is_empty() {
            return Ok(());
        }

        for (protocol, paths) in &policies {
            let filter = filter_map([
                ("interface", string_filter(RECORDS_INTERFACE)),
                ("method", string_filter(WRITE_METHOD)),
                ("protocol", string_filter(protocol)),
            ]);
            let records = self
                .message_store
                .query(tenant, Filters::from(filter), None, None, None)
                .await
                .map(|result| result.messages)
                .map_err(|err| store_error_reply(err.to_string()))?;
            for record in &records {
                let descriptor = records_write_descriptor(record)
                    .map_err(|err| store_error_reply(err.to_string()))?;
                let Some(required) = paths.get(&descriptor.protocol_path) else {
                    continue;
                };
                let encrypted = write_fields(record)
                    .map(|fields| fields.encryption.is_some())
                    .map_err(|err| store_error_reply(err.to_string()))?;
                if encrypted == *required {
                    continue;
                }
                return Err(Response::bad_request(format!(
                    "ProtocolsConfigureEncryptionPolicyImmutable: cannot change encryption policy for protocol path '{}' imported by protocol '{protocol}' after records exist; install the changed definition under a new protocol URI.",
                    descriptor.protocol_path
                )));
            }
        }
        Ok(())
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
            None,
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
