use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde_json::Value as JsonValue;

use crate::dwn::DwnReply;
use crate::interfaces::messages::protocols::{self as protocol_types, Definition};
use crate::permissions;
use crate::{MessageSort, SortDirection};

use super::common::*;
use super::{fetch_protocol_definition, ProtocolDefinitionLookupError, ProtocolsConfigureHandler};
impl<MessageStore, StateIndex> ProtocolsConfigureHandler<MessageStore, StateIndex>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
    StateIndex: crate::stores::StateIndex + Clone + Send + Sync + 'static,
{
    pub(crate) async fn handle_configure(&self, tenant: &str, raw_message: &JsonValue) -> DwnReply {
        let message = match parse_message(raw_message) {
            Ok(message) => message,
            Err(detail) => return DwnReply::bad_request(detail),
        };
        let descriptor = match protocols_configure_descriptor(&message) {
            Ok(descriptor) => descriptor,
            Err(detail) => return DwnReply::bad_request(detail),
        };

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
