//! The effective policy governing one records write: the definition,
//! rule set, type, and key agreement resolved for the record timestamp.
//!
//! Extracted from the write handler so timestamp-relative definition
//! resolution (`DWN-PROTO-004`), `$ref` composition (`DWN-PROTO-005`), and the
//! encryption-representation gate (`DWN-ENC-001`) read in one place instead of
//! interleaved with enforcement. Enforcement stays with the caller.

use crate::descriptors::records::records_write_descriptor;
use crate::descriptors::{Descriptor, RecordsWriteDescriptor};
use crate::dwn::core_protocol::CoreProtocolRegistry;
use crate::handlers::protocols::configure::fetch_protocol_definition;
use crate::interfaces::messages::protocols::{Definition, ProtocolKeyAgreement, RuleSet};
use crate::Message;

use super::common::governing_timestamp;
use super::write::RecordsWriteValidationError;

/// The protocol rules governing one write, resolved for its timestamp.
pub(crate) struct EffectivePolicy {
    pub definition: Definition,
    pub rule_set: RuleSet,
    pub type_name: String,
    pub encryption_required: bool,
    pub key_agreement: Option<ProtocolKeyAgreement>,
}

impl EffectivePolicy {
    pub(crate) async fn resolve<MessageStore>(
        tenant: &str,
        message: &Message<Descriptor>,
        author: &str,
        registry: &CoreProtocolRegistry,
        message_store: &MessageStore,
    ) -> Result<Self, RecordsWriteValidationError>
    where
        MessageStore: crate::stores::MessageStore + Sync,
    {
        let descriptor = records_write_descriptor(message).map_err(|error| error.to_string())?;
        let governing_timestamp =
            governing_timestamp(tenant, message, message_store, author).await?;

        // check if protocol is defined in the core_protocol_registry and use that
        // definition, otherwise fetch the protocol definition from the message store
        let definition = if registry.has(&descriptor.protocol) {
            registry
                .get_definition(&descriptor.protocol)
                .ok_or_else(|| {
                    format!(
                        "ProtocolAuthorizationInvalidProtocol: {} is not defined",
                        descriptor.protocol
                    )
                })?
        } else {
            fetch_protocol_definition(
                tenant,
                &descriptor.protocol,
                message_store,
                Some(&governing_timestamp),
            )
            .await?
        };
        let rule_set = definition
            .rule_at(descriptor.protocol_path.as_str())
            .ok_or_else(|| {
                format!(
                    "ProtocolAuthorizationInvalidProtocolPath: {} is not defined",
                    descriptor.protocol_path
                )
            })?
            .clone();

        // Covers: DWN-PROTO-001, DWN-PROTO-004, DWN-PROTO-005, DWN-ENC-001
        // Protocol-declared encryption representation is enforced at admission
        // against the definition governing the record timestamp. A record at
        // a `$ref` position follows the referenced protocol's type and key
        // namespace at the referenced target path; locally declared
        // descendants follow the composing type map.
        let referenced = referenced_definition_for_ref_path(
            tenant,
            descriptor,
            &definition,
            &governing_timestamp,
            message_store,
        )
        .await?;
        let ref_position = definition.ref_position(descriptor.protocol_path.as_str());
        let (types, type_name) = match (&referenced, &ref_position) {
            (Some(referenced), Some(position)) => (
                &referenced.types,
                position
                    .protocol_path
                    .split('/')
                    .next_back()
                    .unwrap_or_default()
                    .to_string(),
            ),
            _ => (
                &definition.types,
                descriptor
                    .protocol_path
                    .split('/')
                    .next_back()
                    .unwrap_or_default()
                    .to_string(),
            ),
        };
        let key_agreement = match (&referenced, &ref_position) {
            (Some(referenced), Some(position)) => referenced
                .rule_at(position.protocol_path)
                .and_then(|rule_set| rule_set.key_agreement.clone()),
            _ => rule_set.key_agreement.clone(),
        };
        let encryption_required = types
            .get(&type_name)
            .and_then(|protocol_type| protocol_type.encryption_required)
            == Some(true);

        Ok(Self {
            definition,
            rule_set,
            type_name,
            encryption_required,
            key_agreement,
        })
    }
}

async fn referenced_definition_for_ref_path<MessageStore>(
    tenant: &str,
    descriptor: &RecordsWriteDescriptor,
    definition: &Definition,
    governing_timestamp: &str,
    message_store: &MessageStore,
) -> Result<Option<Definition>, RecordsWriteValidationError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    let Some(parsed) = definition.ref_position(descriptor.protocol_path.as_str()) else {
        return Ok(None);
    };
    let ref_uri = definition
        .uses
        .as_ref()
        .and_then(|uses| uses.get(parsed.alias))
        .ok_or_else(|| {
            format!(
                "ProtocolsConfigureInvalidRefAlias: '$ref' alias '{}' at protocol path '{}' does not exist in the 'uses' map.",
                parsed.alias, descriptor.protocol_path
            )
        })?;
    Ok(Some(
        fetch_protocol_definition(tenant, ref_uri, message_store, Some(governing_timestamp))
            .await?,
    ))
}
