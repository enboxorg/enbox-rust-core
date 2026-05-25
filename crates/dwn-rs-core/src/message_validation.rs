//! JSON Schema validation for inbound DWN messages.
//!
//! Validates messages in `Dwn::process_message` using the same schema corpus
//! as `@enbox/dwn-sdk-js`.

use std::collections::HashMap;
use std::sync::OnceLock;

use jsonschema::{Draft, Registry, Resource, Validator};
use serde_json::Value;

use crate::dwn::MessageKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageValidationError {
    pub detail: String,
}

impl MessageValidationError {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for MessageValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for MessageValidationError {}

static VALIDATORS: OnceLock<HashMap<String, Validator>> = OnceLock::new();

const SCHEMA_SOURCES: &[(&str, &str)] = &[
    (
        "https://identity.foundation/dwn/json-schemas/authorization.json",
        include_str!("../schemas/authorization.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/authorization-delegated-grant.json",
        include_str!("../schemas/authorization-delegated-grant.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/authorization-owner.json",
        include_str!("../schemas/authorization-owner.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/defs.json",
        include_str!("../schemas/definitions.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/general-jws.json",
        include_str!("../schemas/general-jws.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/jwk-verification-method.json",
        include_str!("../schemas/jwk-verification-method.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/jwk/general-jwk.json",
        include_str!("../schemas/jwk/general-jwk.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/jwk/public-jwk.json",
        include_str!("../schemas/jwk/public-jwk.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/messages-filter.json",
        include_str!("../schemas/interface-methods/messages-filter.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/messages-read.json",
        include_str!("../schemas/interface-methods/messages-read.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/messages-subscribe.json",
        include_str!("../schemas/interface-methods/messages-subscribe.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/messages-sync.json",
        include_str!("../schemas/interface-methods/messages-sync.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/number-range-filter.json",
        include_str!("../schemas/interface-methods/number-range-filter.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/pagination-cursor.json",
        include_str!("../schemas/interface-methods/pagination-cursor.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/progress-token.json",
        include_str!("../schemas/interface-methods/progress-token.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/protocol-definition.json",
        include_str!("../schemas/interface-methods/protocol-definition.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/protocol-rule-set.json",
        include_str!("../schemas/interface-methods/protocol-rule-set.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/protocols-configure.json",
        include_str!("../schemas/interface-methods/protocols-configure.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/protocols-query.json",
        include_str!("../schemas/interface-methods/protocols-query.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-count.json",
        include_str!("../schemas/interface-methods/records-count.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-delete.json",
        include_str!("../schemas/interface-methods/records-delete.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-filter.json",
        include_str!("../schemas/interface-methods/records-filter.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-query.json",
        include_str!("../schemas/interface-methods/records-query.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-read.json",
        include_str!("../schemas/interface-methods/records-read.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-subscribe.json",
        include_str!("../schemas/interface-methods/records-subscribe.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-write.json",
        include_str!("../schemas/interface-methods/records-write.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-write-data-encoded.json",
        include_str!("../schemas/interface-methods/records-write-data-encoded.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-write-unidentified.json",
        include_str!("../schemas/interface-methods/records-write-unidentified.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/string-range-filter.json",
        include_str!("../schemas/interface-methods/string-range-filter.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/generic-signature-payload.json",
        include_str!("../schemas/signature-payloads/generic-signature-payload.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/records-write-signature-payload.json",
        include_str!("../schemas/signature-payloads/records-write-signature-payload.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/permission-grant-data.json",
        include_str!("../schemas/permissions/permission-grant-data.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/permission-request-data.json",
        include_str!("../schemas/permissions/permission-request-data.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/permission-revocation-data.json",
        include_str!("../schemas/permissions/permission-revocation-data.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/permissions-definitions.json",
        include_str!("../schemas/permissions/permissions-definitions.json"),
    ),
    (
        "https://identity.foundation/dwn/json-schemas/permissions/scopes.json",
        include_str!("../schemas/permissions/scopes.json"),
    ),
];

fn validators() -> &'static HashMap<String, Validator> {
    VALIDATORS.get_or_init(|| {
        let resources = SCHEMA_SOURCES
            .iter()
            .map(|(id, source)| {
                let schema: Value = serde_json::from_str(source)
                    .unwrap_or_else(|err| panic!("invalid embedded schema {id}: {err}"));
                let resource = Resource::from_contents(schema)
                    .unwrap_or_else(|err| panic!("invalid embedded resource {id}: {err}"));
                ((*id).to_string(), resource)
            })
            .collect::<Vec<_>>();
        let registry = Registry::options()
            .draft(Draft::Draft202012)
            .build(resources)
            .expect("schema registry must compile");
        SCHEMA_SOURCES
            .iter()
            .map(|(id, source)| {
                let schema: Value = serde_json::from_str(source)
                    .unwrap_or_else(|err| panic!("invalid embedded schema {id}: {err}"));
                let validator = jsonschema::options()
                    .with_draft(Draft::Draft202012)
                    .with_registry(registry.clone())
                    .build(&schema)
                    .unwrap_or_else(|err| panic!("validator for {id} must compile: {err}"));
                (id.to_string(), validator)
            })
            .collect()
    })
}

fn schema_id_for_kind(kind: &MessageKind) -> Option<&'static str> {
    match (kind.interface.as_str(), kind.method.as_str()) {
        ("Messages", "Read") => Some("https://identity.foundation/dwn/json-schemas/messages-read.json"),
        ("Messages", "Subscribe") => {
            Some("https://identity.foundation/dwn/json-schemas/messages-subscribe.json")
        }
        ("Messages", "Sync") => Some("https://identity.foundation/dwn/json-schemas/messages-sync.json"),
        ("Protocols", "Configure") => {
            Some("https://identity.foundation/dwn/json-schemas/protocols-configure.json")
        }
        ("Protocols", "Query") => Some("https://identity.foundation/dwn/json-schemas/protocols-query.json"),
        ("Records", "Count") => Some("https://identity.foundation/dwn/json-schemas/records-count.json"),
        ("Records", "Delete") => Some("https://identity.foundation/dwn/json-schemas/records-delete.json"),
        ("Records", "Query") => Some("https://identity.foundation/dwn/json-schemas/records-query.json"),
        ("Records", "Read") => Some("https://identity.foundation/dwn/json-schemas/records-read.json"),
        ("Records", "Subscribe") => {
            Some("https://identity.foundation/dwn/json-schemas/records-subscribe.json")
        }
        ("Records", "Write") => Some("https://identity.foundation/dwn/json-schemas/records-write.json"),
        _ => None,
    }
}

pub fn validate_message(raw_message: &Value) -> Result<(), MessageValidationError> {
    let kind = MessageKind::from_message(raw_message).map_err(|err| match err {
        crate::dwn::DwnValidationError::MissingInterfaceMethod { interface, method } => {
            MessageValidationError::new(format!(
                "Both interface and method must be present, interface: {interface}, method: {method}"
            ))
        }
    })?;
    let Some(schema_id) = schema_id_for_kind(&kind) else {
        return Err(MessageValidationError::new(format!(
            "SchemaValidatorSchemaNotFound: schema for {}{} not found",
            kind.interface, kind.method
        )));
    };
    let validator = validators().get(schema_id).ok_or_else(|| {
        MessageValidationError::new(format!(
            "SchemaValidatorSchemaNotFound: schema for {}{} not found",
            kind.interface, kind.method
        ))
    })?;
    if let Some(error) = validator.iter_errors(raw_message).next() {
        return Err(MessageValidationError::new(format!(
            "SchemaValidatorFailure: {error}"
        )));
    }
    Ok(())
}
