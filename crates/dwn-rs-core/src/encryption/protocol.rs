//! Fixed core definition for the DWN encryption protocol.
//!
//! Mirrors `EncryptionProtocol.definition` from `@enbox/dwn-sdk-js`
//! (`protocols/encryption.ts:54-100`): the two immutable root types
//! `grantKey` (encrypted) and `wrappedGrantKey` (plaintext envelope), with
//! create/anyone and read/recipient-of-that-path actions. Like every core
//! protocol this definition is returned by lookup precedence, never installed.

use std::collections::BTreeMap;

use crate::descriptors::records::records_write_descriptor;
use crate::descriptors::Descriptor;
use crate::encryption::{
    ENCRYPTION_PROTOCOL_GRANT_KEY_PATH, ENCRYPTION_PROTOCOL_URI,
    ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
};
use crate::interfaces::messages::protocols::{
    Action, ActionWho, Can, Definition, ProvidedTags, RuleSet, TagType, Tags, Type, Who,
};
use crate::Message;

/// Schema URI for the decrypted `grantKey` payload shape (no local file: the
/// SDK carries no `grant-key.json`; the shape is enforced by agent code).
pub const GRANT_KEY_PAYLOAD_SCHEMA_URI: &str =
    "https://identity.foundation/dwn/json-schemas/encryption/grant-key.json";
/// Schema URI for the `wrappedGrantKey` inline envelope.
pub const WRAPPED_GRANT_KEY_ENVELOPE_SCHEMA_URI: &str =
    "https://identity.foundation/dwn/json-schemas/encryption/wrapped-grant-key-envelope.json";

fn string_tag(min_length: Option<usize>, max_length: Option<usize>) -> ProvidedTags {
    ProvidedTags {
        tag_type: TagType::String,
        items: None,
        contains: None,
        enum_values: Vec::new(),
        max_length,
        min_length,
        minimum: None,
        maximum: None,
        exclusive_minimum: None,
        exclusive_maximum: None,
        min_items: None,
        max_items: None,
        unique_items: None,
        min_contains: None,
        max_contains: None,
    }
}

fn delivery_tags() -> Tags {
    Tags {
        required_tags: vec![
            "grantId".to_string(),
            "protocol".to_string(),
            "keyId".to_string(),
        ],
        allow_undefined_tags: Some(false),
        tags: BTreeMap::from([
            ("grantId".to_string(), string_tag(None, None)),
            // Upstream additionally constrains keyId by pattern
            // `^[A-Za-z0-9_-]{43}$`; the typed tag model carries lengths only,
            // so the pattern is enforced by delivery admission instead.
            ("keyId".to_string(), string_tag(Some(43), Some(43))),
            ("protocol".to_string(), string_tag(None, None)),
            ("protocolPath".to_string(), string_tag(None, None)),
        ]),
    }
}

fn delivery_rule_set(path: &str) -> RuleSet {
    RuleSet {
        immutable: Some(true),
        actions: vec![
            Action::Who(ActionWho {
                who: Who::Anyone,
                of: None,
                can: vec![Can::Create],
            }),
            Action::Who(ActionWho {
                who: Who::Recipient,
                of: Some(path.to_string()),
                can: vec![Can::Read],
            }),
        ],
        tags: Some(delivery_tags()),
        ..Default::default()
    }
}

pub fn encryption_protocol_definition() -> Definition {
    Definition {
        protocol: ENCRYPTION_PROTOCOL_URI.to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([
            (
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH.to_string(),
                Type {
                    schema: Some(GRANT_KEY_PAYLOAD_SCHEMA_URI.to_string()),
                    data_formats: Some(vec!["application/json".to_string()]),
                    encryption_required: Some(true),
                },
            ),
            (
                ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH.to_string(),
                Type {
                    schema: Some(WRAPPED_GRANT_KEY_ENVELOPE_SCHEMA_URI.to_string()),
                    data_formats: Some(vec!["application/json".to_string()]),
                    encryption_required: None,
                },
            ),
        ]),
        structure: BTreeMap::from([
            (
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH.to_string(),
                delivery_rule_set(ENCRYPTION_PROTOCOL_GRANT_KEY_PATH),
            ),
            (
                ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH.to_string(),
                delivery_rule_set(ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH),
            ),
        ]),
    }
}

/// Rejects records under the encryption protocol at any path other than the
/// two delivery roots. Payload validation needs the data bytes and lands
/// separately; this runs on descriptor metadata alone.
pub fn validate_encryption_record_schema(message: &Message<Descriptor>) -> Result<(), String> {
    let descriptor = records_write_descriptor(message).map_err(|error| error.to_string())?;
    if descriptor.protocol.as_str() != ENCRYPTION_PROTOCOL_URI {
        return Ok(());
    }
    match descriptor.protocol_path.as_str() {
        ENCRYPTION_PROTOCOL_GRANT_KEY_PATH | ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH => Ok(()),
        protocol_path => Err(format!(
            "EncryptionProtocolValidateSchemaUnexpectedRecord: unexpected encryption record: {protocol_path}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptors::{Records, RecordsWriteDescriptor};
    use crate::fields::WriteFields;

    // Covers: ENBOX-ENC-002
    #[test]
    fn encryption_protocol_definition_matches_typescript() {
        let definition = encryption_protocol_definition();
        assert_eq!(
            definition.protocol, ENCRYPTION_PROTOCOL_URI,
            "published core URI"
        );
        assert!(definition.published, "core definition is published");

        let grant_key = &definition.types[ENCRYPTION_PROTOCOL_GRANT_KEY_PATH];
        assert_eq!(
            grant_key.data_formats.as_deref(),
            Some(["application/json".to_string()].as_slice())
        );
        assert_eq!(grant_key.encryption_required, Some(true));
        assert_eq!(
            grant_key.schema.as_deref(),
            Some(GRANT_KEY_PAYLOAD_SCHEMA_URI)
        );

        let wrapped = &definition.types[ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH];
        assert_eq!(
            wrapped.data_formats.as_deref(),
            Some(["application/json".to_string()].as_slice())
        );
        assert_eq!(wrapped.encryption_required, None);
        assert_eq!(
            wrapped.schema.as_deref(),
            Some(WRAPPED_GRANT_KEY_ENVELOPE_SCHEMA_URI)
        );

        for (path, of) in [
            (
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
                ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
            ),
            (
                ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
                ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
            ),
        ] {
            let rule_set = definition
                .rule_at(path)
                .unwrap_or_else(|| panic!("{path} is a root type"));
            assert_eq!(rule_set.immutable, Some(true));
            assert_eq!(
                rule_set.actions,
                vec![
                    Action::Who(ActionWho {
                        who: Who::Anyone,
                        of: None,
                        can: vec![Can::Create],
                    }),
                    Action::Who(ActionWho {
                        who: Who::Recipient,
                        of: Some(of.to_string()),
                        can: vec![Can::Read],
                    }),
                ],
                "{path} actions"
            );
            let tags = rule_set.tags.as_ref().expect("{path} carries tags");
            assert_eq!(
                tags.required_tags,
                vec![
                    "grantId".to_string(),
                    "protocol".to_string(),
                    "keyId".to_string()
                ]
            );
            assert_eq!(tags.allow_undefined_tags, Some(false));
            let key_id = &tags.tags["keyId"];
            assert_eq!(key_id.min_length, Some(43));
            assert_eq!(key_id.max_length, Some(43));
        }
    }

    // Covers: ENBOX-ENC-002
    #[test]
    fn encryption_record_schema_accepts_only_delivery_paths() {
        for path in [
            ENCRYPTION_PROTOCOL_GRANT_KEY_PATH,
            ENCRYPTION_PROTOCOL_WRAPPED_GRANT_KEY_PATH,
        ] {
            let message = delivery_message(path);
            assert!(
                validate_encryption_record_schema(&message).is_ok(),
                "{path} is a delivery root"
            );
        }
        let message = delivery_message("epochKey");
        let error = validate_encryption_record_schema(&message).expect_err("third path rejected");
        assert!(
            error.starts_with("EncryptionProtocolValidateSchemaUnexpectedRecord"),
            "unexpected identity: {error}"
        );
    }

    fn delivery_message(protocol_path: &str) -> Message<Descriptor> {
        Message {
            descriptor: Descriptor::Records(Box::new(Records::Write(Box::new(
                RecordsWriteDescriptor {
                    protocol: ENCRYPTION_PROTOCOL_URI.to_string(),
                    protocol_path: protocol_path.to_string(),
                    ..Default::default()
                },
            )))),
            fields: crate::Fields::Write(WriteFields::default()),
        }
    }
}
