use std::collections::BTreeMap;

use crate::interfaces::messages::descriptors::{CONFIGURE, PROTOCOLS};
use crate::protocols::{self, ActionWho};
use crate::canonical_rfc3339;

use super::*;
use chrono::Utc;
use serde_json::json;
use ssi_jwk::JWK;

#[test]
fn test_configure_descriptor() {
    let message_timestamp =
        chrono::DateTime::parse_from_rfc3339(canonical_rfc3339(Utc::now()).as_str())
            .unwrap()
            .with_timezone(&Utc);
    let definition = protocols::Definition {
        protocol: "example".to_string(),
        published: true,
        uses: None,
        types: BTreeMap::new(),
        structure: BTreeMap::new(),
    };
    let descriptor = ConfigureDescriptor {
        message_timestamp,
        definition,
        permission_grant_id: None,
    };
    let json = json!({
        "messageTimestamp": canonical_rfc3339(message_timestamp),
        "definition": {
            "protocol": "example",
            "published": true,
            "types": {},
            "structure": {},
        },
        "interface": PROTOCOLS,
        "method": CONFIGURE,
    });
    assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<ConfigureDescriptor>(json).unwrap(),
        descriptor
    );
}

#[test]
fn test_protocol_definition() {
    let protocol = "example".to_string();
    let published = true;
    let types = BTreeMap::new();
    let structure = BTreeMap::new();
    let definition = protocols::Definition {
        protocol: protocol.clone(),
        published,
        uses: None,
        types,
        structure,
    };
    let json = json!({
        "protocol": protocol,
        "published": published,
        "types": {},
        "structure": {},
    });
    assert_eq!(serde_json::to_value(&definition).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<protocols::Definition>(json).unwrap(),
        definition
    );
}

#[test]
fn test_protocol_type() {
    let schema = Some("schema".to_string());
    let data_formats = Some(vec!["format".to_string()]);
    let protocol_type = protocols::Type {
        schema: schema.clone(),
        data_formats: data_formats.clone(),
        encryption_required: None,
    };
    let json = json!({
        "schema": schema,
        "dataFormats": data_formats,
    });
    assert_eq!(serde_json::to_value(&protocol_type).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<protocols::Type>(json).unwrap(),
        protocol_type
    );
}

#[test]
fn test_protocol_rule() {
    let encryption = Some(protocols::PathEncryption {
        root_key_id: "root".to_string(),
        public_key_jwk: JWK::generate_ed25519().unwrap(),
    });
    let actions = vec![protocols::Action::Who(ActionWho {
        who: protocols::Who::Anyone,
        of: None,
        can: vec![protocols::Can::Read],
    })];

    let role = Some(true);
    let size = Some(protocols::Size {
        min: None,
        max: None,
    });
    let tags = Some(protocols::Tags {
        required_tags: vec!["tag".to_string()],
        allow_undefined_tags: Some(true),
        tags: BTreeMap::new(),
    });

    let rules: BTreeMap<String, protocols::RuleSet> = BTreeMap::new();
    let protocol_rule = protocols::RuleSet {
        encryption: encryption.clone(),
        actions: actions.clone(),
        role,
        reference: None,
        size: size.clone(),
        tags: tags.clone(),
        record_limit: None,
        immutable: None,
        delivery: None,
        squash: None,
        rules,
    };

    let json = json!({
        "$encryption": encryption.clone(),
        "$actions": actions,
        "$role": role,
        "$size": size,
        "$tags": tags,
    });

    assert_eq!(serde_json::to_value(&protocol_rule).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<protocols::RuleSet>(json).unwrap(),
        protocol_rule
    );

    let json = json!({
        "$encryption": encryption,
        "$actions": actions,
        "$role": role,
        "$size": size,
        "$tags": tags,
        "key": {},
    });

    let mut rules: BTreeMap<String, protocols::RuleSet> = BTreeMap::new();
    rules.insert("key".to_string(), protocols::RuleSet::default());
    let protocol_rule = protocols::RuleSet {
        encryption,
        actions,
        role,
        reference: None,
        size,
        tags,
        record_limit: None,
        immutable: None,
        delivery: None,
        squash: None,
        rules,
    };

    assert_eq!(serde_json::to_value(&protocol_rule).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<protocols::RuleSet>(json).unwrap(),
        protocol_rule
    );
}
