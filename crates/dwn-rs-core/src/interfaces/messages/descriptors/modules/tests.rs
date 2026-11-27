use std::collections::BTreeMap;

use crate::canonical_rfc3339;
use crate::interfaces::messages::descriptors::{CONFIGURE, MODULES};
use crate::modules::{self, ActionWho};

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
    let definition = modules::Definition {
        module: "example".to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::new(),
        structure: BTreeMap::new(),
    };
    let descriptor = ModulesConfigureDescriptor {
        message_timestamp,
        definition,
        permission_grant_id: None,
    };
    let json = json!({
        "messageTimestamp": canonical_rfc3339(message_timestamp),
        "definition": {
            "module": "example",
            "published": true,
            "types": {},
            "structure": {},
        },
        "interface": MODULES,
        "method": CONFIGURE,
    });
    assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<ModulesConfigureDescriptor>(json).unwrap(),
        descriptor
    );
}

#[test]
fn test_module_definition() {
    let module = "example".to_string();
    let published = true;
    let types = BTreeMap::new();
    let structure = BTreeMap::new();
    let definition = modules::Definition {
        module: module.clone(),
        published,
        uses: None,
        key_agreement: None,
        types,
        structure,
    };
    let json = json!({
        "module": module,
        "published": published,
        "types": {},
        "structure": {},
    });
    assert_eq!(serde_json::to_value(&definition).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<modules::Definition>(json).unwrap(),
        definition
    );
}

#[test]
fn test_module_type() {
    let schema = Some("schema".to_string());
    let data_formats = Some(vec!["format".to_string()]);
    let module_type = modules::Type {
        schema: schema.clone(),
        data_formats: data_formats.clone(),
        encryption_required: None,
    };
    let json = json!({
        "schema": schema,
        "dataFormats": data_formats,
    });
    assert_eq!(serde_json::to_value(&module_type).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<modules::Type>(json).unwrap(),
        module_type
    );
}

#[test]
fn test_module_rule() {
    let public_key_jwk: JWK = serde_json::from_value(serde_json::json!({
        "kty": "OKP",
        "crv": "X25519",
        "x": "GDW9p9yD8p7p9yD8p7p9yD8p7p9yD8p7p9yD8p4"
    }))
    .unwrap();
    let key_agreement = Some(modules::ModuleKeyAgreement { public_key_jwk });
    let actions = vec![modules::Action::Who(ActionWho {
        who: modules::Who::Anyone,
        of: None,
        can: vec![modules::Can::Read],
    })];

    let role = Some(true);
    let size = Some(modules::Size {
        min: None,
        max: None,
    });
    let tags = Some(modules::Tags {
        required_tags: vec!["tag".to_string()],
        allow_undefined_tags: Some(true),
        tags: BTreeMap::new(),
    });

    let rules: BTreeMap<String, modules::RuleSet> = BTreeMap::new();
    let module_rule = modules::RuleSet {
        key_agreement: key_agreement.clone(),
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
        "$keyAgreement": key_agreement.clone(),
        "$actions": actions,
        "$role": role,
        "$size": size,
        "$tags": tags,
    });

    assert_eq!(serde_json::to_value(&module_rule).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<modules::RuleSet>(json).unwrap(),
        module_rule
    );

    let json = json!({
        "$keyAgreement": key_agreement,
        "$actions": actions,
        "$role": role,
        "$size": size,
        "$tags": tags,
        "key": {},
    });

    let mut rules: BTreeMap<String, modules::RuleSet> = BTreeMap::new();
    rules.insert("key".to_string(), modules::RuleSet::default());
    let module_rule = modules::RuleSet {
        key_agreement,
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

    assert_eq!(serde_json::to_value(&module_rule).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<modules::RuleSet>(json).unwrap(),
        module_rule
    );
}
