//! Wire-format assertions for the `Modules` cutover.

use std::collections::BTreeMap;

use dwn_rs_core::descriptors::modules::ModulesMethod;
use dwn_rs_core::descriptors::{ModulesConfigureDescriptor, ModulesQueryDescriptor};
use dwn_rs_core::dwn::validation as message_validation;
use dwn_rs_core::dwn::MessageKind;
use dwn_rs_core::encryption::{DerivationScheme, KeyEncryption, ENCRYPTION_MODULE_URI};
use dwn_rs_core::errors::DwnErrorCode;
use dwn_rs_core::interfaces::messages::modules::{Definition, RuleSet, Type};
use dwn_rs_core::permissions::PERMISSIONS_MODULE_URI;
use dwn_rs_core::testing::parse_time;
use serde_json::{json, Value};

fn definition() -> Definition {
    Definition {
        module: "https://example.com/modules/notes".to_string(),
        published: true,
        uses: None,
        key_agreement: None,
        types: BTreeMap::from([(
            "note".to_string(),
            Type {
                schema: None,
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([("note".to_string(), RuleSet::default())]),
    }
}

fn configure_message(interface: &str) -> Value {
    json!({
        "descriptor": {
            "interface": interface,
            "method": "Configure",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z",
            "definition": {
                "module": "https://example.com/modules/notes",
                "published": true,
                "types": { "note": {} },
                "structure": { "note": {} }
            }
        },
        "authorization": {}
    })
}

// Covers: DWN-PROTO-001
#[test]
fn modules_configure_and_query_serialize_modules_vocabulary() {
    let descriptor = ModulesConfigureDescriptor {
        message_timestamp: parse_time("2025-01-01T00:00:00.000000Z"),
        definition: definition(),
        permission_grant_id: None,
    };
    let wire = serde_json::to_value(&descriptor).expect("descriptor must serialize");
    assert_eq!(wire["interface"], "Modules");
    assert_eq!(wire["method"], "Configure");
    assert_eq!(
        wire["definition"]["module"],
        "https://example.com/modules/notes"
    );
    assert!(wire["definition"].get("protocol").is_none());

    let query = ModulesQueryDescriptor {
        message_timestamp: parse_time("2025-01-01T00:00:00.000000Z"),
        filter: Some(dwn_rs_core::descriptors::modules::QueryFilter {
            module: Some("https://example.com/modules/notes".to_string()),
            recipient: None,
        }),
        permission_grant_id: None,
    };
    let wire = serde_json::to_value(&query).expect("descriptor must serialize");
    assert_eq!(wire["interface"], "Modules");
    assert_eq!(wire["method"], "Query");
    assert_eq!(
        wire["filter"]["module"],
        "https://example.com/modules/notes"
    );
    assert!(wire["filter"].get("protocol").is_none());

    let kind = MessageKind::from_message(&configure_message("Modules"))
        .expect("Modules interface must route");
    assert_eq!(kind, MessageKind::Modules(ModulesMethod::Configure));
}

// Covers: ENBOX-ERR-001
#[test]
fn retired_protocols_interface_and_error_codes_are_rejected() {
    assert!(MessageKind::from_message(&configure_message("Protocols")).is_err());
    assert!(message_validation::validate_message(&configure_message("Protocols")).is_err());
    message_validation::validate_message(&configure_message("Modules"))
        .expect("Modules interface must validate");

    assert_eq!(
        DwnErrorCode::ModuleAuthorizationImmutableRecord.as_str(),
        "ModuleAuthorizationImmutableRecord"
    );
    assert_eq!(
        DwnErrorCode::ModulesConfigureReservedEncryptionControlPath.as_str(),
        "ModulesConfigureReservedEncryptionControlPath"
    );
    assert!(DwnErrorCode::try_from("ProtocolsConfigureReservedEncryptionControlPath").is_err());
}

// Covers: DWN-PROTO-001
#[test]
fn messages_filter_rejects_module_path_with_module_path_prefix() {
    let message = json!({
        "descriptor": {
            "interface": "Messages",
            "method": "Query",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z",
            "filters": [
                { "modulePath": "note", "modulePathPrefix": "note" }
            ]
        },
        "authorization": {}
    });
    let error = message_validation::validate_message(&message)
        .expect_err("mutually exclusive module filters must be rejected");
    assert_eq!(error.code, DwnErrorCode::SchemaValidatorFailure);

    let accepted = json!({
        "descriptor": {
            "interface": "Messages",
            "method": "Query",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z",
            "filters": [{ "interface": "Modules", "module": "https://example.com/modules/notes" }]
        },
        "authorization": {}
    });
    message_validation::validate_message(&accepted).expect("a single Modules filter must validate");
}

// Covers: DWN-PROTO-006
#[test]
fn key_encryption_entries_describe_module_derived_keys() {
    let module_path: KeyEncryption = serde_json::from_value(json!({
        "algorithm": "X25519-HKDF-SHA256+A256KW",
        "keyId": "qKpn4plbkMfU3yWDjgvuQc0qGzvQJn031umInc0PnAE",
        "derivationScheme": "modulePath",
        "ephemeralPublicKey": { "kty": "OKP", "crv": "X25519", "x": "GDW9p9yD8p7p9yD8p7p9yD8p7p9yD8p7p9yD8p4" },
        "encryptedKey": "AAAAAAAAAAAAAAAA"
    }))
    .expect("modulePath entry must deserialize");
    assert_eq!(
        module_path.derivation_scheme(),
        DerivationScheme::ModulePath
    );
    assert_eq!(module_path.module(), None);

    let role_audience: KeyEncryption = serde_json::from_value(json!({
        "algorithm": "X25519-HKDF-SHA256+A256KW",
        "keyId": "qKpn4plbkMfU3yWDjgvuQc0qGzvQJn031umInc0PnAE",
        "derivationScheme": "roleAudience",
        "module": "https://example.com/modules/notes",
        "rolePath": "note/member",
        "ephemeralPublicKey": { "kty": "OKP", "crv": "X25519", "x": "GDW9p9yD8p7p9yD8p7p9yD8p7p9yD8p7p9yD8p4" },
        "encryptedKey": "AAAAAAAAAAAAAAAA"
    }))
    .expect("roleAudience entry must deserialize");
    assert_eq!(
        role_audience.derivation_scheme(),
        DerivationScheme::RoleAudience
    );
    assert_eq!(
        role_audience.module(),
        Some("https://example.com/modules/notes")
    );

    assert!(
        serde_json::from_value::<KeyEncryption>(json!({
            "algorithm": "X25519-HKDF-SHA256+A256KW",
            "keyId": "qKpn4plbkMfU3yWDjgvuQc0qGzvQJn031umInc0PnAE",
            "derivationScheme": "roleAudience",
            "protocol": "https://example.com/modules/notes",
            "rolePath": "note/member",
            "ephemeralPublicKey": { "kty": "OKP", "crv": "X25519", "x": "GDW9p9yD8p7p9yD8p7p9yD8p7p9yD8p7p9yD8p4" },
            "encryptedKey": "AAAAAAAAAAAAAAAA"
        }))
        .is_err(),
        "the retired roleAudience protocol field must not be accepted"
    );
    assert_eq!(
        ENCRYPTION_MODULE_URI,
        "https://identity.foundation/dwn/modules/encryption"
    );
    assert_eq!(
        PERMISSIONS_MODULE_URI,
        "https://identity.foundation/dwn/permissions"
    );
}
