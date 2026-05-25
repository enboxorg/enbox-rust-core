//! Minimal in-memory SQLite native DWN example.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p dwn-rs-stores --example in_memory_dwn
//! ```

use std::collections::BTreeMap;

use dwn_rs_core::auth::{
    Jws, JwsPrivateJwk, JwsPublicJwk, PrivateJwkSigner, StaticPublicKeyResolver,
};
use dwn_rs_core::cid::generate_cid_from_json;
use dwn_rs_core::descriptors::ConfigureDescriptor;
use dwn_rs_core::interfaces::messages::protocols::{
    Action, ActionWho, Can, Definition, RuleSet, Type, Who,
};
use dwn_rs_stores::SqliteNativeDwn;
use serde_json::json;

const TENANT: &str = "did:example:alice";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let node = SqliteNativeDwn::open_in_memory(test_resolver()).await?;

    let configure = signed_configure_message(
        "http://example.com/in-memory-dwn",
        true,
        "2025-01-01T00:00:00.000000Z",
    )?;
    let configure_cid = generate_cid_from_json(&configure)?.to_string();

    let configure_reply = node.dwn().process_message(TENANT, configure).await;
    println!(
        "ProtocolsConfigure -> {} {}",
        configure_reply.status.code, configure_reply.status.detail
    );

    let read = signed_messages_read(&configure_cid, "2025-01-01T00:00:01.000000Z")?;
    let read_reply = node.dwn().process_message(TENANT, read).await;
    println!(
        "MessagesRead -> {} {}",
        read_reply.status.code, read_reply.status.detail
    );
    println!(
        "entry.messageCid = {}",
        read_reply.body["entry"]["messageCid"]
    );

    Ok(())
}

fn signed_configure_message(
    protocol: &str,
    published: bool,
    timestamp: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let definition = Definition {
        protocol: protocol.to_string(),
        published,
        uses: None,
        types: BTreeMap::from([(
            "note".to_string(),
            Type {
                schema: Some("http://schema.example.com/note".to_string()),
                data_formats: Some(vec!["text/plain".to_string()]),
                encryption_required: None,
            },
        )]),
        structure: BTreeMap::from([(
            "note".to_string(),
            RuleSet {
                actions: vec![Action::Who(ActionWho {
                    who: Who::Anyone,
                    of: None,
                    can: vec![Can::Create, Can::Read],
                })],
                ..Default::default()
            },
        )]),
    };
    let descriptor = ConfigureDescriptor {
        message_timestamp: timestamp.parse()?,
        permission_grant_id: None,
        definition,
    };
    let descriptor_json = serde_json::to_value(descriptor)?;
    sign_message(descriptor_json, json!({}))
}

fn signed_messages_read(
    message_cid: &str,
    timestamp: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let descriptor = json!({
        "interface": "Messages",
        "method": "Read",
        "messageCid": message_cid,
        "messageTimestamp": timestamp,
    });
    sign_message(descriptor, json!({}))
}

fn sign_message(
    descriptor: serde_json::Value,
    extra_payload: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut payload = json!({
        "descriptorCid": generate_cid_from_json(&descriptor)?.to_string(),
    });
    if let (Some(payload_obj), Some(extra_obj)) =
        (payload.as_object_mut(), extra_payload.as_object())
    {
        for (key, value) in extra_obj {
            payload_obj.insert(key.clone(), value.clone());
        }
    }
    let signature =
        Jws::create_general(serde_json::to_vec(&payload)?.as_slice(), &[test_signer()])?;
    Ok(json!({
        "descriptor": descriptor,
        "authorization": { "signature": signature }
    }))
}

fn test_signer() -> PrivateJwkSigner {
    PrivateJwkSigner::new(
        "did:example:alice#key1",
        "EdDSA",
        JwsPrivateJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            d: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string(),
            x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
            y: None,
            kid: Some("did:example:alice#key1".to_string()),
            alg: Some("EdDSA".to_string()),
        },
    )
}

fn test_resolver() -> StaticPublicKeyResolver {
    StaticPublicKeyResolver::new(BTreeMap::from([(
        "did:example:alice#key1".to_string(),
        JwsPublicJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".to_string(),
            y: None,
            kid: Some("did:example:alice#key1".to_string()),
            alg: Some("EdDSA".to_string()),
        },
    )]))
}
