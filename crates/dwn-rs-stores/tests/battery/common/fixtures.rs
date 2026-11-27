//! Shared message/index/resolver fixtures for the #169 battery.
//!
//! One copy of each builder so C1/C4/C5 assert against identical fixtures
//! instead of drifting per-file copies.

use std::collections::BTreeMap;

use dwn_rs_core::auth::{ed25519_jwk, StaticPublicKeyResolver};
use dwn_rs_core::descriptors::{DeleteDescriptor, Records, RecordsWriteDescriptor};
use dwn_rs_core::fields::{MessageFields, WriteFields};
use dwn_rs_core::stores::{EventLogReadOptions, KeyValues, ReplicationFeedReader};
use dwn_rs_core::{Descriptor, Fields, Message, Value};

/// RecordsDelete fixture (feed-eligible).
pub fn delete_message(record_id: &str, timestamp: &str) -> Message<Descriptor> {
    Message {
        descriptor: Descriptor::Records(Box::new(Records::Delete(Box::new(DeleteDescriptor {
            message_timestamp: timestamp.parse().expect("valid fixture timestamp"),
            record_id: record_id.to_string(),
            prune: false,
            permission_grant_id: None,
        })))),
        fields: Fields::Authorization(Default::default()),
    }
}

/// RecordsWrite fixture (feed-eligible) with a deterministic record id.
pub fn write_message(
    timestamp: &str,
    module: &str,
    encoded_data: Option<&str>,
) -> Message<Descriptor> {
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let descriptor =
        Descriptor::Records(Box::new(Records::Write(Box::new(RecordsWriteDescriptor {
            module: module.to_string(),
            module_path: "note".to_string(),
            recipient: None,
            schema: None,
            tags: None,
            parent_id: None,
            data_cid: "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e".to_string(),
            data_size: 11,
            date_created: timestamp,
            message_timestamp: timestamp,
            published: None,
            date_published: None,
            data_format: "text/plain".to_string(),
            permission_grant_id: None,
            squash: None,
        }))));
    let fields = Fields::Write(WriteFields {
        record_id: Some(format!("record-{timestamp}")),
        encoded_data: encoded_data.map(ToString::to_string),
        ..Default::default()
    });

    Message { descriptor, fields }
}

/// Canonical CID of a fixture (fields normalized first).
pub fn message_cid(message: &Message<Descriptor>) -> String {
    let mut canonical = message.clone();
    canonical.fields.encoded_data();
    canonical.cid().unwrap().to_string()
}

/// Indexes derived from a write fixture's descriptor.
pub fn indexes_for_message(message: &Message<Descriptor>) -> KeyValues {
    let mut indexes = BTreeMap::new();
    indexes.insert(
        "messageTimestamp".to_string(),
        Value::String(
            serde_json::to_value(&message.descriptor).unwrap()["messageTimestamp"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
    );
    indexes.insert(
        "interface".to_string(),
        Value::String("Records".to_string()),
    );
    indexes.insert("method".to_string(), Value::String("Write".to_string()));
    if let Some(module) = serde_json::to_value(&message.descriptor).unwrap()["module"].as_str() {
        indexes.insert("module".to_string(), Value::String(module.to_string()));
    }
    indexes
}

/// Feed indexes with explicit module / tag.module / marker values.
pub fn feed_indexes(module: Option<&str>, tag_module: Option<&str>, marker: &str) -> KeyValues {
    let mut out = KeyValues::new();
    out.insert("marker".to_string(), Value::String(marker.to_string()));
    if let Some(module) = module {
        out.insert("module".to_string(), Value::String(module.to_string()));
    }
    if let Some(tagged) = tag_module {
        out.insert("tag.module".to_string(), Value::String(tagged.to_string()));
    }
    out
}

/// Full feed read as `(seq, message_cid)` pairs.
pub async fn full_read(store: &impl ReplicationFeedReader, tenant: &str) -> Vec<(String, String)> {
    store
        .log_read(tenant, EventLogReadOptions::default())
        .await
        .expect("feed read")
        .events
        .into_iter()
        .map(|entry| (entry.seq, entry.message_cid.expect("feed entry has a CID")))
        .collect()
}

/// Single-key test resolver (did:example:alice#key1).
pub fn test_resolver() -> StaticPublicKeyResolver {
    StaticPublicKeyResolver::new(BTreeMap::from([(
        "did:example:alice#key1".to_string(),
        ed25519_jwk(
            "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            None,
            Some("did:example:alice#key1"),
        )
        .unwrap(),
    )]))
}
