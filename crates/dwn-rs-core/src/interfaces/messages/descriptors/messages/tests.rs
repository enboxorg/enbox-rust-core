use std::collections::BTreeMap;
use std::str::FromStr;

use crate::canonical_rfc3339;
use crate::filters::message_filters::Messages as MessagesFilter;
use crate::interfaces::messages::descriptors::{MESSAGES, QUERY, READ, SUBSCRIBE, SYNC};

use super::*;
use chrono::{DateTime, Utc};
use cid::Cid;
use serde_json::json;

#[test]
fn test_read_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    // new random DagCbor encoded CID
    let message_cid = Cid::new_v1(0x71, cid::multihash::Multihash::default());
    let descriptor = ReadDescriptor {
        message_timestamp,
        message_cid: Some(message_cid),
        permission_grant_id: None,
    };
    let json = json!({
        "messageTimestamp": message_timestamp,
        "messageCid": message_cid.to_string(),
        "interface": MESSAGES,
        "method": READ,
    });
    assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<ReadDescriptor>(json).unwrap(),
        descriptor
    );
}

#[test]
fn test_query_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    let filters = vec![MessagesFilter::default()];
    let cursor = Some(crate::Cursor::default());
    let descriptor = QueryDescriptor {
        message_timestamp,
        filters,
        cursor: cursor.clone(),
    };
    let json = json!({
        "messageTimestamp": message_timestamp,
        "filters": [MessagesFilter::default()],
        "cursor": cursor,
        "interface": MESSAGES,
        "method": QUERY,
    });
    assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<QueryDescriptor>(json).unwrap(),
        descriptor
    );
}

#[test]
fn test_subscribe_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    let filters = vec![MessagesFilter::default()];
    let descriptor = SubscribeDescriptor {
        message_timestamp,
        filters,
        permission_grant_id: None,
        cursor: None,
    };
    let json = json!({
        "messageTimestamp": message_timestamp,
        "filters": [MessagesFilter::default()],
        "interface": MESSAGES,
        "method": SUBSCRIBE
    });
    assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<SubscribeDescriptor>(json).unwrap(),
        descriptor
    );
}

#[test]
fn test_sync_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    let descriptor = SyncDescriptor {
        message_timestamp,
        action: SyncAction::Diff,
        protocol: Some("http://example.com/protocol".to_string()),
        prefix: None,
        permission_grant_id: Some("grant-1".to_string()),
        hashes: Some(BTreeMap::from([(
            "0101".to_string(),
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        )])),
        depth: Some(4),
    };
    let json = json!({
        "messageTimestamp": message_timestamp,
        "interface": MESSAGES,
        "method": SYNC,
        "action": "diff",
        "protocol": "http://example.com/protocol",
        "permissionGrantId": "grant-1",
        "hashes": {
            "0101": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        },
        "depth": 4,
    });
    assert_eq!(serde_json::to_value(&descriptor).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<SyncDescriptor>(json).unwrap(),
        descriptor
    );
}
