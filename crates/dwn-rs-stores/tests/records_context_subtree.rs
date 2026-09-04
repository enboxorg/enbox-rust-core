//! Commit 1 of #190: `contextId` subtree selection must be boundary-aware
//! on both store backends.
//!
//! Scope `a/b` selects `a/b` and `a/b/...` but never the lexical sibling
//! `a/bc`. Memory matching runs the shared `matches_filters` engine while
//! SQLite translates `Filter::Subtree` to SQL; both populations must agree.
//!
//! Covers: DWN-PROTO-001, DWN-PROTO-002

use std::collections::{BTreeMap, BTreeSet};

use dwn_rs_core::stores::memory::MemoryMessageStore;
use dwn_rs_core::stores::{KeyValues, MessageStore};
use dwn_rs_core::{Descriptor, Filter, FilterKey, Filters, Message, SubtreeFilter, Value};
use serde_json::json;

use dwn_rs_stores::SqliteStore;

const TENANT: &str = "did:example:alice";

const CONTEXTS: [&str; 4] = ["a/b", "a/b/c", "a/bc", "a/b-sibling"];

fn context_message(record_id: &str, context_id: &str) -> Message<Descriptor> {
    serde_json::from_value(json!({
        "descriptor": {
            "interface": "Records",
            "method": "Write",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z",
            "dateCreated": "2025-01-01T00:00:00.000000Z",
            "dataCid": "bafkreighhqlnlu3xumutodqyjeg6dkd6bhuhqydnemkjgoyn7eveukkfai",
            "dataSize": 0,
            "dataFormat": "text/plain",
            "protocol": "https://example.com/protocol/threads",
            "protocolPath": "thread/message"
        },
        "recordId": record_id,
        "contextId": context_id
    }))
    .expect("context message must deserialize")
}

fn context_indexes(record_id: &str, context_id: &str) -> KeyValues {
    BTreeMap::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        ("method".to_string(), Value::String("Write".to_string())),
        (
            "protocol".to_string(),
            Value::String("https://example.com/protocol/threads".to_string()),
        ),
        (
            "protocolPath".to_string(),
            Value::String("thread/message".to_string()),
        ),
        ("recordId".to_string(), Value::String(record_id.to_string())),
        (
            "contextId".to_string(),
            Value::String(context_id.to_string()),
        ),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "messageTimestamp".to_string(),
            Value::String("2025-01-01T00:00:00.000000Z".to_string()),
        ),
    ])
}

fn subtree_filter(scope: &str) -> Filters {
    Filters::from(BTreeMap::from([(
        FilterKey::Index("contextId".to_string()),
        Filter::Subtree(SubtreeFilter {
            subtree: scope.to_string(),
        }),
    )]))
}

async fn seed(store: &impl MessageStore) -> BTreeMap<String, String> {
    let mut cids = BTreeMap::new();
    for (index, context_id) in CONTEXTS.iter().enumerate() {
        let record_id = format!("ctx-record-{index}");
        let message = context_message(&record_id, context_id);
        cids.insert(
            context_id.to_string(),
            message.cid().expect("message must have a CID").to_string(),
        );
        store
            .put(TENANT, message, context_indexes(&record_id, context_id))
            .await
            .expect("seed message must be stored");
    }
    cids
}

async fn query_cids(store: &impl MessageStore, scope: &str) -> BTreeSet<String> {
    store
        .query(TENANT, subtree_filter(scope), None, None)
        .await
        .expect("subtree query must succeed")
        .messages
        .iter()
        .map(|message| message.cid().expect("message must have a CID").to_string())
        .collect()
}

#[tokio::test]
async fn context_subtree_scope_agrees_across_backends() {
    let mut memory = MemoryMessageStore::default();
    MessageStore::open(&mut memory)
        .await
        .expect("memory store must open");
    let mut sqlite = SqliteStore::in_memory(None);
    MessageStore::open(&mut sqlite)
        .await
        .expect("sqlite store must open");

    let memory_cids = seed(&memory).await;
    let sqlite_cids = seed(&sqlite).await;
    assert_eq!(
        memory_cids, sqlite_cids,
        "identical seed messages must produce identical CIDs"
    );

    let expected: BTreeSet<String> = ["a/b", "a/b/c"]
        .into_iter()
        .map(|context| memory_cids[context].clone())
        .collect();

    let memory_result = query_cids(&memory, "a/b").await;
    let sqlite_result = query_cids(&sqlite, "a/b").await;

    assert_eq!(
        memory_result, expected,
        "memory scope a/b must select exact and descendant contexts only"
    );
    assert_eq!(
        sqlite_result, expected,
        "sqlite scope a/b must select exact and descendant contexts only"
    );
    assert_eq!(
        memory_result, sqlite_result,
        "both backends must return the same population"
    );

    // The lexical sibling is addressable on its own scope in both backends.
    let sibling_expected: BTreeSet<String> = [memory_cids["a/bc"].clone()].into_iter().collect();
    assert_eq!(query_cids(&memory, "a/bc").await, sibling_expected);
    assert_eq!(query_cids(&sqlite, "a/bc").await, sibling_expected);
}
