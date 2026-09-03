//! JSON-RPC store bridge for TypeScript TestSuite store injection.
//!
//! Delegates MessageStore operations to [`SqliteStore`] (the same backend used by
//! [`SqliteNativeDwn`]). One request/response per line on stdin/stdout.
//!
//! ```bash
//! cargo run -p dwn-rs-stores --example store_injection_server
//! ENBOX_TS_ROOT=../enbox bun test tools/interop/testsuite-injection.test.ts
//! ```

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

use dwn_rs_core::filters::{Filter, FilterKey, Filters, MessageSort, Pagination};
use dwn_rs_core::interfaces::messages::Descriptor;
use dwn_rs_core::stores::{KeyValues, MessageStore};
use dwn_rs_core::Message;
use dwn_rs_stores::SqliteStore;
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};

/// The TS adapter sends `{}` for "no sort"; an empty map is not a valid
/// `MessageSort` enum, so normalize it (and null/missing) to `None`.
fn empty_sort_as_none<'de, D>(deserializer: D) -> Result<Option<MessageSort>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<JsonValue>::deserialize(deserializer)?;
    match value {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Object(map)) if map.is_empty() => Ok(None),
        Some(other) => serde_json::from_value(other)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = SqliteStore::in_memory(None);
    store.open().await?;

    println!("READY");
    io::stdout().flush()?;

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim() == "stop" {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }

        let request: RpcRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(err) => {
                write_response(None, None, Some(err.to_string()))?;
                continue;
            }
        };

        let response = handle_request(&store, &request.method, request.params).await;
        match response {
            Ok(result) => write_response(Some(request.id), Some(result), None)?,
            Err(err) => write_response(Some(request.id), None, Some(err))?,
        }
    }

    store.close().await;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    id: u64,
    method: String,
    params: JsonValue,
}

async fn handle_request(
    store: &SqliteStore,
    method: &str,
    params: JsonValue,
) -> Result<JsonValue, String> {
    match method {
        "open" => {
            // Store is opened at startup; idempotent for TestStores lifecycle.
            Ok(JsonValue::Null)
        }
        "close" => Ok(JsonValue::Null),
        "clear" => store
            .clear()
            .await
            .map(|_| JsonValue::Null)
            .map_err(|err| err.to_string()),
        "put" => {
            #[derive(Deserialize)]
            struct PutParams {
                tenant: String,
                message: JsonValue,
                indexes: JsonValue,
            }
            let params: PutParams =
                serde_json::from_value(params).map_err(|err| err.to_string())?;
            let message: Message<Descriptor> =
                serde_json::from_value(params.message).map_err(|err| err.to_string())?;
            let indexes: KeyValues =
                serde_json::from_value(params.indexes).map_err(|err| err.to_string())?;
            let message_cid = message
                .message_cid()
                .map(|cid| cid.to_string())
                .map_err(|err| err.to_string())?;
            store
                .put(&params.tenant, message, indexes)
                .await
                .map(|_| json!({ "messageCid": message_cid }))
                .map_err(|err| err.to_string())
        }
        "get" => {
            #[derive(Deserialize)]
            struct GetParams {
                tenant: String,
                cid: String,
            }
            let params: GetParams =
                serde_json::from_value(params).map_err(|err| err.to_string())?;
            match store.get(&params.tenant, &params.cid).await {
                Ok(Some(message)) => serde_json::to_value(message).map_err(|err| err.to_string()),
                Ok(None) => Ok(JsonValue::Null),
                Err(err) => Err(err.to_string()),
            }
        }
        "query" => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct QueryParams {
                tenant: String,
                filters: JsonValue,
                #[serde(default, deserialize_with = "empty_sort_as_none")]
                message_sort: Option<MessageSort>,
                #[serde(default)]
                pagination: Option<Pagination>,
            }
            let params: QueryParams =
                serde_json::from_value(params).map_err(|err| format!("params: {err}"))?;
            let filters =
                filters_from_json(&params.filters).map_err(|err| format!("filters: {err}"))?;
            let result = store
                .query(
                    &params.tenant,
                    filters,
                    params.message_sort,
                    params.pagination,
                )
                .await
                .map_err(|err| err.to_string())?;
            serde_json::to_value(result).map_err(|err| err.to_string())
        }
        "count" => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct CountParams {
                tenant: String,
                filters: JsonValue,
                #[serde(default, deserialize_with = "empty_sort_as_none")]
                message_sort: Option<MessageSort>,
            }
            let params: CountParams =
                serde_json::from_value(params).map_err(|err| err.to_string())?;
            let filters = filters_from_json(&params.filters)?;
            store
                .count(&params.tenant, filters, params.message_sort)
                .await
                .map(|count| json!(count))
                .map_err(|err| err.to_string())
        }
        "delete" => {
            #[derive(Deserialize)]
            struct DeleteParams {
                tenant: String,
                cid: String,
            }
            let params: DeleteParams =
                serde_json::from_value(params).map_err(|err| err.to_string())?;
            store
                .delete(&params.tenant, &params.cid)
                .await
                .map(|_| JsonValue::Null)
                .map_err(|err| err.to_string())
        }
        "updateIndexes" => {
            #[derive(Deserialize)]
            struct UpdateIndexesParams {
                tenant: String,
                #[serde(rename = "messageCid")]
                cid: String,
                indexes: JsonValue,
            }
            let params: UpdateIndexesParams =
                serde_json::from_value(params).map_err(|err| err.to_string())?;
            let indexes: KeyValues =
                serde_json::from_value(params.indexes).map_err(|err| err.to_string())?;
            store
                .update_indexes(&params.tenant, &params.cid, indexes)
                .await
                .map(|_| JsonValue::Null)
                .map_err(|err| err.to_string())
        }
        "updateMessageAndIndexes" => {
            #[derive(Deserialize)]
            struct UpdateMessageParams {
                tenant: String,
                #[serde(rename = "messageCid")]
                cid: String,
                message: JsonValue,
                indexes: JsonValue,
            }
            let params: UpdateMessageParams =
                serde_json::from_value(params).map_err(|err| err.to_string())?;
            let message: Message<Descriptor> =
                serde_json::from_value(params.message).map_err(|err| err.to_string())?;
            let indexes: KeyValues =
                serde_json::from_value(params.indexes).map_err(|err| err.to_string())?;
            store
                .update_message_and_indexes(&params.tenant, &params.cid, message, indexes)
                .await
                .map(|_| JsonValue::Null)
                .map_err(|err| err.to_string())
        }
        other => Err(format!("unsupported method: {other}")),
    }
}

fn filters_from_json(value: &JsonValue) -> Result<Filters, String> {
    // NOTE: `Filter` deserializes untagged with `Equal` first, so every JSON
    // value would land as `Equal` (ranges, prefixes, and subtrees included).
    // Subtree shapes are intercepted here at the raw level; only `contextId`
    // and `protocolPath` carry hierarchical path semantics, matching the
    // SDK's `assertValidSubtreeFilters`. Other non-equal shapes remain a
    // known gap of this bridge.
    let raw: Vec<BTreeMap<String, JsonValue>> =
        serde_json::from_value(value.clone()).map_err(|err| err.to_string())?;
    let mut sets = Vec::new();
    for set in raw {
        let mut out = BTreeMap::new();
        for (key, filter_value) in set {
            let is_subtree = filter_value.as_object().is_some_and(|map| {
                map.len() == 1 && map.get("subtree").is_some_and(|v| v.is_string())
            });
            let filter = if is_subtree {
                if key != "contextId" && key != "protocolPath" {
                    return Err(format!("SubtreeFilter is not supported for index '{key}'"));
                }
                Filter::Subtree(dwn_rs_core::filters::SubtreeFilter {
                    subtree: filter_value
                        .get("subtree")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_string(),
                })
            } else {
                serde_json::from_value(filter_value)
                    .map_err(|err: serde_json::Error| err.to_string())?
            };
            let filter_key = if let Some(tag) = key.strip_prefix("tag.") {
                FilterKey::Tag(tag.to_string())
            } else {
                FilterKey::Index(key)
            };
            out.insert(filter_key, filter);
        }
        sets.push(out);
    }
    Ok(Filters::from(sets))
}

fn write_response(
    id: Option<u64>,
    result: Option<JsonValue>,
    error: Option<String>,
) -> Result<(), io::Error> {
    let response = match (result, error) {
        (_, Some(error)) => json!({ "id": id, "error": error }),
        (Some(result), None) => json!({ "id": id, "result": result }),
        (None, None) => json!({ "id": id, "result": null }),
    };
    writeln!(io::stdout(), "{response}")?;
    io::stdout().flush()
}
