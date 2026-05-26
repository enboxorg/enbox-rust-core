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

use dwn_rs_core::filters::{
    Filter, FilterKey, Filters, MessageSort, Pagination, ValueFilter,
};
use dwn_rs_core::interfaces::messages::Descriptor;
use dwn_rs_core::stores::{KeyValues, MessageStore};
use dwn_rs_core::{Message, Value};
use dwn_rs_stores::SqliteStore;
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = SqliteStore::in_memory();
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
            store
                .put(&params.tenant, message, indexes)
                .await
                .map(|_| JsonValue::Null)
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
            struct QueryParams {
                tenant: String,
                filters: JsonValue,
                #[serde(default)]
                message_sort: Option<MessageSort>,
                #[serde(default)]
                pagination: Option<Pagination>,
            }
            let params: QueryParams =
                serde_json::from_value(params).map_err(|err| err.to_string())?;
            let filters = filters_from_json(&params.filters)?;
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
            struct CountParams {
                tenant: String,
                filters: JsonValue,
                #[serde(default)]
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
        other => Err(format!("unsupported method: {other}")),
    }
}

fn filters_from_json(value: &JsonValue) -> Result<Filters, String> {
    let raw: Vec<BTreeMap<String, Filter<Value>>> =
        serde_json::from_value(value.clone()).map_err(|err| err.to_string())?;
    let sets = raw
        .into_iter()
        .map(|filter| {
            filter
                .into_iter()
                .map(|(key, filter)| {
                    let filter_key = if let Some(tag) = key.strip_prefix("tag.") {
                        FilterKey::Tag(tag.to_string())
                    } else {
                        FilterKey::Index(key)
                    };
                    (filter_key, filter)
                })
                .collect::<ValueFilter<FilterKey>>()
        })
        .collect::<Vec<_>>();
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
