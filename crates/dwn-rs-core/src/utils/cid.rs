use bytes::Bytes;
use futures_util::TryStreamExt;
use ipld_core::ipld::Ipld;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::TryReserveError;

use cid::Cid;
use futures_util::TryStream;
use multihash_codetable::Code;
use multihash_codetable::MultihashDigest;
use serde_ipld_dagcbor::EncodeError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek};

const DAG_CBOR_CODEC: u64 = 0x71;

pub fn generate_cid<B>(data: B) -> Result<Cid, EncodeError<TryReserveError>>
where
    B: AsRef<[u8]>,
{
    let mh = Code::Sha2_256.digest(data.as_ref());
    let cid = Cid::new_v1(DAG_CBOR_CODEC, mh);

    Ok(cid)
}

pub fn generate_cid_from_serialized<T: serde::Serialize>(
    data: T,
) -> Result<Cid, EncodeError<TryReserveError>> {
    let serialized = serde_ipld_dagcbor::to_vec(&data)?;
    generate_cid(serialized)
}

/// Generates a DAG-CBOR CID from JSON using IPLD numeric semantics.
pub fn generate_cid_from_json(value: &Value) -> Result<Cid, EncodeError<TryReserveError>> {
    generate_cid_from_serialized(json_value_to_ipld(value))
}

/// Converts JSON into IPLD before DAG-CBOR serialization.
pub fn json_value_to_ipld(value: &Value) -> Ipld {
    match value {
        Value::Null => Ipld::Null,
        Value::Bool(value) => Ipld::Bool(*value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ipld::Integer(value.into())
            } else if let Some(value) = value.as_u64() {
                Ipld::Integer(value.into())
            } else {
                Ipld::Float(value.as_f64().expect("JSON number must be finite"))
            }
        }
        Value::String(value) => Ipld::String(value.clone()),
        Value::Array(values) => Ipld::List(values.iter().map(json_value_to_ipld).collect()),
        Value::Object(values) => Ipld::Map(
            values
                .iter()
                .map(|(key, value)| (key.clone(), json_value_to_ipld(value)))
                .collect::<BTreeMap<_, _>>(),
        ),
    }
}

pub async fn generate_cid_from_stream<S: TryStream<Ok = Bytes> + Unpin>(
    stream: S,
) -> Result<Cid, EncodeError<TryReserveError>>
where
    S::Error: Into<EncodeError<TryReserveError>>,
{
    let mut buf = Vec::new();
    let _ = stream
        .try_for_each(|chunk| {
            buf.extend_from_slice(&chunk);
            async { Ok(()) }
        })
        .await;

    let mh = Code::Sha2_256.digest(&buf);
    let cid = Cid::new_v1(DAG_CBOR_CODEC, mh);

    Ok(cid)
}

pub async fn generate_cid_from_asyncreader<R>(
    reader: R,
) -> Result<Cid, EncodeError<TryReserveError>>
where
    R: AsyncRead + AsyncSeek + Unpin,
{
    let mut buf = Vec::new();
    reader
        .take(1024 * 1024)
        .read_to_end(&mut buf)
        .await
        .map_err(EncodeError::Write)
        .unwrap();

    let mh = Code::Sha2_256.digest(&buf);
    let cid = Cid::new_v1(DAG_CBOR_CODEC, mh);

    Ok(cid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;
    use std::str::FromStr;

    #[test]
    fn test_generate_cid() {
        let data = json!({
            "hello": "world",
        });

        let cid = generate_cid(data.to_string()).unwrap();

        assert_eq!(
            cid,
            Cid::from_str("bafyreietui4xdkiu4xvmx4fi2jivjtndbhb4drzpxomrjvd4mdz4w2avra").unwrap(),
        );
        assert_eq!(cid.codec(), DAG_CBOR_CODEC);
    }

    #[test]
    fn test_json_value_to_ipld_uses_ipld_numeric_types() {
        let data = json!({
            "integer": 1,
            "negative": -1,
            "float": 1.5,
            "list": [true, null, "value"],
        });

        let converted = json_value_to_ipld(&data);
        let expected = Ipld::Map(BTreeMap::from([
            ("float".to_string(), Ipld::Float(1.5)),
            ("integer".to_string(), Ipld::Integer(1.into())),
            (
                "list".to_string(),
                Ipld::List(vec![
                    Ipld::Bool(true),
                    Ipld::Null,
                    Ipld::String("value".to_string()),
                ]),
            ),
            ("negative".to_string(), Ipld::Integer((-1).into())),
        ]));

        assert_eq!(converted, expected);
    }

    #[tokio::test]
    async fn test_generate_cid_from_asyncreader() {
        // Define some sample data to read
        let data = b"Sample data to generate CID";

        // Create a cursor over the data, which implements AsyncRead + AsyncSeek
        let cursor = Cursor::new(data);

        // Call the function with the cursor
        let cid = generate_cid_from_asyncreader(cursor).await;
        assert!(cid.is_ok());
        let cid = cid.unwrap();

        // Verify that the CID is generated correctly
        // For a real test, you might compare the cid with a known value
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), DAG_CBOR_CODEC);

        // For demonstration: hash the data using the same logic to get the expected hash
        let expected_mh = multihash_codetable::Code::Sha2_256.digest(data);

        // Compare multihashes
        assert_eq!(cid.hash(), &expected_mh);
    }
}
