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

const DAG_PB_CODEC: u64 = 0x70;
const DAG_CBOR_CODEC: u64 = 0x71;
const RAW_CODEC: u64 = 0x55;
const UNIXFS_CHUNK_SIZE: usize = 262_144;

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

/// Generates a message CID matching TypeScript `Message.getCid`.
///
/// Inline `encodedData` is transport-only and excluded from CID computation.
pub fn generate_message_cid_from_json(value: &Value) -> Result<Cid, EncodeError<TryReserveError>> {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("encodedData");
    }
    generate_cid_from_json(&value)
}

/// Generates a CID matching TypeScript `Cid.computeDagPbCidFromBytes`.
pub fn generate_dag_pb_cid_from_bytes<B>(data: B) -> Cid
where
    B: AsRef<[u8]>,
{
    let data = data.as_ref();

    if data.len() <= UNIXFS_CHUNK_SIZE {
        return generate_raw_cid(data);
    }

    let links = data
        .chunks(UNIXFS_CHUNK_SIZE)
        .map(|chunk| (generate_raw_cid(chunk), chunk.len() as u64))
        .collect::<Vec<_>>();
    let block_sizes = links.iter().map(|(_, size)| *size).collect::<Vec<_>>();
    let unixfs_data = encode_unixfs_file(data.len() as u64, &block_sizes);
    let dag_pb_node = encode_dag_pb_node(&unixfs_data, &links);

    Cid::new_v1(DAG_PB_CODEC, Code::Sha2_256.digest(&dag_pb_node))
}

/// Generates a CID matching TypeScript `Cid.computeDagPbCidFromStream`.
pub async fn generate_dag_pb_cid_from_stream<S, E>(mut stream: S) -> Result<Cid, E>
where
    S: TryStream<Ok = Bytes, Error = E> + Unpin,
{
    let mut buf = Vec::new();
    while let Some(chunk) = stream.try_next().await? {
        buf.extend_from_slice(&chunk);
    }

    Ok(generate_dag_pb_cid_from_bytes(buf))
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

fn generate_raw_cid(data: &[u8]) -> Cid {
    Cid::new_v1(RAW_CODEC, Code::Sha2_256.digest(data))
}

fn encode_unixfs_file(file_size: u64, block_sizes: &[u64]) -> Vec<u8> {
    let mut data = Vec::new();
    push_varint_field(&mut data, 1, 2);
    push_varint_field(&mut data, 3, file_size);

    for block_size in block_sizes {
        push_varint_field(&mut data, 4, *block_size);
    }

    data
}

fn encode_dag_pb_node(data: &[u8], links: &[(Cid, u64)]) -> Vec<u8> {
    let mut node = Vec::new();

    for (cid, total_size) in links {
        let link = encode_dag_pb_link(cid, *total_size);
        push_bytes_field(&mut node, 2, &link);
    }

    push_bytes_field(&mut node, 1, data);

    node
}

fn encode_dag_pb_link(cid: &Cid, total_size: u64) -> Vec<u8> {
    let mut link = Vec::new();
    push_bytes_field(&mut link, 1, &cid.to_bytes());
    push_bytes_field(&mut link, 2, b"");
    push_varint_field(&mut link, 3, total_size);
    link
}

fn push_bytes_field(out: &mut Vec<u8>, field_number: u64, value: &[u8]) {
    push_varint(out, (field_number << 3) | 2);
    push_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn push_varint_field(out: &mut Vec<u8>, field_number: u64, value: u64) {
    push_varint(out, field_number << 3);
    push_varint(out, value);
}

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }

    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
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
    fn generate_message_cid_from_json_excludes_encoded_data() {
        let with_encoded = json!({
            "descriptor": { "interface": "Records", "method": "Write" },
            "encodedData": "aGVsbG8"
        });
        let without_encoded = json!({
            "descriptor": { "interface": "Records", "method": "Write" }
        });

        assert_eq!(
            generate_message_cid_from_json(&with_encoded).unwrap(),
            generate_cid_from_json(&without_encoded).unwrap()
        );
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

    #[test]
    fn test_generate_dag_pb_cid_from_bytes_matches_typescript_vectors() {
        assert_eq!(
            generate_dag_pb_cid_from_bytes([]).to_string(),
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
        assert_eq!(
            generate_dag_pb_cid_from_bytes(b"hello world").to_string(),
            "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
        );
        assert_eq!(
            generate_dag_pb_cid_from_bytes((0_u8..16).collect::<Vec<_>>()).to_string(),
            "bafkreif6ixfsmbn7g27l3zueqqncr4h5ipdjqufd3ts75w5gteuo4oujse"
        );
        assert_eq!(
            generate_dag_pb_cid_from_bytes(vec![97; 300_000]).to_string(),
            "bafybeicnrogxohr6rp6rlbv6s4q5gkpx5cmlm3oxqr3a7sfghbnz6sdyvq"
        );
    }

    #[tokio::test]
    async fn test_generate_dag_pb_cid_from_stream_matches_bytes() {
        let chunks = vec![
            Ok::<_, std::convert::Infallible>(Bytes::from(vec![97; 65_536])),
            Ok(Bytes::from(vec![98; 270_000])),
        ];
        let stream = stream::iter(chunks);
        let cid = generate_dag_pb_cid_from_stream(stream).await.unwrap();

        let mut data = vec![97; 65_536];
        data.extend(vec![98; 270_000]);

        assert_eq!(cid, generate_dag_pb_cid_from_bytes(data));
    }
}
