//! Single-body framing for HTTP DWN RPC.
//!
//! A request body starts with a five-byte header: one byte of flags followed by
//! the unsigned big-endian length of the UTF-8 JSON-RPC envelope. The envelope
//! follows the header, and optional raw record data follows the envelope when
//! the data-follows flag is set.

use bytes::Bytes;
use serde_json::Value;
use thiserror::Error;

/// Vendor media type selecting HTTP DWN RPC body framing.
pub const HTTP_DWN_RPC_MEDIA_TYPE: &str = "application/vnd.enbox.dwn-rpc";

/// Maximum JSON-RPC envelope size accepted by the framing.
pub const HTTP_DWN_RPC_MAX_ENVELOPE_BYTES: usize = 1_048_576;

const FRAME_DATA_FOLLOWS_FLAG: u8 = 0x01;
const FRAME_HEADER_BYTES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HttpRpcFramingError {
    #[error("HTTP DWN RPC envelope exceeds the {HTTP_DWN_RPC_MAX_ENVELOPE_BYTES}-byte limit")]
    EnvelopeTooLarge,
    #[error("HTTP DWN RPC body contains unsupported flags: {0}")]
    UnsupportedFlags(u8),
    #[error("HTTP DWN RPC body ended before its framed envelope was complete")]
    TruncatedBody,
    #[error("HTTP DWN RPC body contains data without the data-follows flag")]
    UnexpectedData,
    #[error("HTTP DWN RPC envelope is not valid JSON: {0}")]
    EnvelopeNotJson(String),
}

/// A parsed DWN RPC request body.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHttpDwnRpcRequest {
    pub envelope: Value,
    pub data: Option<Bytes>,
}

/// Whether a `Content-Type` header value selects DWN RPC body framing.
///
/// Media-type parameters are not part of the protocol, so any `;` is rejected.
pub fn is_http_dwn_rpc_content_type(value: &str) -> bool {
    if value.contains(';') {
        return false;
    }
    value == HTTP_DWN_RPC_MEDIA_TYPE || value.trim().eq_ignore_ascii_case(HTTP_DWN_RPC_MEDIA_TYPE)
}

/// Frames an envelope and optional record data into one request body.
pub fn encode_request_body(
    envelope: &[u8],
    data: Option<&[u8]>,
) -> Result<Bytes, HttpRpcFramingError> {
    let prefix = frame_request_header(envelope, data.is_some())?;
    match data {
        None => Ok(prefix),
        Some(data) => {
            let mut body = Vec::with_capacity(prefix.len() + data.len());
            body.extend_from_slice(&prefix);
            body.extend_from_slice(data);
            Ok(Bytes::from(body))
        }
    }
}

/// Frames the short header and envelope, leaving record data to be streamed
/// after it.
pub fn frame_request_header(envelope: &[u8], has_data: bool) -> Result<Bytes, HttpRpcFramingError> {
    if envelope.len() > HTTP_DWN_RPC_MAX_ENVELOPE_BYTES {
        return Err(HttpRpcFramingError::EnvelopeTooLarge);
    }
    let mut framed = Vec::with_capacity(FRAME_HEADER_BYTES + envelope.len());
    framed.push(if has_data { FRAME_DATA_FOLLOWS_FLAG } else { 0 });
    framed.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    framed.extend_from_slice(envelope);
    Ok(Bytes::from(framed))
}

/// Parses a complete request body into its JSON-RPC envelope and record data.
pub fn parse_request_body(body: &[u8]) -> Result<ParsedHttpDwnRpcRequest, HttpRpcFramingError> {
    if body.len() < FRAME_HEADER_BYTES {
        return Err(HttpRpcFramingError::TruncatedBody);
    }
    let flags = body[0];
    if flags & !FRAME_DATA_FOLLOWS_FLAG != 0 {
        return Err(HttpRpcFramingError::UnsupportedFlags(flags));
    }
    let envelope_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if envelope_len > HTTP_DWN_RPC_MAX_ENVELOPE_BYTES {
        return Err(HttpRpcFramingError::EnvelopeTooLarge);
    }
    if body.len() < FRAME_HEADER_BYTES + envelope_len {
        return Err(HttpRpcFramingError::TruncatedBody);
    }
    let envelope_bytes = &body[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + envelope_len];
    let envelope = serde_json::from_slice::<Value>(envelope_bytes)
        .map_err(|err| HttpRpcFramingError::EnvelopeNotJson(err.to_string()))?;

    let data = &body[FRAME_HEADER_BYTES + envelope_len..];
    if flags & FRAME_DATA_FOLLOWS_FLAG == 0 {
        if !data.is_empty() {
            return Err(HttpRpcFramingError::UnexpectedData);
        }
        return Ok(ParsedHttpDwnRpcRequest {
            envelope,
            data: None,
        });
    }

    Ok(ParsedHttpDwnRpcRequest {
        envelope,
        data: (!data.is_empty()).then(|| Bytes::copy_from_slice(data)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":"1","method":"dwn.processMessage","params":{}}"#.to_vec()
    }

    #[test]
    fn frames_and_parses_an_envelope_without_data() {
        let body = encode_request_body(&envelope(), None).expect("frame");
        let parsed = parse_request_body(&body).expect("parse");
        assert_eq!(parsed.envelope["method"], "dwn.processMessage");
        assert!(parsed.data.is_none());
    }

    #[test]
    fn frames_and_parses_an_envelope_with_data() {
        let body = encode_request_body(&envelope(), Some(b"record bytes")).expect("frame");
        assert_eq!(body[0], FRAME_DATA_FOLLOWS_FLAG);
        let parsed = parse_request_body(&body).expect("parse");
        assert_eq!(parsed.data.as_deref(), Some(&b"record bytes"[..]));
    }

    #[test]
    fn rejects_media_type_parameters() {
        assert!(is_http_dwn_rpc_content_type(HTTP_DWN_RPC_MEDIA_TYPE));
        assert!(is_http_dwn_rpc_content_type(&format!(
            "  {}  ",
            HTTP_DWN_RPC_MEDIA_TYPE.to_uppercase()
        )));
        assert!(!is_http_dwn_rpc_content_type(&format!(
            "{HTTP_DWN_RPC_MEDIA_TYPE}; charset=utf-8"
        )));
        assert!(!is_http_dwn_rpc_content_type("application/json"));
    }

    #[test]
    fn rejects_unsupported_flag_bits() {
        let mut body = encode_request_body(&envelope(), None)
            .expect("frame")
            .to_vec();
        body[0] = 0x02;
        assert_eq!(
            parse_request_body(&body).unwrap_err(),
            HttpRpcFramingError::UnsupportedFlags(0x02)
        );
    }

    #[test]
    fn rejects_envelopes_over_the_size_limit() {
        let mut body = Vec::from([0u8, 0, 0, 0, 0]);
        body[1..5].copy_from_slice(&(HTTP_DWN_RPC_MAX_ENVELOPE_BYTES as u32 + 1).to_be_bytes());
        assert_eq!(
            parse_request_body(&body).unwrap_err(),
            HttpRpcFramingError::EnvelopeTooLarge
        );
        let oversized = vec![b'{'; HTTP_DWN_RPC_MAX_ENVELOPE_BYTES + 1];
        assert_eq!(
            encode_request_body(&oversized, None).unwrap_err(),
            HttpRpcFramingError::EnvelopeTooLarge
        );
    }

    #[test]
    fn rejects_data_without_the_data_follows_flag() {
        let mut body = encode_request_body(&envelope(), None)
            .expect("frame")
            .to_vec();
        body.extend_from_slice(b"unexpected");
        assert_eq!(
            parse_request_body(&body).unwrap_err(),
            HttpRpcFramingError::UnexpectedData
        );
    }
}
