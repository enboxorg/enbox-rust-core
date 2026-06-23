use std::str::FromStr;

use chrono::{DateTime, Utc};

use crate::canonical_rfc3339;
use crate::descriptors::MessageParameters;
use crate::encryption::DerivationScheme;
use crate::filters::message_filters::Records as RecordsFilter;
use crate::Pagination;

use super::*;

#[tokio::test]
async fn test_read_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    let rp = ReadParameters {
        message_timestamp: Some(message_timestamp),
        filters: RecordsFilter::default(),
        ..Default::default()
    };

    let (build_rd, _) = rp.build().await.unwrap();

    let rd = ReadDescriptor {
        message_timestamp,
        filter: RecordsFilter::default(),
        permission_grant_id: None,
        date_sort: None,
    };

    let ser = serde_json::to_string(&rd).unwrap();
    let de: ReadDescriptor = serde_json::from_str(&ser).unwrap();

    assert_eq!(rd, de);
    assert_eq!(build_rd, de);
}

#[tokio::test]
async fn test_query_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    let qp = QueryParameters {
        message_timestamp: Some(message_timestamp),
        filter: Some(RecordsFilter::default()),
        date_sort: Some(DateSort::CreatedAscending),
        pagination: Some(Pagination::default()),
        ..Default::default()
    };

    let qd = QueryDescriptor {
        message_timestamp,
        filter: Default::default(),
        pagination: Some(Pagination::default()),
        date_sort: Some(DateSort::CreatedAscending),
    };

    let (build_qd, _) = qp.build().await.unwrap();

    let ser = serde_json::to_string(&qd).unwrap();
    let de: QueryDescriptor = serde_json::from_str(&ser).unwrap();

    assert_eq!(qd, de);
    assert_eq!(build_qd, de);
}

#[tokio::test]
async fn test_count_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    let cp = CountParameters {
        message_timestamp: Some(message_timestamp),
        filter: RecordsFilter::default(),
        ..Default::default()
    };

    let cd = CountDescriptor {
        message_timestamp,
        filter: Default::default(),
    };

    let (build_cd, _) = cp.build().await.unwrap();

    let ser = serde_json::to_string(&cd).unwrap();
    let de: CountDescriptor = serde_json::from_str(&ser).unwrap();

    assert_eq!(cd, de);
    assert_eq!(build_cd, de);
}

#[tokio::test]
async fn test_write_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    let wd = WriteDescriptor {
        protocol: None,
        protocol_path: None,
        recipient: None,
        schema: None,
        tags: None,
        parent_id: None,
        data_cid: "test".to_string(),
        data_size: 0,
        date_created: message_timestamp,
        message_timestamp,
        published: None,
        date_published: None,
        data_format: "test".to_string(),
        permission_grant_id: None,
        squash: None,
    };

    let (build_wd, _) = WriteParameters {
        data_cid: Some("test".to_string()),
        data_size: Some(0),
        date_created: Some(message_timestamp),
        message_timestamp: Some(message_timestamp),
        data_format: "test".to_string(),
        ..Default::default()
    }
    .build()
    .await
    .unwrap();

    let ser = serde_json::to_string(&wd).unwrap();
    let de: WriteDescriptor = serde_json::from_str(&ser).unwrap();

    assert_eq!(wd, de);
    assert_eq!(build_wd, de);
}

#[tokio::test]
async fn test_write_builds_jwe_encryption_fields() {
    let public_key = serde_json::from_value(serde_json::json!({
        "kty": "OKP",
        "crv": "X25519",
        "x": "NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ",
        "kid": "5_RYhfysTyU1BDBnv9LSpAGNHJ_A1_UesBCKoRG370E"
    }))
    .unwrap();
    let (_, fields) = WriteParameters {
        protocol: Some("https://example.com/protocol/jwe".to_string()),
        protocol_path: Some("thread/message".to_string()),
        data_cid: Some("bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e".to_string()),
        data_size: Some(32),
        data_format: "text/plain".to_string(),
        encryption_input: Some(EncryptionInput {
            algorithm: Some(crate::encryption::ContentEncryptionAlgorithm::A256GCM),
            key: (0u8..32).collect(),
            initialization_vector: vec![0xa0; 12],
            authentication_tag: vec![0x42; 16],
            key_encryption_inputs: vec![KeyEncryptionInput {
                derivation_scheme: DerivationScheme::ProtocolPath,
                public_key_id: "5_RYhfysTyU1BDBnv9LSpAGNHJ_A1_UesBCKoRG370E".to_string(),
                public_key,
                algorithm: None,
            }],
        }),
        ..Default::default()
    }
    .build()
    .await
    .unwrap();

    let encryption = fields.unwrap().encryption.unwrap();
    assert_eq!(
        encryption.protected_header().unwrap(),
        crate::encryption::JweProtectedHeader {
            alg: crate::encryption::KeyAgreementAlgorithm::EcdhEsA256kw,
            enc: crate::encryption::ContentEncryptionAlgorithm::A256GCM,
        }
    );
    let encryption_json = serde_json::to_value(encryption).unwrap();
    assert!(encryption_json.get("protected").is_some());
    assert!(encryption_json.get("iv").is_some());
    assert!(encryption_json.get("tag").is_some());
    assert!(encryption_json.get("recipients").is_some());
    assert!(encryption_json.get("keyEncryption").is_none());
    assert_eq!(
        encryption_json["recipients"][0]["header"]["derivationScheme"],
        "protocolPath"
    );
    assert!(!encryption_json["recipients"][0]["encrypted_key"]
        .as_str()
        .unwrap()
        .is_empty());
}

#[test]
fn test_subscribe_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    let sd = SubscribeDescriptor {
        message_timestamp,
        filter: Default::default(),
        date_sort: None,
        pagination: None,
        cursor: None,
    };

    let ser = serde_json::to_string(&sd).unwrap();
    let de: SubscribeDescriptor = serde_json::from_str(&ser).unwrap();

    assert_eq!(sd, de);
}

#[test]
fn test_delete_descriptor() {
    let message_timestamp = DateTime::from_str(canonical_rfc3339(Utc::now()).as_str()).unwrap();

    let dd = DeleteDescriptor {
        message_timestamp,
        record_id: "test".to_string(),
        prune: false,
    };

    let ser = serde_json::to_string(&dd).unwrap();
    let de: DeleteDescriptor = serde_json::from_str(&ser).unwrap();

    assert_eq!(dd, de);
}
