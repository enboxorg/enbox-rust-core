//! Current-format encryption survives a real-disk reopen; obsolete JWE shapes
//! are rejected outright.
//!
//! Replaces the deleted `legacy_encryption_upgrade.rs`. #272 removes legacy JWE
//! read/decrypt compatibility (packet requirements 26-27), but the same packet
//! keeps "reject obsolete; current crypto/reopen succeeds" in its test matrix:
//! removing the compatibility branch must not also remove the evidence that
//! current-format custody material is durable. There is deliberately no
//! conversion, dual-read fallback, or old-ciphertext migration path here.
//!
//! Covers: ENBOX-ENC-001, DWN-REC-006

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use dwn_rs_core::auth::JWK;
use dwn_rs_core::cid::generate_dag_pb_cid_from_bytes;
use dwn_rs_core::encryption::{
    seal_unwrap, seal_wrap, ContentEncryptionAlgorithm, EncryptionEnvelope, EncryptionInput,
    KeyAgreementAlgorithm, KeyEncryptionInput, SealKeyWrap, SealKeyWrapInput,
};
use dwn_rs_core::stores::wake::WakePublishHandler;
use dwn_rs_core::stores::{DataStore, MessageStore};
use dwn_rs_core::{Descriptor, Filters, Message, Value};
use futures_util::{stream, TryStreamExt};
use rusqlite::Connection;
use serde_json::json;

use common::TempDb;
use dwn_rs_stores::SqliteStore;

const TENANT: &str = "did:example:alice";
const RECORD_ID: &str = "encrypted-record";
const SEAL_RECORD_ID: &str = "sealed-key-record";
const PLAINTEXT: &[u8] = b"current envelope plaintext";
const PROTOCOL: &str = "https://example.com/protocol/threads";
const ROLE_PATH: &str = "thread/member";
const CONTEXT_ID: &str = "thread-1";

/// Fixed X25519 recipient keypair (`d` is 32 bytes of 0x03), carried over from
/// the removed upgrade test so the same recipient identity is exercised.
const PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"X25519","x":"Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI","d":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"}"#;
const PUBLIC_JWK: &str =
    r#"{"kty":"OKP","crv":"X25519","x":"Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI"}"#;
const RECIPIENT_PRIVATE_BYTES: [u8; 32] = [3u8; 32];

/// Obsolete pre-A256CTR flattened JWE (`protected`/`iv`/`tag`/`recipients`),
/// verbatim from the removed upgrade test: the exact shape that used to be
/// accepted must now fail to parse.
const OBSOLETE_JWE: &str = r#"{"protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00ifQ","iv":"CQkJCQkJCQkJCQkJ","tag":"pr5lZdaYTajVA0gqMvwlQw","recipients":[{"header":{"kid":"legacy-key","epk":{"kty":"OKP","crv":"X25519","x":"B6r_Pp_BZydVRPTDpqF82Dfy7G54zYpXsePfs8wDWnY"},"derivationScheme":"protocolPath"},"encrypted_key":"T42gGabDj__6KG89Wz97VBmlDEmkJj3HjLh-dPX-KzEbTi6z6DMLoA"}]}"#;

// Covers: ENBOX-ENC-001
#[test]
fn obsolete_jwe_shape_is_rejected_with_no_fallback() {
    let obsolete: serde_json::Value = serde_json::from_str(OBSOLETE_JWE).unwrap();

    let parsed = serde_json::from_value::<EncryptionEnvelope>(obsolete.clone());
    assert!(
        parsed.is_err(),
        "obsolete flattened JWE must not parse as a current envelope"
    );

    // The rejection is a real field-level parse failure, not a generic
    // "matched no variant" from a vestigial wrapper enum.
    let error = parsed.unwrap_err().to_string();
    assert!(
        error.contains("algorithm"),
        "expected a field-level parse error, got: {error}"
    );

    // The same shape must not slip in through RecordsWrite fields either.
    assert!(
        serde_json::from_value::<Message<Descriptor>>(json!({
            "descriptor": {
                "interface": "Records",
                "method": "Write",
                "protocol": PROTOCOL,
                "protocolPath": "thread/message",
                "dataCid": generate_dag_pb_cid_from_bytes(PLAINTEXT).to_string(),
                "dataSize": PLAINTEXT.len(),
                "dataFormat": "application/octet-stream",
                "dateCreated": "2025-01-01T00:00:00.000000Z",
                "messageTimestamp": "2025-01-01T00:00:00.000000Z"
            },
            "recordId": RECORD_ID,
            "encryption": obsolete
        }))
        .is_err(),
        "a RecordsWrite carrying an obsolete envelope must not deserialize"
    );
}

// Covers: ENBOX-ENC-001, DWN-REC-006
#[tokio::test]
async fn current_envelope_and_seal_survive_fresh_file_backed_reopen() {
    let public_jwk: JWK = serde_json::from_str(PUBLIC_JWK).unwrap();
    let key_id = public_jwk.thumbprint().unwrap();

    // Current A256CTR content encryption with an X25519-HKDF-A256KW wrapped CEK.
    let cek = [7u8; 32];
    let iv = [9u8; 16];
    let ciphertext = EncryptionEnvelope::ctr_encrypt(&cek, &iv, PLAINTEXT).unwrap();
    let envelope = EncryptionEnvelope::build_encryption(&EncryptionInput {
        algorithm: Some(ContentEncryptionAlgorithm::A256Ctr),
        key: cek.to_vec(),
        initialization_vector: iv.to_vec(),
        key_encryption_inputs: vec![KeyEncryptionInput::ProtocolPath {
            algorithm: KeyAgreementAlgorithm::X25519HkdfSha256A256Kw,
            key_id: key_id.clone(),
            public_key: public_jwk.clone(),
        }],
    })
    .unwrap();

    // A seal wrap over an audience private key, bound to protocol/role/context.
    let sealed_private_key = [11u8; 32];
    let seal = seal_wrap(
        &SealKeyWrapInput {
            algorithm: KeyAgreementAlgorithm::X25519HkdfSha256A256Kw,
            key_id: key_id.clone(),
            public_key: public_jwk.clone(),
            protocol: PROTOCOL,
            role_path: ROLE_PATH,
            context_id: CONTEXT_ID,
            audience_key_id: &key_id,
        },
        &sealed_private_key,
    )
    .unwrap();
    let seal_bytes = serde_json::to_vec(&seal).unwrap();

    let data_cid = generate_dag_pb_cid_from_bytes(&ciphertext).to_string();
    let seal_cid = generate_dag_pb_cid_from_bytes(&seal_bytes).to_string();
    let record = write_message(RECORD_ID, &data_cid, ciphertext.len(), Some(&envelope));
    let seal_record = write_message(SEAL_RECORD_ID, &seal_cid, seal_bytes.len(), None);
    let record_cid = record.cid().unwrap().to_string();

    let db = TempDb::new("encryption-persistence");
    let json_before = {
        let mut store = SqliteStore::new(db.path(), WakePublishHandler::new(Arc::new(())));
        MessageStore::open(&mut store).await.unwrap();
        for (message, record_id, cid, bytes) in [
            (record.clone(), RECORD_ID, &data_cid, ciphertext.clone()),
            (seal_record, SEAL_RECORD_ID, &seal_cid, seal_bytes.clone()),
        ] {
            MessageStore::put(&store, TENANT, message, timestamp_index())
                .await
                .unwrap();
            DataStore::put(
                &store,
                TENANT,
                record_id,
                cid,
                stream::iter(vec![Bytes::from(bytes)]),
            )
            .await
            .unwrap();
        }
        MessageStore::close(&mut store).await;
        // `close` stops the pools handing out connections, but the store still
        // owns them; drop before reopening so every platform releases the
        // SQLite handles deterministically.
        drop(store);
        stored_message_json(db.path(), &record_cid)
    };

    // Fresh handle on the same file: the reopen half of the durability cycle.
    let mut reopened = SqliteStore::new(db.path(), WakePublishHandler::new(Arc::new(())));
    MessageStore::open(&mut reopened).await.unwrap();

    let by_get = MessageStore::get(&reopened, TENANT, &record_cid)
        .await
        .unwrap()
        .expect("encrypted record through get");
    let by_query = MessageStore::query(&reopened, TENANT, Filters::default(), None, None, None)
        .await
        .unwrap()
        .messages
        .into_iter()
        .find(|message| message.cid().unwrap().to_string() == record_cid)
        .expect("encrypted record through query");

    let stored_ciphertext = read_data(&reopened, RECORD_ID, &data_cid).await;
    let stored_seal: SealKeyWrap =
        serde_json::from_slice(&read_data(&reopened, SEAL_RECORD_ID, &seal_cid).await).unwrap();
    MessageStore::close(&mut reopened).await;
    drop(reopened);

    let private_jwk = serde_json::from_str(PRIVATE_JWK).unwrap();
    for (source, message) in [("get", by_get), ("query", by_query)] {
        let stored = match message.fields {
            dwn_rs_core::Fields::Write(fields) => fields.encryption.expect("current envelope"),
            other => panic!("expected RecordsWrite fields via {source}, got {other:?}"),
        };
        assert_eq!(
            stored, envelope,
            "envelope must survive reopen via {source}"
        );
        assert_eq!(
            stored.decrypt(&private_jwk, &stored_ciphertext).unwrap(),
            PLAINTEXT,
            "reopened envelope must still decrypt via {source}"
        );
    }

    // Seal custody survives the same cycle and stays bound to its context.
    assert_eq!(
        seal_unwrap(
            &RECIPIENT_PRIVATE_BYTES,
            &stored_seal,
            PROTOCOL,
            ROLE_PATH,
            CONTEXT_ID,
            &key_id,
        )
        .unwrap(),
        sealed_private_key,
        "reopened seal must unwrap to the original audience key"
    );
    assert!(
        seal_unwrap(
            &RECIPIENT_PRIVATE_BYTES,
            &stored_seal,
            PROTOCOL,
            ROLE_PATH,
            "other-context",
            &key_id,
        )
        .is_err(),
        "seal KEK must stay bound to its context"
    );

    // Storage is not allowed to rewrite retained message JSON.
    assert_eq!(stored_message_json(db.path(), &record_cid), json_before);
}

fn write_message(
    record_id: &str,
    data_cid: &str,
    data_size: usize,
    encryption: Option<&EncryptionEnvelope>,
) -> Message<Descriptor> {
    let mut value = json!({
        "descriptor": {
            "interface": "Records",
            "method": "Write",
            "protocol": PROTOCOL,
            "protocolPath": "thread/message",
            "dataCid": data_cid,
            "dataSize": data_size,
            "dataFormat": "application/octet-stream",
            "dateCreated": "2025-01-01T00:00:00.000000Z",
            "messageTimestamp": "2025-01-01T00:00:00.000000Z"
        },
        "recordId": record_id
    });
    if let Some(encryption) = encryption {
        value["encryption"] = serde_json::to_value(encryption).unwrap();
    }
    serde_json::from_value(value).expect("RecordsWrite fixture must deserialize")
}

fn timestamp_index() -> BTreeMap<String, Value> {
    BTreeMap::from([(
        "messageTimestamp".to_string(),
        Value::String("2025-01-01T00:00:00.000000Z".to_string()),
    )])
}

async fn read_data(store: &SqliteStore, record_id: &str, data_cid: &str) -> Vec<u8> {
    DataStore::get(store, TENANT, record_id, data_cid)
        .await
        .unwrap()
        .expect("stored data")
        .data_stream
        .try_fold(Vec::new(), |mut bytes, chunk| async move {
            bytes.extend_from_slice(&chunk);
            Ok::<_, std::io::Error>(bytes)
        })
        .await
        .unwrap()
}

fn stored_message_json(path: &std::path::Path, message_cid: &str) -> String {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT message_json FROM messages WHERE tenant = ?1 AND message_cid = ?2",
            [TENANT, message_cid],
            |row| row.get(0),
        )
        .unwrap()
}
