//! Vault at-rest JWE interop: pinned fixture proof plus the rejection matrix.
//!
//! The fixture direction proves cross-runtime decryption; the matrix proves
//! allow-lists, header authentication, and malformed-input rejection through
//! the public codec only.

use base64::prelude::BASE64_URL_SAFE_NO_PAD as base64url;
use base64::Engine as _;
use dwn_rs_agent::agent::{
    decrypt_data, decrypt_did, derive_agent_keys, encrypt_data, encrypt_did, unwrap_cek, wrap_cek,
    AgentDidCreateRequest, DidDhtProvider, DidProvider, VaultStatus,
};
use serde_json::Value;

const FIXTURE_PATH: &str = "../../fixtures/interop/vault-jwe.json";
const RUST_BLOB_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/vault-jwe-rust-to-ts.json"
);
const RECOVERY_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSWORD: &[u8] = b"vault-interop-password";
const RUST_PASSWORD: &[u8] = b"rust-emit-password";

fn b64(bytes: &[u8]) -> String {
    base64url.encode(bytes)
}

fn segments(jwe: &str) -> Vec<String> {
    jwe.split('.').map(str::to_string).collect()
}

fn splice(jwe: &str, index: usize, segment: &str) -> String {
    let mut parts = segments(jwe);
    parts[index] = segment.to_string();
    parts.join(".")
}

fn protected_of(jwe: &str) -> Value {
    serde_json::from_slice(&base64url.decode(&segments(jwe)[0]).unwrap()).unwrap()
}

/// Decode a valid JWE's protected header, mutate it, and re-encode without
/// retagging. Rejections observed through these JWEs prove header validation
/// fires before (or regardless of) authentication.
fn with_header(jwe: &str, mutate: impl FnOnce(&mut Value)) -> String {
    let mut header = protected_of(jwe);
    mutate(&mut header);
    splice(jwe, 0, &b64(&serde_json::to_vec(&header).unwrap()))
}

fn flip_last(segment: &str) -> String {
    let mut bytes = segment.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).unwrap()
}

/// Direct-encryption JWE under a caller-chosen protected header document.
/// Used to prove reordered headers authenticate when retagged.
fn direct_jwe_with_header(cek: &[u8; 32], header_json: &str, plaintext: &[u8]) -> String {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    let protected = b64(header_json.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(cek).unwrap();
    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv).unwrap();
    let combined = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: protected.as_bytes(),
            },
        )
        .unwrap();
    let (ciphertext, tag) = combined.split_at(combined.len() - 16);
    format!("{protected}..{}.{}.{}", b64(&iv), b64(ciphertext), b64(tag))
}

fn fixture() -> Value {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE_PATH).unwrap()).unwrap()
}

#[test]
fn ts_vault_values_open_in_rust() {
    let fixture = fixture();
    let password = fixture["inputs"]["password"].as_str().unwrap().as_bytes();
    let (cek, header) = unwrap_cek(
        fixture["vector"]["contentEncryptionKey"].as_str().unwrap(),
        password,
    )
    .unwrap();
    assert_eq!(header.p2c, 1);

    let did_bytes = decrypt_did(fixture["vector"]["did"].as_str().unwrap(), &cek).unwrap();
    let did: Value = serde_json::from_slice(&did_bytes).unwrap();
    assert_eq!(
        did["uri"].as_str().unwrap(),
        fixture["vector"]["portableDidUri"].as_str().unwrap()
    );

    for (jwe_key, plain_key) in [
        ("dataJwe", "dataPlaintext"),
        ("binaryJwe", "binaryPlaintext"),
    ] {
        let plaintext = decrypt_data(fixture["vector"][jwe_key].as_str().unwrap(), &cek).unwrap();
        assert_eq!(
            b64(&plaintext),
            fixture["inputs"][plain_key].as_str().unwrap()
        );
    }

    let status = VaultStatus::parse(Some(
        fixture["vector"]["vaultStatus"]
            .as_str()
            .unwrap()
            .as_bytes(),
    ))
    .unwrap();
    assert!(status.initialized);
}

#[test]
fn reordered_header_opens_when_retagged() {
    let cek = [0x42; 32];
    let plaintext = b"header order must not matter";
    // Writer emits {"alg":"dir","enc":"A256GCM"}; reorder the members.
    let jwe = direct_jwe_with_header(&cek, r#"{"enc":"A256GCM","alg":"dir"}"#, plaintext);
    assert_eq!(decrypt_data(&jwe, &cek).unwrap(), plaintext);
}

#[test]
fn retagging_is_required_after_header_change() {
    let cek = [0x42; 32];
    let jwe = encrypt_data(b"tamper me", &cek).unwrap();
    let mut tampered = segments(&jwe)[0].clone().into_bytes();
    tampered[0] = if tampered[0] == b'e' { b'f' } else { b'e' };
    assert!(decrypt_data(
        &splice(&jwe, 0, &String::from_utf8(tampered).unwrap()),
        &cek
    )
    .is_err());

    let cek_jwe = wrap_cek(PASSWORD, &cek, &[0x11; 32], 1).unwrap();
    let mut tampered = segments(&cek_jwe)[0].clone().into_bytes();
    tampered[0] = if tampered[0] == b'e' { b'f' } else { b'e' };
    assert!(unwrap_cek(
        &splice(&cek_jwe, 0, &String::from_utf8(tampered).unwrap()),
        PASSWORD
    )
    .is_err());
}

#[test]
fn algorithm_allow_lists_reject_cross_use() {
    let cek = [0x42; 32];
    let dir_jwe = encrypt_data(b"direct", &cek).unwrap();
    assert!(unwrap_cek(&dir_jwe, PASSWORD).is_err());

    let cek_jwe = wrap_cek(PASSWORD, &cek, &[0x11; 32], 1).unwrap();
    assert!(decrypt_did(&cek_jwe, &cek).is_err());
    assert!(decrypt_data(&cek_jwe, &cek).is_err());

    assert!(decrypt_data(
        &with_header(&dir_jwe, |h| h["enc"] =
            Value::String("A128GCM".to_string())),
        &cek
    )
    .is_err());
    assert!(unwrap_cek(
        &with_header(&cek_jwe, |h| h["alg"] = Value::String("dir".to_string())),
        PASSWORD
    )
    .is_err());
}

#[test]
fn malformed_inputs_fail_closed() {
    let cek = [0x42; 32];
    let cek_jwe = wrap_cek(PASSWORD, &cek, &[0x11; 32], 1).unwrap();
    let dir_jwe = encrypt_data(b"data", &cek).unwrap();

    // Mutations of a CEK JWE must fail the CEK reader; mutations of a
    // direct JWE must fail the direct reader. Neither may yield plaintext.
    let cek_bad = [
        with_header(&cek_jwe, |h| h["p2c"] = Value::Number(0.into())),
        with_header(&cek_jwe, |h| {
            h.as_object_mut().unwrap().remove("p2c");
        }),
        with_header(&cek_jwe, |h| {
            h["p2c"] = Value::Number(serde_json::Number::from_f64(1.5).unwrap())
        }),
        with_header(&cek_jwe, |h| h["p2c"] = Value::String("210000".to_string())),
        with_header(&cek_jwe, |h| h["p2s"] = Value::String("!!!".to_string())),
        with_header(&cek_jwe, |h| {
            h.as_object_mut().unwrap().remove("p2s");
        }),
        splice(&cek_jwe, 1, ""),
        splice(&cek_jwe, 4, &flip_last(&segments(&cek_jwe)[4])),
    ];
    for bad in cek_bad {
        assert!(unwrap_cek(&bad, PASSWORD).is_err());
    }

    let dir_bad = [
        splice(&dir_jwe, 0, "!!!"),
        splice(&dir_jwe, 0, &b64(b"[1,2")),
        splice(&dir_jwe, 2, "AA"),
        splice(&dir_jwe, 2, &flip_last(&segments(&dir_jwe)[2])),
        splice(&dir_jwe, 4, &flip_last(&segments(&dir_jwe)[4])),
        splice(&dir_jwe, 3, &flip_last(&segments(&dir_jwe)[3])),
        splice(&dir_jwe, 1, "eA"),
    ];
    for bad in dir_bad {
        assert!(decrypt_data(&bad, &cek).is_err());
    }

    for bad in ["a.b.c", "a.b.c.d.e.f", "!!!..AA.AA.AA"] {
        assert!(decrypt_data(bad, &cek).is_err());
        assert!(unwrap_cek(bad, PASSWORD).is_err());
    }

    assert!(decrypt_data(&dir_jwe, &[0x99; 32]).is_err());
    assert!(unwrap_cek(&cek_jwe, b"wrong").is_err());
}

/// Rust-emitted vault values for the pinned TS consumer.
///
/// Run with `BLESS_VAULT_FIXTURES=1` to regenerate after an intended codec
/// change; otherwise the checked-in blob must open against the fixed
/// phrase and password. The blob lives under `crates/` so the TS-parity
/// provenance gate does not apply to it.
#[tokio::test]
async fn rust_vault_values_for_ts_consumer() {
    let derived = derive_agent_keys(RECOVERY_PHRASE).unwrap();
    let cek: [u8; 32] = derived
        .vault_content_encryption_key
        .as_slice()
        .try_into()
        .unwrap();
    let salt: [u8; 32] = derived.vault_unlock_salt.as_slice().try_into().unwrap();
    let portable_did = DidDhtProvider::default()
        .create_did(AgentDidCreateRequest {
            identity_private_jwk: derived.identity_private_jwk,
            signing_private_jwk: derived.signing_private_jwk,
            encryption_private_jwk: derived.encryption_private_jwk,
            dwn_endpoints: vec!["https://dwn.example".to_string()],
        })
        .await
        .unwrap();
    let did_json = serde_json::to_vec(&portable_did).unwrap();
    let plaintext = b"rust to typescript";
    let blob = serde_json::json!({
        "schemaVersion": 1,
        "oracle": "rust",
        "source": {
            "repository": "enboxorg/enbox-rust-core",
            "tool": "crates/dwn-rs-agent/tests/vault_jwe_interop.rs",
            "generator": "BLESS_VAULT_FIXTURES=1",
        },
        "inputs": {
            "recoveryPhrase": RECOVERY_PHRASE,
            "password": String::from_utf8_lossy(RUST_PASSWORD),
            "p2c": 1,
            "dataPlaintext": b64(plaintext),
            "cek": b64(&cek),
        },
        "vector": {
            "contentEncryptionKey": wrap_cek(RUST_PASSWORD, &cek, &salt, 1).unwrap(),
            "did": encrypt_did(&did_json, &cek).unwrap(),
            "vaultStatus": String::from_utf8(
                VaultStatus { initialized: true, last_backup: None, last_restore: None }
                    .encode()
                    .unwrap(),
            )
            .unwrap(),
            "portableDidUri": portable_did.uri,
            "dataJwe": encrypt_data(plaintext, &cek).unwrap(),
        },
    });

    if std::env::var("BLESS_VAULT_FIXTURES").is_ok() {
        std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")).unwrap();
        std::fs::write(
            RUST_BLOB_PATH,
            serde_json::to_string_pretty(&blob).unwrap() + "\n",
        )
        .unwrap();
    }
    let checked_in: Value = serde_json::from_str(&std::fs::read_to_string(RUST_BLOB_PATH).unwrap())
        .expect("run with BLESS_VAULT_FIXTURES=1 to create the blob");
    let password = checked_in["inputs"]["password"]
        .as_str()
        .unwrap()
        .as_bytes();
    let (opened_cek, _) = unwrap_cek(
        checked_in["vector"]["contentEncryptionKey"]
            .as_str()
            .unwrap(),
        password,
    )
    .unwrap();
    assert_eq!(
        b64(&opened_cek),
        checked_in["inputs"]["cek"].as_str().unwrap()
    );
    let did_bytes =
        decrypt_did(checked_in["vector"]["did"].as_str().unwrap(), &opened_cek).unwrap();
    let did: Value = serde_json::from_slice(&did_bytes).unwrap();
    assert_eq!(
        did["uri"].as_str().unwrap(),
        checked_in["vector"]["portableDidUri"].as_str().unwrap()
    );
    assert_eq!(
        decrypt_data(
            checked_in["vector"]["dataJwe"].as_str().unwrap(),
            &opened_cek
        )
        .unwrap(),
        plaintext
    );
}
