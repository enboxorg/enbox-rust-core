use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ssi_dids_core::DID;

use crate::auth::resolver::ResolverError;

const SIGNATURE_LEN: usize = 64;
const SEQUENCE_LEN: usize = 8;
const HEADER_LEN: usize = SIGNATURE_LEN + SEQUENCE_LEN;
const MAX_VALUE_LEN: usize = 1000;
const MIN_RELAY_PAYLOAD_LEN: usize = HEADER_LEN;
const MAX_RELAY_PAYLOAD_LEN: usize = HEADER_LEN + MAX_VALUE_LEN;

fn decode_identity_key(did: &DID) -> Result<VerifyingKey, ResolverError> {
    if did.method_name() != "dht" {
        return Err(ResolverError::MethodNotSupported(
            did.method_name().to_string(),
        ));
    }

    let decoded =
        z32::decode(did.method_specific_id_bytes()).map_err(|_| ResolverError::InvalidPublicKey)?;

    let found = decoded.len();
    let bytes: [u8; 32] =
        decoded
            .try_into()
            .map_err(|_| ResolverError::InvalidPublicKeyLength {
                expected: 32,
                found,
            })?;

    VerifyingKey::from_bytes(&bytes).map_err(|_| ResolverError::InvalidPublicKey)
}

pub(super) struct Bep44Message<'a> {
    pub signature: &'a [u8; 64],
    pub sequence: u64,
    pub value: &'a [u8],
}

pub(super) fn parse_relay_payload(payload: &[u8]) -> Result<Bep44Message<'_>, ResolverError> {
    if !(MIN_RELAY_PAYLOAD_LEN..=MAX_RELAY_PAYLOAD_LEN).contains(&payload.len()) {
        return Err(ResolverError::InvalidDocumentLength {
            min: MIN_RELAY_PAYLOAD_LEN,
            max: MAX_RELAY_PAYLOAD_LEN,
            found: payload.len(),
        });
    }

    let signature = payload[..SIGNATURE_LEN]
        .try_into()
        .expect("slice is the right length");

    let sequence = u64::from_be_bytes(
        payload[SIGNATURE_LEN..HEADER_LEN]
            .try_into()
            .expect("slice is the right length"),
    );

    Ok(Bep44Message {
        signature,
        sequence,
        value: &payload[HEADER_LEN..],
    })
}

fn bep44_signing_payload(sequence: u64, value: &[u8]) -> Vec<u8> {
    let prefix = format!("3:seqi{sequence}e1:v{}:", value.len());

    let mut payload = Vec::with_capacity(prefix.len() + value.len());
    payload.extend_from_slice(prefix.as_bytes());
    payload.extend_from_slice(value);
    payload
}

fn verify_bep44_message(
    key: &VerifyingKey,
    message: &Bep44Message<'_>,
) -> Result<(), ResolverError> {
    let signature = Signature::from_bytes(message.signature);

    let payload = bep44_signing_payload(message.sequence, message.value);

    key.verify(&payload, &signature)
        .map_err(|_| ResolverError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use ssi_dids_core::DIDBuf;

    use super::*;

    const VECTOR_1_IDENTIFIER: &str = "cyuoqaf7itop8ohww4yn5ojg13qaq83r9zihgqntc5i9zwrfdfoo";
    const VECTOR_1_PUBLIC_KEY: [u8; 32] = [
        96, 39, 7, 96, 189, 172, 96, 211, 195, 148, 166, 128, 45, 193, 38, 150, 93, 135, 31, 36,
        253, 235, 195, 56, 81, 102, 235, 251, 208, 133, 25, 97,
    ];

    fn did(method: &str, identifier: &str) -> DIDBuf {
        format!("did:{method}:{identifier}").parse().unwrap()
    }

    #[test]
    fn decodes_official_vector_identity_key() {
        let key = decode_identity_key(&did("dht", VECTOR_1_IDENTIFIER)).unwrap();

        assert_eq!(key.to_bytes(), VECTOR_1_PUBLIC_KEY);
        assert_eq!(z32::encode(&VECTOR_1_PUBLIC_KEY), VECTOR_1_IDENTIFIER);
    }

    #[test]
    fn rejects_a_different_did_method() {
        assert!(matches!(
            decode_identity_key(&did("web", "example.com")),
            Err(ResolverError::MethodNotSupported(method)) if method == "web"
        ));
    }

    #[test]
    fn rejects_invalid_zbase32() {
        // `0` is valid DID method-specific-id syntax but is not in the z-base-32 alphabet.
        assert_eq!(
            decode_identity_key(&did("dht", "0")),
            Err(ResolverError::InvalidPublicKey)
        );
    }

    #[test]
    fn rejects_identity_keys_with_the_wrong_length() {
        for (bytes, expected_found) in [(vec![7; 31], 31), (vec![7; 33], 33)] {
            let identifier = z32::encode(&bytes);

            assert!(matches!(
                decode_identity_key(&did("dht", &identifier)),
                Err(ResolverError::InvalidPublicKeyLength {
                    expected: 32,
                    found,
                }) if found == expected_found
            ));
        }
    }

    #[test]
    fn rejects_invalid_ed25519_key_material() {
        let invalid_key = (0..=u8::MAX)
            .map(|byte| [byte; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("at least one repeated-byte encoding is not an Edwards point");
        let identifier = z32::encode(&invalid_key);

        assert_eq!(
            decode_identity_key(&did("dht", &identifier)),
            Err(ResolverError::InvalidPublicKey)
        );
    }

    #[test]
    fn parses_relay_payload_layout() {
        let signature = [0xa5; SIGNATURE_LEN];
        let sequence: u64 = 0x0102_0304_0506_0708;
        let value = [0x00, 0x61, 0xff];
        let mut payload = Vec::new();
        payload.extend_from_slice(&signature);
        payload.extend_from_slice(&sequence.to_be_bytes());
        payload.extend_from_slice(&value);

        let message = parse_relay_payload(&payload).unwrap();

        assert_eq!(message.signature, &signature);
        assert_eq!(message.sequence, sequence);
        assert_eq!(message.value, value);
    }

    #[test]
    fn accepts_relay_payload_length_boundaries() {
        let minimum = vec![0; MIN_RELAY_PAYLOAD_LEN];
        let maximum = vec![0; MAX_RELAY_PAYLOAD_LEN];

        assert!(parse_relay_payload(&minimum).is_ok());
        assert!(parse_relay_payload(&maximum).is_ok());
    }

    #[test]
    fn rejects_relay_payload_outside_length_boundaries() {
        for found in [MIN_RELAY_PAYLOAD_LEN - 1, MAX_RELAY_PAYLOAD_LEN + 1] {
            assert!(matches!(
                parse_relay_payload(&vec![0; found]),
                Err(ResolverError::InvalidDocumentLength {
                    min: MIN_RELAY_PAYLOAD_LEN,
                    max: MAX_RELAY_PAYLOAD_LEN,
                    found: actual,
                }) if actual == found
            ));
        }
    }

    #[test]
    fn encodes_bep44_signing_payload_vectors() {
        let vectors: &[(u64, &[u8], &[u8])] = &[
            (0, b"", b"3:seqi0e1:v0:"),
            (42, &[0, b'a', 0xff], b"3:seqi42e1:v3:\x00a\xff"),
            (1_700_000_000, b"hello", b"3:seqi1700000000e1:v5:hello"),
        ];

        for (sequence, value, expected) in vectors {
            assert_eq!(bep44_signing_payload(*sequence, value), *expected);
        }
    }

    #[test]
    fn verifies_a_bep44_message() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signature = signing_key.sign(b"3:seqi42e1:v5:hello").to_bytes();
        let message = Bep44Message {
            signature: &signature,
            sequence: 42,
            value: b"hello",
        };

        assert_eq!(
            verify_bep44_message(&signing_key.verifying_key(), &message),
            Ok(())
        );
    }

    #[test]
    fn rejects_tampered_bep44_messages() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signature = signing_key.sign(b"3:seqi42e1:v5:hello").to_bytes();
        let verifying_key = signing_key.verifying_key();
        let tampered_messages = [
            Bep44Message {
                signature: &signature,
                sequence: 43,
                value: b"hello",
            },
            Bep44Message {
                signature: &signature,
                sequence: 42,
                value: b"jello",
            },
        ];

        for message in tampered_messages {
            assert_eq!(
                verify_bep44_message(&verifying_key, &message),
                Err(ResolverError::InvalidSignature)
            );
        }

        let mut tampered_signature = signature;
        tampered_signature[0] ^= 0xff;
        let message = Bep44Message {
            signature: &tampered_signature,
            sequence: 42,
            value: b"hello",
        };
        assert_eq!(
            verify_bep44_message(&verifying_key, &message),
            Err(ResolverError::InvalidSignature)
        );

        let other_key = SigningKey::from_bytes(&[8; 32]).verifying_key();
        let message = Bep44Message {
            signature: &signature,
            sequence: 42,
            value: b"hello",
        };
        assert_eq!(
            verify_bep44_message(&other_key, &message),
            Err(ResolverError::InvalidSignature)
        );
    }
}
