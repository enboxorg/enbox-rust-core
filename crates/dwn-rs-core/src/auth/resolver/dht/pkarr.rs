use ed25519_dalek::VerifyingKey;
use ssi_dids_core::DID;

use crate::auth::resolver::ResolverError;

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

#[cfg(test)]
mod tests {
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
}
