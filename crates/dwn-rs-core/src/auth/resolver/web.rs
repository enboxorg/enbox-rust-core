//! `did:web` document resolution with Enbox-compatible URL and error semantics.
//!
//! Resolution starts at an HTTPS URL derived from the DID and uses the shared public-URL
//! transport for manual redirects and literal-host filtering. That policy intentionally does not
//! resolve DNS names or claim protection against DNS rebinding. See `docs/DID_RESOLUTION.md` for
//! the complete compatibility and security contract.

use std::sync::Arc;
use std::time::Duration;

use percent_encoding::percent_decode_str;
use ssi_dids_core::{Document, DID};
use url::Url;

use super::http::{
    fetch_public_url, HttpExecutor, HttpRequest, PublicHttpError, ReqwestHttpExecutor,
};
use super::{DidMethodResolver, Resolution, ResolverError, ResolverFuture};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Network limits applied to one complete `did:web` resolution, including redirects.
pub struct WebResolverConfig {
    /// Deadline shared by the initial request and every followed redirect.
    pub timeout: Duration,
    /// Maximum number of redirects followed after the initial request.
    pub max_redirects: usize,
}

impl Default for WebResolverConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_redirects: DEFAULT_MAX_REDIRECTS,
        }
    }
}

#[derive(Clone)]
/// Resolves `did:web` identifiers into complete SSI DID documents.
pub struct WebResolver {
    config: WebResolverConfig,
    http: Arc<dyn HttpExecutor>,
}

impl WebResolver {
    /// Create a resolver using the native HTTP client and the supplied limits.
    pub fn new(config: WebResolverConfig) -> Self {
        Self {
            config,
            http: Arc::new(ReqwestHttpExecutor::default()),
        }
    }

    #[cfg(test)]
    fn with_executor(config: WebResolverConfig, http: Arc<dyn HttpExecutor>) -> Self {
        Self { config, http }
    }
}

impl Default for WebResolver {
    fn default() -> Self {
        Self::new(WebResolverConfig::default())
    }
}

impl DidMethodResolver for WebResolver {
    fn method_name(&self) -> &str {
        "web"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> ResolverFuture<'a, Result<Resolution, ResolverError>> {
        Box::pin(async move {
            if did.method_name() != self.method_name() {
                return Err(ResolverError::MethodNotSupported(
                    did.method_name().to_string(),
                ));
            }

            let url = document_url(did)?;
            let response = fetch_public_url(
                self.http.as_ref(),
                HttpRequest::get(url),
                self.config.timeout,
                self.config.max_redirects,
                "did:web document URL",
            )
            .await
            .map_err(|error| resolution_not_found(did, error))?;

            if !response.status.is_success() {
                return Err(ResolverError::NotFound);
            }

            let document = serde_json::from_slice::<Document>(&response.body).map_err(|error| {
                tracing::debug!(%did, %error, "did:web response was not a valid DID document");
                ResolverError::NotFound
            })?;
            Ok(Resolution::new(document))
        })
    }
}

fn document_url(did: &DID) -> Result<Url, ResolverError> {
    if did.method_name() != "web" {
        return Err(ResolverError::MethodNotSupported(
            did.method_name().to_string(),
        ));
    }

    document_url_from_identifier(did.method_specific_id())
}

fn document_url_from_identifier(identifier: &str) -> Result<Url, ResolverError> {
    if identifier.is_empty() {
        return Err(ResolverError::InvalidDid);
    }

    let has_path = identifier.contains(':');
    let encoded_authority_and_path = identifier.replace(':', "/");
    validate_percent_encoding(&encoded_authority_and_path)?;
    let authority_and_path = percent_decode_str(&encoded_authority_and_path)
        .decode_utf8()
        .map_err(|_| ResolverError::InvalidDid)?;
    let suffix = if has_path {
        "/did.json"
    } else {
        "/.well-known/did.json"
    };

    Url::parse(&format!("https://{authority_and_path}{suffix}"))
        .map_err(|_| ResolverError::InvalidDid)
}

fn validate_percent_encoding(value: &str) -> Result<(), ResolverError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(ResolverError::InvalidDid);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn resolution_not_found(did: &DID, error: PublicHttpError) -> ResolverError {
    tracing::debug!(%did, %error, "did:web document could not be fetched");
    ResolverError::NotFound
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use bytes::Bytes;
    use reqwest::header::HeaderMap;
    use reqwest::StatusCode;
    use serde_json::json;
    use ssi_dids_core::DIDBuf;
    use ssi_jwk::{Algorithm, JWK};

    use super::*;
    use crate::auth::resolver::{DidResolver, StaticPublicKeyResolver, UniversalResolver};
    use crate::auth::{Jws, PrivateJwkSigner};

    struct FakeExecutor {
        response: Mutex<Option<Result<super::super::http::HttpResponse, PublicHttpError>>>,
        requests: Mutex<Vec<(Url, Duration)>>,
    }

    impl FakeExecutor {
        fn responding(status: StatusCode, body: impl Into<Bytes>) -> Arc<Self> {
            Arc::new(Self {
                response: Mutex::new(Some(Ok(super::super::http::HttpResponse {
                    status,
                    headers: HeaderMap::new(),
                    body: body.into(),
                }))),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn failing(error: PublicHttpError) -> Arc<Self> {
            Arc::new(Self {
                response: Mutex::new(Some(Err(error))),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    impl HttpExecutor for FakeExecutor {
        fn execute_once<'a>(
            &'a self,
            request: HttpRequest,
            timeout: Duration,
        ) -> ResolverFuture<'a, Result<super::super::http::HttpResponse, PublicHttpError>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push((request.url, timeout));
                self.response
                    .lock()
                    .unwrap()
                    .take()
                    .expect("fake response must be configured")
            })
        }
    }

    fn did(value: &str) -> DIDBuf {
        value.parse().unwrap()
    }

    fn resolver(http: Arc<FakeExecutor>) -> WebResolver {
        WebResolver::with_executor(WebResolverConfig::default(), http)
    }

    // URL vectors mirror enboxorg/enbox did-web.ts at
    // c63bf424ac0997583db825e8a5fddf1507d30c40.
    #[test]
    fn derives_well_known_url_for_bare_domain() {
        assert_eq!(
            document_url(&did("did:web:example.com")).unwrap().as_str(),
            "https://example.com/.well-known/did.json"
        );
    }

    #[test]
    fn derives_path_url_by_replacing_literal_colons() {
        assert_eq!(
            document_url(&did("did:web:example.com:users:alice"))
                .unwrap()
                .as_str(),
            "https://example.com/users/alice/did.json"
        );
    }

    #[test]
    fn percent_decodes_after_replacing_path_separators() {
        assert_eq!(
            document_url(&did("did:web:example.com%3A8443:users:alice"))
                .unwrap()
                .as_str(),
            "https://example.com:8443/users/alice/did.json"
        );
        assert_eq!(
            document_url(&did("did:web:example.com%3A8443"))
                .unwrap()
                .as_str(),
            "https://example.com:8443/.well-known/did.json"
        );
    }

    #[test]
    fn rejects_malformed_percent_encoding_and_wrong_methods() {
        for identifier in [
            "example.com%",
            "example.com%2",
            "example.com%GG",
            "example.com%FF",
        ] {
            assert_eq!(
                document_url_from_identifier(identifier),
                Err(ResolverError::InvalidDid)
            );
        }
        assert!(matches!(
            document_url(&did("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")),
            Err(ResolverError::MethodNotSupported(method)) if method == "key"
        ));
    }

    #[tokio::test]
    async fn parses_and_preserves_the_complete_ssi_document() {
        let body = serde_json::to_vec(&json!({
            "@context": ["https://www.w3.org/ns/did/v1", {"custom": "https://example.com/custom#"}],
            "id": "did:web:example.com",
            "alsoKnownAs": ["https://example.com/alice"],
            "controller": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#key-1",
                    "type": "JsonWebKey2020",
                    "controller": "did:web:example.com",
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "11qYAYdk9JqpfCzb7pJkq73LnYl9qShPBy9jKmctL1U"
                    }
                },
                {
                    "id": "did:web:example.com#key-2",
                    "type": "JsonWebKey2020",
                    "controller": "did:web:example.com",
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": "LclKkU9xZcTmG5qLeA-M4mDExXQ7OasLdm8ELW4BTJ0"
                    }
                }
            ],
            "authentication": ["did:web:example.com#key-1"],
            "assertionMethod": ["did:web:example.com#key-1"],
            "keyAgreement": ["did:web:example.com#key-2"],
            "capabilityInvocation": ["did:web:example.com#key-1"],
            "capabilityDelegation": ["did:web:example.com#key-1"],
            "service": [{
                "id": "did:web:example.com#dwn",
                "type": "DecentralizedWebNode",
                "serviceEndpoint": "https://dwn.example.com"
            }],
            "custom": {"enabled": true}
        }))
        .unwrap();
        let http = FakeExecutor::responding(StatusCode::OK, body);
        let resolution = resolver(http.clone())
            .resolve(&did("did:web:example.com"))
            .await
            .unwrap();
        let document = serde_json::to_value(resolution.document).unwrap();

        assert_eq!(document["id"], "did:web:example.com");
        assert_eq!(
            document["alsoKnownAs"],
            json!(["https://example.com/alice"])
        );
        assert_eq!(document["controller"], "did:web:example.com");
        assert_eq!(document["verificationMethod"].as_array().unwrap().len(), 2);
        assert_eq!(
            document["authentication"],
            json!(["did:web:example.com#key-1"])
        );
        assert_eq!(
            document["keyAgreement"],
            json!(["did:web:example.com#key-2"])
        );
        assert_eq!(
            document["service"][0]["serviceEndpoint"],
            "https://dwn.example.com"
        );
        assert_eq!(document["custom"], json!({"enabled": true}));
        assert_eq!(http.request_count(), 1);
        let requests = http.requests.lock().unwrap();
        assert_eq!(
            requests[0].0.as_str(),
            "https://example.com/.well-known/did.json"
        );
        assert!(requests[0].1 <= DEFAULT_TIMEOUT);
    }

    #[tokio::test]
    async fn accepts_any_success_status_with_a_valid_document() {
        let body = br#"{"id":"did:web:example.com"}"#.as_slice();
        let resolution = resolver(FakeExecutor::responding(StatusCode::CREATED, body))
            .resolve(&did("did:web:example.com"))
            .await
            .unwrap();
        assert_eq!(resolution.document.id, "did:web:example.com");
    }

    #[tokio::test]
    async fn maps_http_transport_status_and_json_failures_to_not_found() {
        let cases = [
            resolver(FakeExecutor::failing(PublicHttpError::Request(
                "offline".to_string(),
            ))),
            resolver(FakeExecutor::responding(
                StatusCode::NOT_FOUND,
                Bytes::new(),
            )),
            resolver(FakeExecutor::responding(StatusCode::OK, "not json")),
        ];

        for resolver in cases {
            assert_eq!(
                resolver.resolve(&did("did:web:example.com")).await,
                Err(ResolverError::NotFound)
            );
        }
    }

    #[tokio::test]
    async fn rejects_private_targets_before_executing_a_request() {
        let http =
            FakeExecutor::responding(StatusCode::OK, br#"{"id":"did:web:127.0.0.1"}"#.as_slice());
        assert_eq!(
            resolver(http.clone())
                .resolve(&did("did:web:127.0.0.1"))
                .await,
            Err(ResolverError::NotFound)
        );
        assert_eq!(http.request_count(), 0);
    }

    #[tokio::test]
    async fn rejects_a_did_for_another_method() {
        let http = FakeExecutor::responding(StatusCode::OK, Bytes::new());
        assert!(matches!(
            resolver(http.clone())
                .resolve(&did("did:example:alice"))
                .await,
            Err(ResolverError::MethodNotSupported(method)) if method == "example"
        ));
        assert_eq!(http.request_count(), 0);
    }

    #[tokio::test]
    async fn universal_resolver_rejects_a_fetched_document_with_the_wrong_id() {
        let body = br#"{"id":"did:web:other.example"}"#.as_slice();
        let resolver = UniversalResolver::new()
            .with_method(resolver(FakeExecutor::responding(StatusCode::OK, body)));

        assert!(matches!(
            resolver.resolve("did:web:example.com").await,
            Err(ResolverError::InvalidDocument(message))
                if message.contains("did:web:other.example")
                    && message.contains("did:web:example.com")
        ));
    }

    #[tokio::test]
    async fn native_web_resolution_cannot_be_shadowed_by_static_keys() {
        let did = "did:web:127.0.0.1";
        let fallback = StaticPublicKeyResolver::new(std::collections::BTreeMap::from([(
            format!("{did}#key-1"),
            JWK::generate_ed25519().unwrap(),
        )]));
        let resolver = UniversalResolver::with_fallback(fallback);

        // The native did:web resolver rejects the loopback URL. If `web` were not registered,
        // the static fallback would synthesize a document and this call would succeed.
        assert_eq!(resolver.resolve(did).await, Err(ResolverError::NotFound));
    }

    #[tokio::test]
    async fn jws_verification_resolves_the_signing_key_from_a_web_document() {
        let private_jwk = JWK::generate_ed25519().unwrap();
        let public_jwk = private_jwk.to_public();
        let did = "did:web:example.com";
        let kid = format!("{did}#key-1");
        let signer = PrivateJwkSigner::new(&kid, Algorithm::EdDSA, private_jwk);
        let jws = Jws::create(b"resolved through did:web".as_slice(), &[signer])
            .await
            .unwrap();
        let body = serde_json::to_vec(&json!({
            "id": did,
            "verificationMethod": [{
                "id": kid,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_jwk,
            }]
        }))
        .unwrap();
        let resolver = UniversalResolver::new()
            .with_method(resolver(FakeExecutor::responding(StatusCode::OK, body)));

        assert_eq!(jws.verify_signatures(&resolver).await.unwrap(), [did]);
    }
}
