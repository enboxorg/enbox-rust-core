use std::{sync::Arc, time::Duration};

use ssi_dids_core::DID;
use url::Url;

use crate::auth::resolver::{
    http::{
        fetch_url, HttpExecutor, HttpRequest, PublicHttpError, ReqwestHttpExecutor, TargetPolicy,
    },
    DidMethodResolver, Resolution, ResolverError, ResolverFuture,
};

mod dns;
mod pkarr;

const DEFAULT_GATEWAY_URI: &str = "https://enbox-did-dht.fly.dev";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Network and target-policy settings for one DID DHT resolution.
pub struct DhtResolverConfig {
    /// Base URL of the Pkarr relay or DID DHT gateway.
    pub gateway_uri: Url,
    /// Deadline shared by the initial request and all redirects.
    pub timeout: Duration,
    /// Maximum number of redirects followed after the initial request.
    pub max_redirects: usize,
    /// Permit explicitly configured private or loopback gateways for development and CI.
    pub allow_private_gateway_uri: bool,
}

impl Default for DhtResolverConfig {
    fn default() -> Self {
        Self {
            gateway_uri: Url::parse(DEFAULT_GATEWAY_URI).expect("valid default gateway URI"),
            timeout: DEFAULT_TIMEOUT,
            max_redirects: MAX_REDIRECTS,
            allow_private_gateway_uri: false,
        }
    }
}

#[derive(Clone)]
/// Resolves `did:dht` identifiers through a Pkarr-compatible HTTP gateway.
pub struct DhtResolver {
    config: DhtResolverConfig,
    http: Arc<dyn HttpExecutor>,
}

impl DhtResolver {
    /// Create a resolver with the native HTTP executor and supplied configuration.
    pub fn new(config: DhtResolverConfig) -> Self {
        Self {
            config,
            http: Arc::new(ReqwestHttpExecutor::default()),
        }
    }

    #[cfg(test)]
    fn with_executor(config: DhtResolverConfig, http: Arc<dyn HttpExecutor>) -> Self {
        Self { config, http }
    }
}

impl DidMethodResolver for DhtResolver {
    fn method_name(&self) -> &str {
        "dht"
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

            let url = pkarr::gateway_identity_uri(&self.config.gateway_uri, did)?;
            let target_policy = if self.config.allow_private_gateway_uri {
                TargetPolicy::AllowPrivate
            } else {
                TargetPolicy::PublicOnly
            };
            let response = fetch_url(
                self.http.as_ref(),
                HttpRequest::get(url),
                self.config.timeout,
                self.config.max_redirects,
                "Pkarr gateway URL",
                target_policy,
            )
            .await
            .map_err(map_gateway_error)?;

            if !response.status.is_success() {
                return Err(ResolverError::NotFound);
            }

            pkarr::resolve_relay_payload(did, &response.body)
        })
    }
}

impl Default for DhtResolver {
    fn default() -> Self {
        Self::new(DhtResolverConfig::default())
    }
}

fn map_gateway_error(error: PublicHttpError) -> ResolverError {
    match error {
        PublicHttpError::InvalidScheme { .. }
        | PublicHttpError::MissingHostname { .. }
        | PublicHttpError::PrivateHostname { .. }
        | PublicHttpError::InvalidRedirect => ResolverError::InvalidGatewayUri(error.to_string()),
        PublicHttpError::TooManyRedirects(_)
        | PublicHttpError::DeadlineExceeded
        | PublicHttpError::ClientUnavailable(_)
        | PublicHttpError::Request(_)
        | PublicHttpError::ResponseBody(_) => ResolverError::Internal(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use bytes::Bytes;
    use ed25519_dalek::{Signer, SigningKey};
    use reqwest::header::HeaderMap;
    use reqwest::StatusCode;
    use simple_dns::rdata::{RData, TXT};
    use simple_dns::{Name, Packet, ResourceRecord, CLASS};
    use ssi_dids_core::DIDBuf;

    use super::*;
    use crate::auth::resolver::http::HttpResponse;

    struct FakeExecutor {
        responses: Mutex<VecDeque<Result<HttpResponse, PublicHttpError>>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl FakeExecutor {
        fn new(responses: impl IntoIterator<Item = Result<HttpResponse, PublicHttpError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    impl HttpExecutor for FakeExecutor {
        fn execute_once<'a>(
            &'a self,
            request: HttpRequest,
            _timeout: Duration,
        ) -> ResolverFuture<'a, Result<HttpResponse, PublicHttpError>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request);
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("fake response must be configured")
            })
        }
    }

    fn response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status,
            headers: HeaderMap::new(),
            body: Bytes::from(body),
        }
    }

    fn signed_relay_payload(sequence: u64) -> (DIDBuf, Vec<u8>) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let identifier = z32::encode(signing_key.verifying_key().as_bytes());
        let did = format!("did:dht:{identifier}").parse().unwrap();
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());

        let mut packet = Packet::new_reply(0);
        let root_name = format!("_did.{identifier}.");
        packet.answers.push(ResourceRecord::new(
            Name::new(&root_name).unwrap(),
            CLASS::IN,
            7200,
            RData::TXT(TXT::try_from("v=0;vm=k0;auth=k0;asm=k0;inv=k0;del=k0").unwrap()),
        ));
        let key_record = format!("t=0;k={public_key}");
        packet.answers.push(ResourceRecord::new(
            Name::new("_k0._did.").unwrap(),
            CLASS::IN,
            7200,
            RData::TXT(TXT::try_from(key_record.as_str()).unwrap()),
        ));
        let value = packet.build_bytes_vec_compressed().unwrap();
        let prefix = format!("3:seqi{sequence}e1:v{}:", value.len());
        let mut signing_payload = prefix.into_bytes();
        signing_payload.extend_from_slice(&value);
        let signature = signing_key.sign(&signing_payload);

        let mut payload = Vec::with_capacity(72 + value.len());
        payload.extend_from_slice(&signature.to_bytes());
        payload.extend_from_slice(&sequence.to_be_bytes());
        payload.extend_from_slice(&value);
        (did, payload)
    }

    fn resolver(
        config: DhtResolverConfig,
        response: Result<HttpResponse, PublicHttpError>,
    ) -> (DhtResolver, Arc<FakeExecutor>) {
        let http = Arc::new(FakeExecutor::new([response]));
        (DhtResolver::with_executor(config, http.clone()), http)
    }

    #[tokio::test]
    async fn resolves_a_signed_relay_document() {
        let (did, payload) = signed_relay_payload(42);
        let config = DhtResolverConfig {
            gateway_uri: Url::parse("https://gateway.example/pkarr").unwrap(),
            ..DhtResolverConfig::default()
        };
        let (resolver, http) = resolver(config, Ok(response(StatusCode::OK, payload)));

        let resolution = resolver.resolve(&did).await.unwrap();

        assert_eq!(resolution.document.id, did);
        assert_eq!(resolution.document.verification_method.len(), 1);
        assert_eq!(
            resolution.document_metadata.version_id.as_deref(),
            Some("42")
        );
        assert_eq!(resolution.document_metadata.properties["published"], true);
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url,
            Url::parse(&format!(
                "https://gateway.example/pkarr/{}",
                did.method_specific_id()
            ))
            .unwrap()
        );
    }

    #[tokio::test]
    async fn private_gateway_requires_explicit_opt_in() {
        let (did, payload) = signed_relay_payload(1);
        let config = DhtResolverConfig {
            gateway_uri: Url::parse("http://127.0.0.1:7527").unwrap(),
            ..DhtResolverConfig::default()
        };
        let (resolver, http) = resolver(config, Ok(response(StatusCode::OK, payload)));

        assert!(matches!(
            resolver.resolve(&did).await,
            Err(ResolverError::InvalidGatewayUri(_))
        ));
        assert_eq!(http.request_count(), 0);
    }

    #[tokio::test]
    async fn private_gateway_can_be_explicitly_enabled() {
        let (did, payload) = signed_relay_payload(1);
        let config = DhtResolverConfig {
            gateway_uri: Url::parse("http://127.0.0.1:7527").unwrap(),
            allow_private_gateway_uri: true,
            ..DhtResolverConfig::default()
        };
        let (resolver, http) = resolver(config, Ok(response(StatusCode::OK, payload)));

        assert!(resolver.resolve(&did).await.is_ok());
        assert_eq!(http.request_count(), 1);
    }

    #[tokio::test]
    async fn treats_missing_relay_values_as_not_found() {
        let (did, _) = signed_relay_payload(1);
        let (resolver, http) = resolver(
            DhtResolverConfig::default(),
            Ok(response(StatusCode::NOT_FOUND, Vec::new())),
        );

        assert_eq!(resolver.resolve(&did).await, Err(ResolverError::NotFound));
        assert_eq!(http.request_count(), 1);
    }

    #[tokio::test]
    async fn maps_gateway_transport_failures_to_internal_errors() {
        let (did, _) = signed_relay_payload(1);
        let (resolver, http) = resolver(
            DhtResolverConfig::default(),
            Err(PublicHttpError::Request("connection refused".to_string())),
        );

        assert!(matches!(
            resolver.resolve(&did).await,
            Err(ResolverError::Internal(_))
        ));
        assert_eq!(http.request_count(), 1);
    }
}
