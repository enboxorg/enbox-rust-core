//! `did:dht` resolution through the method crate's gateway client.
//!
//! Method logic (codec, BEP44, sequence, publish surface) lives in the
//! `did-dht` crate. This module only adapts it: it injects the core HTTP
//! executor as the method transport, maps method errors into [`ResolverError`],
//! and builds core [`Resolution`] values. `DhtResolver::publish` lands here in
//! a later unit, reusing the same transport.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use did_dht::{DhtTransport, RelayResponse};
use reqwest::Method;
use serde_json::Value;
use ssi_dids_core::DID;

use super::http::{
    fetch_url, HttpExecutor, HttpRequest, PublicHttpError, ReqwestHttpExecutor, TargetPolicy,
};
use super::{DidMethodResolver, Resolution, ResolverError, ResolverFuture};

pub use did_dht::{DhtPublishError, DhtResolver, DhtResolverConfig};

/// Build a `did:dht` client wired to the native HTTP executor.
pub fn new_dht_resolver(config: DhtResolverConfig) -> DhtResolver {
    DhtResolver::new(
        config,
        Arc::new(NativeTransport {
            http: Arc::new(ReqwestHttpExecutor::default()),
        }),
    )
}

struct NativeTransport {
    http: Arc<dyn HttpExecutor>,
}

impl DhtTransport for NativeTransport {
    fn fetch<'a>(
        &'a self,
        request: did_dht::RelayRequest,
        timeout: Duration,
        max_redirects: usize,
        allow_private: bool,
    ) -> Pin<Box<dyn Future<Output = Result<RelayResponse, DhtPublishError>> + Send + 'a>> {
        Box::pin(async move {
            let target_policy = if allow_private {
                TargetPolicy::AllowPrivate
            } else {
                TargetPolicy::PublicOnly
            };
            let request = convert_request(&request)?;
            let response = fetch_url(
                self.http.as_ref(),
                request,
                timeout,
                max_redirects,
                "Pkarr gateway URL",
                target_policy,
            )
            .await
            .map_err(map_transport_error)?;
            Ok(convert_response(response))
        })
    }
}

fn convert_request(request: &did_dht::RelayRequest) -> Result<HttpRequest, DhtPublishError> {
    let method = match request.method {
        did_dht::RelayMethod::Get => Method::GET,
        did_dht::RelayMethod::Put => Method::PUT,
    };
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in &request.headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| DhtPublishError::Transport(error.to_string()))?;
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|error| DhtPublishError::Transport(error.to_string()))?;
        headers.insert(name, value);
    }
    Ok(HttpRequest {
        method,
        url: request.url.clone(),
        headers,
        body: request.body.clone().map(bytes::Bytes::from),
    })
}

fn convert_response(response: super::http::HttpResponse) -> RelayResponse {
    RelayResponse {
        status: response.status.as_u16(),
        headers: Vec::new(),
        body: response.body.to_vec(),
    }
}

fn map_transport_error(error: PublicHttpError) -> DhtPublishError {
    match error {
        PublicHttpError::InvalidScheme { .. }
        | PublicHttpError::MissingHostname { .. }
        | PublicHttpError::PrivateHostname { .. }
        | PublicHttpError::InvalidRedirect => DhtPublishError::InvalidGatewayUri(error.to_string()),
        PublicHttpError::TooManyRedirects(_)
        | PublicHttpError::DeadlineExceeded
        | PublicHttpError::ClientUnavailable(_)
        | PublicHttpError::Request(_)
        | PublicHttpError::ResponseBody(_) => DhtPublishError::Transport(error.to_string()),
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
            let resolved = DhtResolver::resolve(self, did)
                .await
                .map_err(map_resolve_error)?;
            Ok(to_resolution(resolved))
        })
    }
}

fn to_resolution(resolved: did_dht::ResolvedDhtDocument) -> Resolution {
    let mut resolution = Resolution::new(resolved.document);
    resolution.document_metadata.version_id = Some(resolved.sequence.to_string());
    resolution
        .document_metadata
        .properties
        .insert("published".to_string(), Value::Bool(true));
    if let Some(types) = resolved.types {
        resolution.document_metadata.properties.insert(
            "types".to_string(),
            Value::Array(types.into_iter().map(|t| Value::Number(t.into())).collect()),
        );
    }
    resolution
}

fn map_resolve_error(error: DhtPublishError) -> ResolverError {
    match error {
        DhtPublishError::InvalidDocument(message) => ResolverError::InvalidDocument(message),
        DhtPublishError::MethodNotSupported(method) => ResolverError::MethodNotSupported(method),
        DhtPublishError::NotFound => ResolverError::NotFound,
        DhtPublishError::InvalidDocumentLength { min, max, found } => {
            ResolverError::InvalidDocumentLength { min, max, found }
        }
        DhtPublishError::InvalidGatewayUri(message) => ResolverError::InvalidGatewayUri(message),
        DhtPublishError::InvalidPublicKey => ResolverError::InvalidPublicKey,
        DhtPublishError::InvalidPublicKeyLength { expected, found } => {
            ResolverError::InvalidPublicKeyLength { expected, found }
        }
        DhtPublishError::InvalidPublicKeyType { found } => {
            ResolverError::InvalidPublicKeyType { found }
        }
        DhtPublishError::InvalidSignature => ResolverError::InvalidSignature,
        DhtPublishError::Transport(message) => ResolverError::Internal(message),
        // Publish-only variants never surface on the resolve path.
        DhtPublishError::GatewayRejected { status, sequence } => ResolverError::Internal(format!(
            "gateway rejected publication: status {status}, sequence {sequence}"
        )),
        DhtPublishError::Signer(message) => ResolverError::Internal(message),
        DhtPublishError::ValueTooLarge { found } => {
            ResolverError::Internal(format!("document too large: {found} bytes"))
        }
        DhtPublishError::TimeBeforeEpoch => {
            ResolverError::Internal("time is before the unix epoch".to_string())
        }
        DhtPublishError::SequenceOverflow => {
            ResolverError::Internal("sequence number overflowed".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use bytes::Bytes;
    use reqwest::header::{HeaderMap, HeaderValue, LOCATION};
    use reqwest::StatusCode;
    use ssi_dids_core::DIDBuf;
    use url::Url;

    use super::super::http::HttpResponse;
    use super::*;

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

    fn response(status: StatusCode) -> HttpResponse {
        HttpResponse {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    fn redirect(location: &str) -> HttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, HeaderValue::from_str(location).unwrap());
        HttpResponse {
            status: StatusCode::FOUND,
            headers,
            body: Bytes::new(),
        }
    }

    fn resolver(
        config: DhtResolverConfig,
        response: Result<HttpResponse, PublicHttpError>,
    ) -> (DhtResolver, Arc<FakeExecutor>) {
        let http = Arc::new(FakeExecutor::new([response]));
        let transport = Arc::new(NativeTransport { http: http.clone() });
        (DhtResolver::new(config, transport), http)
    }

    #[tokio::test]
    async fn rejects_a_different_did_method_before_transport() {
        let web = "did:web:example.com".parse::<DIDBuf>().unwrap();
        let (resolver, http) = resolver(DhtResolverConfig::default(), Ok(response(StatusCode::OK)));

        assert_eq!(
            DidMethodResolver::resolve(&resolver, &web).await,
            Err(ResolverError::MethodNotSupported("web".to_string()))
        );
        assert_eq!(http.request_count(), 0);
    }

    #[tokio::test]
    async fn private_gateway_requires_explicit_opt_in() {
        let did = "did:dht:cyuoqaf7itop8ohww4yn5ojg13qaq83r9zihgqntc5i9zwrfdfoo"
            .parse::<DIDBuf>()
            .unwrap();
        let config = DhtResolverConfig {
            gateway_uri: Url::parse("http://127.0.0.1:7527").unwrap(),
            ..DhtResolverConfig::default()
        };
        let (resolver, http) = resolver(config, Ok(response(StatusCode::OK)));

        assert!(matches!(
            DidMethodResolver::resolve(&resolver, &did).await,
            Err(ResolverError::InvalidGatewayUri(_))
        ));
        assert_eq!(http.request_count(), 0);
    }

    #[tokio::test]
    async fn private_gateway_opt_in_reaches_transport() {
        let did = "did:dht:cyuoqaf7itop8ohww4yn5ojg13qaq83r9zihgqntc5i9zwrfdfoo"
            .parse::<DIDBuf>()
            .unwrap();
        let config = DhtResolverConfig {
            gateway_uri: Url::parse("http://127.0.0.1:7527").unwrap(),
            allow_private_gateway_uri: true,
            ..DhtResolverConfig::default()
        };
        let (resolver, http) = resolver(config, Ok(response(StatusCode::NOT_FOUND)));

        // The 404 proves the request fired; the signed-payload success path is
        // covered in the method crate.
        assert_eq!(
            DidMethodResolver::resolve(&resolver, &did).await,
            Err(ResolverError::NotFound)
        );
        assert_eq!(http.request_count(), 1);
    }

    #[tokio::test]
    async fn treats_missing_relay_values_as_not_found() {
        let did = "did:dht:cyuoqaf7itop8ohww4yn5ojg13qaq83r9zihgqntc5i9zwrfdfoo"
            .parse::<DIDBuf>()
            .unwrap();
        let (resolver, http) = resolver(
            DhtResolverConfig::default(),
            Ok(response(StatusCode::NOT_FOUND)),
        );

        assert_eq!(
            DidMethodResolver::resolve(&resolver, &did).await,
            Err(ResolverError::NotFound)
        );
        assert_eq!(http.request_count(), 1);
    }

    #[tokio::test]
    async fn put_redirect_preserves_method_headers_and_body() {
        let http = Arc::new(FakeExecutor::new([
            Ok(redirect("/next")),
            Ok(response(StatusCode::OK)),
        ]));
        let transport = NativeTransport { http: http.clone() };
        let request = did_dht::RelayRequest {
            method: did_dht::RelayMethod::Put,
            url: Url::parse("https://example.com/put").unwrap(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            )],
            body: Some(vec![1, 2, 3]),
        };

        let response = transport
            .fetch(request, Duration::from_secs(30), 5, false)
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].method, Method::PUT);
        assert_eq!(
            requests[1].headers["content-type"],
            "application/octet-stream"
        );
        assert_eq!(requests[1].body, Some(Bytes::from_static(&[1, 2, 3])));
    }

    #[tokio::test]
    async fn maps_gateway_transport_failures_to_internal_errors() {
        let did = "did:dht:cyuoqaf7itop8ohww4yn5ojg13qaq83r9zihgqntc5i9zwrfdfoo"
            .parse::<DIDBuf>()
            .unwrap();
        let (resolver, http) = resolver(
            DhtResolverConfig::default(),
            Err(PublicHttpError::Request("connection refused".to_string())),
        );

        assert!(matches!(
            DidMethodResolver::resolve(&resolver, &did).await,
            Err(ResolverError::Internal(_))
        ));
        assert_eq!(http.request_count(), 1);
    }
}
