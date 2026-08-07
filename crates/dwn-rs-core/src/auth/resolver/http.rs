//! HTTP primitives shared by network-backed DID method resolvers.
//!
//! Redirects are driven manually so every target is validated before it is requested. The
//! literal-host policy intentionally matches the pinned Enbox `fetchPublicUrl` implementation;
//! it does not resolve DNS names or claim protection against DNS rebinding.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use reqwest::header::{HeaderMap, LOCATION};
use reqwest::{Method, StatusCode};
use url::{Host, Url};

use super::ResolverFuture;

const REDIRECT_STATUS_CODES: [StatusCode; 5] = [
    StatusCode::MOVED_PERMANENTLY,
    StatusCode::FOUND,
    StatusCode::SEE_OTHER,
    StatusCode::TEMPORARY_REDIRECT,
    StatusCode::PERMANENT_REDIRECT,
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum PublicHttpError {
    #[error("{description} must use HTTP or HTTPS, got '{scheme}'")]
    InvalidScheme { description: String, scheme: String },
    #[error("{description} must specify a hostname")]
    MissingHostname { description: String },
    #[error("{description} must not target a private, loopback, or link-local host")]
    PrivateHostname { description: String },
    #[error("invalid redirect location")]
    InvalidRedirect,
    #[error("maximum redirect count ({0}) exceeded")]
    TooManyRedirects(usize),
    #[error("request deadline exceeded")]
    DeadlineExceeded,
    #[error("HTTP client unavailable: {0}")]
    ClientUnavailable(String),
    #[error("HTTP request failed: {0}")]
    Request(String),
    #[error("HTTP response body failed: {0}")]
    ResponseBody(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetPolicy {
    /// Reject private, loopback, and link-local targets at every request hop.
    PublicOnly,
    /// Permit private hosts while retaining scheme, hostname, redirect, and deadline checks.
    AllowPrivate,
}

#[derive(Clone)]
pub(crate) struct HttpRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
}

impl HttpRequest {
    pub fn get(url: Url) -> Self {
        Self {
            method: Method::GET,
            url,
            headers: HeaderMap::new(),
            body: None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Executes exactly one HTTP request without following redirects.
pub(crate) trait HttpExecutor: Send + Sync {
    fn execute_once<'a>(
        &'a self,
        request: HttpRequest,
        timeout: Duration,
    ) -> ResolverFuture<'a, Result<HttpResponse, PublicHttpError>>;
}

#[derive(Clone, Default)]
pub(crate) struct ReqwestHttpExecutor {
    client: Arc<OnceLock<Result<reqwest::Client, Arc<str>>>>,
}

impl ReqwestHttpExecutor {
    fn client(&self) -> Result<reqwest::Client, PublicHttpError> {
        match self.client.get_or_init(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(format!("enbox-did-resolver/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|error| Arc::<str>::from(error.to_string()))
        }) {
            Ok(client) => Ok(client.clone()),
            Err(error) => Err(PublicHttpError::ClientUnavailable(error.to_string())),
        }
    }
}

impl HttpExecutor for ReqwestHttpExecutor {
    fn execute_once<'a>(
        &'a self,
        request: HttpRequest,
        timeout: Duration,
    ) -> ResolverFuture<'a, Result<HttpResponse, PublicHttpError>> {
        Box::pin(async move {
            let client = self.client()?;
            let mut builder = client
                .request(request.method, request.url)
                .headers(request.headers)
                .timeout(timeout);
            if let Some(body) = request.body {
                builder = builder.body(body);
            }

            let response = builder.send().await.map_err(|error| {
                if error.is_timeout() {
                    PublicHttpError::DeadlineExceeded
                } else {
                    PublicHttpError::Request(error.to_string())
                }
            })?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = if status.is_success() {
                response
                    .bytes()
                    .await
                    .map_err(|error| PublicHttpError::ResponseBody(error.to_string()))?
            } else {
                Bytes::new()
            };

            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

/// Fetch a public URL while validating the initial target and every redirect target.
pub(crate) async fn fetch_public_url(
    executor: &dyn HttpExecutor,
    request: HttpRequest,
    timeout: Duration,
    max_redirects: usize,
    description: &str,
) -> Result<HttpResponse, PublicHttpError> {
    fetch_url(
        executor,
        request,
        timeout,
        max_redirects,
        description,
        TargetPolicy::PublicOnly,
    )
    .await
}

pub(crate) async fn fetch_url(
    executor: &dyn HttpExecutor,
    mut request: HttpRequest,
    timeout: Duration,
    max_redirects: usize,
    description: &str,
    target_policy: TargetPolicy,
) -> Result<HttpResponse, PublicHttpError> {
    let started = Instant::now();
    let mut redirects_followed = 0;

    loop {
        validate_target_url(&request.url, description, target_policy)?;
        let remaining = timeout
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PublicHttpError::DeadlineExceeded)?;
        let response = executor.execute_once(request.clone(), remaining).await?;

        if !REDIRECT_STATUS_CODES.contains(&response.status) {
            return Ok(response);
        }

        let Some(location) = response.headers.get(LOCATION) else {
            return Ok(response);
        };
        if redirects_followed >= max_redirects {
            return Err(PublicHttpError::TooManyRedirects(max_redirects));
        }

        let location = location
            .to_str()
            .map_err(|_| PublicHttpError::InvalidRedirect)?;
        let redirect_url = request
            .url
            .join(location)
            .map_err(|_| PublicHttpError::InvalidRedirect)?;
        validate_target_url(&redirect_url, description, target_policy)?;

        request.url = redirect_url;
        redirects_followed += 1;
    }
}

#[cfg(test)]
fn validate_public_url(url: &Url, description: &str) -> Result<(), PublicHttpError> {
    validate_target_url(url, description, TargetPolicy::PublicOnly)
}

fn validate_target_url(
    url: &Url,
    description: &str,
    target_policy: TargetPolicy,
) -> Result<(), PublicHttpError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(PublicHttpError::InvalidScheme {
            description: description.to_string(),
            scheme: url.scheme().to_string(),
        });
    }

    let host = url.host().ok_or_else(|| PublicHttpError::MissingHostname {
        description: description.to_string(),
    })?;
    if target_policy == TargetPolicy::PublicOnly && is_private_host(host) {
        return Err(PublicHttpError::PrivateHostname {
            description: description.to_string(),
        });
    }

    Ok(())
}

fn is_private_host(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            domain == "localhost" || domain.ends_with(".localhost")
        }
        Host::Ipv4(address) => is_private_ipv4(address),
        Host::Ipv6(address) => is_private_ipv6(address),
    }
}

fn is_private_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    a == 0
        || a == 10
        || (a == 100 && (64..=127).contains(&b))
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || a >= 224
}

fn is_private_ipv6(address: Ipv6Addr) -> bool {
    let [h0, h1, h2, h3, h4, h5, h6, h7] = address.segments();
    let first_six_zero = h0 == 0 && h1 == 0 && h2 == 0 && h3 == 0 && h4 == 0 && h5 == 0;

    address.is_unspecified()
        || address.is_loopback()
        || (h0 & 0xfe00) == 0xfc00
        || (h0 & 0xffc0) == 0xfe80
        || (h0 & 0xff00) == 0xff00
        || (h0 == 0x0064
            && h1 == 0xff9b
            && h2 == 0
            && h3 == 0
            && h4 == 0
            && h5 == 0
            && is_private_ipv4(hextets_to_ipv4(h6, h7)))
        || (h0 == 0
            && h1 == 0
            && h2 == 0
            && h3 == 0
            && h4 == 0
            && h5 == 0xffff
            && is_private_ipv4(hextets_to_ipv4(h6, h7)))
        || first_six_zero
}

fn hextets_to_ipv4(high: u16, low: u16) -> Ipv4Addr {
    Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::thread;

    use reqwest::header::HeaderValue;

    use super::*;

    #[derive(Default)]
    struct FakeExecutor {
        responses: Mutex<VecDeque<Result<HttpResponse, PublicHttpError>>>,
        requests: Mutex<Vec<(HttpRequest, Duration)>>,
        delay: Duration,
    }

    impl FakeExecutor {
        fn new(responses: impl IntoIterator<Item = HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().map(Ok).collect()),
                ..Self::default()
            }
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
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
        ) -> ResolverFuture<'a, Result<HttpResponse, PublicHttpError>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push((request, timeout));
                if !self.delay.is_zero() {
                    thread::sleep(self.delay);
                }
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
        let mut response = response(StatusCode::FOUND);
        response
            .headers
            .insert(LOCATION, HeaderValue::from_str(location).unwrap());
        response
    }

    #[test]
    fn accepts_public_http_hosts() {
        for url in [
            "https://example.com/did.json",
            "http://8.8.8.8/did.json",
            "https://[2001:4860:4860::8888]/did.json",
            "https://example.com./did.json",
        ] {
            validate_public_url(&Url::parse(url).unwrap(), "test URL").unwrap();
        }
    }

    #[test]
    fn rejects_non_network_schemes() {
        assert!(matches!(
            validate_public_url(&Url::parse("file:///etc/hosts").unwrap(), "test URL"),
            Err(PublicHttpError::InvalidScheme { .. })
        ));
    }

    #[test]
    fn rejects_private_ipv4_hosts() {
        for host in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            let url = Url::parse(&format!("http://{host}/did.json")).unwrap();
            assert!(matches!(
                validate_public_url(&url, "test URL"),
                Err(PublicHttpError::PrivateHostname { .. })
            ));
        }
    }

    #[test]
    fn rejects_private_ipv6_hosts() {
        for host in [
            "::",
            "::1",
            "fc00::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b::7f00:1",
            "::ffff:127.0.0.1",
            "::192.0.2.1",
        ] {
            let url = Url::parse(&format!("http://[{host}]/did.json")).unwrap();
            assert!(matches!(
                validate_public_url(&url, "test URL"),
                Err(PublicHttpError::PrivateHostname { .. })
            ));
        }
    }

    #[test]
    fn rejects_localhost_names() {
        for host in ["localhost", "api.localhost", "LOCALHOST."] {
            let url = Url::parse(&format!("http://{host}/did.json")).unwrap();
            assert!(matches!(
                validate_public_url(&url, "test URL"),
                Err(PublicHttpError::PrivateHostname { .. })
            ));
        }
    }

    #[tokio::test]
    async fn follows_relative_redirect_and_preserves_request() {
        let executor =
            FakeExecutor::new([redirect("../identity/did.json"), response(StatusCode::OK)]);
        let mut request = HttpRequest::get(Url::parse("https://example.com/users/alice").unwrap());
        request
            .headers
            .insert("x-test", HeaderValue::from_static("1"));

        let result = fetch_public_url(&executor, request, Duration::from_secs(30), 5, "test URL")
            .await
            .unwrap();

        assert_eq!(result.status, StatusCode::OK);
        let requests = executor.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].0.url,
            Url::parse("https://example.com/identity/did.json").unwrap()
        );
        assert_eq!(requests[1].0.headers["x-test"], "1");
    }

    #[tokio::test]
    async fn does_not_request_private_initial_url() {
        let executor = FakeExecutor::default();

        assert!(matches!(
            fetch_public_url(
                &executor,
                HttpRequest::get(Url::parse("https://127.0.0.1/did.json").unwrap()),
                Duration::from_secs(30),
                5,
                "test URL",
            )
            .await,
            Err(PublicHttpError::PrivateHostname { .. })
        ));
        assert_eq!(executor.request_count(), 0);
    }

    #[tokio::test]
    async fn allow_private_policy_requests_private_initial_url() {
        let executor = FakeExecutor::new([response(StatusCode::OK)]);

        let response = fetch_url(
            &executor,
            HttpRequest::get(Url::parse("http://127.0.0.1/did.json").unwrap()),
            Duration::from_secs(30),
            5,
            "test URL",
            TargetPolicy::AllowPrivate,
        )
        .await
        .unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(executor.request_count(), 1);
    }

    #[tokio::test]
    async fn does_not_follow_private_or_non_network_redirects() {
        for location in ["http://169.254.169.254/metadata", "file:///etc/hosts"] {
            let executor = FakeExecutor::new([redirect(location)]);

            assert!(fetch_public_url(
                &executor,
                HttpRequest::get(Url::parse("https://example.com/did.json").unwrap()),
                Duration::from_secs(30),
                5,
                "test URL",
            )
            .await
            .is_err());
            assert_eq!(executor.request_count(), 1);
        }
    }

    #[tokio::test]
    async fn allow_private_policy_allows_private_redirects_but_not_non_network_ones() {
        let executor =
            FakeExecutor::new([redirect("http://127.0.0.1/next"), response(StatusCode::OK)]);

        let response = fetch_url(
            &executor,
            HttpRequest::get(Url::parse("https://example.com/did.json").unwrap()),
            Duration::from_secs(30),
            5,
            "test URL",
            TargetPolicy::AllowPrivate,
        )
        .await
        .unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(executor.request_count(), 2);

        let executor = FakeExecutor::new([redirect("file:///etc/hosts")]);
        assert!(matches!(
            fetch_url(
                &executor,
                HttpRequest::get(Url::parse("https://example.com/did.json").unwrap()),
                Duration::from_secs(30),
                5,
                "test URL",
                TargetPolicy::AllowPrivate,
            )
            .await,
            Err(PublicHttpError::InvalidScheme { .. })
        ));
        assert_eq!(executor.request_count(), 1);
    }

    #[tokio::test]
    async fn returns_redirect_without_location() {
        let executor = FakeExecutor::new([response(StatusCode::NOT_MODIFIED)]);

        let response = fetch_public_url(
            &executor,
            HttpRequest::get(Url::parse("https://example.com/did.json").unwrap()),
            Duration::from_secs(30),
            5,
            "test URL",
        )
        .await
        .unwrap();

        assert_eq!(response.status, StatusCode::NOT_MODIFIED);
        assert_eq!(executor.request_count(), 1);
    }

    #[tokio::test]
    async fn enforces_redirect_limit() {
        let executor = FakeExecutor::new((0..=5).map(|index| redirect(&format!("/{index}"))));

        assert!(matches!(
            fetch_public_url(
                &executor,
                HttpRequest::get(Url::parse("https://example.com/start").unwrap()),
                Duration::from_secs(30),
                5,
                "test URL",
            )
            .await,
            Err(PublicHttpError::TooManyRedirects(5))
        ));
        assert_eq!(executor.request_count(), 6);
    }

    #[tokio::test]
    async fn uses_one_deadline_across_redirects() {
        let executor = FakeExecutor::new([redirect("/next"), response(StatusCode::OK)])
            .with_delay(Duration::from_millis(5));

        fetch_public_url(
            &executor,
            HttpRequest::get(Url::parse("https://example.com/start").unwrap()),
            Duration::from_secs(1),
            5,
            "test URL",
        )
        .await
        .unwrap();

        let requests = executor.requests.lock().unwrap();
        assert!(requests[1].1 < requests[0].1);
    }
}
