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
