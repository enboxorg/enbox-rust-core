//! HTTP-backed [`TenantRegistrationClient`] for `@enbox/dwn-server`-style
//! servers.
//!
//! Endpoints used (paths are relative to the registered DWN URL):
//!
//! | Method | Path | Body |
//! |---|---|---|
//! | `GET` | `/info` | — (returns [`DwnServerInfo`]) |
//! | `POST` | `/registration` | `{ "did": "..." }` (anonymous) or `{ "did": "...", "registrationToken": "..." }` (provider-auth-v0) |
//! | `POST` | `<refresh_url>` | `{ "refreshToken": "..." }` (returns [`RegistrationTokenData`]) |
//!
//! All non-2xx responses surface as `AgentIdentityError` with a stable
//! `code` so FFI callers can distinguish transport failures from server
//! rejections.

use dwn_rs_core::agent::{AgentIdentityError, AgentIdentityResult};
use dwn_rs_core::setup::{
    DwnServerInfo, RegistrationTokenData, SetupFuture, TenantRegistrationClient,
};
use serde::Serialize;

const SERVER_INFO_PATH: &str = "/info";
const REGISTRATION_PATH: &str = "/registration";

#[derive(Clone)]
pub struct HttpTenantRegistrationClient {
    client: reqwest::Client,
}

impl HttpTenantRegistrationClient {
    pub fn new() -> AgentIdentityResult<Self> {
        let client = reqwest::Client::builder()
            .user_agent(format!("enbox-ffi/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| {
                AgentIdentityError::new("HttpRegistrationClientBuildFailed", err.to_string())
            })?;
        Ok(Self { client })
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    async fn post_registration<T: Serialize + ?Sized>(
        &self,
        endpoint: &str,
        body: &T,
    ) -> AgentIdentityResult<()> {
        let url = join_url(endpoint, REGISTRATION_PATH);
        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|err| {
                AgentIdentityError::new("HttpRegistrationTransportFailed", err.to_string())
            })?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AgentIdentityError::new(
                "HttpRegistrationRejected",
                format!("server returned HTTP {status} for {url}: {body}"),
            ));
        }
        Ok(())
    }
}

impl TenantRegistrationClient for HttpTenantRegistrationClient {
    fn server_info<'a>(&'a self, endpoint: &'a str) -> SetupFuture<'a, DwnServerInfo> {
        Box::pin(async move {
            let url = join_url(endpoint, SERVER_INFO_PATH);
            let response = self.client.get(&url).send().await.map_err(|err| {
                AgentIdentityError::new("HttpRegistrationTransportFailed", err.to_string())
            })?;
            if !response.status().is_success() {
                return Err(AgentIdentityError::new(
                    "HttpRegistrationServerInfoFailed",
                    format!("server returned HTTP {} for {url}", response.status()),
                ));
            }
            response.json::<DwnServerInfo>().await.map_err(|err| {
                AgentIdentityError::new("HttpRegistrationServerInfoFailed", err.to_string())
            })
        })
    }

    fn register_tenant<'a>(&'a self, endpoint: &'a str, did: &'a str) -> SetupFuture<'a, ()> {
        let body = serde_json::json!({ "did": did });
        Box::pin(async move { self.post_registration(endpoint, &body).await })
    }

    fn register_tenant_with_token<'a>(
        &'a self,
        endpoint: &'a str,
        did: &'a str,
        registration_token: &'a str,
    ) -> SetupFuture<'a, ()> {
        let body = serde_json::json!({
            "did": did,
            "registrationToken": registration_token,
        });
        Box::pin(async move { self.post_registration(endpoint, &body).await })
    }

    fn refresh_registration_token<'a>(
        &'a self,
        refresh_url: &'a str,
        refresh_token: &'a str,
    ) -> SetupFuture<'a, RegistrationTokenData> {
        Box::pin(async move {
            let response = self
                .client
                .post(refresh_url)
                .json(&serde_json::json!({ "refreshToken": refresh_token }))
                .send()
                .await
                .map_err(|err| {
                    AgentIdentityError::new("HttpRegistrationTransportFailed", err.to_string())
                })?;
            if !response.status().is_success() {
                return Err(AgentIdentityError::new(
                    "HttpRegistrationRefreshFailed",
                    format!(
                        "refresh returned HTTP {} for {refresh_url}",
                        response.status()
                    ),
                ));
            }
            response
                .json::<RegistrationTokenData>()
                .await
                .map_err(|err| {
                    AgentIdentityError::new("HttpRegistrationRefreshFailed", err.to_string())
                })
        })
    }
}

fn join_url(base: &str, path: &str) -> String {
    let trimmed_base = base.trim_end_matches('/');
    let trimmed_path = path.trim_start_matches('/');
    format!("{trimmed_base}/{trimmed_path}")
}
