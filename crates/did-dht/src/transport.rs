//! Transport injection for the Pkarr-compatible gateway client.
//!
//! The implementor owns HTTP execution, including redirects, private-target
//! policy, and the shared deadline. The method crate only describes requests
//! with plain data so it never depends on an HTTP client.

use std::{future::Future, pin::Pin, time::Duration};

use url::Url;

use super::error::DhtPublishError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMethod {
    Get,
    Put,
}

#[derive(Debug, Clone)]
pub struct RelayRequest {
    pub method: RelayMethod,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl RelayRequest {
    pub fn get(url: Url) -> Self {
        Self {
            method: RelayMethod::Get,
            url,
            headers: Vec::new(),
            body: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelayResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Executes one gateway request with redirects, target policy, and deadline
/// already applied. Failures that describe the gateway target surface as
/// [`DhtPublishError::InvalidGatewayUri`]; the rest as
/// [`DhtPublishError::Transport`].
pub trait DhtTransport: Send + Sync {
    fn fetch<'a>(
        &'a self,
        request: RelayRequest,
        timeout: Duration,
        max_redirects: usize,
        allow_private: bool,
    ) -> Pin<Box<dyn Future<Output = Result<RelayResponse, DhtPublishError>> + Send + 'a>>;
}
