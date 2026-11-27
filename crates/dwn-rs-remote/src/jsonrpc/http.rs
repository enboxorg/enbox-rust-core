use std::{future::Future, pin::Pin};

use bytes::Bytes;
use dwn_rs_core::utils::http_rpc_framing::{self, HTTP_DWN_RPC_MEDIA_TYPE};
use dwn_rs_core::{Reply, Response as DWNResponse};
use futures_core::{stream::BoxStream, TryStream};
use futures_util::{StreamExt, TryStreamExt};
use http::header;
use tower::Service;
use tracing::trace;

use crate::jsonrpc::ResultError;

use super::{JSONRpcError, JSONRpcErrorCodes, Request, Response};

pub const USER_AGENT: &str = concat!(
    "rpc-",
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "(",
    env!("CARGO_CRATE_NAME"),
    ")"
);

pub struct HTTPTransport {
    url: String,
    client: reqwest::Client,
}

impl<S> Service<(Request, Option<S>)> for HTTPTransport
where
    S: TryStream + Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    Bytes: From<S::Ok>,
{
    type Response = Response<(
        DWNResponse<Reply>,
        BoxStream<'static, Result<Bytes, JSONRpcError>>,
    )>;
    type Error = JSONRpcError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&mut self, request: (Request, Option<S>)) -> Self::Future {
        let url = self.url.clone();
        let mut client = self.client.clone();

        Box::pin(async move {
            let stream = request.1;
            let envelope = serde_json::to_vec(&request.0)?;
            let prefix = http_rpc_framing::frame_request_header(&envelope, stream.is_some())
                .map_err(|err| JSONRpcError {
                    code: JSONRpcErrorCodes::InternalError,
                    message: err.to_string(),
                    data: None,
                })?;

            let mut rb = client
                .clone()
                .request(http::method::Method::POST, url)
                .header(header::CONTENT_TYPE, HTTP_DWN_RPC_MEDIA_TYPE);

            rb = match stream {
                Some(data) => {
                    let data = data
                        .map_ok(Bytes::from)
                        .map_err(|err| std::io::Error::other(err.into().to_string()));
                    type BodyStream = BoxStream<'static, Result<Bytes, std::io::Error>>;
                    let body: BodyStream =
                        futures_util::stream::once(async move { Ok::<_, std::io::Error>(prefix) })
                            .chain(data)
                            .boxed();
                    rb.body(reqwest::Body::wrap_stream::<BodyStream>(body))
                }
                None => rb.body(prefix),
            };

            let req = rb.build()?;

            let res = client.call(req).await?;

            trace!(?res, "Received response");

            let resp = match res.headers().get("dwn-response") {
                Some(h) => {
                    let resp =
                        serde_json::from_slice::<Response<DWNResponse<Reply>>>(h.as_bytes())?;
                    let body = Box::pin(
                        res.bytes_stream()
                            .map_err(JSONRpcError::from)
                            .map_ok(|b| b)
                            .into_stream(),
                    )
                        as BoxStream<'static, Result<Bytes, JSONRpcError>>;

                    (resp, body)
                }
                None => {
                    let body = res.bytes().await?;

                    let resp: Response<DWNResponse<Reply>> = serde_json::from_slice(&body)?;
                    trace!(?resp, "Response in body");
                    let empty =
                        Box::pin(futures_util::stream::empty::<Result<Bytes, JSONRpcError>>())
                            as BoxStream<'static, Result<Bytes, JSONRpcError>>;

                    (resp, empty)
                }
            };

            let msg = match resp.0.result {
                ResultError::Result(m) => Ok(m.result),
                ResultError::Error(e) => Err(JSONRpcError::from(e)),
            }?
            .reply;
            let body = resp.1;

            Ok(Response::new_v2(resp.0.id, (msg, body)))
        })
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.client.poll_ready(cx).map_err(|e| JSONRpcError {
            code: JSONRpcErrorCodes::InternalError,
            message: e.to_string(),
            data: None,
        })
    }
}

impl HTTPTransport {
    pub fn new(uri: String) -> Result<Self, JSONRpcError> {
        let content_type = HTTP_DWN_RPC_MEDIA_TYPE.parse().map_err(|e| JSONRpcError {
            code: JSONRpcErrorCodes::InternalError,
            message: format!("Failed to parse Content-Type header: {}", e),
            data: None,
        })?;

        let c = reqwest::ClientBuilder::new()
            .user_agent(USER_AGENT)
            .default_headers(header::HeaderMap::from_iter(vec![(
                header::CONTENT_TYPE,
                content_type,
            )]))
            .deflate(true)
            .gzip(true)
            .build()
            .map_err(|e| JSONRpcError {
                code: JSONRpcErrorCodes::InternalError,
                message: e.to_string(),
                data: None,
            });

        Ok(Self {
            url: uri,
            client: c?,
        })
    }
}
