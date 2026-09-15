use std::{sync::Arc, time::Duration};

use ssi_dids_core::{Document, DID};
use url::Url;

use super::bep44::{
    decode_identity_key, gateway_identity_uri, parse_relay_payload, verify_bep44_message,
};
use super::codec::decode_document;
use super::error::DhtPublishError;
use super::transport::{DhtTransport, RelayRequest};

const DEFAULT_GATEWAY_URI: &str = "https://enbox-did-dht.fly.dev";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Network and target-policy settings for one DID DHT gateway client.
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Decoded `did:dht` document with its relay metadata.
pub struct ResolvedDhtDocument {
    pub document: Document,
    pub sequence: u64,
    pub types: Option<Vec<u64>>,
}

#[derive(Clone)]
/// `did:dht` gateway client over an injected [`DhtTransport`].
///
/// Reads (`resolve`) and, once the publish operation lands, writes share this
/// one configuration and transport. The transport applies redirects,
/// private-target policy, and the shared deadline.
pub struct DhtResolver {
    config: DhtResolverConfig,
    transport: Arc<dyn DhtTransport>,
}

impl DhtResolver {
    /// Create a client with the supplied configuration and transport.
    pub fn new(config: DhtResolverConfig, transport: Arc<dyn DhtTransport>) -> Self {
        Self { config, transport }
    }

    /// Resolve a `did:dht` identifier through the configured gateway.
    pub async fn resolve(&self, did: &DID) -> Result<ResolvedDhtDocument, DhtPublishError> {
        if did.method_name() != "dht" {
            return Err(DhtPublishError::MethodNotSupported(
                did.method_name().to_string(),
            ));
        }

        let url = gateway_identity_uri(&self.config.gateway_uri, did)?;
        let response = self
            .transport
            .fetch(
                RelayRequest::get(url),
                self.config.timeout,
                self.config.max_redirects,
                self.config.allow_private_gateway_uri,
            )
            .await?;

        if !(200..300).contains(&response.status) {
            return Err(DhtPublishError::NotFound);
        }

        let key = decode_identity_key(did)?;
        let message = parse_relay_payload(&response.body)?;
        verify_bep44_message(&key, &message)?;
        let (document, types) = decode_document(did, message.value)?;

        Ok(ResolvedDhtDocument {
            document,
            sequence: message.sequence,
            types,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use simple_dns::rdata::{RData, TXT};
    use simple_dns::{Name, Packet, ResourceRecord, CLASS};
    use ssi_dids_core::DIDBuf;

    use super::super::transport::RelayResponse;
    use super::*;

    struct FakeTransport {
        responses: Mutex<VecDeque<Result<RelayResponse, DhtPublishError>>>,
        requests: Mutex<Vec<RelayRequest>>,
    }

    impl FakeTransport {
        fn new(
            responses: impl IntoIterator<Item = Result<RelayResponse, DhtPublishError>>,
        ) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl DhtTransport for FakeTransport {
        fn fetch<'a>(
            &'a self,
            request: RelayRequest,
            _timeout: Duration,
            _max_redirects: usize,
            _allow_private: bool,
        ) -> Pin<Box<dyn Future<Output = Result<RelayResponse, DhtPublishError>> + Send + 'a>>
        {
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

    fn response(status: u16, body: Vec<u8>) -> RelayResponse {
        RelayResponse {
            status,
            headers: Vec::new(),
            body,
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
        response: Result<RelayResponse, DhtPublishError>,
    ) -> (DhtResolver, Arc<FakeTransport>) {
        let transport = Arc::new(FakeTransport::new([response]));
        (DhtResolver::new(config, transport.clone()), transport)
    }

    #[tokio::test]
    async fn resolves_a_signed_relay_document() {
        let (did, payload) = signed_relay_payload(42);
        let config = DhtResolverConfig {
            gateway_uri: Url::parse("https://gateway.example/pkarr").unwrap(),
            ..DhtResolverConfig::default()
        };
        let (resolver, transport) = resolver(config, Ok(response(200, payload)));

        let resolved = resolver.resolve(&did).await.unwrap();

        assert_eq!(resolved.document.id, did);
        assert_eq!(resolved.document.verification_method.len(), 1);
        assert_eq!(resolved.sequence, 42);
        let requests = transport.requests.lock().unwrap();
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
    async fn rejects_a_different_did_method_before_transport() {
        let (did, _) = signed_relay_payload(1);
        let web = "did:web:example.com".parse::<DIDBuf>().unwrap();
        let (resolver, transport) =
            resolver(DhtResolverConfig::default(), Ok(response(200, Vec::new())));
        let _ = did;

        assert_eq!(
            resolver.resolve(&web).await,
            Err(DhtPublishError::MethodNotSupported("web".to_string()))
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn treats_missing_relay_values_as_not_found() {
        let (did, _) = signed_relay_payload(1);
        let (resolver, transport) =
            resolver(DhtResolverConfig::default(), Ok(response(404, Vec::new())));

        assert_eq!(resolver.resolve(&did).await, Err(DhtPublishError::NotFound));
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn surfaces_transport_failures() {
        let (did, _) = signed_relay_payload(1);
        let (resolver, transport) = resolver(
            DhtResolverConfig::default(),
            Err(DhtPublishError::Transport("connection refused".to_string())),
        );

        assert_eq!(
            resolver.resolve(&did).await,
            Err(DhtPublishError::Transport("connection refused".to_string()))
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }
}
