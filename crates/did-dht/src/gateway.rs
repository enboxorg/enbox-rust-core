use std::{sync::Arc, time::Duration};

use ssi_dids_core::{Document, DID};
use ssi_jws::JwsSigner;
use url::Url;

use super::bep44::{
    decode_identity_key, gateway_identity_uri, parse_relay_payload, verify_bep44_message,
};
use super::codec::decode_document;
use super::error::DhtPublishError;
use super::publish::{relay_body, sign_publish};
use super::transport::{DhtTransport, RelayMethod, RelayRequest};

#[cfg(test)]
use std::{collections::VecDeque, future::Future, pin::Pin, sync::Mutex};

#[cfg(test)]
use super::transport::RelayResponse;

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

    /// Publish `document` through the configured gateway.
    ///
    /// Encodes with the configured gateway as the single authoritative NS
    /// target, signs through `signer`, and PUTs the relay envelope. Success
    /// returns the published sequence. Any terminal non-2xx — including a
    /// concurrent writer's 409 — is a typed rejection carrying the submitted
    /// sequence, never success. Callers retry explicitly: same sequence and
    /// bytes for an exact retry, a fresh sequence for changed content.
    pub async fn publish<S: JwsSigner>(
        &self,
        document: &Document,
        types: &[u64],
        sequence: u64,
        signer: &S,
    ) -> Result<u64, DhtPublishError> {
        let signed = sign_publish(
            document,
            types,
            std::slice::from_ref(&self.config.gateway_uri),
            sequence,
            signer,
        )
        .await?;
        let url = gateway_identity_uri(&self.config.gateway_uri, &document.id)?;
        let response = self
            .transport
            .fetch(
                RelayRequest {
                    method: RelayMethod::Put,
                    url,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "application/octet-stream".to_string(),
                    )],
                    body: Some(relay_body(&signed)),
                },
                self.config.timeout,
                self.config.max_redirects,
                self.config.allow_private_gateway_uri,
            )
            .await?;

        if (200..300).contains(&response.status) {
            Ok(sequence)
        } else {
            Err(DhtPublishError::GatewayRejected {
                status: response.status,
                sequence,
            })
        }
    }
}

#[cfg(test)]
pub(crate) struct FakeTransport {
    pub responses: Mutex<VecDeque<Result<RelayResponse, DhtPublishError>>>,
    pub requests: Mutex<Vec<RelayRequest>>,
}

#[cfg(test)]
impl FakeTransport {
    pub(crate) fn new(
        responses: impl IntoIterator<Item = Result<RelayResponse, DhtPublishError>>,
    ) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
impl DhtTransport for FakeTransport {
    fn fetch<'a>(
        &'a self,
        request: RelayRequest,
        _timeout: Duration,
        _max_redirects: usize,
        _allow_private: bool,
    ) -> Pin<Box<dyn Future<Output = Result<RelayResponse, DhtPublishError>> + Send + 'a>> {
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

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use simple_dns::rdata::{RData, TXT};
    use simple_dns::{Name, Packet, ResourceRecord, CLASS};
    use ssi_dids_core::DIDBuf;

    use super::super::transport::RelayResponse;
    use super::*;

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
    // Covers: DID-DHT-001
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
    // Covers: DID-DHT-001
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

#[cfg(test)]
mod publish_tests {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use simple_dns::rdata::RData;
    use simple_dns::Packet;

    use super::super::transport::{RelayMethod, RelayResponse};
    use super::*;
    use crate::test_support::{agent_document, TestSigner};

    fn ok_response(status: u16) -> RelayResponse {
        RelayResponse {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn publish_resolver(
        config: DhtResolverConfig,
        response: Result<RelayResponse, DhtPublishError>,
    ) -> (DhtResolver, Arc<FakeTransport>) {
        let transport = Arc::new(FakeTransport::new([response]));
        (DhtResolver::new(config, transport.clone()), transport)
    }

    #[tokio::test]
    // Covers: DID-DHT-005
    async fn publishes_the_signed_envelope_and_returns_the_sequence() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (did, document) = agent_document(&identity);
        let config = DhtResolverConfig {
            gateway_uri: Url::parse("https://gateway.example/pkarr").unwrap(),
            ..DhtResolverConfig::default()
        };
        let (resolver, transport) = publish_resolver(config, Ok(ok_response(200)));

        assert_eq!(
            resolver
                .publish(&document, &[], 42, &TestSigner::plain(identity))
                .await,
            Ok(42)
        );

        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, RelayMethod::Put);
        assert_eq!(
            request.url,
            Url::parse(&format!(
                "https://gateway.example/pkarr/{}",
                did.method_specific_id()
            ))
            .unwrap()
        );
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "Content-Type" && value == "application/octet-stream"));
        let body = request.body.as_ref().expect("relay body");
        assert!(body.len() > 72);
        assert_eq!(&body[64..72], &42u64.to_be_bytes());
        let (decoded, _) = decode_document(&did, &body[72..]).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(document).unwrap()
        );
    }

    #[tokio::test]
    // Covers: DID-DHT-005
    async fn rejections_carry_status_and_sequence() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (_, document) = agent_document(&identity);

        for status in [400, 404, 409, 500] {
            let (resolver, transport) =
                publish_resolver(DhtResolverConfig::default(), Ok(ok_response(status)));
            assert_eq!(
                resolver
                    .publish(&document, &[], 42, &TestSigner::plain(identity.clone()))
                    .await,
                Err(DhtPublishError::GatewayRejected {
                    status,
                    sequence: 42
                })
            );
            assert_eq!(transport.requests.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    // Covers: DID-DHT-003
    async fn publish_encodes_the_configured_gateway_as_ns() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (_, document) = agent_document(&identity);
        let config = DhtResolverConfig {
            gateway_uri: Url::parse("https://gateway.example").unwrap(),
            ..DhtResolverConfig::default()
        };
        let (resolver, transport) = publish_resolver(config, Ok(ok_response(200)));

        resolver
            .publish(&document, &[], 1, &TestSigner::plain(identity))
            .await
            .unwrap();

        let requests = transport.requests.lock().unwrap();
        let body = requests[0].body.as_ref().expect("relay body");
        let packet = Packet::parse(&body[72..]).unwrap();
        let ns = packet
            .answers
            .iter()
            .filter_map(|answer| match &answer.rdata {
                RData::NS(name) => Some(name.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(ns, ["gateway.example"]);
    }

    #[tokio::test]
    async fn transport_errors_propagate() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (_, document) = agent_document(&identity);
        let (resolver, _) = publish_resolver(
            DhtResolverConfig::default(),
            Err(DhtPublishError::Transport("connection refused".to_string())),
        );

        assert_eq!(
            resolver
                .publish(&document, &[], 1, &TestSigner::plain(identity))
                .await,
            Err(DhtPublishError::Transport("connection refused".to_string()))
        );
    }

    #[tokio::test]
    async fn invalid_documents_fail_before_transport() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let (_, mut document) = agent_document(&identity);
        document.verification_method.clear();
        let (resolver, transport) =
            publish_resolver(DhtResolverConfig::default(), Ok(ok_response(200)));

        assert!(matches!(
            resolver
                .publish(&document, &[], 1, &TestSigner::plain(identity))
                .await,
            Err(DhtPublishError::InvalidDocument(_))
        ));
        assert_eq!(transport.requests.lock().unwrap().len(), 0);
    }
}
