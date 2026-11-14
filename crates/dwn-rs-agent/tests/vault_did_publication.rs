//! Agent DID publication and vault reconciliation, exercised over a scripted
//! `did:dht` transport so the whole suite runs offline.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{TimeZone, Utc};
use did_dht::{
    DhtPublishError, DhtResolver, DhtResolverConfig, DhtTransport, RelayMethod, RelayRequest,
    RelayResponse, ResolvedDhtDocument,
};
use dwn_rs_agent::agent::{
    derive_agent_keys, AgentDerivedKeys, AgentDidCreateRequest, AgentDidSigner, AgentIdentityError,
    AgentIdentityFuture, DerivedIdentitySigner, DidDhtNetwork, DidDhtProvider, DidProvider,
    IdentityVault, MemorySecretStore, SecretStore, VAULT_CEK_JWE_KEY, VAULT_DID_JWE_KEY,
    VAULT_STATUS_KEY,
};
use dwn_rs_core::auth::PrivateJwkSigner;
use serde_json::{json, Value};
use ssi_dids_core::{DIDBuf, Document};
use ssi_jwk::Algorithm;
use url::Url;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER_PHRASE: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PASSWORD: &str = "vault-password";
const PASSWORD_2: &str = "vault-password-2";
const DID_URI: &str = "did:dht:qftx7z968xcpfy1a1diu75pg5meap3gdtg6ezagaw849wdh6oubo";
const NOW: u64 = 1_700_000_000;

#[derive(Default)]
struct Script {
    gets: VecDeque<Result<RelayResponse, DhtPublishError>>,
    puts: VecDeque<Result<RelayResponse, DhtPublishError>>,
    requests: Vec<RelayRequest>,
}

#[derive(Clone, Default)]
struct ScriptedTransport {
    state: Arc<Mutex<Script>>,
}

impl ScriptedTransport {
    fn push_get(&self, response: Result<RelayResponse, DhtPublishError>) {
        self.state.lock().unwrap().gets.push_back(response);
    }

    fn push_put(&self, response: Result<RelayResponse, DhtPublishError>) {
        self.state.lock().unwrap().puts.push_back(response);
    }

    fn requests(&self) -> Vec<RelayRequest> {
        self.state.lock().unwrap().requests.clone()
    }

    fn puts(&self) -> Vec<RelayRequest> {
        self.requests()
            .into_iter()
            .filter(|request| request.method == RelayMethod::Put)
            .collect()
    }
}

impl DhtTransport for ScriptedTransport {
    fn fetch<'a>(
        &'a self,
        request: RelayRequest,
        _timeout: Duration,
        _max_redirects: usize,
        _allow_private: bool,
    ) -> Pin<Box<dyn Future<Output = Result<RelayResponse, DhtPublishError>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            state.requests.push(request.clone());
            let queue = match request.method {
                RelayMethod::Get => &mut state.gets,
                RelayMethod::Put => &mut state.puts,
            };
            queue
                .pop_front()
                .unwrap_or_else(|| Ok(default_response(request.method)))
        })
    }
}

fn default_response(method: RelayMethod) -> RelayResponse {
    RelayResponse {
        status: match method {
            RelayMethod::Get => 404,
            RelayMethod::Put => 200,
        },
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn response(status: u16) -> RelayResponse {
    RelayResponse {
        status,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn config() -> DhtResolverConfig {
    DhtResolverConfig {
        gateway_uri: Url::parse("https://gateway.example").unwrap(),
        ..DhtResolverConfig::default()
    }
}

struct Harness {
    vault: Arc<IdentityVault>,
    store: Arc<MemorySecretStore>,
    transport: Arc<ScriptedTransport>,
    clock: Arc<AtomicU64>,
}

fn harness() -> Harness {
    harness_with(Arc::new(DidDhtProvider::default()), None)
}

fn harness_with(
    did_provider: Arc<dyn DidProvider>,
    signer: Option<Arc<dyn AgentDidSigner>>,
) -> Harness {
    let transport = Arc::new(ScriptedTransport::default());
    let resolver = DhtResolver::new(config(), transport.clone());
    let store = Arc::new(MemorySecretStore::default());
    let clock = Arc::new(AtomicU64::new(NOW));
    let source = clock.clone();
    let mut vault = IdentityVault::with_did_network(
        store.clone(),
        did_provider,
        1,
        Arc::new(DidDhtNetwork::new(resolver)),
    )
    .with_clock(move || {
        Utc.timestamp_opt(source.load(Ordering::SeqCst) as i64, 0)
            .unwrap()
    });
    if let Some(signer) = signer {
        vault = vault.with_signer(signer);
    }
    Harness {
        vault: Arc::new(vault),
        store,
        transport,
        clock,
    }
}

impl Harness {
    async fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        let mut values = BTreeMap::new();
        for key in [VAULT_CEK_JWE_KEY, VAULT_DID_JWE_KEY, VAULT_STATUS_KEY] {
            if let Some(value) = self.store.get(key).await.unwrap() {
                values.insert(key.to_string(), value);
            }
        }
        values
    }

    fn set_clock(&self, seconds: u64) {
        self.clock.store(seconds, Ordering::SeqCst);
    }
}

async fn ready_response(document: &Document, types: &[u64], sequence: u64) -> RelayResponse {
    let keys = derive_agent_keys(PHRASE).unwrap();
    RelayResponse {
        status: 200,
        headers: Vec::new(),
        body: signed_envelope(document, types, sequence, &keys.identity_private_jwk).await,
    }
}

async fn signed_envelope(
    document: &Document,
    types: &[u64],
    sequence: u64,
    identity_jwk: &ssi_jwk::JWK,
) -> Vec<u8> {
    let signer = PrivateJwkSigner::new(
        format!("{}#0", document.id),
        Algorithm::EdDSA,
        identity_jwk.clone(),
    );
    let signed = did_dht::sign_publish(document, types, &[], sequence, &signer)
        .await
        .unwrap();
    let mut body = Vec::with_capacity(72 + signed.value.len());
    body.extend_from_slice(&signed.signature);
    body.extend_from_slice(&signed.sequence.to_be_bytes());
    body.extend_from_slice(&signed.value);
    body
}

async fn derived_document(keys: &AgentDerivedKeys, endpoints: Vec<String>) -> Document {
    DidDhtProvider::default()
        .create_did(AgentDidCreateRequest {
            identity_private_jwk: keys.identity_private_jwk.clone(),
            signing_private_jwk: keys.signing_private_jwk.clone(),
            encryption_private_jwk: keys.encryption_private_jwk.clone(),
            dwn_endpoints: endpoints,
        })
        .await
        .unwrap()
        .document
}

fn with_extra_service(mut document: Document) -> Document {
    document.service.push(
        serde_json::from_value(json!({
            "id": format!("{}#extra", document.id),
            "type": "Other",
            "serviceEndpoint": ["https://extra.example"],
        }))
        .unwrap(),
    );
    document
}

async fn decode_envelope(body: Vec<u8>, did: &str) -> ResolvedDhtDocument {
    let transport = Arc::new(ScriptedTransport::default());
    transport.push_get(Ok(RelayResponse {
        status: 200,
        headers: Vec::new(),
        body,
    }));
    let resolver = DhtResolver::new(config(), transport);
    resolver
        .resolve(&did.parse::<DIDBuf>().unwrap())
        .await
        .unwrap()
}

fn endpoints(document: &Document) -> Option<Value> {
    let value = serde_json::to_value(document).unwrap();
    value["service"]
        .as_array()?
        .iter()
        .find(|service| service["type"] == "DecentralizedWebNode")
        .map(|service| service["serviceEndpoint"].clone())
}

fn relationship_ids(document: &Document) -> Vec<String> {
    document
        .verification_method
        .iter()
        .map(|method| method.id.to_string())
        .collect()
}

#[tokio::test]
// Covers: DID-DHT-001, DID-DHT-006
async fn initialize_through_the_vault_builds_the_did_dht_agent_shape() {
    let harness = harness();
    let initialization = harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://dwn.example".to_string()],
        )
        .await
        .unwrap();

    let portable_did = &initialization.portable_did;
    assert_eq!(portable_did.uri, DID_URI);
    let document = &portable_did.document;
    assert_eq!(document.id.to_string(), DID_URI);
    assert_eq!(
        relationship_ids(document),
        [
            format!("{DID_URI}#0"),
            format!("{DID_URI}#sig"),
            format!("{DID_URI}#enc"),
        ]
    );
    assert_eq!(endpoints(document), Some(json!(["https://dwn.example"])));
    assert_eq!(
        serde_json::to_value(document).unwrap().get("@context"),
        None
    );
}

#[tokio::test]
// Covers: DID-DHT-004, DID-DHT-005
async fn fresh_initialize_publishes_before_committing() {
    let harness = harness();
    let initialization = harness
        .vault
        .initialize(PASSWORD, None, vec!["https://dwn.example/".to_string()])
        .await
        .unwrap();

    let puts = harness.transport.puts();
    assert_eq!(puts.len(), 1);
    let did_uri = initialization.portable_did.uri.clone();
    let request = &puts[0];
    assert_eq!(request.method, RelayMethod::Put);
    assert_eq!(
        request.url,
        Url::parse(&format!(
            "https://gateway.example/{}",
            did_uri.trim_start_matches("did:dht:")
        ))
        .unwrap()
    );
    assert!(request
        .headers
        .iter()
        .any(|(name, value)| name == "Content-Type" && value == "application/octet-stream"));

    let body = request.body.as_ref().expect("relay body");
    let submitted = u64::from_be_bytes(body[64..72].try_into().unwrap());
    assert_eq!(submitted, NOW);
    let resolved = decode_envelope(body.clone(), &did_uri).await;
    assert_eq!(resolved.sequence, NOW);
    assert_eq!(resolved.types, None);
    assert_eq!(
        endpoints(&resolved.document),
        Some(json!(["https://dwn.example"]))
    );

    // The stored document decodes to itself and records the published sequence.
    assert_eq!(
        serde_json::to_value(&initialization.portable_did.document).unwrap(),
        serde_json::to_value(&resolved.document).unwrap()
    );
    assert_eq!(initialization.portable_did.metadata.published, Some(true));
    assert_eq!(
        initialization.portable_did.metadata.extra.get("versionId"),
        Some(&json!(NOW.to_string()))
    );
    assert_eq!(harness.vault.get_did().await.unwrap().uri, did_uri);

    // Decoder fixpoint on the published value.
    let keys = derive_agent_keys(&initialization.recovery_phrase).unwrap();
    let re_encoded = signed_envelope(
        &resolved.document,
        &[],
        submitted,
        &keys.identity_private_jwk,
    )
    .await;
    let round_tripped = decode_envelope(re_encoded, &did_uri).await;
    assert_eq!(
        serde_json::to_value(round_tripped.document).unwrap(),
        serde_json::to_value(resolved.document).unwrap()
    );
}

#[tokio::test]
// Covers: DID-DHT-004, DID-DHT-005
async fn fresh_publish_rejections_leave_the_vault_uninitialized() {
    for failure in [
        Ok(response(409)),
        Ok(response(400)),
        Ok(response(500)),
        Err(DhtPublishError::Transport("connection refused".to_string())),
    ] {
        let harness = harness();
        harness.transport.push_put(failure);
        let error = harness
            .vault
            .initialize(PASSWORD, None, vec![])
            .await
            .unwrap_err();
        assert_eq!(error.code(), "AgentIdentityDidError");
        assert!(harness.snapshot().await.is_empty());
        assert!(!harness.vault.status().await.unwrap().initialized);
    }
}

#[tokio::test]
// Covers: DID-DHT-004
async fn oversized_documents_fail_before_transport() {
    let harness = harness();
    let endpoint = format!("https://{}.example", "x".repeat(2000));
    let error = harness
        .vault
        .initialize(PASSWORD, None, vec![endpoint])
        .await
        .unwrap_err();
    assert!(error.detail().contains("too large"), "{error}");
    assert!(harness.transport.puts().is_empty());
    assert!(harness.snapshot().await.is_empty());
}

#[tokio::test]
// Covers: DID-DHT-004
async fn signer_failures_leave_the_vault_uninitialized() {
    struct FailingSigner;

    impl AgentDidSigner for FailingSigner {
        fn sign<'a>(&'a self, _bytes: &'a [u8]) -> AgentIdentityFuture<'a, Vec<u8>> {
            Box::pin(async move {
                Err(AgentIdentityError::new(
                    "AgentIdentityDidError",
                    "injected signer failure",
                ))
            })
        }
    }

    let harness = harness_with(
        Arc::new(DidDhtProvider::default()),
        Some(Arc::new(FailingSigner)),
    );
    let error = harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://stored.example".to_string()],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentIdentityDidError");
    assert!(harness.transport.puts().is_empty());
    assert!(harness.snapshot().await.is_empty());
}

#[tokio::test]
// Covers: DID-DHT-004
async fn a_signer_with_the_wrong_key_fails_before_transport() {
    let other = derive_agent_keys(OTHER_PHRASE).unwrap();
    let wrong = DerivedIdentitySigner::from_jwk(&other.identity_private_jwk).unwrap();
    let harness = harness_with(Arc::new(DidDhtProvider::default()), Some(Arc::new(wrong)));

    let error = harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://stored.example".to_string()],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentIdentityDidError");
    assert!(harness.transport.puts().is_empty());
    assert!(harness.snapshot().await.is_empty());
}

#[tokio::test]
// Covers: DID-DHT-004
async fn injected_signers_are_used_for_every_publication() {
    struct RecordingSigner {
        inner: DerivedIdentitySigner,
        calls: Arc<AtomicUsize>,
    }

    impl AgentDidSigner for RecordingSigner {
        fn sign<'a>(&'a self, bytes: &'a [u8]) -> AgentIdentityFuture<'a, Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(bytes)
        }
    }

    let keys = derive_agent_keys(PHRASE).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let signer = RecordingSigner {
        inner: DerivedIdentitySigner::from_jwk(&keys.identity_private_jwk).unwrap(),
        calls: calls.clone(),
    };
    let harness = harness_with(Arc::new(DidDhtProvider::default()), Some(Arc::new(signer)));

    harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://dwn.example".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.transport.puts().len(), 1);
}

#[tokio::test]
// Covers: DID-DHT-006
async fn recovery_ready_without_replacement_adopts_the_resolved_service() {
    let keys = derive_agent_keys(PHRASE).unwrap();
    let remote = derived_document(&keys, vec!["https://resolved.example".to_string()]).await;
    let harness = harness();
    harness
        .transport
        .push_get(Ok(ready_response(&remote, &[], 7).await));

    let initialization = harness
        .vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap();

    assert!(harness.transport.puts().is_empty());
    assert_eq!(
        harness
            .transport
            .requests()
            .into_iter()
            .filter(|request| request.method == RelayMethod::Get)
            .count(),
        1
    );
    assert_eq!(
        endpoints(&initialization.portable_did.document),
        Some(json!(["https://resolved.example"]))
    );
    assert_eq!(
        initialization.portable_did.metadata.extra.get("versionId"),
        Some(&json!("7"))
    );
    assert_eq!(
        harness.vault.get_did().await.unwrap(),
        initialization.portable_did
    );
}

#[tokio::test]
// Covers: DID-DHT-006
async fn recovery_initialize_always_defers_endpoint_replacement() {
    let keys = derive_agent_keys(PHRASE).unwrap();
    let remote = derived_document(&keys, vec!["https://resolved.example".to_string()]).await;
    let harness = harness();
    harness
        .transport
        .push_get(Ok(ready_response(&remote, &[], 7).await));

    let initialization = harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://caller.example".to_string()],
        )
        .await
        .unwrap();

    assert!(harness.transport.puts().is_empty());
    assert_eq!(
        endpoints(&initialization.portable_did.document),
        Some(json!(["https://resolved.example"]))
    );
}

#[tokio::test]
// Covers: DID-DHT-006
async fn recovery_without_a_usable_service_requires_replacement_endpoints() {
    let keys = derive_agent_keys(PHRASE).unwrap();
    let remote = derived_document(&keys, vec![]).await;
    let harness = harness();
    harness
        .transport
        .push_get(Ok(ready_response(&remote, &[], 7).await));

    let error = harness
        .vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap_err();
    assert!(error.detail().contains("#dwn"), "{error}");
    assert!(harness.transport.puts().is_empty());
    assert!(harness.snapshot().await.is_empty());
}

#[tokio::test]
// Covers: DID-DHT-006
async fn not_ready_with_replacement_publishes_the_resolved_document() {
    let keys = derive_agent_keys(PHRASE).unwrap();
    let remote = with_extra_service(derived_document(&keys, vec![]).await);
    let harness = harness();
    harness
        .transport
        .push_get(Ok(ready_response(&remote, &[1, 2], 7).await));

    let initialization = harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://replacement.example".to_string()],
        )
        .await
        .unwrap();

    let puts = harness.transport.puts();
    assert_eq!(puts.len(), 1);
    let published = decode_envelope(puts[0].body.clone().unwrap(), DID_URI).await;
    assert!(published.sequence > 7, "sequence {}", published.sequence);
    assert_eq!(published.types, Some(vec![1, 2]));
    assert_eq!(
        endpoints(&published.document),
        Some(json!(["https://replacement.example"]))
    );
    // Remote-only content survives the republication.
    assert!(published
        .document
        .service
        .iter()
        .any(|service| service.id.as_str().ends_with("#extra")));
    // The stored document is the locally derived one plus the replacement.
    assert_eq!(
        endpoints(&initialization.portable_did.document),
        Some(json!(["https://replacement.example"]))
    );
    assert!(!initialization
        .portable_did
        .document
        .service
        .iter()
        .any(|service| service.id.as_str().ends_with("#extra")));
}

#[tokio::test]
// Covers: DID-DHT-006
async fn not_found_with_endpoints_publishes_the_derived_shape() {
    let harness = harness();
    let initialization = harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://dwn.example".to_string()],
        )
        .await
        .unwrap();

    let puts = harness.transport.puts();
    assert_eq!(puts.len(), 1);
    let published = decode_envelope(puts[0].body.clone().unwrap(), DID_URI).await;
    assert_eq!(published.sequence, NOW);
    assert_eq!(published.types, None);
    assert_eq!(
        endpoints(&published.document),
        Some(json!(["https://dwn.example"]))
    );
    assert_eq!(
        endpoints(&initialization.portable_did.document),
        Some(json!(["https://dwn.example"]))
    );
}

#[tokio::test]
// Covers: DID-DHT-006
async fn not_found_without_endpoints_cannot_bootstrap_recovery() {
    let harness = harness();
    let error = harness
        .vault
        .initialize(PASSWORD, Some(PHRASE), vec![])
        .await
        .unwrap_err();
    assert!(error.detail().contains("DWN endpoints"), "{error}");
    assert!(harness.transport.puts().is_empty());
    assert!(harness.snapshot().await.is_empty());
}

#[tokio::test]
async fn resolution_failures_are_not_treated_as_not_found() {
    for failure in [
        Ok(response(408)),
        Ok(response(429)),
        Ok(response(500)),
        Ok(response(503)),
        Err(DhtPublishError::Transport("connection refused".to_string())),
    ] {
        let harness = harness();
        harness.transport.push_get(failure);
        let error = harness
            .vault
            .initialize(
                PASSWORD,
                Some(PHRASE),
                vec!["https://dwn.example".to_string()],
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "AgentIdentityDidError");
        assert!(harness.transport.puts().is_empty());
        assert!(harness.snapshot().await.is_empty());
    }
}

#[tokio::test]
async fn an_empty_success_body_is_not_found() {
    let harness = harness();
    harness.transport.push_get(Ok(response(200)));
    let initialization = harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://dwn.example".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(initialization.portable_did.uri, DID_URI);
    assert_eq!(harness.transport.puts().len(), 1);
}

#[tokio::test]
// Covers: DID-DHT-006
async fn reset_ready_with_endpoints_republishes_only_the_dwn_service() {
    let harness = harness();
    harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://stored.example".to_string()],
        )
        .await
        .unwrap();

    let keys = derive_agent_keys(PHRASE).unwrap();
    let remote = with_extra_service(
        derived_document(&keys, vec!["https://resolved.example".to_string()]).await,
    );
    harness
        .transport
        .push_get(Ok(ready_response(&remote, &[3], 500).await));
    harness.set_clock(100);

    harness
        .vault
        .reset_password_with_recovery_phrase(
            PHRASE,
            PASSWORD_2,
            Some(vec!["https://new.example".to_string()]),
        )
        .await
        .unwrap();

    let puts = harness.transport.puts();
    assert_eq!(puts.len(), 2);
    let published = decode_envelope(puts[1].body.clone().unwrap(), DID_URI).await;
    assert_eq!(published.sequence, 501);
    assert_eq!(published.types, Some(vec![3]));
    assert_eq!(
        endpoints(&published.document),
        Some(json!(["https://new.example"]))
    );
    assert!(published
        .document
        .service
        .iter()
        .any(|service| service.id.as_str().ends_with("#extra")));

    let stored = harness.vault.get_did().await.unwrap();
    assert_eq!(
        endpoints(&stored.document),
        Some(json!(["https://new.example"]))
    );
    assert!(!stored
        .document
        .service
        .iter()
        .any(|service| service.id.as_str().ends_with("#extra")));

    harness.vault.lock().await.unwrap();
    harness.vault.unlock(PASSWORD_2).await.unwrap();
}

#[tokio::test]
// Covers: DID-DHT-004
async fn sequence_continuity_survives_a_clock_rollback() {
    let harness = harness();
    harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://stored.example".to_string()],
        )
        .await
        .unwrap();

    let keys = derive_agent_keys(PHRASE).unwrap();
    let remote = derived_document(&keys, vec!["https://resolved.example".to_string()]).await;
    harness
        .transport
        .push_get(Ok(ready_response(&remote, &[], 1_700_000_100).await));
    harness.set_clock(100);

    harness
        .vault
        .reset_password_with_recovery_phrase(
            PHRASE,
            PASSWORD_2,
            Some(vec!["https://new.example".to_string()]),
        )
        .await
        .unwrap();

    let puts = harness.transport.puts();
    let body = puts.last().unwrap().body.as_ref().unwrap();
    let submitted = u64::from_be_bytes(body[64..72].try_into().unwrap());
    assert!(submitted > 1_700_000_100, "submitted {submitted}");
}

#[tokio::test]
async fn reset_without_endpoints_makes_no_network_call() {
    let harness = harness();
    harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://stored.example".to_string()],
        )
        .await
        .unwrap();
    let requests = harness.transport.requests().len();

    harness
        .vault
        .reset_password_with_recovery_phrase(PHRASE, PASSWORD_2, None)
        .await
        .unwrap();

    assert_eq!(harness.transport.requests().len(), requests);
    harness.vault.lock().await.unwrap();
    harness.vault.unlock(PASSWORD_2).await.unwrap();
}

#[tokio::test]
async fn reset_phrase_mismatch_fails_before_any_network_access() {
    let harness = harness();
    harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://stored.example".to_string()],
        )
        .await
        .unwrap();
    let requests = harness.transport.requests().len();

    let error = harness
        .vault
        .reset_password_with_recovery_phrase(
            OTHER_PHRASE,
            PASSWORD_2,
            Some(vec!["https://dwn.example".to_string()]),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "HD_IDENTITY_VAULT_RECOVERY_PHRASE_MISMATCH");
    assert_eq!(harness.transport.requests().len(), requests);
}

#[tokio::test]
async fn reset_resolution_failure_keeps_stored_state() {
    let harness = harness();
    harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://stored.example".to_string()],
        )
        .await
        .unwrap();
    let before = harness.snapshot().await;
    harness.transport.push_get(Ok(response(503)));

    let error = harness
        .vault
        .reset_password_with_recovery_phrase(
            PHRASE,
            PASSWORD_2,
            Some(vec!["https://new.example".to_string()]),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentIdentityDidError");
    assert_eq!(harness.snapshot().await, before);
    assert_eq!(harness.transport.puts().len(), 1);
}

#[tokio::test]
async fn invalid_replacement_endpoints_fail_before_publish() {
    let harness = harness();
    harness
        .vault
        .initialize(
            PASSWORD,
            Some(PHRASE),
            vec!["https://stored.example".to_string()],
        )
        .await
        .unwrap();
    let keys = derive_agent_keys(PHRASE).unwrap();
    let remote = derived_document(&keys, vec![]).await;
    harness
        .transport
        .push_get(Ok(ready_response(&remote, &[], 9).await));

    let error = harness
        .vault
        .reset_password_with_recovery_phrase(
            PHRASE,
            PASSWORD_2,
            Some(vec!["not a url".to_string()]),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "AgentIdentityDidError");
    assert_eq!(harness.transport.puts().len(), 1);
}

#[tokio::test]
async fn work_factor_does_not_affect_publication() {
    let transport = Arc::new(ScriptedTransport::default());
    let resolver = DhtResolver::new(config(), transport.clone());
    let store = Arc::new(MemorySecretStore::default());
    let vault = IdentityVault::with_did_network(
        store,
        Arc::new(DidDhtProvider::default()),
        10_000,
        Arc::new(DidDhtNetwork::new(resolver)),
    );
    vault
        .initialize(PASSWORD, None, vec!["https://dwn.example".to_string()])
        .await
        .unwrap();
    assert_eq!(transport.puts().len(), 1);
}
