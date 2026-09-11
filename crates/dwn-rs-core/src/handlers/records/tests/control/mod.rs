//! Shared fixtures for the encryption control-plane tests.
//!
//! The control plane is admitted, authorized, read, projected and repaired by
//! `records::control`; the tests are split the same way, and everything they
//! all need to build a tenant, a protocol and a control record lives here.

use super::*;

mod admission;
mod authorization;
mod projection;
mod repair;
mod visibility;

const CONTROL_PROTOCOL: &str = "http://example.com/control-threads";

const CONTROL_TENANT: &str = "did:example:alice";

const AUDIENCE_PATH: &str = "$encryption/audience";

const DELIVERY_PATH: &str = "$encryption/delivery";

/// X25519 key the `member` role is keyed with; its thumbprint is the seal key id.
fn role_key_jwk() -> JWK {
    serde_json::from_value(json!({
        "kty": "OKP", "crv": "X25519",
        "x": "C4ZHfPBV5nB76CSpZyGYMNa-xl0iQD5lEunvuXvGBEc"
    }))
    .unwrap()
}

/// A second publishable key, so a role can hold more than one valid audience.
fn other_audience_key_jwk() -> JWK {
    serde_json::from_value(json!({
        "kty": "OKP", "crv": "X25519",
        "x": "B6r_Pp_BZydVRPTDpqF82Dfy7G54zYpXsePfs8wDWnY"
    }))
    .unwrap()
}

/// A distinct key, the one an audience record publishes.
fn audience_key_jwk() -> JWK {
    serde_json::from_value(json!({
        "kty": "OKP", "crv": "X25519",
        "x": "Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI"
    }))
    .unwrap()
}

/// `member` is a root role carrying `$keyAgreement`; `thread/participant` is a
/// nested one, so the two context depths are both reachable.
fn control_definition() -> Definition {
    let keyed_role = || RuleSet {
        role: Some(true),
        key_agreement: Some(ProtocolKeyAgreement {
            public_key_jwk: role_key_jwk(),
        }),
        ..Default::default()
    };
    Definition {
        protocol: CONTROL_PROTOCOL.to_string(),
        published: true,
        uses: None,
        key_agreement: Some(ProtocolKeyAgreement {
            public_key_jwk: role_key_jwk(),
        }),
        types: BTreeMap::from([
            (
                "member".to_string(),
                Type {
                    schema: None,
                    data_formats: None,
                    encryption_required: None,
                },
            ),
            (
                "thread".to_string(),
                Type {
                    schema: None,
                    data_formats: None,
                    encryption_required: None,
                },
            ),
            (
                "plain".to_string(),
                Type {
                    schema: None,
                    data_formats: None,
                    encryption_required: None,
                },
            ),
            // Declared because `thread/participant` exists in the structure:
            // the real configure handler rejects a rule set whose record type
            // the definition never declares.
            (
                "participant".to_string(),
                Type {
                    schema: None,
                    data_formats: None,
                    encryption_required: None,
                },
            ),
        ]),
        structure: BTreeMap::from([
            ("member".to_string(), keyed_role()),
            ("plain".to_string(), RuleSet::default()),
            (
                "thread".to_string(),
                RuleSet {
                    rules: BTreeMap::from([("participant".to_string(), keyed_role())]),
                    ..Default::default()
                },
            ),
        ]),
    }
}

fn audience_tags(role_path: &str, context_id: &str, key_id: &str) -> MapValue {
    MapValue::from([
        (
            "protocol".to_string(),
            Value::String(CONTROL_PROTOCOL.to_string()),
        ),
        ("rolePath".to_string(), Value::String(role_path.to_string())),
        (
            "contextId".to_string(),
            Value::String(context_id.to_string()),
        ),
        ("keyId".to_string(), Value::String(key_id.to_string())),
    ])
}

fn audience_payload(role_path: &str, context_id: &str, key_id: &str, seal_key_id: &str) -> Bytes {
    audience_payload_for(
        &audience_key_jwk(),
        role_path,
        context_id,
        key_id,
        seal_key_id,
    )
}

/// Builds an audience payload publishing `public_key`. `key_id` is separate so
/// a test can deliberately name a key the payload does not carry.
fn audience_payload_for(
    public_key: &JWK,
    role_path: &str,
    context_id: &str,
    key_id: &str,
    seal_key_id: &str,
) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&json!({
            "protocol": CONTROL_PROTOCOL,
            "rolePath": role_path,
            "contextId": context_id,
            "keyId": key_id,
            "publicKeyJwk": serde_json::to_value(public_key).unwrap(),
            "sealedPrivateKey": {
                "algorithm": "X25519-HKDF-SHA256+A256KW",
                "derivationScheme": "seal",
                "keyId": seal_key_id,
                "ephemeralPublicKey": serde_json::to_value(role_key_jwk()).unwrap(),
                "encryptedKey": "T42gGabDj__6KG89Wz97VBmlDEmkJj3HjLh-dPX-KzEbTi6z6DMLoA"
            }
        }))
        .unwrap(),
    )
}

struct ControlFixture {
    // `MemoryMessageStore` rather than `TestMessageStore`: the test double
    // truncates to a pagination limit without ever returning a cursor, so any
    // page-refill behaviour tested against it would be silently untested.
    handler: RecordsWriteHandler<MemoryMessageStore, TestDataStore>,
    message_store: MemoryMessageStore,
    audience_key_id: String,
    seal_key_id: String,
}

async fn control_fixture() -> ControlFixture {
    control_fixture_on(MemoryMessageStore::default()).await
}

/// The same fixture over a caller-supplied store, for the live tests that need
/// one wired to a wake bus.
async fn control_fixture_on(mut message_store: MemoryMessageStore) -> ControlFixture {
    let mut data_store = TestDataStore::default();
    message_store.open().await.unwrap();
    data_store.open().await.unwrap();
    put_protocol_definition(
        CONTROL_TENANT,
        &message_store,
        control_definition(),
        "2025-01-01T00:00:00.000000Z",
    )
    .await;
    ControlFixture {
        handler: RecordsWriteHandler::new(
            message_store.clone(),
            data_store,
            Some(Arc::new(test_resolver())),
        ),
        message_store,
        audience_key_id: audience_key_jwk().thumbprint().unwrap(),
        seal_key_id: role_key_jwk().thumbprint().unwrap(),
    }
}

/// Builds a control write, letting each test perturb exactly one thing.
async fn control_write(
    protocol_path: &str,
    tags: MapValue,
    data: &Bytes,
    timestamp: &str,
    mutate: impl FnOnce(&mut WriteSpec),
) -> serde_json::Value {
    let mut spec = WriteSpec {
        protocol: CONTROL_PROTOCOL.to_string(),
        protocol_path: protocol_path.to_string(),
        tags: Some(tags),
        data_cid: generate_dag_pb_cid_from_bytes(data).to_string(),
        data_size: data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new(timestamp)
    };
    mutate(&mut spec);
    signed_write_message(spec).await
}

/// A delivery's envelope. Its contents are never inspected by admission, which
/// is the point: the node has no private key and must not need one.
fn delivery_envelope() -> EncryptionEnvelope {
    envelope_with_entries(vec![KeyEncryption::ProtocolPath {
        algorithm: KeyAgreementAlgorithm::X25519HkdfSha256A256Kw,
        key_id: "delivery-key".to_string(),
        ephemeral_public_key: role_key_jwk(),
        encrypted_key: "T42gGabDj__6KG89Wz97VBmlDEmkJj3HjLh-dPX-KzEbTi6z6DMLoA".to_string(),
    }])
}

fn delivery_tags(role_path: &str, context_id: &str, key_id: &str, authority: &str) -> MapValue {
    let mut tags = audience_tags(role_path, context_id, key_id);
    tags.insert(
        "recipientAuthority".to_string(),
        Value::String(authority.to_string()),
    );
    tags
}

/// Grants `recipient` the `member` role by storing a role record directly:
/// role membership is the protocol's business, not the control plane's.
async fn grant_member_role(message_store: &MemoryMessageStore, recipient: &str, timestamp: &str) {
    let role = signed_write_message(WriteSpec {
        protocol: CONTROL_PROTOCOL.to_string(),
        protocol_path: "member".to_string(),
        recipient: Some(recipient.to_string()),
        ..WriteSpec::new(timestamp)
    })
    .await;
    let message: Message<Descriptor> = serde_json::from_value(role).unwrap();
    let indexes = KeyValues::from([
        (
            "interface".to_string(),
            Value::String("Records".to_string()),
        ),
        ("method".to_string(), Value::String("Write".to_string())),
        (
            "protocol".to_string(),
            Value::String(CONTROL_PROTOCOL.to_string()),
        ),
        (
            "protocolPath".to_string(),
            Value::String("member".to_string()),
        ),
        (
            "recipient".to_string(),
            Value::String(recipient.to_string()),
        ),
        ("isLatestBaseState".to_string(), Value::Bool(true)),
        (
            "messageTimestamp".to_string(),
            Value::String(timestamp.to_string()),
        ),
        // Sort properties are load-bearing: a store drops rows missing the one
        // a query sorts by, so an index-light fixture would be invisible to
        // Query while still being counted.
        (
            "dateCreated".to_string(),
            Value::String(timestamp.to_string()),
        ),
    ]);
    message_store
        .put(CONTROL_TENANT, message, indexes)
        .await
        .unwrap();
}

async fn admit_audience(fixture: &ControlFixture, key_id: &str, timestamp: &str) {
    let data = audience_payload("member", "", key_id, &fixture.seal_key_id);
    let write = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", key_id),
        &data,
        timestamp,
        |_| {},
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &write, Some(data))
        .await;
    assert_eq!(
        reply.status.code, 202,
        "audience must admit: {}",
        reply.status.detail
    );
}

/// Issues a tenant-to-Bob Records Write grant scoped to `protocol_path`.
async fn issue_write_grant(
    fixture: &ControlFixture,
    protocol_path: &str,
    timestamp: &str,
) -> String {
    issue_grant(
        fixture,
        "Write",
        "did:example:bob",
        protocol_path,
        timestamp,
    )
    .await
}

/// Issues a tenant-issued Records grant to `grantee`, scoped to `protocol_path`.
async fn issue_grant(
    fixture: &ControlFixture,
    method: &str,
    grantee: &str,
    protocol_path: &str,
    timestamp: &str,
) -> String {
    let data = Bytes::from(
        serde_json::to_vec(&json!({
            // Far future rather than merely "after the fixture timestamps":
            // checks that run at *now* — delivery reauthorization does — would
            // otherwise start failing once the wall clock passed the expiry.
            "dateExpires": "2099-01-01T00:00:00.000000Z",
            "scope": {
                "interface": "Records",
                "method": method,
                "protocol": CONTROL_PROTOCOL,
                "protocolPath": protocol_path
            },
            "delegated": true
        }))
        .unwrap(),
    );
    let grant = signed_write_message(WriteSpec {
        protocol: permissions::PERMISSIONS_PROTOCOL_URI.to_string(),
        protocol_path: permissions::PERMISSIONS_GRANT_PATH.to_string(),
        recipient: Some(grantee.to_string()),
        tags: Some(MapValue::from([(
            "protocol".to_string(),
            Value::String(CONTROL_PROTOCOL.to_string()),
        )])),
        data_cid: generate_dag_pb_cid_from_bytes(&data).to_string(),
        data_size: data.len() as u64,
        data_format: "application/json".to_string(),
        ..WriteSpec::new(timestamp)
    })
    .await;
    let grant_id = grant["recordId"].as_str().unwrap().to_string();
    assert_eq!(
        fixture
            .handler
            .run(CONTROL_TENANT, &grant, Some(data))
            .await
            .status
            .code,
        202,
        "grant fixture must store"
    );
    grant_id
}

/// Signs a Read/Query request as `signer`, so the requester is someone other
/// than the tenant.
async fn signed_request(
    mut request: serde_json::Value,
    signer: crate::auth::PrivateJwkSigner,
    grant_id: Option<&str>,
) -> serde_json::Value {
    if let Some(grant_id) = grant_id {
        request["descriptor"]["permissionGrantId"] = json!(grant_id);
    }
    let descriptor = request["descriptor"].clone();
    let extra = match grant_id {
        Some(grant_id) => json!({ "permissionGrantId": grant_id }),
        None => json!({}),
    };
    let signature = signature_for_descriptor(&descriptor, extra, signer).await;
    request["authorization"] = json!({ "signature": signature });
    request
}

fn exact_tuple_filter(key_id: Option<&str>) -> serde_json::Value {
    let mut tags = json!({
        "protocol": CONTROL_PROTOCOL,
        "rolePath": "member",
        "contextId": "",
    });
    if let Some(key_id) = key_id {
        tags["keyId"] = json!(key_id);
    }
    json!({
        "protocol": CONTROL_PROTOCOL,
        "protocolPath": AUDIENCE_PATH,
        "tags": tags,
    })
}

/// Admits an audience publishing `public_key`, signed by `signer`.
async fn admit_audience_signed(
    fixture: &ControlFixture,
    public_key: &JWK,
    author: &str,
    signer: crate::auth::PrivateJwkSigner,
    timestamp: &str,
    grant_id: Option<&str>,
) -> String {
    let key_id = public_key.thumbprint().unwrap();
    let data = audience_payload_for(public_key, "member", "", &key_id, &fixture.seal_key_id);
    let write = control_write(
        AUDIENCE_PATH,
        audience_tags("member", "", &key_id),
        &data,
        timestamp,
        |spec| {
            spec.author = author.to_string();
            spec.signer = signer;
            spec.permission_grant_id = grant_id.map(str::to_string);
        },
    )
    .await;
    let reply = fixture
        .handler
        .run(CONTROL_TENANT, &write, Some(data))
        .await;
    assert_eq!(
        reply.status.code, 202,
        "audience must admit: {}",
        reply.status.detail
    );
    key_id
}

/// Installs `definition` at `timestamp`, so a later configuration can change
/// what an already-stored record means.
async fn reconfigure(fixture: &ControlFixture, definition: Definition, timestamp: &str) {
    put_protocol_definition(
        CONTROL_TENANT,
        &fixture.message_store,
        definition,
        timestamp,
    )
    .await;
}
