# Conformance Testing

The conformance suite is intentionally implementation-neutral. Fixtures live under `fixtures/`, and each implementation provides a thin runner that applies the same assertions to the same JSON cases.

## Fixture Contract

`fixtures/manifest.json` is the entry point. Each suite entry declares:

- `id`: stable suite identifier used by runners and issue comments.
- `path`: fixture file path relative to `fixtures/`.
- `assertions`: assertion types that runners should apply.

Current assertion types:

- `cid.message`: compute a DAG-CBOR CID for `case.message` and compare it to `case.messageCid`.
- `cid.descriptor`: compute a DAG-CBOR CID for `case.message.descriptor` and compare it to `case.descriptorCid`.
- `cid.json`: compute a DAG-CBOR CID for `case.value` and compare it to `case.cid`.
- `cid.dagpb.bytes`: compute a DAG-PB/UnixFS CID for `case.data` bytes and compare it to `case.cid`.
- `cid.dagpb.stream`: compute a DAG-PB/UnixFS CID for `case.data` as a stream and compare it to `case.cid`.
- `jws.general.sign`: create a General JWS from fixture payload/signers and compare it to `case.jws`.
- `jws.general.verify`: verify `case.jws` signatures against fixture public keys and compare signers or expected error code.
- `jws.general.payload`: encode fixture payload bytes and compare them to `case.jws.payload`.
- `jwe.envelope`: validate the current `DwnEncryption` envelope shape (`algorithm` A256CTR, `initializationVector`, and each `keyEncryption` entry's algorithm/`keyId`/ephemeral key).
- `jwe.aead`: encrypt/decrypt fixture plaintext with the fixed CEK, IV, and A256CTR content-encryption algorithm.
- `jwe.keywrap`: wrap/unwrap the CEK with X25519-HKDF-SHA256+A256KW using fixed recipient and ephemeral keys.
- `jwe.decrypt`: unwrap the CEK from a fixture `keyEncryption` entry and decrypt fixture ciphertext, comparing plaintext or an expected failure.
- `state-index.operations`: apply Rust-native StateIndex insert/delete/read operations and compare roots, protocol roots, subtree hashes, and leaves for supported cases. `StateIndex` was removed from upstream Enbox (`25821eda`) and is an intentional Rust extension; see [TEST_COVERAGE.md](./TEST_COVERAGE.md#rust-extension-fixtures).
- `messages-sync.replies`: seed native sync state from fixture entries and compare Rust-native `MessagesSync` root/subtree/leaves/diff replies. `MessagesSync` was removed from upstream Enbox and is an intentional Rust extension; see [TEST_COVERAGE.md](./TEST_COVERAGE.md#rust-extension-fixtures).
- `message.process`: route a fixture message through the native `Dwn.process_message` boundary and compare the fixture reply/status shape; suites using this assertion must include valid and invalid cases for every current handler key.
- `protocol.authorization-corpus`: validate protocol definition directives and grant authorization status/error outcomes for scope, publication conditions, expiry, delegation, and revocation.
- `descriptor.roundtrip`: parse and re-serialize supported descriptors without changing JSON shape.

Each case contains current TypeScript outputs and a Rust migration status:

- `supported`: the active Rust model is expected to pass all applicable assertions.
- `known_gap`: the fixture captures valid TypeScript behavior that Rust does not model yet. CID assertions still run because they only require raw JSON compatibility.

## Rust-extension fixtures

Surfaces that upstream Enbox removed (e.g. `MessagesSync`, `StateIndex`, and the sparse-merkle
trie) are kept in Rust as intentional extensions. Their fixtures are tagged `oracle:
"rust-extension"`, pin `source.commit` to the last upstream commit that contained the surface, and
record the removal commit in `removedUpstreamAt` plus an `issue` link. They are exempt from the
`.enbox-version` equality rule in `tools/conformance/check-fixture-provenance.sh`, and there is no
TypeScript adapter for them because the upstream modules no longer exist. Rust validates these
fixtures directly through `conformance_fixtures.rs`; the parity story is tracked in #187/#188/#192.

## Current Runners

Rust CI runs `crates/dwn-rs-core/tests/conformance_fixtures.rs` as part of `cargo test --workspace`. This runner discovers suites from `fixtures/manifest.json`, computes JSON CIDs with `dwn_rs_core::cid::generate_cid_from_json`, and does not require Bun, Node, or the TypeScript workspace.

Optional TypeScript runners are available under `tools/conformance/`. CI also runs them against a pinned Enbox commit from `.enbox-version` (see the `typescript-conformance` job in `.github/workflows/tests.yaml`).

Store injection phase 1 lives under `tools/interop/`: a JSON-RPC bridge (`store_injection_server`) exposes Rust `SqliteStore` to dwn-sdk-js tests via `TestStores.override`. See [TEST_COVERAGE.md](./TEST_COVERAGE.md#store-injection-layer-5-phase-1).

```bash
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-cid.test.ts
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-jws.test.ts tools/conformance/typescript-jwe.test.ts
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-descriptor-roundtrip.test.ts
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-message-process.test.ts
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-protocol-authorization.test.ts
```

If `ENBOX_TS_ROOT` is not set, the runners look for a sibling `../enbox` checkout. They import the current TypeScript implementations and verify the manifest assertions where a TypeScript adapter exists.

## Adapter Model

As Rust gains full DWN engine behavior, add new assertion types rather than duplicating fixture files. Expected future adapters:

- `descriptor.parse`: parse valid descriptors and reject invalid descriptors with expected error codes.
- `message.process`: process a message against a seeded store and compare reply/status output; the current corpus records per-handler messages, CIDs, and reply shapes so implementations can replace the fixture echo adapter with real handlers incrementally.
- `protocol.authorization-corpus`: compare protocol-definition validation and grant authorization decisions against the shared corpus as authorization behavior moves from fixture evaluation into full handler execution.
- `crypto.jws` and `crypto.jwe`: validate signature/encryption/decryption behavior using deterministic vectors where possible.

The rule is: one fixture case, multiple implementation adapters. Differences should be represented as `known_gap` status or explicit expected error/status output, not by forking fixtures per language.

## DID resolver parity

Native `did:jwk` and `did:key` shapes are covered by `fixtures/spec/did/`. Fixed upstream
`did:web` and `did:dht` document-resolution vectors live in `fixtures/parity/did/` and are loaded
by Rust resolver tests without live network access. Redirect, SSRF, error, and JWS-integration
cases remain unit tests under `auth::resolver::{http,web}`. See
[`DID_RESOLUTION.md`](./DID_RESOLUTION.md) for the behavioral and security contract.
