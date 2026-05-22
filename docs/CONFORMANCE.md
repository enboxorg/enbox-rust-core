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
- `jwe.protected`: parse the JWE protected header and verify the deterministic base64url encoding.
- `jwe.aead`: encrypt/decrypt fixture plaintext with the fixed CEK, IV, and content-encryption algorithm.
- `jwe.keywrap`: wrap/unwrap the CEK with X25519 ECDH-ES plus A256KW using fixed recipient and ephemeral keys.
- `jwe.decrypt`: unwrap the CEK from `case.jwe`, decrypt fixture ciphertext, and compare plaintext or expected failure.
- `state-index.operations`: apply StateIndex insert/delete/read operations and compare roots, protocol roots, subtree hashes, and leaves for supported cases.
- `descriptor.roundtrip`: parse and re-serialize supported descriptors without changing JSON shape.

Each case contains current TypeScript outputs and a Rust migration status:

- `supported`: the active Rust model is expected to pass all applicable assertions.
- `known_gap`: the fixture captures valid TypeScript behavior that Rust does not model yet. CID assertions still run because they only require raw JSON compatibility.

## Current Runners

Rust CI runs `crates/dwn-rs-core/tests/conformance_fixtures.rs` as part of `cargo test --workspace`. This runner discovers suites from `fixtures/manifest.json`, computes JSON CIDs with `dwn_rs_core::cid::generate_cid_from_json`, and does not require Bun, Node, or the TypeScript workspace.

Optional TypeScript runners are available under `tools/conformance/`:

```bash
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-cid.test.ts
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-jws.test.ts tools/conformance/typescript-jwe.test.ts
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-state-index.test.ts
```

If `ENBOX_TS_ROOT` is not set, the runners look for a sibling `../enbox` checkout. They import the current TypeScript implementations and verify the same assertions in the fixture manifest.

## Adapter Model

As Rust gains full DWN engine behavior, add new assertion types rather than duplicating fixture files. Expected future adapters:

- `descriptor.parse`: parse valid descriptors and reject invalid descriptors with expected error codes.
- `message.process`: process a message against a seeded store and compare reply/status output.
- `state-index.operations`: apply fixture operations and compare roots, subtree hashes, and leaves.
- `crypto.jws` and `crypto.jwe`: validate signature/encryption/decryption behavior using deterministic vectors where possible.

The rule is: one fixture case, multiple implementation adapters. Differences should be represented as `known_gap` status or explicit expected error/status output, not by forking fixtures per language.
