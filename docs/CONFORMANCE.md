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
- `descriptor.roundtrip`: parse and re-serialize supported descriptors without changing JSON shape.

Each case contains current TypeScript outputs and a Rust migration status:

- `supported`: the active Rust model is expected to pass all applicable assertions.
- `known_gap`: the fixture captures valid TypeScript behavior that Rust does not model yet. CID assertions still run because they only require raw JSON compatibility.

## Current Runners

Rust CI runs `crates/dwn-rs-core/tests/conformance_fixtures.rs` as part of `cargo test --workspace`. This runner discovers suites from `fixtures/manifest.json`, computes JSON CIDs with `dwn_rs_core::cid::generate_cid_from_json`, and does not require Bun, Node, or the TypeScript workspace.

An optional TypeScript runner is available at `tools/conformance/typescript-cid.test.ts`:

```bash
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-cid.test.ts
```

If `ENBOX_TS_ROOT` is not set, the runner looks for a sibling `../enbox` checkout. It imports the current TypeScript `Cid.computeCid` implementation and verifies the same CID assertions in the fixture manifest.

## Adapter Model

As Rust gains full DWN engine behavior, add new assertion types rather than duplicating fixture files. Expected future adapters:

- `descriptor.parse`: parse valid descriptors and reject invalid descriptors with expected error codes.
- `message.process`: process a message against a seeded store and compare reply/status output.
- `state-index`: apply fixture operations and compare roots, subtree hashes, and leaves.
- `crypto.jws` and `crypto.jwe`: validate signature/encryption/decryption behavior using deterministic vectors where possible.

The rule is: one fixture case, multiple implementation adapters. Differences should be represented as `known_gap` status or explicit expected error/status output, not by forking fixtures per language.
