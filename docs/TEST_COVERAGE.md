# Test Coverage Dashboard

This repository validates DWN behavior through **three independent layers**. They share JSON fixtures where possible, but they are not a single unified suite. Use this matrix to see what each layer covers and which CI job runs it.

## Enbox pin

| Field | Value |
|-------|-------|
| Pin file | [`.enbox-version`](../.enbox-version) |
| Current commit | `1a227b0179f33e5d9ce3d68ba6275533ae306e2d` |
| Fixture `source.commit` | Must match `.enbox-version` (checked in CI) |

## Layer overview

| Layer | Runner | CI job | Validates Rust? | Validates TS reference? |
|-------|--------|--------|-----------------|-------------------------|
| 1 — Rust native | `cargo test --workspace` | `rust-tests` | Yes | Indirect (shared fixtures) |
| 2 — Shared fixtures (TS) | `bun test tools/conformance/typescript-*.test.ts` | `typescript-conformance` | No | Partial (adapter subset) |
| 3 — dwn-sdk-js native | `bun run --filter @enbox/dwn-sdk-js test:node` | `dwn-sdk-js-reference` | No | Yes (full SDK suite) |
| 4 — Loopback RPC interop | `bun test tools/interop/loopback-interop.test.ts` | `loopback-interop` | Cross-runtime | Client ↔ Rust server |
| 5 — Store injection (future) | `TestSuite.runInjectableDependentTests` | Not in CI yet | Target | Same specs, Rust stores |

## Shared fixture assertion matrix

[`fixtures/manifest.json`](../fixtures/manifest.json) defines **15 assertion types** across **13 suites**.

| Assertion | Rust (`conformance_fixtures.rs`) | TS (`tools/conformance/`) | dwn-sdk-js native | Loopback interop | Status |
|-----------|----------------------------------|---------------------------|-------------------|------------------|--------|
| `cid.message` | yes | `typescript-cid.test.ts` | utils/cid specs | — | covered |
| `cid.descriptor` | yes | `typescript-cid.test.ts` | utils/cid specs | — | covered |
| `cid.json` | yes | `typescript-cid.test.ts` | utils/cid specs | — | covered |
| `cid.dagpb.bytes` | yes | `typescript-cid.test.ts` | utils/cid specs | — | covered |
| `cid.dagpb.stream` | yes | `typescript-cid.test.ts` | utils/cid specs | — | covered |
| `jws.general.sign` | yes | `typescript-jws.test.ts` | utils/jws specs | — | covered |
| `jws.general.verify` | yes | `typescript-jws.test.ts` | utils/jws specs | — | covered |
| `jws.general.payload` | yes | `typescript-jws.test.ts` | utils/jws specs | — | covered |
| `jwe.protected` | yes | `typescript-jwe.test.ts` | utils/encryption specs | — | covered |
| `jwe.aead` | yes | `typescript-jwe.test.ts` | utils/encryption specs | — | covered |
| `jwe.keywrap` | yes | `typescript-jwe.test.ts` | utils/encryption specs | — | covered |
| `jwe.decrypt` | yes | `typescript-jwe.test.ts` | utils/encryption specs | — | covered |
| `state-index.operations` | yes | `typescript-state-index.test.ts` | store/state-index specs | — | covered |
| `messages-sync.replies` | yes | `typescript-messages-sync.test.ts` | handlers/messages-sync specs | — | covered |
| `native-sync.engine` | yes (`native_dwn_sync_integration.rs`) | — | — | — | covered |
| `descriptor.roundtrip` | yes | `typescript-descriptor-roundtrip.test.ts` | handler descriptor specs | — | covered |
| `message.process` | yes (`SqliteNativeDwn`) | `typescript-message-process.test.ts` | handlers/*.spec.ts | partial (RPC smoke) | partial |
| `protocol.authorization-corpus` | yes | `typescript-protocol-authorization.test.ts` | features/permissions specs | — | partial |

**Loopback interop (layer 4)** now covers unsigned `RecordsQuery`, signed `ProtocolsConfigure`, signed `RecordsWrite` + `RecordsRead` round-trip (`tools/interop/loopback-interop.test.ts`).

**Partial** means the shared fixture corpus exercises a slice of the behavior; the dwn-sdk-js native suite covers the full handler/feature/scenario surface.

## dwn-sdk-js native categories (Enbox `@enbox/dwn-sdk-js`)

These specs live in the pinned Enbox checkout and run in the `dwn-sdk-js-reference` CI job. They are **not** duplicated by fixture runners.

| Category | Location (under `packages/dwn-sdk-js/tests/`) | Approx. specs | In enbox-rust-core CI |
|----------|-----------------------------------------------|---------------|------------------------|
| Handlers | `handlers/*.spec.ts` | 11 | reference gate only |
| Features | `features/*.spec.ts` | 16 | reference gate only |
| Scenarios | `scenarios/*.spec.ts` | 5 | reference gate only |
| Store | `store/*.spec.ts` | ~10 | reference gate only |
| Utils / core | `utils/*.spec.ts`, `dwn.spec.ts`, … | ~15 | reference gate only |
| Fuzz | `fuzz/*.fuzz.spec.ts` | 25 | not on every PR |

Non-fuzz total: **~85** spec files (**~110** including fuzz).

## CI jobs

| Job | Command | Purpose |
|-----|---------|---------|
| `rust-tests` | `cargo test --workspace` | Execute all Rust tests including `conformance_fixtures.rs` |
| `typescript-conformance` | `bun test tools/conformance/typescript-*.test.ts` | Shared JSON fixtures via TS adapters at pinned Enbox |
| `dwn-sdk-js-reference` | `bun run --filter @enbox/dwn-sdk-js test:node` | Full SDK regression at pinned Enbox |
| `loopback-interop` | build server + `bun test tools/interop/loopback-interop.test.ts` | TS HTTP client against Rust `LoopbackDwnServer` |
| Fixture provenance | `tools/conformance/check-fixture-provenance.sh` | Fail if any fixture `source.commit` ≠ `.enbox-version` |

## Gaps and roadmap

| Gap | Mitigation | Status |
|-----|------------|--------|
| Fixture echo `message.process` replies vs real handler bodies | Rust uses `SqliteNativeDwn` dispatch; fixture handlers still stub replies for parity | in progress |
| Filter engine DateTime/Cid index coercion | Fixed RFC3339 range + CID string equality in `filters/matching.rs` | done |
| HTTP RecordsWrite data not wired to handler | `process_message_with_data` + loopback processor pass request body | done |
| No Rust-backed `TestSuite.runInjectableDependentTests` | Scaffold in `tools/interop/testsuite-injection.test.ts`; wire via `enbox-ffi` / WASM | planned |
| `NativeSyncEngine` not wired to `SqliteNativeDwn` | `sync_once_with_peer` + `DirectSyncEndpoint` integration test | done |
| Scenario/end-to-end specs use in-process `Dwn`, not HTTP | Expand `loopback-interop` harness incrementally | started |
| Fuzz specs expensive / non-deterministic | Run nightly in Enbox CI, not every PR here | by design |

## Local commands

```bash
# Rust (all workspace tests)
cargo test --workspace

# Shared fixture TS runners (requires Enbox checkout)
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-*.test.ts

# dwn-sdk-js reference suite
cd enbox && bun run --filter @enbox/dwn-sdk-js test:node

# Loopback interop (starts Rust server automatically in test)
ENBOX_TS_ROOT=/path/to/enbox bun test tools/interop/loopback-interop.test.ts
```

See also [CONFORMANCE.md](./CONFORMANCE.md) for the fixture contract and adapter model.
