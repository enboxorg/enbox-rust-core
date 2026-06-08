# Using Rust stores with dwn-sdk-js

The Enbox product path uses **native SQLite** (`SqliteNativeDwn` in `dwn-rs-stores`) behind `enbox-ffi` or the loopback HTTP server. The TypeScript SDK still owns the full handler/feature/scenario regression in CI; Rust validates the same behavior through shared fixtures and loopback interop.

## Native SQLite (production)

| Surface | Crate | Notes |
|---------|-------|-------|
| Mobile / desktop host | `enbox-ffi` | `EnboxCore::open`, `process_message`, sync APIs |
| Loopback dev server | `dwn-rs-core` desktop server | HTTP + WebSocket JSON-RPC; see [`tools/interop/loopback-interop.test.ts`](../tools/interop/loopback-interop.test.ts) |
| Direct Rust tests | `dwn-rs-stores` | `SqliteNativeDwn`, integration tests under `crates/dwn-rs-stores/tests/` |

`Dwn::create({ messageStore, dataStore, stateIndex, eventLog, resumableTaskStore })` in TypeScript maps to constructing a `SqliteNativeDwn` (or in-memory test node) in Rust and calling `process_message` on the embedded `Dwn` instance.

## TypeScript SDK behavior parity

Three layers prove the Rust SQLite implementation matches `@enbox/dwn-sdk-js`:

1. **Shared fixtures** (`tools/conformance/typescript-*.test.ts`) — 15 assertion types across CID, JWS, JWE, StateIndex, MessagesSync, descriptor roundtrip, message.process, and protocol authorization. Same fixtures consumed by Rust (`conformance_fixtures.rs`) and TS (pinned `@enbox/dwn-sdk-js`).
2. **dwn-sdk-js native suite** (`bun run --filter @enbox/dwn-sdk-js test:node`) — full handler/feature/scenario coverage runs at the pinned Enbox commit; protects against TS-side regressions before Rust touches behavior.
3. **Loopback interop** (`tools/interop/loopback-interop.test.ts`) — TS HTTP and WebSocket clients call into the Rust `LoopbackDwnServer`, covering signed Records, Protocols, Permissions grants, `RecordsSubscribe` over WebSocket, and `MessagesSync` root.

See [`TEST_COVERAGE.md`](./TEST_COVERAGE.md) for the full matrix and CI jobs.

## In-process TypeScript stores (default SDK tests)

`packages/dwn-sdk-js/tests/test-stores.ts` provides in-memory implementations. Handler specs call `TestStores.get()` unless overrides are passed to `TestSuite.runInjectableDependentTests`. This is what the `dwn-sdk-js-reference` CI job runs.

## Future: Rust stores via FFI store injection

Phase 1 scaffold: [`tools/interop/testsuite-injection.test.ts`](../tools/interop/testsuite-injection.test.ts).

Target wiring (not yet implemented):

1. Thin adapters in `enbox-ffi` (or a small TS package) that implement `MessageStore`, `DataStore`, `StateIndex`, `EventLog`, and `ResumableTaskStore` by calling into `SqliteNativeDwn` / store traits.
2. A dedicated Bun harness (not the scaffold file) that imports `TestSuite` once and calls `runInjectableDependentTests({ … })`.
3. Optional CI job after loopback interop proves HTTP parity.

Do **not** import `test-suite.ts` from the scaffold: many Enbox spec modules self-register tests at import time.

## Choosing an approach

| Goal | Approach |
|------|----------|
| Ship mobile/desktop native DWN | `enbox-ffi` + `SqliteNativeDwn` |
| Prove TS client ↔ Rust server | Loopback interop tests |
| Run full SDK store-dependent specs against Rust persistence | FFI store adapters + injectable harness (planned) |

See also [`TEST_COVERAGE.md`](./TEST_COVERAGE.md) (layer 5) and [`MIGRATION_GUIDE.md`](./MIGRATION_GUIDE.md) (identity/recovery boundary).
