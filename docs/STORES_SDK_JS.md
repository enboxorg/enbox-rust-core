# Using Rust stores with dwn-sdk-js

The Enbox product path uses **native SQLite** (`SqliteNativeDwn` in `dwn-rs-stores`) behind `enbox-ffi` or the loopback HTTP server. For **behavior parity** against the TypeScript SDK, you can still run `dwn-sdk-js` handler specs with Rust-backed persistence in two ways: WASM Surreal adapters (today) and future FFI store injection (planned).

## Native SQLite (production)

| Surface | Crate | Notes |
|---------|-------|-------|
| Mobile / desktop host | `enbox-ffi` | `EnboxCore::open`, `process_message`, sync APIs |
| Loopback dev server | `dwn-rs-core` desktop server | HTTP + WebSocket JSON-RPC; see [`tools/interop/loopback-interop.test.ts`](../tools/interop/loopback-interop.test.ts) |
| Direct Rust tests | `dwn-rs-stores` | `SqliteNativeDwn`, integration tests under `crates/dwn-rs-stores/tests/` |

`Dwn::create({ messageStore, dataStore, stateIndex, eventLog, resumableTaskStore })` in TypeScript maps to constructing a `SqliteNativeDwn` (or in-memory test node) in Rust and calling `process_message` on the embedded `Dwn` instance.

## WASM Surreal adapters (SDK injectable suite)

The inherited `dwn-rs-wasm` crate exposes Surreal-backed store implementations that implement the same contracts `dwn-sdk-js` expects for `TestSuite.runInjectableDependentTests`:

```javascript
import { TestSuite } from "@enbox/dwn-sdk-js/tests";
import {
  SurrealDataStore,
  SurrealMessageStore,
  SurrealEventLog,
  SurrealResumableTaskStore,
  EventStream,
} from "../pkg/index.js"; // wasm-pack output

await messageStore.connect("mem://");
// … connect other stores …

TestSuite.runInjectableDependentTests({
  messageStore,
  dataStore,
  eventLog,
  eventStream: new EventStream(),
  resumableTaskStore,
});
```

Reference harness: [`crates/dwn-rs-wasm/tests/test.js`](../crates/dwn-rs-wasm/tests/test.js).

Build (from repo root, with wasm-pack installed):

```bash
cd crates/dwn-rs-wasm
wasm-pack build --target web --features surrealdb
```

Browser runs use the package’s Web Test Runner config (`web-test-runner.config.mjs`).

## In-process TypeScript stores (default SDK tests)

`packages/dwn-sdk-js/tests/test-stores.ts` provides in-memory implementations. Handler specs call `TestStores.get()` unless overrides are passed to `TestSuite.runInjectableDependentTests`. This is what CI runs in the Enbox monorepo (`bun run --filter @enbox/dwn-sdk-js test:node`).

## Future: Rust stores via FFI in CI

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
| Run full SDK store-dependent specs on Rust persistence today | `dwn-rs-wasm` Surreal adapters |
| Long-term CI parity without WASM | FFI store adapters + injectable harness (planned) |

See also [`TEST_COVERAGE.md`](./TEST_COVERAGE.md) (layer 5) and [`MIGRATION_GUIDE.md`](./MIGRATION_GUIDE.md) (identity/recovery boundary).
