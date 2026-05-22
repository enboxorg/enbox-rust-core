# Native Binding Strategy

## Decision

Use direct Rust APIs inside Rust consumers, UniFFI as the primary mobile binding layer for Swift and Kotlin, and a small C ABI only as a compatibility layer for hosts that cannot consume UniFFI. Desktop should prefer direct Rust embedding when Enbox owns the process, with an optional local HTTP/WebSocket server mode when a separate app process needs to talk to the local node.

WASM is not part of the native mobile or desktop runtime strategy. It may be revisited for browser experiments, but the Rust core must run without Bun, Node, React Native, or a JavaScript bridge.

## Why UniFFI First For Mobile

UniFFI is the best default for iOS and Android because it gives Enbox typed Swift/Kotlin APIs without maintaining handwritten wrappers for every model. It also supports async functions, records, enums, callback interfaces, and generated error mapping, which matches the DWN core boundary better than a raw C API.

The Rust core should expose a small `enbox-ffi` facade rather than exporting every internal crate type. That facade should own FFI-safe DTOs, operation handles, stream handles, subscription handles, and error enums. Internal crates can still use idiomatic Rust types and streams.

## Desktop Strategy

Desktop has two supported shapes:

| Shape | Use When | Boundary |
| --- | --- | --- |
| Direct Rust embedding | The desktop shell can link Rust crates directly. | Call `enbox-dwn-core`, `enbox-agent-core`, and store crates directly. |
| Local node service | The app process should be isolated from the DWN node or multiple local clients need access. | Start a local Rust process exposing HTTP/WebSocket or JSON-RPC over loopback. |

Direct Rust embedding is preferred for lower latency, simpler deployment, and typed errors. The local service mode is useful for Electron-like shells, debugging tools, or multi-process desktop apps, but it is a product integration layer, not the core API.

## C ABI Role

The C ABI is a fallback, not the main mobile binding. It should be limited to opaque handles and simple functions:

- Create and destroy a core handle.
- Start operations and return operation handles.
- Poll or cancel operations by handle.
- Read stream chunks by stream handle.
- Register callback trampolines for subscriptions.
- Fetch the last typed error as a stable code plus JSON detail.

This keeps the ABI stable and avoids exposing Rust layout, generic types, async traits, or nested DWN models directly through C.

## Streams

FFI consumers should not receive Rust streams directly. The facade should convert them into explicit handles:

- `DataStreamHandle.read(max_bytes) -> bytes | end` for downloaded record data.
- `DataSinkHandle.write(bytes)` and `finish()` for uploads if the host cannot pass a file path.
- Chunk sizes are caller-controlled so mobile background tasks can honor time and memory budgets.
- Closing a stream handle must release Rust-side resources even if the operation is cancelled.

Direct Rust consumers can continue using `Stream<Item = Bytes>` and `AsyncRead`-style APIs internally.

## Callbacks And Subscriptions

Subscriptions should use explicit handles and callback interfaces:

- `subscribe_messages(...) -> SubscriptionHandle` registers a callback/listener.
- Events are delivered as typed DTOs with progress tokens.
- End-of-snapshot is delivered as an explicit `eose` event.
- `SubscriptionHandle.close()` stops delivery and releases resources.
- Callback errors are logged and surfaced through subscription state, not panics across FFI.

The FFI layer must preserve ProgressToken, EOSE, and gap metadata exactly so mobile and desktop clients can resume safely after process death.

## Errors

UniFFI bindings should expose typed error enums for stable categories and carry string/JSON detail for diagnostics. The first categories should mirror the core domains:

- `DwnError`
- `AuthError`
- `StoreError`
- `SyncError`
- `CryptoError`
- `Cancelled`
- `DeadlineExceeded`

C ABI callers receive a numeric status plus an error object containing `code`, `message`, and optional structured `details`. No Rust panic may cross the FFI boundary.

## Cancellation And Deadlines

Every long-running FFI operation should accept a deadline or cancellation token. The facade should return an `OperationHandle` for work that may outlive a single call:

- `OperationHandle.cancel()` requests cancellation.
- Cancellation is cooperative and checked between store reads/writes, network calls, crypto batches, and stream chunks.
- Deadlines are enforced in Rust so background mobile calls remain bounded even if the host forgets to cancel.
- Cancelled operations return a typed `Cancelled` or `DeadlineExceeded` error and leave durable checkpoints when partial work is valid.

## Runtime Ownership

The native core owns its Rust async runtime behind the FFI facade. Host apps do not need Bun, Node, React Native, or a JS event loop to run local DWN work.

Direct Rust embedding may use the caller's runtime. UniFFI and C ABI entry points should create or share a Rust runtime inside `CoreHandle`, with deterministic shutdown on `close()`.

## Compatibility Boundary

The FFI API should be smaller and more stable than the internal crate graph:

- Keep DWN wire messages as JSON-compatible DTOs at the boundary.
- Keep large record data as stream/file handles, not embedded JSON.
- Preserve TypeScript DWN semantics through shared conformance fixtures.
- Do not expose SQLite implementation details through mobile APIs.
- Do not require a legacy WASM bridge for native integrations.

## Open Implementation Notes

- Generate UniFFI scaffolding from the future `enbox-ffi` crate after `Dwn.processMessage`, stores, and sync APIs stabilize.
- Add C ABI wrappers only around the finalized facade, not around internal crates.
- Keep desktop local service mode optional and layered above the same Rust facade.
- Recheck callback threading requirements when concrete iOS and Android app integrations start.
