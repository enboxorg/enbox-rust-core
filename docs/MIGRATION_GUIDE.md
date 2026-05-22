# TypeScript Local DWN To Rust Core Migration Guide

## Scope

This guide documents the expected migration path from the current TypeScript local DWN stack to the native Rust core. It covers local mobile/desktop nodes. Remote Enbox DWN servers remain wire-compatible peers and do not require app-local storage migration.

## Current TypeScript Local Path

`AgentDwnApi.createDwn()` currently constructs an in-process TypeScript DWN with these default dependencies:

| TypeScript Dependency | Current Role | Rust Target |
| --- | --- | --- |
| `Dwn.create()` | Opens stores, resolver, handlers, tenant gate, and processMessage dispatch. | `enbox-dwn-core` engine facade with native handler dispatch. |
| `MessageStoreLevel` | Stores encoded messages and query indexes in LevelDB-backed stores. | `enbox-dwn-sqlite` `MessageStore` with Enbox indexes, pagination, and sort parity. |
| `DataStoreLevel` | Stores record data blocks/content by tenant, record ID, and data CID. | `enbox-dwn-sqlite` `DataStore` with content-addressed data refs and stream handles. |
| `StateIndexLevel` | Stores global and protocol-scoped SMT state for `MessagesSync`. | `enbox-dwn-state-index`, backed by SQLite for durable local nodes. |
| `ResumableTaskStoreLevel` | Persists deferred/resumable DWN tasks. | Native `ResumableTaskStore`, sharing SQLite persistence. |
| `EventEmitterEventLog` | In-process event publication for subscriptions. | Native `EventLog` with durable progress tokens, EOSE, replay, and gap metadata. |
| `UniversalResolver` + `DidResolverCacheLevel` | Resolves DID methods and persists resolver cache. | Rust DID resolver boundary with a native cache. |
| `TenantGate` | Validates whether a DID is an active local tenant. | Rust tenant gate and tenant registry. |
| `SyncEngineLevel` | LevelDB sync ledger, live subscriptions, repair, and SMT diff reconciliation. | `enbox-dwn-sync` with durable checkpoints and background-safe entry points. |

The initial Rust port keeps the external DWN wire behavior stable while replacing the local runtime, persistence, and binding layers.

## API Mapping

Application code should move away from directly constructing TypeScript stores. The stable boundary should become the Rust facade exposed through direct Rust APIs, UniFFI, or desktop service mode.

| Current App Pattern | Rust-Core Direction |
| --- | --- |
| `agent.dwn.processRequest(...)` | Keep the high-level semantic operation. Internally route to Rust `process_message`/typed facade calls. |
| `agent.dwn.node.processMessage(tenant, message, options)` | Replace direct node access with a Rust facade call that accepts tenant, message JSON, and stream handles. |
| `agent.dwn.node.storage.messageStore` advanced access | Replace with explicit admin/debug APIs only where needed. Do not expose SQLite tables. |
| `ReadableStream<Uint8Array>` data input/output | Replace at FFI boundaries with stream handles, byte chunks, or file paths. Direct Rust callers can use Rust streams. |
| Local LevelDB path configuration | Replace with a Rust profile/storage directory containing SQLite databases and data files. |

Wire-level message JSON, CIDs, JWS/JWE shapes, protocol definitions, and status code semantics should remain compatible with current `@enbox/dwn-sdk-js` behavior unless a future issue explicitly changes them.

## Mobile Polyfills And Native Replacements

Current React Native/browser local DWN work depends on JS runtime facilities and storage polyfills. Rust replaces these at the core boundary:

| Current Need | Native Replacement |
| --- | --- |
| LevelDB or IndexedDB-backed stores | SQLite-backed Rust stores. |
| Node/Bun/Web `ReadableStream` bridging | Rust stream handles exposed through FFI. |
| JS timers/background process assumptions | Native background entry points with deadlines and checkpoints. |
| JS DID resolver cache store | Native resolver cache. |
| JS event emitter subscriptions | Native subscription handles and callbacks. |
| React Native app lifetime for sync | Native `sync_once`/`resume_pending` calls from iOS/Android schedulers. |

The Rust local node must run without Bun, Node, React Native, or a WASM bridge.

## Local Data Migration

Existing TypeScript local data is stored in LevelDB/IndexedDB layouts that are not a stable public storage format. Rust SQLite stores should not attempt in-place reads of those directories by default.

Supported migration expectations:

- New installs use Rust SQLite stores directly.
- Apps with a remote Enbox DWN can rebuild local state by syncing from the remote server.
- Apps without remote state need an explicit export/import path before removing the TypeScript local store.
- Encrypted protocol data remains decryptable only if the agent identity and key material migrate correctly.
- Existing local LevelDB/IndexedDB directories should be treated as source data, not modified by Rust.

Potential future migration tools:

- A TypeScript export tool that emits DWN messages, data blobs, StateIndex roots, and sync ledger state in a language-neutral bundle.
- A Rust import tool that validates CIDs/signatures and writes into SQLite stores.
- A one-time app-level migration flow that starts TypeScript local DWN, exports data, imports into Rust, verifies roots, then switches the app profile to Rust.

Until those tools exist, the safest migration path is remote resync or fresh local state.

## Identity And Recovery Boundary

Agent identity migration is separate from DWN store migration:

- Portable DID material and vault recovery must be migrated before encrypted local records can be read.
- Rust key-manager boundaries must preserve Ed25519 signing keys and X25519 key-agreement keys.
- Wallet recovery should prove that encrypted protocol records can be decrypted after restoring the seed/vault.
- Data migration must not introduce plaintext fallback for records whose protocol requires encryption.

## Remote Server Compatibility

Remote Enbox DWN servers remain compatible through the DWN wire protocol:

- Rust local nodes should send the same message JSON, CIDs, JWS/JWE, and protocol records as TypeScript.
- `MessagesSync` root/subtree/leaves/diff replies should remain compatible with current TypeScript fixtures.
- Remote servers do not need to know whether a client local node is TypeScript or Rust.
- Server-side data migration is out of scope for local Rust migration.

## Rollout Plan

1. Add fixture parity for current TypeScript behavior.
2. Port native stores, StateIndex, event log, and resumable task store.
3. Port `Dwn.processMessage()` and handlers behind fixtures.
4. Add the Rust facade and native bindings described in [`BINDINGS.md`](BINDINGS.md).
5. Add background sync entry points described in [`BACKGROUND_SYNC.md`](BACKGROUND_SYNC.md).
6. Add app-level feature flags so a profile can opt into Rust local DWN.
7. Provide export/import or remote-resync migration flows for existing local data.
8. Remove TypeScript local DWN and mobile storage polyfills only after Rust parity and migration paths are verified.

## Compatibility Guarantees

Stable across the migration:

- DWN wire messages and replies.
- CID calculation and descriptor CIDs.
- General JWS and JWE wire shapes.
- Protocol definitions and permission-grant semantics.
- Records data CID and data size behavior.
- Sync roots, subtree hashes, leaves, progress tokens, and gap semantics.

Allowed to change at the app integration boundary:

- Local store file layout.
- Direct access to store instances.
- Stream representation across native bindings.
- Background sync scheduling APIs.
- Internal crate/module names before the first stable Rust release.
