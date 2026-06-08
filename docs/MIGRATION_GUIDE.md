# TypeScript Local DWN To Rust Core Migration Guide

## Status

As of M5/M6, the Rust core ships everything an app previously got from the in-process TypeScript DWN:

- DWN engine (`processMessage`, handlers, descriptor + CID parity).
- SQLite-backed `MessageStore`, `DataStore`, `StateIndex`, `EventLog`, `ResumableTaskStore`, `SyncLedger`.
- `UniversalResolver` with `did:jwk` + `did:key` resolution.
- Native sync engine (`sync_once`, `poll_reconcile`, `resume_pending`) with durable checkpoints.
- Live subscriptions via the loopback WebSocket transport.
- Agent identity (`initialize_agent_identity`, `current_agent_identity`, key derivation, durable vault).
- Tenant registration over HTTP, protocol install/push, restore flow.
- DWeb Connect: permission requests, delegate grants, revocations, delegate-key derivation, context-key derivation, persisted key delivery.

The `enbox-ffi` facade exposes all of it through UniFFI; the loopback `desktop_server` exposes the same engine over the `@enbox/dwn-server` JSON-RPC contract for any TS clients that aren't ready to switch.

Remote `@enbox/dwn-server` peers do not need to change. The Rust core writes the same JSON-RPC messages and CIDs as the pinned TypeScript reference.

## Old → New API mapping

The Rust core does not aim to be a 1:1 type-for-type port of `dwn-sdk-js`. The wire surface stays compatible; the host surface becomes the `EnboxCore` facade.

| TypeScript pattern | Rust facade |
| --- | --- |
| `Dwn.create({ messageStore, dataStore, ... })` | `EnboxCore.open("/path/to/enbox.sqlite")` (opens or migrates SQLite in place). |
| `dwn.processMessage(tenant, message, options)` | `core.process_message(tenant, messageJson)` (signed messages required; unsigned `RecordsQuery` flows are also accepted). |
| `MessageStoreLevel`, `DataStoreLevel`, `StateIndexLevel`, `ResumableTaskStoreLevel`, `EventEmitterEventLog` constructors | Dropped; `EnboxCore::open` wires all stores from the same `SqliteStore` handle. |
| `UniversalResolver` + `DidResolverCacheLevel` | Built into the Rust core; supports `did:jwk` + `did:key` Ed25519 verification. Static fallback registration is in `crates/dwn-rs-core/src/auth/jws.rs`. |
| `SyncEngineLevel` (live + repair) | `core.sync_once(...)`, `core.poll_reconcile(...)`, `core.resume_pending(...)`, `core.list_pending_scopes(...)`. |
| `agent.identity.create(...)` | `core.initialize_agent_identity(request)` / `core.derive_agent_keys_from_phrase(phrase)`. |
| `agent.permissions.createGrant(...)` | `core.create_permission_request(...)`, `core.create_delegate_grant(...)`, `core.create_grant_revocation(...)`. |
| `agent.sync.start(...)` background loop | Host owns scheduling. Call `sync_once` / `resume_pending` from WorkManager (Android) or `BGTaskScheduler` (iOS). See [`BACKGROUND_SYNC.md`](BACKGROUND_SYNC.md). |
| `ReadableStream<Uint8Array>` for record data | Plain `Vec<u8>` over the FFI. For large records, the host should stream over WebSocket or sync, not embed in `processMessage`. |
| Local LevelDB / IndexedDB profile path | A single SQLite database path (`/Documents/enbox.sqlite`, `/data/data/<pkg>/databases/enbox.sqlite`, ...). |

Wire-level message JSON, CIDs, JWS/JWE shapes, protocol definitions, and status code semantics stay compatible with `@enbox/dwn-sdk-js` as pinned in `.enbox-version`. The CI `dwn-sdk-js-reference` and `typescript-conformance` jobs gate that contract.

## Adoption order

The recommended migration is incremental: replace the local DWN engine first, then the sync loop, then the identity vault. Each step is independently verifiable.

### 1. Replace the local DWN engine

Open the Rust core early in app startup, before any TypeScript DWN code runs. Route every existing call site that previously hit `dwn.processMessage(...)` through `core.process_message(tenant, messageJson)` instead.

```typescript
const core = EnboxCore.open(`${appDir}/enbox.sqlite`);
// In the call site that previously called dwn.processMessage(tenant, message):
const replyJson = await core.processMessage(tenant, JSON.stringify(message));
const reply = JSON.parse(replyJson);
```

The reply JSON has the same shape as the TypeScript reply (`{status: {code, detail}, entries?, entry?}`), so consumers downstream of the call site keep working.

### 2. Replace the sync loop

Stop calling the TypeScript `SyncEngineLevel` background loop. Add platform-side scheduling that calls `core.sync_once(...)` with a bounded deadline. On wake (silent push, WorkManager, BGTaskScheduler), call `core.resume_pending(...)`.

```typescript
await core.configureSyncSigner(JSON.stringify({
  keyId: `${aliceDid}#key1`,
  algorithm: 'EdDSA',
  privateJwk: aliceSigningJwk,
}));
await core.registerSyncIdentity(JSON.stringify({
  did: aliceDid,
  protocols: { type: 'all' },
}));

// Foreground manual sync:
await core.syncOnce(JSON.stringify({
  tenant: aliceDid,
  remote: 'https://dwn.example/',
  direction: 'bidirectional',
  deadlineMs: 25_000,
  connectivity: { online: true, expensive: false, roaming: false,
    backgroundRestricted: false, powerSave: false,
    allowMetered: true, allowRoaming: false },
  reason: 'manual',
}));

// Background wake hook (iOS BGAppRefreshTask, Android WorkManager):
await core.resumePending(JSON.stringify({
  tenant: aliceDid,
  deadlineMs: 25_000,
  connectivity: connectivityFromPlatform(),
  reason: 'periodic',
}));
```

The Rust sync engine writes durable `SyncCheckpoint` rows in SQLite, so a `deadlineExceeded` return is normal and resumable. See [`BACKGROUND_SYNC.md`](BACKGROUND_SYNC.md) for the full contract.

### 3. Replace the identity vault

Move identity initialization off the TypeScript `AgentKeyManager` / `Web5UserAgent` paths. The Rust `SqliteSecretStore` persists keys directly in the same SQLite database opened by `EnboxCore.open`.

```typescript
const portableDidJson = await core.initializeAgentIdentity(JSON.stringify({
  recoveryPhrase: bip39Mnemonic, // omit for a fresh random DID
}));
const did = (JSON.parse(portableDidJson) as { uri: string }).uri;
```

For DWeb Connect flows, the previous TypeScript permission helpers map directly:

```typescript
const requestJson = await core.createPermissionRequest(JSON.stringify(req));
const grantJson   = await core.createDelegateGrant(JSON.stringify(grant));
const revokeJson  = await core.createGrantRevocation(JSON.stringify(revocation));
```

Persisted delegate decryption / context keys round-trip through `save_delegate_decryption_keys` / `load_delegate_decryption_keys` (and the corresponding context-key methods) so a recovered agent re-derives the same keys on every device.

### 4. Wire the mobile runtime status

Optional but recommended. The Rust core records biometric unlock reasons and active background-task IDs so audit logs and crash reports have consistent telemetry.

```typescript
core.initializeRuntime(JSON.stringify({
  deviceId: getDeviceId(),
  appGroup: 'group.com.example.app',
  backgroundRefreshEnabled: true,
}));

// After Face ID / Touch ID / BiometricPrompt succeeds:
core.unlockWithReason('user_resume');

// Before a WorkManager / BGTask block:
core.beginBackgroundTask('sync.periodic');
try {
  await core.resumePending(/* ... */);
} finally {
  core.endBackgroundTask('sync.periodic');
}
```

`core.status()` returns the combined view (initialised, locked, deviceId, appGroup, backgroundRefreshEnabled, lastUnlockReason, activeBackgroundTasks) for diagnostic surfaces.

### 5. Retire the TypeScript local DWN code

Once `core.processMessage`, `core.syncOnce`, identity, and the runtime status surface have replaced their TypeScript counterparts in every call site:

- Delete the `Dwn.create({...})` factory and the `MessageStoreLevel` / `DataStoreLevel` / `StateIndexLevel` / `ResumableTaskStoreLevel` / `EventEmitterEventLog` imports.
- Delete the React-Native LevelDB / IndexedDB polyfills.
- Stop bundling `@enbox/dwn-sdk-js` for local-DWN responsibilities. Keep it only if you still rely on the `TestDataGenerator` for fixtures or share types between TS clients and the native core.

## Local data migration

LevelDB / IndexedDB layouts produced by the TypeScript stores are not a stable public format. The Rust SQLite stores do not read them in-place.

Three supported paths:

1. **Fresh install** — easiest. Open `EnboxCore.open("/path/enbox.sqlite")` against a new file and start writing.
2. **Resync from a remote `@enbox/dwn-server`** — if the user has any remote tenant, `core.runRestoreFlow(...)` installs protocols locally and pulls every message. The resulting SQLite is byte-for-byte equivalent to a fresh install that synced from the same remote.
3. **Bridge mode** — keep the TS DWN warm for one app launch, copy messages out via `dwn.processRequest({...messagesQuery})`, write them into the Rust core via `core.processMessage(...)`, then drop the TS path. This is the path for apps with no remote tenant and no acceptable resync window.

There is no in-place LevelDB → SQLite migration tool today and one is not planned: the cost of validating CIDs / signatures across two engines exceeds the cost of a remote resync for the typical app.

Encrypted records remain decryptable only if the agent identity migrates first. See "Replace the identity vault" above.

## Identity and recovery boundary

Identity migration runs independently of DWN store migration:

- Portable DID material and BIP-39 recovery phrases round-trip through `derive_agent_keys_from_phrase` and `initialize_agent_identity`. Both Ed25519 signing keys and X25519 key-agreement keys survive.
- `SqliteSecretStore` is the durable vault; the host never sees raw private keys outside the `PortableDid` JSON the user explicitly exports.
- Wallet recovery must prove that encrypted protocol records can be decrypted after restoring the seed/vault. The integration test `crates/dwn-rs-core/tests/wallet_recovery.rs` exercises this exact flow.
- Data migration must not introduce a plaintext fallback for records whose protocol requires encryption. The Rust handler enforces the encryption requirement on every `RecordsWrite`.

## Remote server compatibility

Remote Enbox DWN servers stay compatible through the wire protocol:

- Rust local nodes send the same message JSON, CIDs, JWS/JWE, and protocol records as TypeScript.
- `MessagesSync` root / subtree / leaves / diff replies stay compatible with current TypeScript fixtures. This is gated by the `loopback-interop` CI job, which runs the pinned `@enbox/dwn-clients` against the Rust server.
- Remote servers don't need to know whether a client local node is TypeScript or Rust.
- Server-side data migration is out of scope for local Rust migration; remote nodes can be migrated independently.

## Compatibility guarantees

Stable across the migration (covered by `typescript-conformance` + `dwn-sdk-js-reference` + `loopback-interop` CI):

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
- Background sync scheduling APIs (the spec in [`BACKGROUND_SYNC.md`](BACKGROUND_SYNC.md) is stable; FFI signatures may add optional fields).
- Internal crate / module names before the first stable Rust release.

## Where to look next

- [`crates/enbox-ffi/README.md`](../crates/enbox-ffi/README.md) — full FFI surface with JSON shapes.
- [`docs/BACKGROUND_SYNC.md`](BACKGROUND_SYNC.md) — the deadline / connectivity / reason contract.
- [`docs/BINDINGS.md`](BINDINGS.md) — UniFFI generation and platform integration notes.
- [`docs/MOBILE_INTEGRATION.md`](MOBILE_INTEGRATION.md) — iOS/Android shell wiring.
- [`docs/SYNC_LIVE_POLL.md`](SYNC_LIVE_POLL.md) — live-subscription degradation modes and the repair path.
- [`docs/TEST_COVERAGE.md`](TEST_COVERAGE.md) — the five-layer test matrix that gates parity.
