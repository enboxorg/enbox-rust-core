# enbox-ffi

UniFFI facade for iOS, Android, and other hosts embedding the Enbox Rust DWN core.

## API surface

| Method | Purpose |
|--------|---------|
| `EnboxCore.open_in_memory()` | Ephemeral SQLite node for tests |
| `EnboxCore.open(database_path)` | Durable SQLite node at a filesystem path |
| `process_message(tenant, message_json)` | Dispatch a DWN message; returns JSON `DwnReply` |
| `configure_sync_signer(signer_json)` | Install a private JWK for signing HTTP sync requests |
| `register_sync_identity(identity_json)` | Register tenant DID + protocol scope for sync |
| `sync_once(request_json)` | Run one sync cycle against a remote DWN URL |
| `poll_reconcile(request_json)` | Pull-only poll reconciliation (live-degraded HTTP fallback) |
| `sync_status(query_json)` | Last sync outcome (in-progress flag, status, error, counters) |
| `initialize_agent_identity(request_json)` | Initialize the shared password vault and its `did:dht` identity |
| `initialize_credential_vault(password, recovery_phrase)` | Initialize password-protected credential storage; returns its recovery phrase |
| `unlock_credential_vault(password)` | Unlock encrypted credentials and enable runtime access |
| `delete_registration_tokens()` | Delete the persisted token entry while locked or unlocked; returns whether it existed |
| `current_agent_identity()` | Decrypt the shared vault’s `PortableDid` JSON, or `None` before initialization |
| `derive_agent_keys_from_phrase(phrase)` | Derive the four-key set (vault/identity/signing/encryption) without persisting; for recovery-screen validation |
| `install_protocol(tenant_did_json, definition_json)` | Install a protocol on the local DWN (signs a `ProtocolsConfigure`, injects encryption when required); idempotent |
| `inject_protocol_encryption(tenant_did_json, definition_json)` | Augment a protocol `Definition` with per-path key-agreement encryption; pure (no I/O) |
| `register_tenant(request_json)` | Register agent + connected DIDs with one or more `@enbox/dwn-server` HTTP endpoints; refreshes provider-auth tokens when expired |
| `push_protocol(request_json)` | Push a protocol to a remote `@enbox/dwn-server` (signs `ProtocolsQuery` first; idempotent) |
| `run_restore_flow(request_json)` | Replay protocol install + push across local + remote endpoints for a recovered agent |
| `create_permission_request(request_json)` | Build a `PermissionRequestRecord` for DWeb Connect; pure |
| `create_delegate_grant(request_json)` | Build a `DelegateGrant` (`{grantor, grantee, scope, dateExpires, description?}`); pure |
| `create_grant_revocation(request_json)` | Build a `GrantRevocation` for an existing grant; pure |
| `derive_delegate_keys(request_json)` | Derive `DelegateDecryptionKey` batch for a connect request; key manager rehydrated from `ownerDid` |
| `derive_context_key(request_json)` | Derive a context-scoped `DelegateContextKey`; key manager rehydrated from `ownerDid` |
| `save_delegate_decryption_keys(keys_json)` | Encrypt and persist `DelegateDecryptionKey[]`; requires an unlocked credential vault |
| `load_delegate_decryption_keys()` | Decrypt `DelegateDecryptionKey[]`; requires an unlocked credential vault (empty array when unset) |
| `save_delegate_context_keys(keys_json)` | Encrypt and persist `DelegateContextKey[]`; requires an unlocked credential vault |
| `load_delegate_context_keys()` | Decrypt `DelegateContextKey[]`; requires an unlocked credential vault (empty array when unset) |
| `lock()` / `unlock()` | Lock clears the credential CEK and gates runtime access; passwordless unlock changes only the runtime flag |

Typed errors (`EnboxError`) cross the FFI boundary. These methods are synchronous; Rust async callers must dispatch them to a blocking thread, except `lock()`, which supports async caller contexts. Calls may wait for an in-flight vault lifecycle operation.

## Credential vault release boundary

This is an incremental credential cutover, not yet a database-reader confidentiality guarantee. [Legacy key cleanup (#327)](https://github.com/enboxorg/enbox-rust-core/issues/327) remains a release prerequisite for upgraded stores. The FFI initializer uses the shared encrypted vault, and the underlying plaintext writer has been removed. Existing databases may still contain raw CEK and private DID material. Reusing a legacy recovery phrase for the credential vault derives that same CEK, so the database alone can decrypt credentials in either initialization order while the raw key remains.

Cleanup must cover already-initialized vaults as well as legacy-only stores. SQL deletion makes entries logically absent; it does not by itself erase recoverable bytes in database pages or WAL files, and cannot revoke old copies or previously learned keys. The cleanup/storage policy must address that before claiming confidentiality.

Initialize the shared vault once with `initialize_agent_identity` (with password and optional endpoints), or `initialize_credential_vault(password, recovery_phrase)` and unlock it after reopen with `unlock_credential_vault(password)`. Persisted registration and delegate-key methods require that shared vault to be unlocked. Passwordless `unlock()` or `unlock_with_reason()` cannot decrypt credentials. If legacy registration bytes cause `AgentSecretInvalidEnvelope`, explicitly call `delete_registration_tokens()` (works while locked), unlock, and obtain fresh credentials; deletion is not secure erasure.

## Agent identity workflow

1. Open a durable node: `EnboxCore.open("/path/to/enbox.sqlite")`
2. Initialize or recover an identity:
   ```json
   initialize_agent_identity({
     "password": "<vault password>",
     "recoveryPhrase": "<12-word BIP-39 phrase, optional>",
     "dwnEndpoints": ["https://dwn.example/"]
   })
   ```
   Returns JSON `VaultInitialization` (`portableDid` + `recoveryPhrase`), without raw vault keys. The host displays the recovery phrase **once**. Identity and credentials use the same password vault; choose either initializer once, since a second initialization returns `AgentVaultAlreadyInitialized`. Missing passwords fail JSON validation and blank passwords fail vault validation.
3. On subsequent launches, call `unlock_credential_vault(password)` before `current_agent_identity()`. Identity access fails with `AgentVaultLocked` until password unlock; before initialization it returns `null`. Runtime-only `unlock()` cannot expose the identity.
4. For recovery-screen validation before committing, call `derive_agent_keys_from_phrase(phrase)` — this is pure and does not persist anything.

`PortableDid` follows [`agent/service.rs`](../dwn-rs-agent/src/agent/service.rs); `VaultInitialization` follows [`agent/vault.rs`](../dwn-rs-agent/src/agent/vault.rs). The secret store layer is `SqliteSecretStore` ([`dwn-rs-agent/src/secrets_store.rs`](../dwn-rs-agent/src/secrets_store.rs), feature `sqlite`), which shares the SQLite database used for DWN data.

The Rust `AgentIdentityService` is now an in-memory derivation/key-import service: use
`derive_from_recovery` and its three-argument constructor (provider, key manager,
resolver cache). Its raw-store constructor argument, `initialize_from_recovery`,
and `stored_agent_did` are removed. Durable identity creation and reads belong to
`IdentityVault`; hosts must unlock it with a password rather than read legacy rows.

## Protocol install workflow

Once an identity exists, install user protocols on the local DWN:

```json
install_protocol(
  <portable_did_json>,
  {
    "protocol": "https://protocol.example/notes",
    "published": true,
    "types": { "note": { "schema": "…", "dataFormats": ["text/plain"] } },
    "structure": { "note": { "$actions": [...] } }
  }
)
```

Returns JSON `ProtocolInstallResult` (`{protocol, installed, encryptionActive}`). Subsequent calls for the same protocol return `installed: false` — the helper queries before configuring, matching [`install_protocol_if_needed`](../dwn-rs-agent/src/auth/setup.rs).

Encrypted protocols (those with `encryptionRequired: true`) have per-path key-agreement encryption injected automatically. For preview or sharing the augmented definition with another agent, call `inject_protocol_encryption` separately — it is pure and does not touch the DWN.

## Remote setup workflow

For HTTP-backed registration and protocol push (closes #145), three additional methods sit alongside the local install helpers:

1. Register the agent with one or more endpoints:
   ```json
   register_tenant({
     "dwnEndpoints": ["https://dwn.example/"],
     "agentDid": "did:dht:agent",
     "connectedDid": "did:dht:connected",
     "registrationTokens": {
       "https://dwn.example/": {
         "registrationToken": "<jwt>",
         "tokenUrl": "https://example/token",
         "refreshUrl": "https://example/refresh",
         "refreshToken": "<refresh>",
         "expiresAt": 1717000000000
       }
     },
     "persistTokens": true
   })
   ```
   The agent calls `GET <endpoint>/info` to discover requirements, refreshes any expired `provider-auth-v0` tokens (`POST <refreshUrl>`), then `POST <endpoint>/registration` per DID. When `persistTokens: true`, the token map is read from and written back to the agent secret store as a vault envelope under `enbox:auth:registrationTokens` (the credential vault must be unlocked). Returns a `TenantRegistrationResult` (per-endpoint `records` + final token map).
2. Push a protocol to a remote DWN:
   ```json
   push_protocol({
     "tenantDid": <portable_did_json>,
     "remoteUrl": "https://dwn.example/",
     "definition": <protocol_definition>
   })
   ```
   Signs a `ProtocolsQuery` against the remote first (idempotent path), otherwise signs and sends a `ProtocolsConfigure` (with encryption injected when required). Same JSON-RPC transport as `HttpSyncEndpoint`: `dwn-request` header on `POST <url>/`, response read from `dwn-response` header or body.
3. Replay a recovery flow across local + remote endpoints:
   ```json
   run_restore_flow({
     "agentDid": <portable_did_json>,
     "remoteUrl": "https://dwn.example/",
     "protocols": [<definition>, ...]
   })
   ```
   For each protocol: local `install_protocol_if_needed` then remote `push_protocol_if_needed`. Returns a `RestoreFlowResult` (`steps`, `localInstalls`, `remotePushes`). Identity tenant restoration is out of scope (see [`run_restore_flow`](../dwn-rs-agent/src/auth/setup.rs) docs).

## DWeb Connect workflow

The connect FFI mirrors [`dwn_rs_agent::auth::connect`](../dwn-rs-agent/src/auth/connect.rs) so a mobile host can drive a delegate session without a JS runtime:

1. Build a permission request to present in UI: `create_permission_request({ requester, scope, delegated, description? })`.
2. After the user approves, mint a delegate grant: `create_delegate_grant({ grantor, grantee, scope, dateExpires, description? })`.
3. Derive decryption keys for the delegate session:
   ```json
   derive_delegate_keys({
     "ownerDid": <portable_did_json>,
     "requests": [{ "protocolDefinition": <Definition>, "permissionScopes": [<PermissionScope>, ...] }]
   })
   ```
   Returns `DelegateKeyDerivationResult` (`decryptionKeys`, `contextKeys`, `multiPartyProtocols`).
4. For multi-party protocols, derive a context key per record context: `derive_context_key({ ownerDid, protocol, contextId })`.
5. Initialize/unlock the credential vault, then persist the derived keys as encrypted envelopes for re-use across launches:
   `save_delegate_decryption_keys(keys_json)` / `save_delegate_context_keys(keys_json)`.
   Re-load them with `load_delegate_decryption_keys()` / `load_delegate_context_keys()` (each returns `[]` when nothing is stored yet).
6. To revoke a grant later, compose `create_grant_revocation({ grant, revocationGrantId })` and push it through `process_message` once the host has chosen a transport.

All key-derivation methods rehydrate a per-call `MemoryKeyManager` from the supplied `PortableDid.privateKeys`, so they refuse to run while the core is locked. The pure constructors (`create_permission_request`, `create_delegate_grant`, `create_grant_revocation`) do not touch the vault and remain available even when locked, mirroring `derive_agent_keys_from_phrase`.

## Mobile runtime status

The Rust facade tracks the bookkeeping a mobile host needs to coordinate biometric prompts, background-task scheduling, and audit telemetry. None of this performs platform work itself — the host stays the source of truth for the biometric prompt and the background scheduler.

| Method | Purpose |
|---|---|
| `initialize_runtime(json)` | Record `deviceId`, `appGroup`, optional `databasePath` override, and `backgroundRefreshEnabled` (matches [`MobileInitializeRequest`](../dwn-rs-core/src/mobile.rs)). |
| `unlock_with_reason(reason)` | Same effect as `unlock()`, but records the reason on the runtime status for audit logs. Use after a successful Face ID / Touch ID / `BiometricPrompt`. |
| `lock()` | Clear the credential CEK, gate runtime access, and clear `last_unlock_reason`. |
| `begin_background_task(taskId)` | Returns `true` if the id was newly registered, `false` if it was already active. Mirrors `MobileCore::track_background_task` idempotency expected by WorkManager / `BGTaskScheduler`. |
| `end_background_task(taskId)` | Returns `true` if removed, `false` if unknown. Safe to call from expiration / cleanup paths. |
| `status()` | Returns `EnboxRuntimeStatus` with `initialized`, `locked`, `databasePath`, `deviceId`, `appGroup`, `backgroundRefreshEnabled`, `lastUnlockReason`, `activeBackgroundTasks`. |

## Sync workflow

1. Open a durable node: `EnboxCore.open("/path/to/enbox.sqlite")`
2. Configure signing keys for sync: `configure_sync_signer(...)`
3. Register identities: `register_sync_identity({"did":"…","protocols":{"type":"all"}})`
4. Run sync: `sync_once({"tenant":"…","remote":"https://dwn.example/","direction":"pull"})`
5. After a live subscription drop, repair with `poll_reconcile` (same request shape as `sync_once`)
6. Poll UI state: `sync_status({"tenant":"…","remote":"https://dwn.example/"})`

`sync_once` and `poll_reconcile` return JSON [`SyncOnceResult`](../../crates/dwn-rs-core/src/sync.rs) mirroring the native engine. HTTP remotes use `@enbox/dwn-server` JSON-RPC via [`HttpSyncEndpoint`](../dwn-rs-core/src/sync_endpoint.rs).

Background-safe request fields (see [`docs/BACKGROUND_SYNC.md`](../../docs/BACKGROUND_SYNC.md)):

| Field | Type | Effect |
|---|---|---|
| `deadlineMs` | `Option<u64>` | Wraps the run in `tokio::time::timeout`; returns `SyncRunStatus::DeadlineExceeded` if exceeded. Durable checkpoints written before the timeout remain in SQLite for the next call. |
| `connectivity` | `Option<SyncConnectivity>` | `{online, expensive, roaming, backgroundRestricted, powerSave, allowMetered, allowRoaming, preferredMaxBytes?}`. Offline/metered/roaming policy is enforced in Rust and short-circuits to `noConnectivity` before any HTTP request. |
| `reason` | `Option<String>` | Caller-supplied telemetry label (`push_notification`, `periodic`, `manual`, `repair`, `startup_resume`, ...). Recorded on the resulting checkpoints. Defaults to `ffi_sync_once` / `ffi_poll_reconcile`. |
| `maxRecords` / `maxBytes` | `Option<usize>` / `Option<u64>` | Soft byte/record budgets enforced inside the sync engine. |

### Resume-pending workflow

For hosts that want to "drain any leftover work" without recomputing which scopes need attention (background wake hooks, app cold-start), the facade exposes a checkpoint-driven path:

- `list_pending_scopes({"tenant": "did:..."})` — returns an array of `FfiPendingScope` entries (`{tenant, remote, protocol, direction, pendingPullCount, pendingPushCount, hasCursor, recordsPulled, recordsPushed, bytesDownloaded, bytesUploaded}`) for any checkpoint whose pending prefixes or cursors are non-empty. Pure read; never touches the network. Optional filters: `remote`, `protocol`, `direction`.
- `resume_pending({"tenant": "did:...", "deadlineMs": 25000, "connectivity": {...}})` — iterates those scopes and re-runs `sync_once` on each under the supplied deadline. The deadline budgets the entire batch, not each scope, so scopes that didn't get a turn stay pending in the ledger for the next call. Optional filters and budgets mirror `sync_once`.

The returned `FfiResumePendingResult` is `{attempted, results, deadlineExceeded}`:

- `attempted`: number of pending scopes that matched the filter.
- `results`: per-scope `SyncOnceResult` entries, in execution order. Empty when the deadline fired before any scope finished.
- `deadlineExceeded`: `true` when the batch timer fired mid-iteration.

## Binding generation

```bash
cd crates/enbox-ffi
./generate-bindings.sh
```

Swift and Kotlin stubs land under `generated/`.

## Tests

```bash
cargo test -p enbox-ffi
```
