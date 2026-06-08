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
| `initialize_agent_identity(request_json)` | Create or recover an agent identity from a BIP-39 recovery phrase; persists `PortableDid` + vault keys |
| `current_agent_identity()` | Return the persisted `PortableDid` JSON, or `None` if none initialized |
| `derive_agent_keys_from_phrase(phrase)` | Derive the four-key set (vault/identity/signing/encryption) without persisting; for recovery-screen validation |
| `install_protocol(tenant_did_json, definition_json)` | Install a protocol on the local DWN (signs a `ProtocolsConfigure`, injects encryption when required); idempotent |
| `inject_protocol_encryption(tenant_did_json, definition_json)` | Augment a protocol `Definition` with per-path key-agreement encryption; pure (no I/O) |
| `lock()` / `unlock()` | Block message/sync processing while vault is locked |

Typed errors (`EnboxError`) cross the FFI boundary without panics.

## Agent identity workflow

1. Open a durable node: `EnboxCore.open("/path/to/enbox.sqlite")`
2. Initialize or recover an identity:
   ```json
   initialize_agent_identity({
     "recoveryPhrase": "<12-word BIP-39 phrase, optional>",
     "dwnEndpoints": ["https://dwn.example/"]
   })
   ```
   Returns JSON `AgentIdentityInitialization` (PortableDid + vault CEK + unlock salt + recovery phrase). The host displays the recovery phrase **once**; the Rust core persists the `PortableDid` to the SQLite-backed `agent_secrets` table.
3. On subsequent launches, `current_agent_identity()` returns the persisted `PortableDid` JSON (or `null` if missing).
4. For recovery-screen validation before committing, call `derive_agent_keys_from_phrase(phrase)` — this is pure and does not persist anything.

`PortableDid` and `AgentIdentityInitialization` shapes follow [`agent.rs`](../../crates/dwn-rs-core/src/agent.rs). The secret store layer is `SqliteSecretStore` ([`crates/dwn-rs-stores/src/sqlite_agent.rs`](../../crates/dwn-rs-stores/src/sqlite_agent.rs)), which shares the SQLite database used for DWN data.

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

Returns JSON `ProtocolInstallResult` (`{protocol, installed, encryptionActive}`). Subsequent calls for the same protocol return `installed: false` — the helper queries before configuring, matching [`install_protocol_if_needed`](../../crates/dwn-rs-core/src/setup.rs).

Encrypted protocols (those with `encryptionRequired: true`) have per-path key-agreement encryption injected automatically. For preview or sharing the augmented definition with another agent, call `inject_protocol_encryption` separately — it is pure and does not touch the DWN.

Pushing to remote DWN servers, tenant registration, and full restore-flow replay are not yet exposed; they are tracked in #145 (HTTP transport follow-up).

## Sync workflow

1. Open a durable node: `EnboxCore.open("/path/to/enbox.sqlite")`
2. Configure signing keys for sync: `configure_sync_signer(...)`
3. Register identities: `register_sync_identity({"did":"…","protocols":{"type":"all"}})`
4. Run sync: `sync_once({"tenant":"…","remote":"https://dwn.example/","direction":"pull"})`
5. After a live subscription drop, repair with `poll_reconcile` (same request shape as `sync_once`)
6. Poll UI state: `sync_status({"tenant":"…","remote":"https://dwn.example/"})`

`sync_once` and `poll_reconcile` return JSON [`SyncOnceResult`](../../crates/dwn-rs-core/src/sync.rs) mirroring the native engine. HTTP remotes use `@enbox/dwn-server` JSON-RPC via [`HttpSyncEndpoint`](../dwn-rs-core/src/sync_endpoint.rs).

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
