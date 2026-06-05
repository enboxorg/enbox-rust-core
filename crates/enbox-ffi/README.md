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
| `lock()` / `unlock()` | Block message/sync processing while vault is locked |

Typed errors (`EnboxError`) cross the FFI boundary without panics.

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
