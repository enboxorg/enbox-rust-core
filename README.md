# enbox-rust-core

Native Rust core for Enbox DWN, agent, sync, wallet, mobile, and desktop infrastructure.

This repository was cloned from [`enmand/dwn-rs`](https://github.com/enmand/dwn-rs) so the original commit history remains intact. The early Rust DWN types, store traits, SurrealDB store work, WASM bindings, and remote-client experiments in this repository come from that project. Enbox is continuing from that foundation while changing the shape of the project toward a native Enbox runtime.

## Goals

- Provide a DWN engine that runs without Bun, Node.js, or JavaScript.
- Preserve Enbox DWN behavior from `@enbox/dwn-sdk-js`, including handlers, authorization, protocol rules, storage semantics, and sync.
- Support mobile and desktop local DWN nodes through native storage and native bindings.
- Support wallet and agent flows: identity lifecycle, tenant registration, protocol installation, delegated grants, encrypted protocol data, key delivery, and sync.
- Keep provenance and attribution for the original `dwn-rs` work while evolving the repository structure as needed.

## Current State

The active Rust workspace builds and tests natively with the pinned Rust toolchain (`rust-toolchain.toml`).

### Runnable local DWN (M7 — complete)

A production-shaped local node is available today:

- [`SqliteNativeDwn`](crates/dwn-rs-stores/src/native_node.rs) — SQLite-backed node with durable `StateIndex`, `EventLog`, and `ResumableTaskStore`
- [`build_native_dwn_with_resolver`](crates/dwn-rs-core/src/native_dwn.rs) — registers all 11 real Enbox method handlers
- [`in_memory_dwn`](crates/dwn-rs-stores/examples/in_memory_dwn.rs) — end-to-end example (ProtocolsConfigure + MessagesRead)
- [`loopback_interop_server`](crates/dwn-rs-stores/examples/loopback_interop_server.rs) — HTTP JSON-RPC server for TypeScript client interop

Core protocol wiring matches TypeScript `Dwn.create()`:

- JSON Schema validation at the `process_message` boundary
- `CoreProtocolRegistry` with permissions lifecycle hooks
- `UniversalResolver` (`did:jwk:` + static fallback) for JWS verification
- `StorageController` + `ResumableTaskManager` resume pending delete/squash tasks on open

### Test coverage (three layers + interop)

See [`docs/TEST_COVERAGE.md`](docs/TEST_COVERAGE.md) for the full matrix. CI runs:

| Job | What it validates |
|-----|-------------------|
| `rust-tests` | `cargo test --workspace` including shared JSON fixtures |
| `typescript-conformance` | Shared fixtures via TS adapters at pinned Enbox |
| `dwn-sdk-js-reference` | Full `@enbox/dwn-sdk-js test:node` at pinned Enbox |
| `loopback-interop` | TS HTTP client against Rust loopback server |
| `fixture-provenance` | Fixture `source.commit` matches `.enbox-version` |

### Sync and transport (M4 — complete)

- `NativeSyncEngine` with `DirectSyncEndpoint` and `HttpSyncEndpoint` in `dwn-rs-core`
- Durable `SqliteSyncLedger` and `SqliteNativeDwn::sync_once_with_http` / `poll_reconcile_with_http` in `dwn-rs-stores`
- Multi-node sync integration tests (direct peer + HTTP loopback); live/poll handoff documented in [`docs/SYNC_LIVE_POLL.md`](docs/SYNC_LIVE_POLL.md)
- WebSocket `RecordsSubscribe` on the loopback server (see `loopback-interop` CI job)

### Mobile bindings (M5 / M6 in progress)

[`enbox-ffi`](crates/enbox-ffi/) exposes a UniFFI facade (`EnboxCore`) covering the full mobile/desktop surface:

- DWN message dispatch and HTTP sync (M4): `process_message`, `sync_once`, `poll_reconcile`, `sync_status`, `lock`/`unlock`.
- Agent identity and vault (M5, [#148](https://github.com/enboxorg/enbox-rust-core/pull/148)): `initialize_agent_identity`, `current_agent_identity`, `derive_agent_keys_from_phrase`; durable `SqliteSecretStore`.
- Protocol install and encryption (M5, [#149](https://github.com/enboxorg/enbox-rust-core/pull/149)): `install_protocol`, `inject_protocol_encryption` against the local `SqliteNativeDwn`.
- DWeb Connect (M5, [#150](https://github.com/enboxorg/enbox-rust-core/pull/150)): `create_permission_request`, `create_delegate_grant`, `create_grant_revocation`, `derive_delegate_keys`, `derive_context_key`, persisted decryption/context keys.
- HTTP register / push / restore (M5, [#151](https://github.com/enboxorg/enbox-rust-core/pull/151)): `register_tenant`, `push_protocol`, `run_restore_flow` against `@enbox/dwn-server`-style endpoints.

See the [FFI README](crates/enbox-ffi/README.md). Android/iOS Nix flake builds were wired in [#142](https://github.com/enboxorg/enbox-rust-core/pull/142).

### Completed milestones (M4, M5, M7, M8)

| Milestone | Epic | Outcome |
|-----------|------|---------|
| **M8** | [#102](https://github.com/enboxorg/enbox-rust-core/issues/102) | Loopback interop, real `message.process` replies, shared fixtures, TestSuite injection scaffold |
| **M4** | [#103](https://github.com/enboxorg/enbox-rust-core/issues/103) | End-to-end sync, WebSocket loopback, FFI sync, HTTP live/poll reconciliation |
| **M5** | #143–#146 | Agent identity, protocol install/push/restore, DWeb Connect, HTTP registration — all exposed via `enbox-ffi` |

Handler modules are split per method under `handlers/{records,messages,protocols}/` ([#68](https://github.com/enboxorg/enbox-rust-core/issues/68), [#93](https://github.com/enboxorg/enbox-rust-core/issues/93)).

## Roadmap

The migration plan is tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md) and mirrored into GitHub milestones/issues.

- **M7** — Runnable local node (complete)
- **M8** — Behavioral parity and cross-runtime validation (complete)
- **M4** — Sync and subscriptions (complete)
- **M5** — Agent, auth, and wallet core (complete)
- **M6** — Native bindings and integration (in progress; FFI surface complete, background sync + mobile shell integration remaining)

See also [`docs/MIGRATION_PLAN.md`](docs/MIGRATION_PLAN.md), [`docs/BINDINGS.md`](docs/BINDINGS.md), [`docs/BACKGROUND_SYNC.md`](docs/BACKGROUND_SYNC.md), [`docs/MIGRATION_GUIDE.md`](docs/MIGRATION_GUIDE.md), and [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md).

## Repository Policy

- Preserve original `dwn-rs` history.
- Prefer mechanical moves/renames in separate commits from semantic code changes.
- Use the current Enbox TypeScript implementation as the behavioral source of truth.
- Add conformance fixtures before porting behavior so Rust and TypeScript outputs can be compared.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the supported Rust toolchain, local checks, and branch policy.

## Development

The supported Rust toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml). Run these checks before pushing changes:

```bash
cargo +1.89.0 fmt --all -- --check
cargo +1.89.0 clippy --workspace --all-targets
cargo +1.89.0 test --workspace
cargo +1.89.0 run -p dwn-rs-stores --example in_memory_dwn
```

Optional interop (requires sibling Enbox checkout):

```bash
ENBOX_TS_ROOT=/path/to/enbox bun test tools/interop/loopback-interop.test.ts
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-*.test.ts
```

## License

This project remains Apache-2.0 licensed. See [`LICENSE`](LICENSE).
