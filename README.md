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

### Runnable local DWN (M7)

A production-shaped local node is available today:

- [`SqliteNativeDwn`](crates/dwn-rs-stores/src/native_node.rs) — SQLite-backed node with durable `StateIndex`, `EventLog`, and `ResumableTaskStore`
- [`build_native_dwn_with_resolver`](crates/dwn-rs-core/src/native_dwn.rs) — registers all 11 real Enbox method handlers
- [`in_memory_dwn`](crates/dwn-rs-stores/examples/in_memory_dwn.rs) — end-to-end example (ProtocolsConfigure + MessagesRead)

Core protocol wiring matches TypeScript `Dwn.create()`:

- JSON Schema validation at the `process_message` boundary
- `CoreProtocolRegistry` with permissions lifecycle hooks
- `UniversalResolver` (`did:jwk:` + static fallback) for JWS verification
- `StorageController` + `ResumableTaskManager` resume pending delete/squash tasks on open

### Mobile bindings

[`enbox-ffi`](crates/enbox-ffi/) exposes a UniFFI facade (`EnboxCore`) with in-memory open, lock/unlock boundary, typed errors, and JSON `process_message`. Run `./crates/enbox-ffi/generate-bindings.sh` to emit Swift/Kotlin scaffolding.

### Remaining gaps

- Desktop loopback HTTP/WebSocket server (#89) — trait scaffolding exists in `desktop.rs`; no real socket yet
- Remote sync HTTP/WebSocket transport (#86) and durable sync ledger (#87)
- CI TypeScript conformance runner against a pinned Enbox checkout (#76)
- Handler module splits (#68, #93)

The inherited WASM bridge (`dwn-rs-wasm`) remains excluded from the active workspace.

## Roadmap

The migration plan is tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md) and mirrored into GitHub milestones/issues.
The active crate audit and target crate graph are tracked in [`docs/MIGRATION_PLAN.md`](docs/MIGRATION_PLAN.md).
The native mobile/desktop binding strategy is tracked in [`docs/BINDINGS.md`](docs/BINDINGS.md).
The mobile background sync entry points are tracked in [`docs/BACKGROUND_SYNC.md`](docs/BACKGROUND_SYNC.md).
The TypeScript local DWN migration guide is tracked in [`docs/MIGRATION_GUIDE.md`](docs/MIGRATION_GUIDE.md).
Conformance fixture contract is in [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md).

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

## License

This project remains Apache-2.0 licensed. See [`LICENSE`](LICENSE).
