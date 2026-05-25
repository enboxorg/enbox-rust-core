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

The active Rust workspace builds and tests natively with the pinned Rust toolchain. Handler logic, protocol authorization, conformance fixtures, and agent/sync modules are largely implemented.

A runnable local node is available via [`SqliteNativeDwn`](crates/dwn-rs-stores/src/native_node.rs) and the [`in_memory_dwn`](crates/dwn-rs-stores/examples/in_memory_dwn.rs) example. Call `build_native_dwn_with_resolver` or `SqliteNativeDwn::open_in_memory` to get a `Dwn` with all 11 real method handlers registered (including `MessagesRead`).

Remaining gaps for production mobile/desktop nodes:

- Durable SQLite `StateIndex`, `EventLog`, and `ResumableTaskStore` (#80)
- `StorageController` / `ResumableTaskManager` wiring (#81)
- JSON Schema validation at the `process_message` boundary (#82)
- Native bindings (`enbox-ffi`) and remote sync transport (#86–#88)

The inherited WASM bridge (`dwn-rs-wasm`) remains excluded from the active workspace.

## Roadmap

The migration plan is tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md) and mirrored into GitHub milestones/issues.
The active crate audit and target crate graph are tracked in [`docs/MIGRATION_PLAN.md`](docs/MIGRATION_PLAN.md).
The native mobile/desktop binding strategy is tracked in [`docs/BINDINGS.md`](docs/BINDINGS.md).
The mobile background sync entry points are tracked in [`docs/BACKGROUND_SYNC.md`](docs/BACKGROUND_SYNC.md).
The TypeScript local DWN migration guide is tracked in [`docs/MIGRATION_GUIDE.md`](docs/MIGRATION_GUIDE.md).

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
```

## License

This project remains Apache-2.0 licensed. See [`LICENSE`](LICENSE).
