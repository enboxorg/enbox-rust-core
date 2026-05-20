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

This repository is at the start of the Enbox migration. The inherited `dwn-rs` code is useful reference material, but it is not yet a complete Enbox DWN engine.

Known inherited gaps:

- DWN message processing is not implemented end-to-end.
- Current Enbox handlers are missing, including Enbox `MessagesSync`.
- Enbox `StateIndex` / Sparse Merkle Tree sync state is missing.
- Current Enbox protocol directives and permission behavior need to be ported.
- The WASM bridge still references the old `@tbd54566975/dwn-sdk-js` package.
- The current build is blocked by an unavailable `multicodec` git revision.

## Roadmap

The migration plan is tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md) and mirrored into GitHub milestones/issues.

## Repository Policy

- Preserve original `dwn-rs` history.
- Prefer mechanical moves/renames in separate commits from semantic code changes.
- Use the current Enbox TypeScript implementation as the behavioral source of truth.
- Add conformance fixtures before porting behavior so Rust and TypeScript outputs can be compared.

## License

This project remains Apache-2.0 licensed. See [`LICENSE`](LICENSE).
