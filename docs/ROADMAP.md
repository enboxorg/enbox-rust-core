# Enbox Rust Core Roadmap

This roadmap tracks the migration from the inherited `dwn-rs` codebase to a native Enbox Rust core.

## Milestone 0: Provenance And Build Baseline

Goal: preserve history, document origin, and make the inherited workspace buildable enough to support incremental work.

- Preserve `enmand/dwn-rs` commit history and upstream remote.
- Add README/NOTICE attribution.
- Decide which inherited crates remain active, move legacy-only pieces behind features or out of the active workspace, and fix the broken `multicodec` dependency.
- Establish CI for format, lint, build, and tests.

The active workspace and target crate migration plan are documented in [`docs/MIGRATION_PLAN.md`](MIGRATION_PLAN.md).

## Milestone 1: Enbox Conformance Fixtures

Goal: capture the current TypeScript behavior before porting.

- Export JSON fixtures for current DWN messages and replies.
- Capture CID/JWS/JWE parity vectors.
- Capture protocol configuration fixtures, including Enbox directives such as `uses`, `$ref`, `$recordLimit`, `$immutable`, `$delivery`, `$squash`, and `encryptionRequired`.
- Capture sync fixtures for `StateIndex` roots, subtree hashes, leaves, and `MessagesSync diff` responses.

## Milestone 2: Native Storage And State Index

Goal: implement the local persistence substrate needed by mobile and desktop.

- Define Rust store traits matching current Enbox contracts: `MessageStore`, `DataStore`, `StateIndex`, `EventLog`, and `ResumableTaskStore`.
- Implement SQLite stores for mobile and desktop.
- Port the Sparse Merkle Tree backed `StateIndex`, including global and protocol-scoped trees.
- Implement content-addressed data storage and inline-data behavior compatible with Enbox.

## Milestone 3: DWN Engine Parity

Goal: port `Dwn.processMessage()` and current Enbox handlers.

- Implement tenant gate, message schema/integrity validation, DID resolution, authentication, and handler dispatch.
- Port `ProtocolsConfigure`, `ProtocolsQuery`, `RecordsWrite`, `RecordsRead`, `RecordsQuery`, `RecordsCount`, `RecordsDelete`, `RecordsSubscribe`, `MessagesRead`, `MessagesSubscribe`, and `MessagesSync`.
- Port permission grants, protocol authorization, core `PermissionsProtocol`, and storage-controller semantics.

## Milestone 4: Sync And Subscriptions

Goal: port Enbox sync behavior for local native nodes.

- Implement `MessagesSync` root/subtree/leaves/diff actions.
- Implement `ProgressToken`, EOSE, gap detection, and replay bounds.
- Port poll/live sync behavior, WebSocket subscription client support, push/pull reconciliation, dead-letter handling, repair, and scoped protocol sync.
- Add mobile-friendly background sync entry points, documented in [`BACKGROUND_SYNC.md`](BACKGROUND_SYNC.md).

## Milestone 5: Agent, Auth, And Wallet Core

Goal: preserve wallet and agent semantics without requiring a JS runtime.

- Port identity lifecycle and vault integration boundaries.
- Port tenant registration and protocol installation flows.
- Port delegated grants, DWeb/App Connect authorization, key delivery, and delegate decryption key handling.
- Preserve encrypted protocol behavior and recovery semantics.

## Milestone 6: Native Bindings And Integration

Goal: expose the Rust core to product surfaces.

- Add mobile bindings for iOS/Android, likely through UniFFI or a C ABI depending on consumer needs.
- Add desktop bindings and optional local HTTP/WebSocket server mode.
- Integrate with mobile notification wake/background sync.
- Produce migration guides from the TypeScript local DWN path to the native core, starting with [`MIGRATION_GUIDE.md`](MIGRATION_GUIDE.md).
