# Crate Migration Plan

This note records the inherited `dwn-rs` workspace audit and the target Enbox Rust crate layout. The goal is to make mechanical moves planable without mixing them with DWN behavior changes.

## Active Workspace

The active workspace is the root `Cargo.toml` member list:

- `crates/dwn-rs-core`
- `crates/dwn-rs-message-derive`
- `crates/dwn-rs-remote`
- `crates/dwn-rs-stores`

## Inherited Crate Decisions

| Crate | Current Contents | Decision | Migration Destination |
| --- | --- | --- | --- |
| `dwn-rs-core` | DWN message descriptors/fields, filters, events, store traits, CID helpers, auth/JWS, inherited encryption helpers, value types. | Keep and adapt as the active behavior porting crate until the first mechanical rename. | `enbox-dwn-core`, with crypto/DID/state-index pieces split only when they become independently reusable. |
| `dwn-rs-message-derive` | Proc macro for descriptor serialization/deserialization boilerplate. | Keep while descriptors are still macro-based; rename mechanically with the core crate if retained. | `enbox-dwn-message-derive` or inline modules in `enbox-dwn-core` if the macro stops paying for itself. |
| `dwn-rs-stores` | SurrealDB-backed `MessageStore`, `DataStore`, `EventLog`, and `ResumableTaskStore` implementations plus query glue. | Adapt as reference only. Enbox native storage should target SQLite first, not SurrealDB. Keep active while tests still cover inherited traits. | Traits move to `enbox-dwn-store`; SQLite implementation goes to `enbox-dwn-sqlite`; SurrealDB either becomes legacy/optional or is removed from the active workspace. |
| `dwn-rs-remote` | JSON-RPC request/response types and an HTTP remote DWN client. | Defer. It may inform a local HTTP/WebSocket server mode, but it is not the native core boundary. | Revisit during desktop/local node integration; likely `enbox-dwn-sync` or a future client/transport crate if needed. |

## Target Crate Graph

The target crate graph should keep low-level primitives reusable while avoiding premature splitting during the behavior port.

```text
enbox-crypto
  enbox-dids
    enbox-dwn-core
      enbox-dwn-store
        enbox-dwn-sqlite
      enbox-dwn-state-index
      enbox-dwn-sync
    enbox-agent-core
      enbox-ffi
```

Planned crate responsibilities:

| Target Crate | Responsibility |
| --- | --- |
| `enbox-crypto` | JWS/JWE, key agreement, content encryption, key wrapping, and deterministic crypto vectors shared by DWN and agent code. |
| `enbox-dids` | DID parsing, resolution interfaces, portable DID/key-manager boundaries, and Enbox DID method support. |
| `enbox-dwn-core` | DWN message models, CID/integrity validation, auth payloads, protocol definitions, handler dispatch, and the native `Dwn.processMessage()` equivalent. |
| `enbox-dwn-store` | Store traits for `MessageStore`, `DataStore`, `StateIndex`, `EventLog`, and `ResumableTaskStore`. |
| `enbox-dwn-sqlite` | SQLite-backed stores for mobile and desktop local nodes. |
| `enbox-dwn-state-index` | Sparse Merkle Tree and `StateIndex` roots/subtrees/leaves used by sync. |
| `enbox-dwn-sync` | `MessagesSync`, sync diff helpers, live/poll reconciliation, replay bounds, and progress tokens. |
| `enbox-agent-core` | Identity lifecycle, tenant registration, protocol installation, delegated grants, key delivery, and wallet recovery semantics. |
| `enbox-ffi` | Mobile/desktop native bindings and optional local server entry points. The binding strategy is documented in [`BINDINGS.md`](BINDINGS.md). |

## Migration Sequence

1. Preserve provenance and keep inherited history intact.
2. Keep the current active workspace buildable while conformance fixtures are added.
3. Finish fixture coverage for current TypeScript behavior before porting handlers.
4. Define Enbox-native store traits, then add SQLite stores and StateIndex implementation.
5. Port `Dwn.processMessage()` and handlers behind fixture-driven tests.
6. Port sync, subscriptions, progress tokens, and repair flows.
7. Port agent/wallet flows that require native DWN behavior.
8. Add mobile/desktop bindings after the native core API stabilizes.
9. Perform mechanical crate renames only when the target boundary is clear; keep those commits free of semantic behavior changes.

## First Mechanical Rename Plan

The first rename/move change should be limited to crate identity and import paths:

- Rename `dwn-rs-core` to `enbox-dwn-core`.
- Rename `dwn-rs-message-derive` only if the macro remains in use.
- Update workspace members, path dependencies, package names, and imports.
- Do not move behavior between modules in the same commit.
- Run `cargo +1.89.0 fmt --all -- --check`, `cargo +1.89.0 clippy --workspace --all-targets`, and `cargo +1.89.0 test --workspace` before follow-up semantic changes.

## Follow-Up Issue Map

| Area | Tracking Issues |
| --- | --- |
| Store traits and SQLite stores | `#10`, `#11`, `#13` |
| StateIndex and sync fixtures/implementation | `#9`, `#12`, `#18`, `#48`, `#49` |
| DWN engine and handlers | `#14`, `#15`, `#16`, `#17` |
| Sync/subscriptions/background entry points | `#19`, `#20`, `#21` |
| Agent, wallet, grants, and recovery | `#22`, `#23`, `#24`, `#25`, `#55` |
| Native bindings and integration | `#26`, `#27`, `#28`, `#29` |

New migration work should either close one of these issues or create a focused follow-up before changing crate boundaries.
