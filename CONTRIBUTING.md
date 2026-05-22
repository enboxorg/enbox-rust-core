# Contributing

This repository is migrating the inherited `dwn-rs` codebase into the native Enbox Rust core. Keep changes incremental and provenance-preserving.

## Toolchain

The supported Rust toolchain is pinned in `rust-toolchain.toml`:

```bash
cargo +1.89.0 fmt --all -- --check
cargo +1.89.0 clippy --workspace --all-targets
cargo +1.89.0 test --workspace
```

CI runs the same format and lint checks, then builds all workspace test targets with `cargo test --workspace --no-run`. Run the full test command locally when changing Rust behavior.

## Repository Policy

- Preserve the original `enmand/dwn-rs` history and attribution.
- Keep mechanical moves, renames, and crate reshaping separate from semantic behavior changes.
- Use the current Enbox TypeScript implementation as the behavior source of truth.
- Add or update shared conformance fixtures before porting behavior when observable TypeScript output is involved.
- Keep Rust tests native-only; optional TypeScript fixture runners may depend on a sibling Enbox checkout.
- Do not add Bun, Node.js, or other JavaScript runtime requirements to the Rust core.

## Pull Request Checks

Before pushing a change, run the checks that match the CI workflow:

```bash
cargo +1.89.0 fmt --all -- --check
cargo +1.89.0 clippy --workspace --all-targets
cargo +1.89.0 test --workspace
```

For conformance fixture changes, also run the relevant optional TypeScript runner when `ENBOX_TS_ROOT` is available:

```bash
ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-cid.test.ts tools/conformance/typescript-jws.test.ts tools/conformance/typescript-jwe.test.ts
```

## Branch Policy

`main` should stay protected by GitHub branch rules. Required checks should include the native Rust workspace CI and security scanning workflows before merge.
