# Enbox Conformance Fixtures

Fixtures under this directory capture observable behavior from the current TypeScript `@enbox/dwn-sdk-js` implementation.

Rust tests must load these files directly and must not require Bun, Node, or the TypeScript workspace at test runtime.

## Status Values

- `supported`: the active Rust model is expected to parse and re-serialize the fixture descriptor byte-for-byte at the JSON level.
- `known_gap`: the fixture is valid current Enbox behavior, but the inherited Rust model does not represent it yet. Raw CID parity is still checked.
