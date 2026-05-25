#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

cargo build -p enbox-ffi
LIB="$ROOT/target/debug/libenbox_ffi.so"
OUT="$ROOT/crates/enbox-ffi/generated"

mkdir -p "$OUT/swift" "$OUT/kotlin"

cargo run -p enbox-ffi --bin uniffi-bindgen -- generate \
  --library "$LIB" \
  --language swift \
  --out-dir "$OUT/swift"

cargo run -p enbox-ffi --bin uniffi-bindgen -- generate \
  --library "$LIB" \
  --language kotlin \
  --out-dir "$OUT/kotlin"

echo "Generated bindings under $OUT"
