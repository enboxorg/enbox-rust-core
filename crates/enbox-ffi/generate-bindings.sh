#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

cargo build -p enbox-ffi

# The cdylib extension is platform-dependent: .dylib on macOS, .so elsewhere.
case "$(uname -s)" in
  Darwin) LIB_EXT="dylib" ;;
  *) LIB_EXT="so" ;;
esac
LIB="$ROOT/target/debug/libenbox_ffi.${LIB_EXT}"
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
