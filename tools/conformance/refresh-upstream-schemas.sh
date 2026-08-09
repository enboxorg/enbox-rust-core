#!/usr/bin/env bash
# Refresh the explicitly allowlisted Rust schema copies from the Enbox checkout
# pinned by .enbox-version. Rust-extension schemas are intentionally excluded.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
enbox_root="${ENBOX_TS_ROOT:-${repo_root}/../enbox}"
upstream_schemas="${enbox_root}/packages/dwn-sdk-js/json-schemas"
local_schemas="${repo_root}/crates/dwn-rs-core/schemas"

pin="$(grep -v '^#' "${repo_root}/.enbox-version" | grep -v '^[[:space:]]*$' | head -1 | tr -d '[:space:]')"
if [[ ! "${pin}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Expected a 40-character commit SHA in .enbox-version, got: ${pin}" >&2
  exit 1
fi

if [ ! -d "${upstream_schemas}" ]; then
  echo "Unable to find dwn-sdk-js schemas at ${upstream_schemas}" >&2
  echo "Set ENBOX_TS_ROOT to the pinned Enbox checkout." >&2
  exit 1
fi

upstream_head="$(git -C "${enbox_root}" rev-parse HEAD)"
if [ "${upstream_head}" != "${pin}" ]; then
  echo "Enbox checkout is at ${upstream_head}; .enbox-version pins ${pin}." >&2
  exit 1
fi

# Keep this list narrow and reviewed. Adding a schema here asserts that Rust
# tracks that upstream surface directly; do not add Rust-extension schemas such
# as interface-methods/messages-sync.json.
schema_paths=(
  "definitions.json"
  "interface-methods/records-write-unidentified.json"
)

for relative_path in "${schema_paths[@]}"; do
  source_path="${upstream_schemas}/${relative_path}"
  destination_path="${local_schemas}/${relative_path}"
  if [ ! -f "${source_path}" ]; then
    echo "Missing upstream schema: ${source_path}" >&2
    exit 1
  fi
  cp "${source_path}" "${destination_path}"
  echo "Refreshed crates/dwn-rs-core/schemas/${relative_path}"
done
