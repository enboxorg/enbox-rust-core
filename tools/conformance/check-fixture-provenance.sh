#!/usr/bin/env bash
# Fail if any fixture source.commit differs from .enbox-version.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
pin_file="${repo_root}/.enbox-version"

pin="$(grep -v '^#' "${pin_file}" | grep -v '^[[:space:]]*$' | head -1 | tr -d '[:space:]')"
if [ "${#pin}" -ne 40 ]; then
  echo "Expected a 40-character commit SHA in .enbox-version, got: ${pin}" >&2
  exit 1
fi

status=0
while IFS= read -r -d '' file; do
  commit="$(grep -o '"commit"[[:space:]]*:[[:space:]]*"[^"]*"' "${file}" | head -1 | sed 's/.*"\([0-9a-f]\{40\}\)".*/\1/' || true)"
  if [ -z "${commit}" ]; then
    continue
  fi
  if [ "${commit}" != "${pin}" ]; then
    echo "${file#${repo_root}/}: source.commit=${commit} expected ${pin}" >&2
    status=1
  fi
done < <(find "${repo_root}/fixtures" -name '*.json' -print0)

exit "${status}"
