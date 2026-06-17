#!/usr/bin/env bash
# Fixture provenance gate.
#
# Two oracle tracks live under fixtures/:
#   - TS-parity fixtures: expected values mirror @enbox/dwn-sdk-js. Each such
#     fixture MUST pin source.commit == .enbox-version.
#   - Spec fixtures (fixtures/spec/**): expected values come from an external
#     specification or test vector. Each MUST declare oracle "spec" and a
#     source.spec block, and MUST NOT carry a source.commit (it is not anchored
#     to the TS impl).
#
# A fixture that fits neither track (no valid enbox commit, no spec source)
# FAILS — silently skipping such files previously let unprovenanced fixtures
# masquerade as conformance.
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
  rel="${file#${repo_root}/}"
  commit="$(grep -o '"commit"[[:space:]]*:[[:space:]]*"[^"]*"' "${file}" | head -1 | sed 's/.*"\([0-9a-f]\{40\}\)".*/\1/' || true)"

  case "${rel}" in
    */manifest.json)
      # Manifest index files list sets/suites; they carry no expected values
      # and therefore need no per-fixture provenance.
      ;;
    fixtures/spec/*)
      # Spec oracle: require oracle="spec" + a source.spec, forbid source.commit.
      if ! grep -Eq '"oracle"[[:space:]]*:[[:space:]]*"spec"' "${file}"; then
        echo "${rel}: spec fixture must declare \"oracle\": \"spec\"" >&2
        status=1
      fi
      if ! grep -Eq '"spec"[[:space:]]*:' "${file}"; then
        echo "${rel}: spec fixture must include a source.spec block" >&2
        status=1
      fi
      if [ -n "${commit}" ]; then
        echo "${rel}: spec fixture must NOT pin source.commit (it is not TS-anchored)" >&2
        status=1
      fi
      ;;
    *)
      # TS-parity oracle: require a source.commit pinned to .enbox-version.
      if [ -z "${commit}" ]; then
        echo "${rel}: no source.commit and not a fixtures/spec/* spec fixture — unprovenanced" >&2
        status=1
      elif [ "${commit}" != "${pin}" ]; then
        echo "${rel}: source.commit=${commit} expected ${pin}" >&2
        status=1
      fi
      ;;
  esac
done < <(find "${repo_root}/fixtures" -name '*.json' -print0)

exit "${status}"
