#!/usr/bin/env bash
# Fixture provenance gate.
#
# Three oracle tracks live under fixtures/:
#   - TS-parity fixtures: expected values mirror @enbox/dwn-sdk-js. Each such
#     fixture MUST pin source.commit == .enbox-version.
#   - Spec fixtures (fixtures/spec/**): expected values come from an external
#     specification or test vector. Each MUST declare oracle "spec" and a
#     source.spec block, and MUST NOT carry a source.commit (it is not anchored
#     to the TS impl).
#   - Rust-extension fixtures: expected values mirror a Rust-native surface that
#     upstream removed (e.g. MessagesSync/StateIndex). Each MUST declare oracle
#     "rust-extension", a source.issue link, and a source.commit pointing at the
#     last upstream commit that still contained the surface (removedUpstreamAt
#     records where it disappeared). These are exempt from the .enbox-version
#     equality rule because the surface no longer exists upstream.
#
# A fixture that fits none of these tracks FAILS — silently skipping such files
# previously let unprovenanced fixtures masquerade as conformance.
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
      if grep -Eq '"oracle"[[:space:]]*:[[:space:]]*"rust-extension"' "${file}"; then
        # Rust-extension oracle: upstream removed the surface. Require an issue
        # link and a 40-char source.commit (last upstream commit that had the
        # surface); do NOT require equality with the current .enbox-version pin.
        if [ -z "${commit}" ]; then
          echo "${rel}: rust-extension fixture must pin a 40-char source.commit" >&2
          status=1
        fi
        removed_at="$(grep -o '"removedUpstreamAt"[[:space:]]*:[[:space:]]*"[^"]*"' "${file}" | head -1 | sed 's/.*"\([0-9a-f]\{40\}\)".*/\1/' || true)"
        if [ "${#removed_at}" -ne 40 ]; then
          echo "${rel}: rust-extension fixture must record a 40-char removedUpstreamAt commit, got: ${removed_at}" >&2
          status=1
        fi
        if ! grep -Eq '"issue"[[:space:]]*:[[:space:]]*"https?://' "${file}"; then
          echo "${rel}: rust-extension fixture must include an absolute source.issue URL" >&2
          status=1
        fi
      else
        # TS-parity oracle: require a source.commit pinned to .enbox-version.
        if [ -z "${commit}" ]; then
          echo "${rel}: no source.commit and not a fixtures/spec/* or rust-extension fixture — unprovenanced" >&2
          status=1
        elif [ "${commit}" != "${pin}" ]; then
          echo "${rel}: source.commit=${commit} expected ${pin}" >&2
          status=1
        fi
      fi
      ;;
  esac
done < <(find "${repo_root}/fixtures" -name '*.json' -print0)

exit "${status}"
