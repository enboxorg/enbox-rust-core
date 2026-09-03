#!/usr/bin/env bash
# Gate for the Layer 5 store-injection suite (issue #169, C9).
#
# Usage: check-injection-results.sh <junit-xml> <allowlist>
#
# Fails when a spec fails that is NOT on the allowlist, or when an allowlisted
# spec passes (stale entries must be removed so the list only ever shrinks).
set -euo pipefail

junit="$1"
allowlist="$2"

python3 - "$junit" "$allowlist" <<'EOF'
import sys
import xml.etree.ElementTree as ET

junit_path, allowlist_path = sys.argv[1], sys.argv[2]

allowed = set()
with open(allowlist_path) as handle:
    for line in handle:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        name, _, _issue = line.rpartition(' #')
        allowed.add(name.strip())

tree = ET.parse(junit_path)
failed = set()
total = 0
for case in tree.getroot().iter('testcase'):
    total += 1
    if case.find('failure') is not None or case.find('error') is not None:
        failed.add((case.get('name') or '').strip())

unexpected = sorted(failed - allowed)
stale = sorted(allowed - failed)

print(f'injection specs: {total} total, {len(failed)} failed, {len(allowed)} allowlisted')
if unexpected:
    print('UNEXPECTED FAILURES (not on the allowlist):')
    for name in unexpected:
        print(f'  - {name}')
if stale:
    print('STALE ALLOWLIST ENTRIES (now passing, remove them):')
    for name in stale:
        print(f'  - {name}')
if unexpected or stale:
    sys.exit(1)
print('injection gate clean')
EOF
