---
name: dwn-implement-contract
description: Implement an approved DWN Behavioural Contract Packet in enbox-rust-core. Loads and executes the canonical ../knowledge/agents/implement-contract.md playbook, requires an approved packet in .agent/contracts/, and adds invariant-linked semantic tests.
---

# dwn-implement-contract

Thin adapter. The workflow is defined canonically in `enboxorg/knowledge` and
must not be restated, summarized, or forked here.

1. Resolve the knowledge repository: `$ENBOX_KNOWLEDGE_ROOT`, else the
   `../knowledge` sibling checkout, else `https://github.com/enboxorg/knowledge`
   (read-only fallback).
2. Read `<knowledge>/agents/implement-contract.md` and execute it in full,
   including its completion-report shape.
3. Apply this repository's `AGENTS.md` — source hierarchy, sibling checkouts,
   invariant contract classes, the `// Covers: <ID>` test convention, and
   architecture constraints. Where the playbook and this adapter disagree, the
   playbook wins.

## Repository bindings

- **Approval gate — check before editing any code.** Locate the packet in
  `.agent/contracts/`; if the caller named one, use it, otherwise list the
  directory and ask which applies rather than guessing. Read its
  `## Human approval` section:
  - `approved` or `approved with changes` → proceed.
  - anything else, or no packet at all → **stop, edit nothing**, and tell the
    user to run `dwn-contract-discovery` and approve the contract first.
- **New evidence:** if implementation reveals that the intended behaviour is not
  what the packet says, stop and return to `dwn-contract-discovery`. Never
  silently rewrite the packet.
- **Checks:** run the format, lint, and test commands in `CONTRIBUTING.md`
  before reporting completion.
