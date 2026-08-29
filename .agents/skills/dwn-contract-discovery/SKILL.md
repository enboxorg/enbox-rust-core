---
name: dwn-contract-discovery
description: Investigation-only DWN contract discovery for enbox-rust-core. Loads and executes the canonical ../knowledge/agents/contract-discovery.md playbook and produces a Behavioural Contract Packet in .agent/contracts/. Use before any non-trivial DWN semantic, parity, authorization, replication, or protocol change. Does not modify production code.
---

# dwn-contract-discovery

Thin adapter. The workflow is defined canonically in `enboxorg/knowledge` and
must not be restated, summarized, or forked here.

1. Resolve the knowledge repository: `$ENBOX_KNOWLEDGE_ROOT`, else the
   `../knowledge` sibling checkout, else `https://github.com/enboxorg/knowledge`
   (read-only fallback).
2. Read `<knowledge>/agents/contract-discovery.md` and execute it in full, using
   `<knowledge>/agents/templates/contract-packet.md` as the output shape.
3. Apply this repository's `AGENTS.md` — source hierarchy, sibling checkouts,
   invariant contract classes, and architecture constraints. Where the playbook
   and this adapter disagree, the playbook wins.

## Repository bindings

- **Input:** the issue number, issue URL, bug report, feature request, failing
  test, or free-form task supplied by the caller. Ask if none was given.
- **Output path:** write the packet to `.agent/contracts/<slug>.md` — a
  meaningful slug such as `issue-189.md` or `records-delete-convergence.md`.
  `.agent/` is gitignored; packets are task artefacts, not knowledge.
- **Also print the completed packet in full** in your reply, not just the path.
- **The packet is the only file this workflow writes.** Production code is off
  limits here; the playbook's stop conditions govern when to hand back to a
  human instead of guessing.
- Leave `Human approval` as `pending`. Approval is a human action — never
  self-approve, and never continue into implementation from this workflow.
