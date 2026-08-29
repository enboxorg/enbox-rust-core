---
name: dwn-review-change
description: Independent semantic review of a DWN change in enbox-rust-core. Loads and executes the canonical ../knowledge/agents/review-change.md playbook against a diff, branch, commit range, or PR and emits a Semantic Review Report with a PASS / PASS WITH FOLLOW-UP / CHANGES REQUIRED verdict. Review-only.
---

# dwn-review-change

Thin adapter. The workflow is defined canonically in `enboxorg/knowledge` and
must not be restated, summarized, or forked here.

1. Resolve the knowledge repository: `$ENBOX_KNOWLEDGE_ROOT`, else the
   `../knowledge` sibling checkout, else `https://github.com/enboxorg/knowledge`
   (read-only fallback).
2. Read `<knowledge>/agents/review-change.md` and execute every review dimension
   it defines, using `<knowledge>/agents/templates/semantic-review.md` as the
   report shape — including its findings severities (`BLOCK`, `GAP`, `RISK`,
   `NOTE`), its edge-case checklist, and its single closing verdict (`PASS`,
   `PASS WITH FOLLOW-UP`, or `CHANGES REQUIRED`).
3. Apply this repository's `AGENTS.md` — source hierarchy, invariant contract
   classes, and architecture constraints, including the prohibition on
   reintroducing `MessagesSync`, `StateIndex`, or SMT reconciliation. Where the
   playbook and this adapter disagree, the playbook wins.

## Repository bindings

- **Target:** the current working-tree diff when nothing is given, otherwise the
  branch, commit range, or PR number/URL supplied. Use `git` locally and `gh`
  for GitHub PRs.
- **Contract Packet:** find the matching packet in `.agent/contracts/`. If none
  exists, continue the review and record a `GAP` — the change was not
  contract-governed.
- **Independence:** prefer a different agent, session, and model from the one
  that implemented the change. If you implemented it in this session, say so in
  the report so the reduced independence is visible.
- **Review-only.** Do not modify implementation code unless the user explicitly
  asks to move from review into remediation.
