# Agent guidance

This repository implements DWN semantics and targets current Enbox
TypeScript behaviour where documented parity decisions exist.

## Semantic and process source of truth

The `enboxorg/knowledge` repository is the curated semantic **and process**
source for this work. It is normally checked out as a sibling at
`../knowledge`; prefer the local checkout so you can search it directly.

Agent engineering workflows are defined there, tool-neutrally, and must not be
forked into this repository:

- [`../knowledge/agents/contract-discovery.md`](../knowledge/agents/contract-discovery.md)
- [`../knowledge/agents/implement-contract.md`](../knowledge/agents/implement-contract.md)
- [`../knowledge/agents/review-change.md`](../knowledge/agents/review-change.md)
- [`../knowledge/agents/templates/contract-packet.md`](../knowledge/agents/templates/contract-packet.md)
- [`../knowledge/agents/templates/semantic-review.md`](../knowledge/agents/templates/semantic-review.md)

The tool wrappers in `.claude/skills/`, `.agents/skills/`, and
`.opencode/commands/` are thin adapters that load and execute those playbooks.
See [`docs/AGENT_WORKFLOWS.md`](docs/AGENT_WORKFLOWS.md) for invocation.

## Local source resolution

Prefer these local sibling repositories when present, and fall back to the
GitHub remotes only when a checkout is missing or freshness must be verified:

| Path | Role |
| --- | --- |
| `../knowledge` | curated semantics, invariants, decisions, agent workflows |
| `../enbox` | current Enbox TypeScript implementation |
| `../dwn-spec` | DWN draft specification |

`ENBOX_KNOWLEDGE_ROOT`, `ENBOX_TS_ROOT`, and `DWN_SPEC_ROOT` override the
default sibling paths when set.

## Skills

Three skills are available to help in development:

- `dwn-contract-discovery`: Used for semantic investigation, using the knowledgebase, TypeScript
  and Rust
- `dwn-implement-contract`: Used to implement an approved contract packet
- `dwn-review-change`: A semantic review of a code change against the knowledge base, TypeScript
  and Rust.

## Source hierarchy

Keep these distinct and never collapse them:

1. DWN draft specification (`../dwn-spec`, `../knowledge/dwn/`) — normative.
2. Current Enbox TypeScript behaviour (`../enbox`, `../knowledge/enbox/`) — the
   parity target where a documented draft divergence exists.
3. Current Rust behaviour (this repository) — implementation, not authority.

Supporting knowledge layers: `../knowledge/implementation/` (engine contracts),
`../knowledge/conformance/` (observable behaviour), `../knowledge/invariants/`
(stable IDs), `../knowledge/decisions/` (accepted ADRs and divergences).

Before changing DWN behaviour, state explicitly whether the intended behaviour
is normative DWN draft, current Enbox parity, a Rust-specific implementation
detail, or an unresolved divergence, and cite the controlling invariant IDs.

**Never infer protocol semantics solely from existing Rust code or tests.**
Rust code and its tests are evidence of current behaviour, not authority over
intended behaviour. **Never treat current TypeScript behaviour as normative**
unless the knowledge base classifies it that way.

## Invariant contract classes

Invariant IDs come from `../knowledge/invariants/`. Preserve each ID's class:

- `normative` — derived from the DWN draft/spec layer.
- `enbox-parity` — current TypeScript Enbox behaviour used as the Rust parity
  target where documented.
- `implementation-contract` — architecture-neutral property required of any
  correct engine.

An `enbox-parity` invariant must never be silently promoted to normative DWN
behaviour. An invariant ID is a traceability anchor, not proof of normativity.

## Semantic change workflow

Non-trivial DWN behavioural changes follow:

```text
contract discovery → human approval → implementation → independent review
```

Human approval of the Behavioural Contract Packet is a hard boundary.
Contract discovery does not modify production code, and implementation does not
silently redefine an approved contract — new evidence returns to discovery.

Prefer a different agent/session/model for review than for implementation.

Contract Packets are task artefacts, not knowledge. They live in the gitignored
`.agent/contracts/` and are summarized in the PR description rather than
committed.

## Tests

Semantic, conformance, and parity tests should reference the invariant IDs they
prove, using a searchable annotation:

```rust
// Covers: DWN-REC-004
```

Do not annotate every unit test mechanically. Use invariant IDs where a test
exists to prove a stable behavioural contract. Prefer table-driven, permutation,
or property-style tests for replay, arrival-order, and convergence invariants.

The invariant-linked test direction is tracked by `enbox-rust-core#249`.

## Architecture constraints

- A DWN message is a signed operation; a Record is logical state derived from
  retained messages.
- Signer and semantic Author are distinct when delegation is involved.
- Replication does not bypass normal DWN admission.
- Arrival order must not determine final Record state.
- Authorization and decryption capability are separate concerns.
- Durable replication uses `MessagesQuery`; `MessagesSubscribe` is a wake layer.
- **Do not reintroduce `MessagesSync`, `StateIndex`, or SMT reconciliation as
  current architecture.** They are legacy and were deliberately removed.

## Repository checks

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the pinned toolchain and the
format, lint, and test commands CI runs.
