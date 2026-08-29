# Agent Workflows

Three AI-agent engineering workflows govern non-trivial DWN behavioural changes
in this repository.

The workflows themselves are **not defined here**. They live in the
`enboxorg/knowledge` repository so Claude, Codex, and OpenCode all execute the
same playbook:

| Workflow | Canonical playbook |
| --- | --- |
| `dwn-contract-discovery` | [`../knowledge/agents/contract-discovery.md`](../../knowledge/agents/contract-discovery.md) |
| `dwn-implement-contract` | [`../knowledge/agents/implement-contract.md`](../../knowledge/agents/implement-contract.md) |
| `dwn-review-change` | [`../knowledge/agents/review-change.md`](../../knowledge/agents/review-change.md) |

Output templates: [`templates/contract-packet.md`](../../knowledge/agents/templates/contract-packet.md)
and [`templates/semantic-review.md`](../../knowledge/agents/templates/semantic-review.md).

## The three workflows

### 1. `dwn-contract-discovery` — investigation only

Takes an issue number, issue URL, bug description, feature request, or free-form
task. Reads `../knowledge`, the TypeScript Enbox implementation, the Rust
implementation, and linked issues, then produces a **Behavioural Contract
Packet**: classification, controlling invariant IDs, draft/TS/Rust behaviour
comparison, required behaviour, edge cases, and a test matrix.

It does not modify production code, and it stops for human resolution when the
intended semantics remain ambiguous.

### 2. `dwn-implement-contract` — implementation

Requires an **approved** Contract Packet. Implements only the approved
behaviour, adds the packet's full test matrix with invariant-linked semantic
tests, and performs no unrelated refactors.

If new evidence changes the intended behaviour, it stops and returns to contract
discovery rather than silently rewriting the packet.

### 3. `dwn-review-change` — independent review

Takes the working-tree diff (default), a branch, a commit range, or a PR, finds
the matching Contract Packet, and produces a **Semantic Review Report** with
findings classified `BLOCK` / `GAP` / `RISK` / `NOTE` and a verdict of `PASS`,
`PASS WITH FOLLOW-UP`, or `CHANGES REQUIRED`.

Review-only by default; it does not modify implementation code unless you
explicitly ask to move into remediation.

## Invocation

### Claude Code

```text
/dwn-contract-discovery 189
/dwn-implement-contract .agent/contracts/issue-189.md
/dwn-review-change
```

Project skills, discovered from `.claude/skills/`. Skills are Claude Code's
current project-scoped mechanism; the older `.claude/commands/*.md`
slash-command convention still works but is not used here, because skills carry
a `name`/`description` pair the model can also select implicitly.

### Codex

```text
$dwn-contract-discovery 189
$dwn-implement-contract .agent/contracts/issue-189.md
$dwn-review-change
```

Repo-level skills, discovered from `.agents/skills/`. `/skills` lists what Codex
found. Codex scans `.agents/skills` from the working directory up to the
repository root, so the checked-in directory ships with the repo.

Codex custom prompts (`~/.codex/prompts/*.md`) are deprecated **and** live in the
user's Codex home rather than the repository, so they cannot ship here. Skills
are the supported repository-local mechanism.

### OpenCode

```text
/dwn-contract-discovery 189
/dwn-implement-contract .agent/contracts/issue-189.md
/dwn-review-change
```

Project commands, discovered from `.opencode/commands/`. Headless equivalent:
`opencode run --command dwn-contract-discovery "189"`.

## How the wrappers avoid duplication

The wrappers are **thin adapters**, roughly 25 lines each. They resolve the
knowledge repository, name the playbook to execute, and add the handful of
bindings that are genuinely repository-local (where packets live, the approval
gate, the review target). Everything else — permitted actions, evidence order,
classification discipline, stop conditions, edge-case checklists, report shapes
— stays in the canonical playbook and is never restated locally.

Shared repository conventions live once in [`AGENTS.md`](../AGENTS.md): sibling
checkout resolution, source hierarchy, invariant contract classes, the
`// Covers: <ID>` test convention, and architecture constraints.

Content is stored once and shared by all three tools:

```text
.agents/skills/<workflow>/SKILL.md      the single canonical wrapper
.claude/skills/<workflow>       ->      symlink to that directory
.opencode/commands/<workflow>.md ->     symlink to that SKILL.md
```

Three files total, ~25 lines each. All three tools execute the exact same bytes,
so the wrappers cannot drift apart.

This works because of three verified properties of the current tool versions:

- Claude Code and OpenCode both follow symlinks when scanning their config
  directories, and Codex reads `.agents/skills` directly.
- `name` is part of OpenCode's own command schema, so the skill frontmatter
  (`name` + `description`) parses cleanly as an OpenCode command.
- OpenCode appends the caller's arguments to the prompt when a template contains
  no `$ARGUMENTS` and no `$1`/`$2` placeholders, so the shared file needs no
  OpenCode-specific placeholder. (Verified in the 1.18.18 template expander:
  `if (X.length === 0 && !Ge && t.arguments.trim()) ne = ne + "\n\n" + t.arguments`.)

One caveat to keep in mind when editing the shared file: OpenCode injects shell
output for the marker `` !`cmd` `` (a `!` immediately before a backtick). Plain
markdown code spans are inert, and these wrappers contain no such marker — but
do not introduce one, since Claude and Codex would treat it as literal text
while OpenCode would execute it.

> Symlinks require `git config core.symlinks true` on Windows checkouts. If that
> is a problem, replace the `.claude/skills/*` and `.opencode/commands/*`
> symlinks with copies of the canonical files — nothing else depends on them
> being links.

Each tool reads repository instructions from a different filename, so
`CLAUDE.md` is a one-line `@AGENTS.md` import rather than a second copy:

| Tool | Reads | Verified |
| --- | --- | --- |
| Codex | `AGENTS.md` | auto-loaded |
| OpenCode | `AGENTS.md` | auto-loaded |
| Claude Code | `CLAUDE.md` → `@AGENTS.md` | `AGENTS.md` alone is **not** picked up |

## Reading the sibling repositories

All three workflows read `../knowledge`, and `../enbox` / `../dwn-spec` when
present. Two of the three tools sandbox reads outside the project root, so the
repository ships the permission config:

- `.claude/settings.json` — `permissions.additionalDirectories`
- `opencode.json` — `permission.external_directory`

Codex needs no equivalent. Without these, Claude Code and OpenCode silently fail
to read the playbook (OpenCode auto-rejects; Claude Code asks, and in a
non-interactive run simply cannot proceed).

`ENBOX_KNOWLEDGE_ROOT`, `ENBOX_TS_ROOT`, and `DWN_SPEC_ROOT` override the default
sibling paths.

## Contract Packets

Contract Packets are **task artefacts, not knowledge**. They live in:

```text
.agent/contracts/issue-189.md
.agent/contracts/records-delete-convergence.md
```

`.agent/` is gitignored. Do not commit packets — summarize them in the PR
description instead:

- the behavioural contract;
- controlling invariant IDs;
- spec/parity classification;
- conformance cases added;
- knowledge impact.

> `.agent/` (task artefacts, ignored) and `.agents/` (Codex skills, committed)
> are different directories. The `.gitignore` rule is anchored as `/.agent/` so
> it cannot match `.agents/`.

## The human approval boundary

Contract discovery ends with the packet's `Human approval` status left as
`pending`. Implementation refuses to start unless a human has set it to
`approved` or `approved with changes`.

This boundary is deliberate. An agent may gather evidence and propose a
behavioural contract, but a non-trivial semantic change must not slide from
investigation into implementation while the intended behaviour is still
ambiguous. Approval is where a human decides *what must be true*; implementation
only decides *how to make it true*.

## Why implementation and review should use separate sessions

An implementing session has already committed to an interpretation of the
contract. Asked to review its own work, it tends to re-derive the same reading
of ambiguous requirements and to treat its own tests as sufficient evidence.

Run `dwn-review-change` in a different session — ideally a different agent and
model — so the review re-reads the contract and the invariants independently
rather than reconstructing the implementer's reasoning. This is exactly why the
three workflows are tool-neutral: discovery in Claude, implementation in Codex,
and review in OpenCode all execute the same playbook.

## Known limitation

No tool can hard-enforce "read-only" for these wrappers through configuration,
because contract discovery must still write its Contract Packet to
`.agent/contracts/`. The investigation-only and review-only constraints are
enforced by the playbook instructions, not by a tool-level permission.

For a hard guarantee on review, run it under OpenCode's read-only `plan` agent
(`opencode run --agent plan --command dwn-review-change`, or add `agent: plan`
to that command's frontmatter), accepting that remediation then requires
switching agents.

## Source of truth

The canonical workflow definitions live in
[`enboxorg/knowledge`](https://github.com/enboxorg/knowledge) under `agents/`.
Change them there, not here. See [`AGENTS.md`](../AGENTS.md) for the source
hierarchy and invariant discipline all three workflows preserve.
