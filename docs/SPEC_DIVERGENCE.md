# Spec Divergence Ledger

This document catalogs every place where this implementation knowingly diverges
from the [DIF Decentralized Web Node (DWN) prose specification](https://identity.foundation/decentralized-web-node/spec/).
It is an **upstream-contribution backlog**, not a conformance suite.

The machine-readable source of truth is
[`fixtures/spec/divergence/ledger.json`](../fixtures/spec/divergence/ledger.json).
This page renders it for humans; when the two disagree, the JSON wins.

## Tiered correctness model

Correctness in this crate is anchored in tiers, from strongest to weakest:

1. **External spec floor.** Where a published specification or test vector
   defines an exact value (e.g. the CIDv1/DAG-CBOR `descriptorCid` algorithm),
   that value is the source of truth. These checks live under
   [`fixtures/spec/`](../fixtures/spec/) with `oracle: "spec"` and are genuine
   PASS/FAIL conformance assertions — independent of any TypeScript output.

2. **DIF reference implementation.** Where the DWN prose spec is silent,
   incomplete, or wrong, behavior matches the DIF reference implementation
   ([`@enbox/dwn-sdk-js`](https://github.com/enboxorg/enbox)) so that this crate
   interoperates with the existing ecosystem. The TS-parity fixtures
   ([`fixtures/manifest.json`](../fixtures/manifest.json)) pin that behavior.

3. **Divergence ledger (this document).** Every gap between tiers 1 and 2 — i.e.
   every place where we follow the reference impl *because* the spec cannot be
   followed — is recorded here as upstream work. A regression-marker test
   (`ledger_divergences_still_hold` in
   `crates/dwn-rs-core/tests/conformance_fixtures.rs`) recomputes the
   contrasting values for entries that have an executable proof and fails loud
   if a divergence is ever silently resolved (by upstream fixing the spec, or by
   someone "fixing" the impl to the broken prose). Either way, the ledger must
   then be updated.

## Divergence classes

| Class | Meaning |
| --- | --- |
| `spec-wrong` | The prose defines an algorithm, but it is incorrect / non-interoperable. |
| `spec-silent` | The behavior is required in practice but the prose never defines it. |
| `spec-todo` | The relevant spec section exists but is an empty `::: todo :::`. |
| `impl-extension` | The spec is correct; **our** impl (often inherited from the enbox fork) is the side that diverges. An our-side matter, not an upstream filing. |

## Seeded entries (RecordsWrite ID surfaces)

| ID | Surface | Class | Impl behavior | Spec says | Disposition |
| --- | --- | --- | --- | --- | --- |
| `records-write-recordid-author` | `RecordsWrite.recordId` | `spec-wrong` | `recordId = CID({ ...descriptor, author })` — all descriptor fields inlined, author DID folded in (`handlers/records/common.rs` `entry_id()`). `entryId` uses the **same** process. | Record ID Generation computes `recordId = CID({ descriptorCid })`: a single-field `{ descriptorCid }` envelope that **omits the author** and **does not inline descriptor fields**. | contribute-upstream |
| `records-write-contextid-todo` | `RecordsWrite.contextId` | `spec-todo` | When `protocol` is set: root `contextId = recordId`; non-root `contextId = parentContextId + "/" + recordId` (concatenates **recordId**, not entryId). | `Computed Context IDs` section is an empty **TODO**; `spec.md:1028` requires the *presence* rule but no algorithm. | contribute-upstream |
| `records-write-contextid-protocol-guard` | `RecordsWrite.contextId` (protocol guard) | `impl-extension` | `validate_records_write_integrity` requires a `contextId` on **every** write and enforces `contextId == recordId` for any parent-less root — with **no `descriptor.protocol` gate** (mirrors the enbox fork). | `spec.md:1028`: a record **not** attached to a Protocol **MUST NOT** have a `contextId`. Upstream `dwn-sdk-js` gates both on `protocol !== undefined`. | needs-owner-decision |

**entryId.** The spec *does* define `entryId` — `spec.md:1186-1187` derives it via the
Record ID Generation Process and uses `entryId == recordId` as the initial-write
check. It is therefore **not** an independent divergence: it inherits the
recordId defect and is folded into that entry. The only residual `entryId`
issue is editorial — there is no standalone "Entry ID Generation" heading — and
that is wording, not a divergence.

### Executable proof: `records-write-recordid-author`

For the reused `records-write-basic` descriptor with author `did:example:alice`:

- `descriptorCid` = `bafyreidgpqe6zujtci3k7gze4dh7e7prapj3tqer6cvpzhuyzil7ju6wo4`
- **impl** `recordId` = `CID({ ...descriptor, author })` = `bafyreig7m4ezumnhkzmnn6gvlxm63lqm63rppi5pt67shyyke7jaasabxa`
- **spec-prose** `recordId` = `CID({ descriptorCid })` = `bafyreicroejdjo7rmrvzohxukhwzefknntzgdhxqxkorbsutqlidm5p7di`

The two differ in both axes captured above (author present vs absent; descriptor
fields inlined vs a single-field envelope). The regression marker pins both
literals and asserts they remain distinct.

The `contextId` entries have no executable proof: the generation algorithm is a
TODO (nothing to recompute), and the protocol-guard divergence is a behavioral
contrast against upstream source rather than a recomputable CID.

## Upstream filing plan (not yet filed)

Nothing here has been filed upstream. When we do file, the plan is:

- **One combined issue, not three.** `recordId` and `contextId` are the same
  family of defect (the RecordsWrite ID surfaces) and `entryId` folds into
  `recordId`. A single issue is clearer than three fragmented ones.
- **Issue-first, not a cold PR.** The DIF spec repo
  (`decentralized-identity/decentralized-web-node`) is ~21 months dormant; open
  an issue to re-establish contact before sending prose.
- **Coordinate with stale draft PR #257.** It touches the same prose but does
  **not** fix these defects; our wording should be reconciled with it rather
  than collide.
- **No `dwn-sdk-js` artifact needed.** The reference impl is already correct
  (it is the de-facto standard); only the spec must catch up.
- **Venue undecided — hold.** Confirm the right venue/maintainer before posting.
- The `contextId` protocol-guard entry is an **our-side** matter
  (`needs-owner-decision`), *not* part of any upstream filing.

## Verification basis

Reconciled against current DIF sources on **2026-06-11**:

- DIF DWN prose spec (`spec.md`) @ commit `fbde42a6` (2024): Record ID
  Generation `spec.md:375` (`#recordid-generation`); entryId `spec.md:1186-1187`
  (`#record-entry-id`); Computed Context IDs `spec.md:1174-1178` — empty
  `::: todo :::` (`#computed-context-ids`); contextId presence rule `spec.md:1028`.
- `@tbd54566975/dwn-sdk-js` @ main (2024): `getEntryId()` = `CID({ ...descriptor, author })`;
  contextId computation and the root integrity check are both gated on
  `descriptor.protocol !== undefined`.
- enbox fork `packages/dwn-sdk-js/src/interfaces/records-write.ts`: protocol gate
  removed ("all records belong to a protocol").
- Rust impl `crates/dwn-rs-core/src/handlers/records/common.rs`: `entry_id()`
  matches upstream `getEntryId()`; `validate_records_write_integrity()` mirrors
  the enbox fork.
