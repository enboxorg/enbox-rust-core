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

## Seeded entries (RecordsWrite ID surfaces)

| ID | Surface | Class | Impl behavior | Spec says | Disposition |
| --- | --- | --- | --- | --- | --- |
| `records-write-recordid-author` | `RecordsWrite.recordId` | `spec-wrong` | `recordId = CID({ ...descriptor, author })` — author DID folded into the CID input (`handlers/records/common.rs` `entry_id()`). | Record ID Generation computes `recordId = CID({ descriptorCid })`, **omitting the author DID**. | contribute-upstream |
| `records-write-entryid-undefined` | `RecordsWrite.entryId` | `spec-silent` | `entryId` is defined as the `recordId` derivation; initial-write detection is `entryId == recordId`. | The prose **never defines** `entryId` as an algorithm. | contribute-upstream |
| `records-write-contextid-todo` | `RecordsWrite.contextId` | `spec-todo` | `contextId = parentContextId + "/" + entryId`; root `contextId == recordId`. | Context ID Generation section is an empty **TODO**. | contribute-upstream |

### Executable proof: `records-write-recordid-author`

For the reused `records-write-basic` descriptor with author `did:example:alice`:

- `descriptorCid` = `bafyreidgpqe6zujtci3k7gze4dh7e7prapj3tqer6cvpzhuyzil7ju6wo4`
- **impl** `recordId` = `CID({ ...descriptor, author })` = `bafyreig7m4ezumnhkzmnn6gvlxm63lqm63rppi5pt67shyyke7jaasabxa`
- **spec-prose** `recordId` = `CID({ descriptorCid })` = `bafyreicroejdjo7rmrvzohxukhwzefknntzgdhxqxkorbsutqlidm5p7di`

The two differ precisely because the prose omits the author. The regression
marker pins both literals and asserts they remain distinct.

The `entryId` and `contextId` entries have no executable proof: there is no
spec-prose algorithm to contrast against (the spec is silent / TODO), so those
entries are documentation-only until upstream defines them.
