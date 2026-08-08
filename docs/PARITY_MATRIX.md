# Parity Matrix — Enbox upstream `c63bf424ac0997583db825e8a5fddf1507d30c40`

Versioned parity inventory for `enbox-rust-core` against the current upstream baseline.

- **Audited upstream:** `enboxorg/enbox@c63bf424ac0997583db825e8a5fddf1507d30c40` (`@enbox/dwn-sdk-js` 0.4.20, `@enbox/agent` 0.8.36, `@enbox/auth` 0.6.82, `@enbox/connect` 0.1.16, `@enbox/dids` 0.1.8, `@enbox/protocols` 0.2.102, `@enbox/local-node` 0.0.22, `@enbox/dwn-server` 0.1.35, `@enbox/dwn-clients` 0.4.27).
- **Pin file:** [`.enbox-version`](../.enbox-version) (enforced by `fixture-provenance` and `schema-drift` CI jobs).
- **Status values:** `parity` (evidenced against the pinned baseline), `intentional Rust extension` (surface removed upstream; retained with a documented boundary), `partial` (subset implemented; gap issue linked), `missing` (not implemented; gap issue linked).
- **Fixture notes:** fixtures tagged `oracle: "rust-extension"` record Rust-native surfaces that upstream removed; they pin `source.commit` to the last upstream commit that contained the surface and are exempt from the `.enbox-version` equality rule.

Rows marked `missing`/`partial` are tracked by the linked issue; closing that issue updates this matrix.

## DWN interface / method surface

Upstream method set at the pinned baseline (dwn-sdk-js 0.4.20) and Rust status.

| Surface | Rust status | Notes / remaining owner |
| --- | --- | --- |
| Records Read | parity | Typed `RecordsReadDescriptor` + handler; covered by conformance `descriptor.roundtrip` and loopback interop. |
| Records Write | parity | Typed `RecordsWriteDescriptor` + handler; convergent latest-state admission, data CID/size integrity, encryption envelope admission (`Encryption::validate`). |
| Records Query | partial — #190 | Handler-backed; current conformance covers tag filters and permissions-grant queries. Read-time `$recordLimit` visibility, boundary-aware `contextId` subtree, and `validationStateReader`-driven population still align to #190. |
| Records Count | missing — #190 | Descriptor deserializable; no handler yet. |
| Records Delete | parity | Typed `DeleteDescriptor` + handler; tombstone/prune semantics. |
| Records Subscribe | partial — #190 | WebSocket subscribe covered in loopback interop; initial-snapshot population parity with Query tracked in #190. |
| Protocols Configure | parity | Typed `ConfigureDescriptor` + handler; Enbox directives (`$role`, `$size`, `$tags`, `$recordLimit`, `$immutable`, `$delivery`, `$squash`, `uses`, `$ref`, `crossProtocolRole`) including role-issuance validation (`ProtocolsConfigureInvalidRoleIssuance`). |
| Protocols Query | parity | Typed `ProtocolQueryDescriptor` + handler. |
| Messages Read | parity | Typed `MessagesReadDescriptor` + handler. |
| Messages Query | missing — #187 | `no_handler` (deserializable for spec parity); durable feed + `MessagesQuery` handler tracked in #187. |
| Messages Subscribe | partial — #187 / #192 | Typed descriptor + handler; live subscription lifecycle on the durable feed tracked in #187/#192. |
| Messages Sync (legacy) | intentional Rust extension — #188 | Upstream removed `MessagesSync`/`StateIndex`/SMT (`25821eda`); Rust retains a native implementation validated by rust-extension fixtures. Migrating to durable feeds is #188. |
| JSON-RPC/HTTP/WS transport | partial — #195 | Rust implements `dwn.processMessage`; `applyReplicatedMessage`, `inboundMessage`, subscription `ack`/`close`, `ping`, framing/payload-size, RPC auth, and rate-limit mapping are #195. |

## Encryption (JWE) model

Current upstream contract: A256CTR content encryption + X25519-HKDF-SHA256+A256KW key agreement, `DwnEncryption` `{algorithm, initializationVector, keyEncryption[]}` envelope.

| Surface | Rust status | Notes / remaining owner |
| --- | --- | --- |
| A256CTR content encryption | parity | AES-256-CTR, 16-byte counter, no AEAD tag; conformance `jwe.aead`. |
| X25519-HKDF-SHA256+A256KW key agreement | parity | Shared secret → HKDF-SHA256 (JSON `info` tuple) → AES-KW; conformance `jwe.keywrap`. |
| `DwnEncryption` envelope + `keyEncryption` entries | parity | Tagged `protocolPath`/`roleAudience` discriminated types; `jwe.envelope`. |
| Inbound IV/entry admission | parity | `Encryption::validate` (16-byte IV, entry algorithm + OKP/X25519 ephemeral key) runs in RecordsWrite integrity validation with upstream wire codes. |
| `roleAudience` derivation scheme | parity | Tagged variant with mandatory `protocol`/`rolePath`; conformance `jwe-a256ctr-role-audience`. |
| Seal key wrapping | parity | Separate `SealKeyWrap` type + `seal_wrap`/`seal_unwrap`; KEK binds `protocol`/`rolePath`/`contextId`/`audienceKeyId`; conformance `jwe-a256ctr-seal`. |
| Encryption control / grant-key delivery protocol | missing — #191 | Encrypted `grantKey` vs `wrappedGrantKey` envelopes, sealed audience controls, role-audience epochs, and control-record delivery are #191. |
| Recipient selection from resolved DID key-agreement | missing — #207 | First `keyAgreement` entry from a resolved document, reference/inline VM support; Ed25519→X25519 conversion and X25519-only upstream parity are #207. |
| Legacy JWE General serialization (`protected/iv/tag/recipients`) | intentional Rust extension | Removed upstream; not presented as current parity. |

## Schema, reply, and authorization shape

| Surface | Rust status | Notes / remaining owner |
| --- | --- | --- |
| RecordsWrite signature payload (`recordId`, `descriptorCid`, `contextId`, `attestationCid`, `encryptionCid`, grant/role fields) | partial — #186 | Core fields validated; canonicalized `permissionGrantIds`, payload-form selection, and full wire parity are #186. |
| Permission scopes (discriminated `Messages.Read`, `Protocols.Configure`/`Query`, `Records.Read`/`Write`/`Delete`) | partial — #186 | Legal scope shapes and selector rules (protocol/protocolPath/contextId) aligned to #186. |
| Grant authorization evaluation | parity | Conformance `protocol.authorization-corpus` covers scope, publication condition, expiry, revocation, and delegation. |
| Protocol definition directives | parity | `protocol.authorization-corpus` covers `uses`, `$ref`, `crossProtocolRole`, `$role`, `$size`, `$tags`, `$recordLimit`, `$immutable`, `$delivery`, `$squash`. |
| Embedded JSON schemas | parity | Refreshable via `tools/conformance/refresh-upstream-schemas.sh`; drift-gated by the `schema-drift` CI job. |

## Store contracts and replication

| Surface | Rust status | Notes / remaining owner |
| --- | --- | --- |
| MessageStore / DataStore / StateIndex / EventLog / ResumableTaskStore contracts | parity | Rust store traits; SQLite + in-memory backends; conformance `message.process`, `state-index.operations`. |
| Durable message feed + progress positions | missing — #187 | Feed substrate, `MessagesQuery`, and durable progress are #187. |
| Reconciliation / replication | intentional Rust extension — #188 | Rust-native `MessagesSync`/SMT reconciliation is retained as an extension; durable-feed reconciliation is #188. |
| Live agent sync + subscriptions | partial — #192 | Poll/live reconciliation implemented; durable-feed live lifecycle is #192. |

## DID resolution

See [`DID_RESOLUTION.md`](./DID_RESOLUTION.md) and the #185 DID parity-matrix comment.

| Surface | Rust status | Notes / remaining owner |
| --- | --- | --- |
| `did:jwk`, `did:key` (signature), `did:web`, `did:dht` resolution | parity | Complete SSI document resolution, typed failures, SSRF/redirect policy, BEP44 verification. |
| Resolver cache + single-flight | missing — #197 | Success-only TTL cache, no negative caching, stale-while-revalidate tracked in #197. |
| Encryption recipient selection from resolved documents | missing — #207 | First key-agreement method selection; Ed25519→X25519 conversion; #207. |
| Static public-key fallback | intentional Rust extension | Compatibility for non-DID kids only after unregistered-method dispatch; cannot shadow native methods. |

## Agent / auth / connect / protocols / local-node surfaces

| Surface | Rust status | Notes / remaining owner |
| --- | --- | --- |
| Agent identity, HD vault, secret store, keys | partial — #199 | `AgentIdentityService`, `SqliteSecretStore`, `derive_agent_keys_from_phrase` implemented; DWN-backed stores, read-through/protocol caches, session lifecycle are #199. |
| Connect kernel (request/response envelope, session grants) | partial — #193 | Legacy grant/key-delivery model retained; current Connect envelope, approval ceremony, and session lifecycle are #193. |
| Tenant registration / provider auth / proof-of-work | partial — #196 | `register_tenant` client path implemented; proof-of-work solve, provider-auth plugin model, and serving-side tenant gate are #196. |
| Local-node discovery / pairing / profile | missing — #198 | Rust serves JSON-RPC + WebSocket; discovery payload, pairing broker/session store, and node profile are #198. |
| Standard protocol definitions (`@enbox/protocols`) | missing — #200 | No pinned Rust artifacts for `connect`/`profile`/`preferences`/permissions/encryption-control protocols; #200. |
| JSON-RPC client surface (`dwn-rs-remote`) | partial — #195 | `dwn.processMessage` only; consolidation with the supported transport and the full method set are #195. |

## Cross-cutting evidence

- Rust native: `cargo test --workspace` (handlers, stores, sync, conformance fixtures).
- Shared fixtures: `tools/conformance/typescript-*.test.ts` at the pinned Enbox commit (CI: `typescript-conformance`).
- dwn-sdk-js native: `bun run --filter @enbox/dwn-sdk-js test:node` (CI: `dwn-sdk-js-reference`).
- Loopback interop: `tools/interop/loopback-interop.test.ts` (CI: `loopback-interop`).
- Provenance/drift gates: `fixture-provenance` (fixture `source.commit` vs `.enbox-version`; rust-extension fixtures exempt) and `schema-drift` (embedded schemas match the pinned commit).
