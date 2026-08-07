# DID Resolution

The authentication pipeline resolves complete SSI DID documents before selecting a JWS signing
key. `UniversalResolver` is registry-based and object-safe, so native and application-supplied
method resolvers use the same asynchronous `DidResolver` boundary.

## Default methods

`UniversalResolver::new()` registers:

| Method | Behavior |
| --- | --- |
| `did:jwk` | Decodes the method-specific identifier into an `ssi_jwk::JWK` and produces the Enbox document shape. |
| `did:key` | Resolves Ed25519 and secp256k1 multicodec keys into `ssi_dids_core::Document`. |
| `did:web` | Fetches and parses the complete remote document as `ssi_dids_core::Document`. |
| `did:dht` | Fetches a signed Pkarr relay value, verifies it against the DID identity key, and decodes its DNS packet into an `ssi_dids_core::Document`. |

Applications may add or replace methods with `with_method`, `register`, or `register_arc`.
Explicit registration replaces an existing method with the same name.

Static public keys are a compatibility fallback, not a method override. The fallback is consulted
only when the DID method is unregistered. A failure from a registered method never falls through to
a static key, so a malformed or unreachable native DID cannot be authenticated with unrelated
local material. Non-DID `kid` values retain exact static lookup behavior.

## `did:web` URL derivation

URL construction matches Enbox behavior:

| DID | Document URL |
| --- | --- |
| `did:web:example.com` | `https://example.com/.well-known/did.json` |
| `did:web:example.com:users:alice` | `https://example.com/users/alice/did.json` |
| `did:web:example.com%3A8443` | `https://example.com:8443/.well-known/did.json` |
| `did:web:example.com%3A8443:users:alice` | `https://example.com:8443/users/alice/did.json` |

Literal colons are changed to path separators before percent decoding. The presence of a literal
colon selects the path form; a percent-encoded port does not. Malformed percent encoding, invalid
UTF-8, and an invalid resulting URL produce `invalidDid`.

The default resolver shares one 30-second deadline across the initial request and all redirects,
and follows at most five redirects. Any 2xx response is accepted and parsed as a complete SSI DID
document. The universal resolver then requires the returned document `id` to equal the requested
DID.

## `did:dht` relay resolution

`did:dht` identifiers are z-base-32-encoded Ed25519 identity public keys. The resolver appends
the canonical identifier to its configured Pkarr-compatible gateway URL, fetches the relay value,
and verifies the BEP44 signature over its sequence number and DNS payload before decoding it.

The decoded DNS document preserves verification methods, relationship references, services,
controllers, aliases, and DID types. A successful DHT resolution sets document metadata
`published: true` and uses the BEP44 sequence number as `versionId`.

`DhtResolver::default()` uses `https://enbox-did-dht.fly.dev`, a 30-second shared deadline, and
at most five redirects. Supply `DhtResolver::new(DhtResolverConfig { .. })` through
`UniversalResolver::with_method` or `register` to select a different gateway. Private, loopback,
and link-local gateway targets remain rejected unless
`DhtResolverConfig::allow_private_gateway_uri` is explicitly enabled for development or CI.

## Network security boundary

The HTTP transport disables automatic redirects and validates the initial target and every redirect
before issuing the request. `did:web` starts on HTTPS; redirects may target HTTP or HTTPS to preserve
Enbox parity. `did:dht` applies the same checks to its configured gateway; development and CI can
explicitly allow private gateway targets without relaxing scheme, hostname, redirect, or deadline
validation.

Literal targets are rejected when they are:

- `localhost` or a subdomain of `.localhost`;
- private, loopback, link-local, unspecified, multicast, or reserved IPv4 addresses;
- loopback, link-local, unique-local, multicast, IPv4-mapped private, or NAT64-embedded private
  IPv6 addresses.

This is intentionally the same literal-host policy as Enbox `fetchPublicUrl`. It does not resolve a
hostname before connecting, pin the connected address, or prevent DNS rebinding. A public hostname
that resolves to an internal address is therefore outside the protection provided here. Consumers
with a stronger SSRF boundary should supply network-level egress controls or replace the `web`
method with a stricter resolver.

The resolver currently has no explicit response-body size limit and no document cache. Those limits
should be supplied by the surrounding network/runtime policy until they are added here.

## Errors

| Condition | Resolver error |
| --- | --- |
| Invalid DID, percent encoding, or derived URL | `InvalidDid` (`invalidDid`) |
| Resolver called for a different method | `MethodNotSupported` (`methodNotSupported`) |
| `did:web` network, timeout, redirect, literal-host policy, non-2xx status, or JSON/document parsing failure | `NotFound` (`notFound`) |
| Returned document ID differs from the requested DID | `InvalidDocument` (`invalidData`) |
| `did:dht` invalid gateway target | `InvalidGatewayUri` (`invalidGatewayUri`) |
| `did:dht` relay transport failure | `Internal` (`internalError`) |
| `did:dht` invalid identity key, relay payload, DNS document, or verification method | typed `invalid*` resolver error |
| `did:dht` invalid BEP44 signature | `InvalidSignature` (`invalidSignature`) |

Transport details are written only to debug tracing; callers receive the stable Enbox error bucket.

## JWS key selection

For a DID URL `kid`, JWS verification:

1. resolves the full DID document asynchronously;
2. requires the document ID to match the requested DID;
3. selects the first `verificationMethod` whose absolute ID is a suffix of the `kid` string;
4. reads `publicKeyJwk` and verifies with its public key material.

Relationship arrays such as `authentication` and `assertionMethod` do not gate selection. This
matches the Enbox verifier. Verification methods without `publicKeyJwk` are not usable for JWS
verification.

## Parity provenance and remaining work

The `did:web` URL, redirect, status, and error vectors were reconciled against
`enboxorg/enbox` commit `c63bf424ac0997583db825e8a5fddf1507d30c40`. They remain Rust unit vectors
rather than shared TypeScript fixtures because `.enbox-version` independently pins the existing
cross-runtime fixture corpus.

Remaining work:

- Resolution and document metadata are still empty for `did:web`.
- Encryption recipient selection does not yet consume resolved `keyAgreement` methods or perform
  the upstream Ed25519-to-X25519 public-key conversion.
- Resolver caching and concurrent-resolution coalescing are not implemented.
- DNS resolution enforcement and a transport-level response-size limit are not implemented.
- Verification method object IDs must remain absolute because SSI represents them as `DIDURLBuf`.
