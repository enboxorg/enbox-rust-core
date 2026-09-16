// Generates the did:dht publish interop fixture from the TypeScript.
//
// Builds the agent DID shape (identity/signing/encryption keys plus a DWN
// service) with fixed seeds, encodes it to a DNS packet, and signs a BEP44
// put message with a fixed sequence so Ed25519 output is fully deterministic.
// Rust reads the document and payload back in `did-dht` fixture tests; a
// separate Bun test feeds Rust-encoded bytes to the pinned TS decoder.
//
// Every verification-method key carries an explicit `alg` so the emitted
// packet is identical across the pinned revisions: freshly generated X25519
// keys omit it, which older revisions serialized as `a=undefined`.
//
// Run with:
//   ENBOX_TS_ROOT=/tmp/enbox-c63bf42 bun tools/interop/generate-did-dht-publish-fixture.ts
//
// The commit recorded in source.commit must match .enbox-version, which the
// provenance gate enforces; this script fails otherwise instead of writing
// a fixture CI would reject.

import { execFileSync } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? resolve(repoRoot, '../enbox');

const pin = readFileSync(resolve(repoRoot, '.enbox-version'), 'utf8')
  .split('\n')
  .map((line) => line.trim())
  .find((line) => line !== '' && !line.startsWith('#'));
const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: enboxTsRoot,
  encoding: 'utf8',
}).trim();
if (commit !== pin) {
  throw new Error(
    `enbox checkout is at ${commit} but .enbox-version pins ${pin}. ` +
    'Point ENBOX_TS_ROOT at the pinned checkout before regenerating.'
  );
}

const Ed25519Primitive = (await import(
  resolve(enboxTsRoot, 'packages/crypto/src/primitives/ed25519.ts')
)).Ed25519;
const X25519Primitive = (await import(
  resolve(enboxTsRoot, 'packages/crypto/src/primitives/x25519.ts')
)).X25519;

const { DeterministicKeyGenerator } = await import(
  resolve(enboxTsRoot, 'packages/agent/src/utils-internal.ts')
);
const { DidDht, DidDhtDocument } = await import(
  resolve(enboxTsRoot, 'packages/dids/src/methods/did-dht.ts')
);
const { encodeBep44SigningPayload } = await import(
  resolve(enboxTsRoot, 'packages/dids/src/methods/did-dht-pkarr.ts')
);
const dnsPacket = await import(
  resolve(enboxTsRoot, 'packages/dids/node_modules/@dnsquery/dns-packet/index.mjs')
);

// Fixed inputs: document these alongside any consumer so both sides agree.
const IDENTITY_SEED = new Uint8Array(32).fill(0x11);
const SIGNING_SEED = new Uint8Array(32).fill(0x22);
const ENCRYPTION_SEED = new Uint8Array(32).fill(0x33);
const SEQUENCE = 1_700_000_000;
const GATEWAY_URI = 'https://gateway.example';
const DWN_ENDPOINT = 'https://dwn.example';
const DID_TYPES = [1, 2, 3];

const identityPrivateKey = await Ed25519Primitive.bytesToPrivateKey({
  privateKeyBytes: IDENTITY_SEED,
});
identityPrivateKey.alg = 'EdDSA';
const signingPrivateKey = await Ed25519Primitive.bytesToPrivateKey({
  privateKeyBytes: SIGNING_SEED,
});
signingPrivateKey.alg = 'EdDSA';
const encryptionPrivateKey = await X25519Primitive.bytesToPrivateKey({
  privateKeyBytes: ENCRYPTION_SEED,
});
encryptionPrivateKey.alg = 'ECDH-ES+A256KW';

const keyManager = new DeterministicKeyGenerator();
await keyManager.addPredefinedKeys({
  privateKeys: [identityPrivateKey, signingPrivateKey, encryptionPrivateKey],
});

const did = await DidDht.create({
  keyManager,
  options: {
    publish             : false,
    verificationMethods : [
      {
        algorithm : 'Ed25519',
        id        : 'sig',
        purposes  : ['authentication', 'assertionMethod'],
      },
      {
        algorithm : 'X25519',
        id        : 'enc',
        purposes  : ['keyAgreement'],
      },
    ],
    services : [
      {
        id              : 'dwn',
        type            : 'DecentralizedWebNode',
        serviceEndpoint : [DWN_ENDPOINT],
      },
    ],
    types : DID_TYPES,
  },
});
const portableDid = await did.export();

const dnsPacketObject = await DidDhtDocument.toDnsPacket({
  didDocument              : portableDid.document,
  didMetadata              : { ...portableDid.metadata, published: true },
  authoritativeGatewayUris : [GATEWAY_URI],
});
const dnsBytes = dnsPacket.encode(dnsPacketObject);
const signingPayload = encodeBep44SigningPayload({
  sequenceNumber : SEQUENCE,
  value          : dnsBytes,
});
const signer = await did.getSigner({ methodId: '0' });
const signature = await signer.sign({ data: signingPayload });

const toBase64Url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64url');
const fromBase64Url = (value: string): Uint8Array =>
  new Uint8Array(Buffer.from(value, 'base64url'));

if (toBase64Url(fromBase64Url(toBase64Url(dnsBytes))) !== toBase64Url(dnsBytes)) {
  throw new Error('base64url round trip failed');
}

const fixture = {
  schemaVersion : 1,
  oracle        : 'enbox',
  source        : {
    repository : 'enboxorg/enbox',
    commit,
    path : 'packages/dids/src/methods/did-dht.ts',
    tool : 'tools/interop/generate-did-dht-publish-fixture.ts',
  },
  inputs: {
    identitySeed   : toBase64Url(IDENTITY_SEED),
    signingSeed    : toBase64Url(SIGNING_SEED),
    encryptionSeed : toBase64Url(ENCRYPTION_SEED),
    sequence       : SEQUENCE,
    gatewayUri     : GATEWAY_URI,
    dwnEndpoints   : [DWN_ENDPOINT],
    types          : DID_TYPES,
  },
  vector: {
    didDocument : portableDid.document,
    didMetadata : { types: DID_TYPES },
    dnsRecords  : dnsPacketObject.answers.map((answer: any) => ({
      name  : answer.name,
      type  : answer.type,
      ttl   : answer.ttl,
      rdata : answer.data,
    })),
    dnsBytes : toBase64Url(dnsBytes),
    bep44    : {
      seq : SEQUENCE,
      sig : toBase64Url(signature),
      v   : toBase64Url(dnsBytes),
    },
  },
};

const outDir = resolve(repoRoot, 'fixtures/interop');
mkdirSync(outDir, { recursive: true });
const outPath = resolve(outDir, 'did-dht-publish.json');
writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n');
console.log(`wrote ${outPath} for ${portableDid.uri}`);
