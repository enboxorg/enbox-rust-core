// Generates the vault at-rest JWE interop fixture from the pinned implementation.
//
// Uses the real HdIdentityVault over a MemoryStore with a fixed phrase and
// password, then re-opens the three stored values in a second vault instance
// to prove they suffice for unlock/getDid/decryptData. Rust loads the stored
// values directly (Unit 3); no TypeScript tooling runs at Rust test time.
//
// DID publication hits the network, so fetch is stubbed to succeed. That only
// skips the DHT put; the three stored values come from the real
// derive/encrypt paths unchanged.
//
// Run with:
//   ENBOX_TS_ROOT=/tmp/enbox-c63bf42 bun tools/interop/generate-vault-jwe-fixture.ts
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

// Stub the DHT gateway: publish (PUT) succeeds; resolve (GET) reports NotFound
// so recovery reconciles and publishes rather than decoding an empty packet.
globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) =>
  new Response(null, { status: init?.method === 'GET' ? 404 : 200 })) as typeof fetch;

const { HdIdentityVault } = await import(
  resolve(enboxTsRoot, 'packages/agent/src/hd-identity-vault.ts')
);
const { MemoryStore } = await import(
  resolve(enboxTsRoot, 'packages/common/src/stores.ts')
);

// Fixed inputs: documented alongside consumers so both sides agree.
const RECOVERY_PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORD = 'vault-interop-password';
const DWN_ENDPOINTS = ['https://dwn.example'];
const DATA_PLAINTEXT = new TextEncoder().encode('hello vault interop');
const BINARY_PLAINTEXT = new Uint8Array([0, 1, 2, 250, 255, 16, 32]);

const toBase64Url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64url');

async function buildProfile(derivationVersion?: 1 | 2) {
  const profileStore = new MemoryStore<string, string>();
  const profileVault = new HdIdentityVault({ keyDerivationWorkFactor: 1, store: profileStore });
  await profileVault.initialize({
    password: PASSWORD,
    recoveryPhrase: RECOVERY_PHRASE,
    dwnEndpoints: DWN_ENDPOINTS,
    derivationVersion,
  });

  const profileContentEncryptionKey = await profileStore.get('contentEncryptionKey');
  const profileDid = await profileStore.get('did');
  const profileVaultStatus = await profileStore.get('vaultStatus');
  if (!profileContentEncryptionKey || !profileDid || !profileVaultStatus) {
    throw new Error('vault did not write all three stored values');
  }

  const profilePortableDid = await profileVault.getDid();
  const profileDataJwe = await profileVault.encryptData({ plaintext: DATA_PLAINTEXT });
  const profileBinaryJwe = await profileVault.encryptData({ plaintext: BINARY_PLAINTEXT });

  // Re-open from the stored values alone, as the Rust tests do.
  const reopenStore = new MemoryStore<string, string>();
  await reopenStore.set('contentEncryptionKey', profileContentEncryptionKey);
  await reopenStore.set('did', profileDid);
  await reopenStore.set('vaultStatus', profileVaultStatus);
  const reopened = new HdIdentityVault({ keyDerivationWorkFactor: 1, store: reopenStore });
  await reopened.unlock({ password: PASSWORD });
  const reopenedDid = await reopened.getDid();
  if (reopenedDid.uri !== profilePortableDid.uri) {
    throw new Error('re-opened vault resolved a different DID');
  }
  const roundTrip = await reopened.decryptData({ jwe: profileDataJwe });
  if (Buffer.from(roundTrip).toString('base64url') !== toBase64Url(DATA_PLAINTEXT)) {
    throw new Error('re-opened vault decrypted different data');
  }

  return {
    contentEncryptionKey: profileContentEncryptionKey,
    did: profileDid,
    vaultStatus: profileVaultStatus,
    portableDidUri: profilePortableDid.uri,
    dataJwe: profileDataJwe,
    binaryJwe: profileBinaryJwe,
  };
}

const v2Profile = await buildProfile(2);
const v1Profile = await buildProfile(1);

const fixture = {
  schemaVersion: 1,
  oracle: 'enbox',
  source: {
    repository: 'enboxorg/enbox',
    commit,
    path: 'packages/agent/src/hd-identity-vault.ts',
    tool: 'tools/interop/generate-vault-jwe-fixture.ts',
  },
  inputs: {
    recoveryPhrase: RECOVERY_PHRASE,
    password: PASSWORD,
    keyDerivationWorkFactor: 1,
    dwnEndpoints: DWN_ENDPOINTS,
    dataPlaintext: toBase64Url(DATA_PLAINTEXT),
    binaryPlaintext: toBase64Url(BINARY_PLAINTEXT),
  },
  vector: v1Profile,
  profiles: {
    v2: v2Profile,
    v1: v1Profile,
  },
};

const outDir = resolve(repoRoot, 'fixtures/interop');
mkdirSync(outDir, { recursive: true });
const outPath = resolve(outDir, 'vault-jwe.json');
writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n');
console.log(`wrote ${outPath} for ${v2Profile.portableDidUri} and ${v1Profile.portableDidUri}`);
