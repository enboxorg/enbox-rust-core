// Vault at-rest JWE interop: the pinned implementation opens Rust-emitted vault
// values, and still opens its own fixture. This is the Rust-to-TS half of the
// offline proof; the TS-to-Rust half runs as native Rust tests with no
// TypeScript tooling (`crates/dwn-rs-agent/tests/vault_jwe_interop.rs`).
//
// Run with:
//   ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-vault-jwe.test.ts
//
// In CI ENBOX_TS_ROOT is the pinned checkout, so this proves the pinned
// decoder accepts Rust output. It is an optional runner: Rust tests never
// depend on it.

import { describe, expect, test } from 'bun:test';
import { Buffer } from 'node:buffer';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const rustBlobPath = resolve(
  repoRoot,
  'crates/dwn-rs-agent/tests/fixtures/vault-jwe-rust-to-ts.json'
);
const tsFixturePath = resolve(repoRoot, 'fixtures/interop/vault-jwe.json');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? resolve(repoRoot, '../enbox');
const compactPath = resolve(enboxTsRoot, 'packages/crypto/src/jose/jwe/compact.ts');
const keyManagerPath = resolve(enboxTsRoot, 'packages/crypto/src/local-key-manager.ts');
const bearerDidPath = resolve(enboxTsRoot, 'packages/dids/src/bearer-did.ts');
const convertPath = resolve(enboxTsRoot, 'packages/common/src/convert.ts');

for (const modulePath of [compactPath, keyManagerPath, bearerDidPath, convertPath, rustBlobPath, tsFixturePath]) {
  if (!existsSync(modulePath)) {
    throw new Error(
      `Unable to find ${modulePath}. ` +
      'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
    );
  }
}

const { CompactJwe } = await import(compactPath);
const { LocalKeyManager } = await import(keyManagerPath);
const { BearerDid } = await import(bearerDidPath);
const { Convert } = await import(convertPath);

async function unlockCek(cekJwe: string, password: string) {
  const { plaintext } = await CompactJwe.decrypt({
    jwe: cekJwe,
    key: Convert.string(password).toUint8Array(),
    keyManager: new LocalKeyManager(),
    options: {
      allowedAlgs: ['PBES2-HS512+A256KW'],
      allowedEncs: ['A256GCM'],
      minP2cCount: 1,
    },
  });
  return Convert.uint8Array(plaintext).toObject();
}

describe('vault at-rest JWE interop', () => {
  test('pinned implementation opens Rust-emitted vault values', async () => {
    const blob = JSON.parse(await readFile(rustBlobPath, 'utf8'));
    const password = blob.inputs.password;

    const contentEncryptionKey = await unlockCek(blob.vector.contentEncryptionKey, password);
    expect(contentEncryptionKey.kty).toBe('oct');
    expect(contentEncryptionKey.k).toBe(blob.inputs.cek);

    const { plaintext: didBytes } = await CompactJwe.decrypt({
      jwe: blob.vector.did,
      key: contentEncryptionKey,
      keyManager: new LocalKeyManager(),
      options: { allowedAlgs: ['dir'], allowedEncs: ['A256GCM'], minP2cCount: 1 },
    });
    const portableDid = Convert.uint8Array(didBytes).toObject();
    const bearerDid = await BearerDid.import({ portableDid });
    expect(bearerDid.uri).toBe(blob.vector.portableDidUri);

    const { plaintext: data } = await CompactJwe.decrypt({
      jwe: blob.vector.dataJwe,
      key: contentEncryptionKey,
      keyManager: new LocalKeyManager(),
      options: { allowedAlgs: ['dir'], allowedEncs: ['A256GCM'], minP2cCount: 1 },
    });
    expect(Buffer.from(data).toString('base64url')).toBe(blob.inputs.dataPlaintext);
  });

  test('pinned implementation still opens its own fixture', async () => {
    const fixture = JSON.parse(await readFile(tsFixturePath, 'utf8'));
    const contentEncryptionKey = await unlockCek(
      fixture.vector.contentEncryptionKey,
      fixture.inputs.password
    );
    const { plaintext: didBytes } = await CompactJwe.decrypt({
      jwe: fixture.vector.did,
      key: contentEncryptionKey,
      keyManager: new LocalKeyManager(),
      options: { allowedAlgs: ['dir'], allowedEncs: ['A256GCM'], minP2cCount: 1 },
    });
    const bearerDid = await BearerDid.import({
      portableDid: Convert.uint8Array(didBytes).toObject(),
    });
    expect(bearerDid.uri).toBe(fixture.vector.portableDidUri);
  });
});
