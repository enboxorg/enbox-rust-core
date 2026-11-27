// Vault backup interop: the pinned TypeScript implementation restores both the
// TS-produced and Rust-produced backups. TypeScript `restore()` reads the
// current stored entries first, so each case starts from an initialized vault
// and the restored backup replaces its identity.
//
// The TS fixture covers both derivation profiles: `v2` (BIP-43 default) and
// legacy `v1`, and restore must preserve the backup's `derivationVersion`.
//
// Run with:
//   ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-vault-backup.test.ts

import { expect, test } from 'bun:test';
import { Buffer } from 'node:buffer';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const root = process.env.ENBOX_TS_ROOT;
if (!root) throw new Error('Set ENBOX_TS_ROOT to the TypeScript checkout');

for (const modulePath of ['packages/common/src/stores.ts', 'packages/agent/src/hd-identity-vault.ts']) {
  if (!existsSync(resolve(root, modulePath))) throw new Error(`Unable to find ${modulePath}`);
}

const { MemoryStore } = await import(resolve(root, 'packages/common/src/stores.ts'));
const { HdIdentityVault } = await import(resolve(root, 'packages/agent/src/hd-identity-vault.ts'));

type Profile = {
  derivationVersion: 1 | 2;
  backup: { data: string; dateCreated: string; size: number };
  contentEncryptionKey: string;
  did: string;
  statusBeforeBackup: string;
  statusAfterBackup: string;
  portableDidUri: string;
};

async function restoreCase(
  label: string,
  fixture: Record<string, any>,
  vector: { backup: Profile['backup']; portableDidUri: string },
  expectedDerivationVersion: 1 | 2 | undefined,
): Promise<void> {
  const store = new MemoryStore();
  const vault = new HdIdentityVault({ store, keyDerivationWorkFactor: 1 });
  await vault.initialize({ password: 'target-vault-password' });

  await vault.restore({ backup: vector.backup, password: fixture.inputs.password });
  expect((await vault.getDid()).uri).toBe(vector.portableDidUri);
  expect(await vault.getStatus()).toEqual({
    initialized: true,
    lastBackup: null,
    lastRestore: expect.any(String),
    ...(expectedDerivationVersion === undefined ? {} : { derivationVersion: expectedDerivationVersion }),
  });
  const protectedHeader = JSON.parse(
    Buffer.from((await store.get('contentEncryptionKey')).split('.')[0], 'base64url').toString()
  );
  expect(protectedHeader).toMatchObject({
    alg: 'PBES2-HS512+A256KW',
    enc: 'A256GCM',
    cty: 'text/plain',
    p2c: fixture.inputs.keyDerivationWorkFactor,
  });
  void label;
}

test('TypeScript restores v1 and v2 TS vault backups preserving derivationVersion', async () => {
  const fixture = JSON.parse(await readFile(resolve(repoRoot, 'fixtures/interop/vault-backup.json'), 'utf8'));
  for (const [label, profile] of Object.entries<Profile>(fixture.profiles)) {
    await restoreCase(label, fixture, profile, profile.derivationVersion);
  }
});

test('TypeScript restores the Rust vault backup', async () => {
  const fixture = JSON.parse(
    await readFile(resolve(repoRoot, 'crates/dwn-rs-agent/tests/fixtures/vault-backup-rust-to-ts.json'), 'utf8')
  );
  const status = JSON.parse(
    Buffer.from(fixture.vector.backup.data, 'base64url').toString()
  ).status;
  await restoreCase('rust', fixture, fixture.vector, status.derivationVersion);
});
