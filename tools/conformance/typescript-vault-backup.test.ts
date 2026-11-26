// Vault backup interop: the pinned TypeScript implementation restores both the
// TS-produced and Rust-produced backups. TypeScript `restore()` reads the
// current stored entries first, so each case starts from an initialized vault
// and the restored backup replaces its identity.
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

const fixtures = [
  resolve(repoRoot, 'fixtures/interop/vault-backup.json'),
  resolve(repoRoot, 'crates/dwn-rs-agent/tests/fixtures/vault-backup-rust-to-ts.json'),
];

test('TypeScript restores TypeScript and Rust vault backups over an initialized vault', async () => {
  for (const fixturePath of fixtures) {
    const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
    const store = new MemoryStore();
    const vault = new HdIdentityVault({ store, keyDerivationWorkFactor: 1 });
    await vault.initialize({
      password: 'target-vault-password',
      recoveryPhrase: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
    });

    await vault.restore({ backup: fixture.vector.backup, password: fixture.inputs.password });
    expect((await vault.getDid()).uri).toBe(fixture.vector.portableDidUri);
    expect(await vault.getStatus()).toEqual({
      initialized: true,
      lastBackup: null,
      lastRestore: expect.any(String),
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
  }
});
