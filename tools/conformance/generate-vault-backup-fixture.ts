// Generates fixtures/interop/vault-backup.json from the pinned TypeScript
// HdIdentityVault at ENBOX_TS_ROOT.
//
// Run with:
//   ENBOX_TS_ROOT=/path/to/enbox bun tools/conformance/generate-vault-backup-fixture.ts

import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const root = process.env.ENBOX_TS_ROOT;
if (!root) throw new Error('Set ENBOX_TS_ROOT to the TypeScript checkout');
const { MemoryStore } = await import(resolve(root, 'packages/common/src/stores.ts'));
const { HdIdentityVault } = await import(resolve(root, 'packages/agent/src/hd-identity-vault.ts'));

const recoveryPhrase =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'vault-interop-password';
const keyDerivationWorkFactor = 1;

const store = new MemoryStore();
const vault = new HdIdentityVault({ store, keyDerivationWorkFactor });
await vault.initialize({ password, recoveryPhrase, dwnEndpoints: ['https://dwn.example'] });

const statusBeforeBackup = await store.get('vaultStatus');
const backup = await vault.backup();

await writeFile('fixtures/interop/vault-backup.json', JSON.stringify({
  schemaVersion: 1,
  oracle: 'enbox',
  source: {
    repository: 'enboxorg/enbox',
    commit: execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    path: 'packages/agent/src/hd-identity-vault.ts',
    tool: 'tools/conformance/generate-vault-backup-fixture.ts',
  },
  inputs: {
    recoveryPhrase,
    password,
    keyDerivationWorkFactor,
    dwnEndpoints: ['https://dwn.example'],
  },
  vector: {
    backup,
    contentEncryptionKey: await store.get('contentEncryptionKey'),
    did: await store.get('did'),
    statusBeforeBackup,
    statusAfterBackup: await store.get('vaultStatus'),
    portableDidUri: (await vault.getDid()).uri,
  },
}, null, 2) + '\n');
