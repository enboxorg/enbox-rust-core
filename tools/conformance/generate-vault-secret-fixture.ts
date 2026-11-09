import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const root = process.env.ENBOX_TS_ROOT;
if (!root) throw new Error('Set ENBOX_TS_ROOT to the TypeScript checkout');
const { MemoryStore } = await import(resolve(root, 'packages/common/src/stores.ts'));
const { HdIdentityVault } = await import(resolve(root, 'packages/agent/src/hd-identity-vault.ts'));
const { VaultBackedSecretStore } = await import(resolve(root, 'packages/agent/src/secret-store.ts'));
const fixture = JSON.parse(await readFile('fixtures/interop/vault-jwe.json', 'utf8'));
const rawVault = new MemoryStore();
for (const key of ['contentEncryptionKey', 'did', 'vaultStatus']) {
  await rawVault.set(key, fixture.vector[key]);
}
const vault = new HdIdentityVault({ store: rawVault, keyDerivationWorkFactor: 1 });
await vault.unlock({ password: fixture.inputs.password });
const rawSecrets = new MemoryStore();
const secrets = new VaultBackedSecretStore({ vault, store: rawSecrets });
const plaintext = new Uint8Array([0, 1, 127, 128, 255]);
const key = 'enbox:auth:registrationTokens';
await secrets.put(key, plaintext, { expiresAt: '2099-01-01T00:00:00.000Z' });
await writeFile('fixtures/interop/vault-secret-envelope.json', JSON.stringify({
  oracle: 'enbox',
  source: {
    commit: execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    generator: 'tools/conformance/generate-vault-secret-fixture.ts',
    implementation: 'packages/agent/src/secret-store.ts',
  },
  inputs: { key, plaintext: Array.from(plaintext) },
  envelope: await rawSecrets.get(key),
}, null, 2) + '\n');
