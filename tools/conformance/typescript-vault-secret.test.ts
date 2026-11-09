import { expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
const root = process.env.ENBOX_TS_ROOT;
if (!root) throw new Error('Set ENBOX_TS_ROOT to the TypeScript checkout');
const { MemoryStore } = await import(resolve(root, 'packages/common/src/stores.ts'));
const { HdIdentityVault } = await import(resolve(root, 'packages/agent/src/hd-identity-vault.ts'));
const { VaultBackedSecretStore } = await import(resolve(root, 'packages/agent/src/secret-store.ts'));

test('TypeScript opens TypeScript and Rust secret envelopes', async () => {
  const vaultFixture = JSON.parse(await readFile('fixtures/interop/vault-jwe.json', 'utf8'));
  const raw = new MemoryStore();
  for (const key of ['contentEncryptionKey', 'did', 'vaultStatus']) await raw.set(key, vaultFixture.vector[key]);
  const vault = new HdIdentityVault({ store: raw, keyDerivationWorkFactor: 1 });
  await vault.unlock({ password: vaultFixture.inputs.password });
  const fixture = JSON.parse(await readFile('fixtures/interop/vault-secret-envelope.json', 'utf8'));
  const rustPath = process.env.VAULT_SECRET_EXPORT ?? 'crates/dwn-rs-agent/tests/fixtures/vault-secret-rust-to-ts.json';
  for (const envelope of [fixture.envelope, await readFile(rustPath, 'utf8')]) {
    const store = new MemoryStore();
    await store.set(fixture.inputs.key, envelope);
    const secrets = new VaultBackedSecretStore({ vault, store });
    expect(Array.from(await secrets.get(fixture.inputs.key))).toEqual(fixture.inputs.plaintext);
  }
});
