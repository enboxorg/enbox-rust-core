// Recovery-phrase acceptance interop: the pinned TypeScript
// `validateMnemonic(phrase, englishWordlist)` matches every row of the shared
// acceptance table. Rust proves the same rows natively.
//
// Run with:
//   ENBOX_TS_ROOT=/path/to/enbox bun test tools/conformance/typescript-vault-phrase.test.ts

import { expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const root = process.env.ENBOX_TS_ROOT;
if (!root) throw new Error('Set ENBOX_TS_ROOT to the TypeScript checkout');

const dependencyPath = (specifier: string) => {
  for (const base of ['packages/agent/node_modules', 'node_modules']) {
    const path = resolve(root, base, specifier);
    if (existsSync(path)) return path;
  }
  throw new Error(`Unable to resolve ${specifier} under ENBOX_TS_ROOT`);
};

const { validateMnemonic } = await import(dependencyPath('@scure/bip39/index.js'));
const { wordlist } = await import(dependencyPath('@scure/bip39/wordlists/english.js'));

test('pinned TypeScript matches the recovery phrase acceptance table', async () => {
  const fixture = JSON.parse(
    await readFile(resolve(repoRoot, 'fixtures/interop/vault-phrase-acceptance.json'), 'utf8')
  );

  for (const row of fixture.cases) {
    expect({ id: row.id, accepted: validateMnemonic(row.phrase, wordlist) }).toEqual({
      id: row.id,
      accepted: row.accepted,
    });
  }
});
