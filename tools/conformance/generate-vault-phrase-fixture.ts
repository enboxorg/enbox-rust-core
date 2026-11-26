// Generates fixtures/interop/vault-phrase-acceptance.json from the pinned
// TypeScript `validateMnemonic(phrase, englishWordlist)` at ENBOX_TS_ROOT.
//
// Run with:
//   ENBOX_TS_ROOT=/path/to/enbox bun tools/conformance/generate-vault-phrase-fixture.ts

import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const root = process.env.ENBOX_TS_ROOT;
if (!root) throw new Error('Set ENBOX_TS_ROOT to the TypeScript checkout');

const dependencyPath = (specifier: string) => {
  for (const base of ['packages/agent/node_modules', 'node_modules']) {
    const path = resolve(root, base, specifier);
    if (existsSync(path)) return path;
  }
  throw new Error(`Unable to resolve ${specifier} under ENBOX_TS_ROOT`);
};

const { entropyToMnemonic, validateMnemonic } = await import(dependencyPath('@scure/bip39/index.js'));
const { wordlist } = await import(dependencyPath('@scure/bip39/wordlists/english.js'));

// A zero-entropy phrase per accepted word count is deterministic and valid.
const phraseFor = (words) => entropyToMnemonic(new Uint8Array(words * 4 / 3), wordlist);
const base = phraseFor(12);

const rows = [
  { id: '12-words', phrase: phraseFor(12), accepted: true },
  { id: '15-words', phrase: phraseFor(15), accepted: true },
  { id: '18-words', phrase: phraseFor(18), accepted: true },
  { id: '21-words', phrase: phraseFor(21), accepted: true },
  { id: '24-words', phrase: phraseFor(24), accepted: true },
  { id: 'nfkd-no-break-space', phrase: base.replace(' ', '\u00a0'), accepted: true },
  { id: 'nfkd-ideographic-space', phrase: base.replace(' ', '\u3000'), accepted: true },
  { id: 'uppercase', phrase: base.toUpperCase(), accepted: false },
  { id: 'leading-space', phrase: ` ${base}`, accepted: false },
  { id: 'trailing-space', phrase: `${base} `, accepted: false },
  { id: 'double-space', phrase: base.replace(' ', '  '), accepted: false },
  { id: 'tab-separator', phrase: base.replace(' ', '\t'), accepted: false },
  { id: 'newline-separator', phrase: base.replace(' ', '\n'), accepted: false },
  // A wordlist word in the wrong position breaks the checksum.
  { id: 'bad-checksum', phrase: base.replace(/^abandon/, 'legal'), accepted: false },
  { id: 'non-wordlist-word', phrase: base.replace(/ about$/, ' notaword'), accepted: false },
  { id: 'thirteen-words', phrase: `${base} about`, accepted: false },
  { id: 'empty', phrase: '', accepted: false },
  { id: 'whitespace-only', phrase: '   ', accepted: false },
];

for (const row of rows) {
  const observed = validateMnemonic(row.phrase, wordlist);
  if (observed !== row.accepted) {
    throw new Error(`${row.id}: expected accepted=${row.accepted}, observed ${observed}`);
  }
}

await writeFile('fixtures/interop/vault-phrase-acceptance.json', JSON.stringify({
  schemaVersion: 1,
  oracle: 'enbox',
  source: {
    repository: 'enboxorg/enbox',
    commit: execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    path: 'packages/agent/src/hd-identity-vault.ts',
    tool: 'tools/conformance/generate-vault-phrase-fixture.ts',
  },
  inputs: { wordlist: 'english', generatedWords: 12 },
  cases: rows,
}, null, 2) + '\n');
