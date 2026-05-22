import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { readFile, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type FixtureManifest = {
  schemaVersion: number;
  suites: FixtureSuiteRef[];
};

type FixtureSuiteRef = {
  id: string;
  path: string;
  assertions: string[];
};

type FixtureSet = {
  schemaVersion: number;
  cases: StateIndexFixtureCase[];
};

type StateIndexFixtureCase = {
  id: string;
  operations?: StateIndexOperation[];
};

type StateIndexOperation =
  | { type: 'insert'; tenant: string; messageCid: string; indexes: Record<string, unknown> }
  | { type: 'delete'; tenant: string; messageCids: string[] }
  | { type: 'getRoot'; tenant: string; expected: string }
  | { type: 'getProtocolRoot'; tenant: string; protocol: string; expected: string }
  | { type: 'getSubtreeHash'; tenant: string; prefix: string; expected: string }
  | { type: 'getProtocolSubtreeHash'; tenant: string; protocol: string; prefix: string; expected: string }
  | { type: 'getLeaves'; tenant: string; prefix: string; expected: string[] }
  | { type: 'getProtocolLeaves'; tenant: string; protocol: string; prefix: string; expected: string[] };

type StateIndex = {
  open(): Promise<void>;
  close(): Promise<void>;
  clear(): Promise<void>;
  insert(tenant: string, messageCid: string, indexes: Record<string, unknown>): Promise<void>;
  delete(tenant: string, messageCids: string[]): Promise<void>;
  getRoot(tenant: string): Promise<Uint8Array>;
  getProtocolRoot(tenant: string, protocol: string): Promise<Uint8Array>;
  getSubtreeHash(tenant: string, prefix: boolean[]): Promise<Uint8Array>;
  getProtocolSubtreeHash(tenant: string, protocol: string, prefix: boolean[]): Promise<Uint8Array>;
  getLeaves(tenant: string, prefix: boolean[]): Promise<string[]>;
  getProtocolLeaves(tenant: string, protocol: string, prefix: boolean[]): Promise<string[]>;
};

type StateIndexModule = {
  StateIndexLevel: new (options: { location: string }) => StateIndex;
};

type SmtUtilsModule = {
  hashToHex(hash: Uint8Array): string;
  initDefaultHashes(): Promise<Uint8Array[]>;
};

const stateIndexOperationsAssertion = 'state-index.operations';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const stateIndexModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/state-index/state-index-level.ts');
const smtUtilsModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/smt/smt-utils.ts');

for (const modulePath of [stateIndexModulePath, smtUtilsModulePath]) {
  if (!existsSync(modulePath)) {
    throw new Error(
      `Unable to find TypeScript DWN SDK at ${modulePath}. ` +
      'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
    );
  }
}

const { StateIndexLevel } = await import(pathToFileURL(stateIndexModulePath).href) as StateIndexModule;
const { hashToHex, initDefaultHashes } = await import(pathToFileURL(smtUtilsModulePath).href) as SmtUtilsModule;
const manifest = await readJson<FixtureManifest>(resolve(fixturesRoot, 'manifest.json'));
const fixtureSuites = await Promise.all(
  manifest.suites.map(async (suite): Promise<{ fixtureSet: FixtureSet; suite: FixtureSuiteRef }> => ({
    suite,
    fixtureSet: await readJson<FixtureSet>(resolve(fixturesRoot, suite.path)),
  }))
);

describe('TypeScript StateIndex conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    if (!suite.assertions.includes(stateIndexOperationsAssertion)) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        test(`${fixtureCase.id} operations`, async () => {
          const location = resolve('/tmp/opencode', `state-index-conformance-${process.pid}-${Date.now()}-${fixtureCase.id}`);
          const stateIndex = new StateIndexLevel({ location });

          await stateIndex.open();
          await initDefaultHashes();

          try {
            for (const operation of operations(fixtureCase)) {
              await executeOperation(stateIndex, operation);
            }
          } finally {
            await stateIndex.clear();
            await stateIndex.close();
            await rm(location, { force: true, recursive: true });
          }
        });
      }
    });
  }
});

async function executeOperation(stateIndex: StateIndex, operation: StateIndexOperation): Promise<void> {
  switch (operation.type) {
  case 'insert':
    await stateIndex.insert(operation.tenant, operation.messageCid, operation.indexes);
    return;
  case 'delete':
    await stateIndex.delete(operation.tenant, operation.messageCids);
    return;
  case 'getRoot':
    expect(hashToHex(await stateIndex.getRoot(operation.tenant))).toBe(operation.expected);
    return;
  case 'getProtocolRoot':
    expect(hashToHex(await stateIndex.getProtocolRoot(operation.tenant, operation.protocol))).toBe(operation.expected);
    return;
  case 'getSubtreeHash':
    expect(hashToHex(await stateIndex.getSubtreeHash(operation.tenant, bitStringToPrefix(operation.prefix)))).toBe(operation.expected);
    return;
  case 'getProtocolSubtreeHash':
    expect(hashToHex(await stateIndex.getProtocolSubtreeHash(operation.tenant, operation.protocol, bitStringToPrefix(operation.prefix)))).toBe(operation.expected);
    return;
  case 'getLeaves':
    expect((await stateIndex.getLeaves(operation.tenant, bitStringToPrefix(operation.prefix))).sort()).toEqual(operation.expected);
    return;
  case 'getProtocolLeaves':
    expect((await stateIndex.getProtocolLeaves(operation.tenant, operation.protocol, bitStringToPrefix(operation.prefix))).sort()).toEqual(operation.expected);
    return;
  }
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

function operations(fixtureCase: StateIndexFixtureCase): StateIndexOperation[] {
  if (fixtureCase.operations === undefined) {
    throw new Error(`${fixtureCase.id} must include StateIndex operations`);
  }

  return fixtureCase.operations;
}

function bitStringToPrefix(prefix: string): boolean[] {
  return [...prefix].map((bit) => bit === '1');
}
