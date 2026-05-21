import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
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
  cases: FixtureCase[];
};

type FixtureCase = {
  id: string;
  cid?: string;
  descriptorCid?: string;
  messageCid?: string;
  message?: {
    descriptor: Record<string, unknown>;
    [key: string]: unknown;
  };
  value?: unknown;
};

type CidModule = {
  Cid: {
    computeCid(payload: unknown): Promise<string>;
  };
};

const cidMessageAssertion = 'cid.message';
const cidDescriptorAssertion = 'cid.descriptor';
const cidJsonAssertion = 'cid.json';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const cidModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/utils/cid.ts');

if (!existsSync(cidModulePath)) {
  throw new Error(
    `Unable to find TypeScript DWN SDK at ${cidModulePath}. ` +
    'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
  );
}

const { Cid } = await import(pathToFileURL(cidModulePath).href) as CidModule;
const manifest = await readJson<FixtureManifest>(resolve(fixturesRoot, 'manifest.json'));
const fixtureSuites = await Promise.all(
  manifest.suites.map(async (suite): Promise<{ fixtureSet: FixtureSet; suite: FixtureSuiteRef }> => ({
    suite,
    fixtureSet: await readJson<FixtureSet>(resolve(fixturesRoot, suite.path)),
  }))
);

describe('TypeScript DWN conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    if (
      !suite.assertions.includes(cidMessageAssertion) &&
      !suite.assertions.includes(cidDescriptorAssertion) &&
      !suite.assertions.includes(cidJsonAssertion)
    ) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        if (suite.assertions.includes(cidMessageAssertion)) {
          test(`${fixtureCase.id} message CID`, async () => {
            await expect(Cid.computeCid(message(fixtureCase))).resolves.toBe(expectedMessageCid(fixtureCase));
          });
        }

        if (suite.assertions.includes(cidDescriptorAssertion)) {
          test(`${fixtureCase.id} descriptor CID`, async () => {
            await expect(Cid.computeCid(message(fixtureCase).descriptor)).resolves.toBe(expectedDescriptorCid(fixtureCase));
          });
        }

        if (suite.assertions.includes(cidJsonAssertion)) {
          test(`${fixtureCase.id} JSON CID`, async () => {
            await expect(Cid.computeCid(jsonValue(fixtureCase))).resolves.toBe(expectedJsonCid(fixtureCase));
          });
        }
      }
    });
  }
});

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

function message(fixtureCase: FixtureCase): NonNullable<FixtureCase['message']> {
  if (fixtureCase.message === undefined) {
    throw new Error(`${fixtureCase.id} must include a message`);
  }

  return fixtureCase.message;
}

function jsonValue(fixtureCase: FixtureCase): unknown {
  if (!Object.prototype.hasOwnProperty.call(fixtureCase, 'value')) {
    throw new Error(`${fixtureCase.id} must include a JSON value`);
  }

  return fixtureCase.value;
}

function expectedMessageCid(fixtureCase: FixtureCase): string {
  if (fixtureCase.messageCid === undefined) {
    throw new Error(`${fixtureCase.id} must include a messageCid`);
  }

  return fixtureCase.messageCid;
}

function expectedDescriptorCid(fixtureCase: FixtureCase): string {
  if (fixtureCase.descriptorCid === undefined) {
    throw new Error(`${fixtureCase.id} must include a descriptorCid`);
  }

  return fixtureCase.descriptorCid;
}

function expectedJsonCid(fixtureCase: FixtureCase): string {
  if (fixtureCase.cid === undefined) {
    throw new Error(`${fixtureCase.id} must include a cid`);
  }

  return fixtureCase.cid;
}
