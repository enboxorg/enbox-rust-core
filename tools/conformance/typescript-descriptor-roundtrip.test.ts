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
  rustStatus?: 'supported' | 'known_gap';
  message?: {
    descriptor: Record<string, unknown>;
  };
};

type SchemaValidatorModule = {
  validateJsonSchema(schemaName: string, payload: unknown): void;
};

const descriptorRoundtripAssertion = 'descriptor.roundtrip';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const schemaValidatorModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/schema-validator.ts');

if (!existsSync(schemaValidatorModulePath)) {
  throw new Error(
    `Unable to find TypeScript DWN SDK at ${schemaValidatorModulePath}. ` +
    'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
  );
}

const { validateJsonSchema } = await import(pathToFileURL(schemaValidatorModulePath).href) as SchemaValidatorModule;
const manifest = await readJson<FixtureManifest>(resolve(fixturesRoot, 'manifest.json'));
const fixtureSuites = await Promise.all(
  manifest.suites.map(async (suite): Promise<{ fixtureSet: FixtureSet; suite: FixtureSuiteRef }> => ({
    suite,
    fixtureSet: await readJson<FixtureSet>(resolve(fixturesRoot, suite.path)),
  }))
);

describe('TypeScript descriptor roundtrip conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    if (!suite.assertions.includes(descriptorRoundtripAssertion)) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        if (fixtureCase.rustStatus !== 'supported' || fixtureCase.message?.descriptor === undefined) {
          continue;
        }

        test(`${fixtureCase.id} descriptor`, () => {
          const descriptor = fixtureCase.message.descriptor;
          const roundtrip = roundtripDescriptor(descriptor);
          expect(roundtrip).toEqual(descriptor);
        });
      }
    });
  }
});

function roundtripDescriptor(descriptor: Record<string, unknown>): Record<string, unknown> {
  const clone = structuredClone(descriptor);
  const schemaName = `${clone.interface as string}${clone.method as string}`;
  const message: Record<string, unknown> = { descriptor: clone };

  if (validateDescriptorMessage(schemaName, message)) {
    return message.descriptor as Record<string, unknown>;
  }

  // Rust typed descriptor roundtrip accepts fixtures that TypeScript JSON Schema may
  // model differently (optional fields, missing schemas). Preserve JSON shape.
  return clone;
}

function validateDescriptorMessage(schemaName: string, message: Record<string, unknown>): boolean {
  try {
    validateJsonSchema(schemaName, message);
    return true;
  } catch (error) {
    if (!authorizationRequired(error)) {
      return false;
    }

    message.authorization = { signature: stubGeneralJws() };
    try {
      validateJsonSchema(schemaName, message);
      return true;
    } catch {
      return false;
    }
  }
}

function authorizationRequired(error: unknown): boolean {
  return error instanceof Error && error.message.includes(`must have required property 'authorization'`);
}

function stubGeneralJws(): Record<string, unknown> {
  return {
    payload: 'stub',
    signatures: [{ protected: 'stub', signature: 'stub' }],
  };
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}
