import { describe, expect, test } from 'bun:test';
import { Buffer } from 'node:buffer';
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
  data?: FixtureData;
  descriptorCid?: string;
  messageCid?: string;
  message?: {
    descriptor: Record<string, unknown>;
    [key: string]: unknown;
  };
  value?: unknown;
};

type FixtureData =
  | { encoding: 'base64url'; value: string }
  | { encoding: 'hex'; value: string }
  | { encoding: 'repeatByte'; byte: number; length: number }
  | { encoding: 'utf8'; value: string };

type CidModule = {
  Cid: {
    computeCid(payload: unknown): Promise<string>;
    computeDagPbCidFromBytes(content: Uint8Array): Promise<string>;
    computeDagPbCidFromStream(dataStream: ReadableStream<Uint8Array>): Promise<string>;
  };
};

const cidMessageAssertion = 'cid.message';
const cidDescriptorAssertion = 'cid.descriptor';
const cidJsonAssertion = 'cid.json';
const cidDagPbBytesAssertion = 'cid.dagpb.bytes';
const cidDagPbStreamAssertion = 'cid.dagpb.stream';

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
      !suite.assertions.includes(cidJsonAssertion) &&
      !suite.assertions.includes(cidDagPbBytesAssertion) &&
      !suite.assertions.includes(cidDagPbStreamAssertion)
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
            await expect(Cid.computeCid(jsonValue(fixtureCase))).resolves.toBe(expectedCid(fixtureCase));
          });
        }

        if (suite.assertions.includes(cidDagPbBytesAssertion)) {
          test(`${fixtureCase.id} DAG-PB bytes CID`, async () => {
            await expect(Cid.computeDagPbCidFromBytes(bytes(fixtureCase))).resolves.toBe(expectedCid(fixtureCase));
          });
        }

        if (suite.assertions.includes(cidDagPbStreamAssertion)) {
          test(`${fixtureCase.id} DAG-PB stream CID`, async () => {
            const payload = bytes(fixtureCase);
            await expect(Cid.computeDagPbCidFromStream(byteStream(payload))).resolves.toBe(expectedCid(fixtureCase));
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

function bytes(fixtureCase: FixtureCase): Uint8Array {
  const data = fixtureCase.data;
  if (data === undefined) {
    throw new Error(`${fixtureCase.id} must include byte data`);
  }

  switch (data.encoding) {
  case 'base64url':
    return Uint8Array.from(Buffer.from(data.value, 'base64url'));
  case 'hex':
    return Uint8Array.from(Buffer.from(data.value, 'hex'));
  case 'repeatByte':
    return new Uint8Array(data.length).fill(data.byte);
  case 'utf8':
    return new TextEncoder().encode(data.value);
  }
}

function byteStream(payload: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller): void {
      for (let offset = 0; offset < payload.length; offset += 65536) {
        controller.enqueue(payload.slice(offset, offset + 65536));
      }

      controller.close();
    },
  });
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

function expectedCid(fixtureCase: FixtureCase): string {
  if (fixtureCase.cid === undefined) {
    throw new Error(`${fixtureCase.id} must include a cid`);
  }

  return fixtureCase.cid;
}
