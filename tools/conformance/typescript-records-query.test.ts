import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { getConformanceAlicePersona } from './conformance-persona.ts';

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
  seedSets?: Record<string, RecordsQuerySeedEntry[]>;
  cases: RecordsQueryFixtureCase[];
};

type RecordsQueryFixtureCase = {
  id: string;
  recordsTagsQuery?: RecordsQueryFixture;
  permissionsGrantQuery?: RecordsQueryFixture;
};

type RecordsQueryFixture = {
  tenant: string;
  seedSet: string;
  request: { message: Record<string, unknown> };
  reply: unknown;
};

type RecordsQuerySeedEntry = {
  id: string;
  messageCid: string;
  indexes: Record<string, unknown>;
  message: Record<string, unknown>;
  encodedData?: string;
};

type MessageStoreLevelModule = {
  MessageStoreLevel: new (options: {
    location?: string;
  }) => MessageStore;
};

type DataStoreLevelModule = {
  DataStoreLevel: new (options: {
    blockstoreLocation?: string;
  }) => DataStore;
};

type RecordsQueryHandlerModule = {
  RecordsQueryHandler: new (deps: {
    didResolver: DidResolver;
    messageStore: MessageStore;
    coreProtocols: CoreProtocolRegistry;
    validationStateReader: ValidationStateReader;
  }) => RecordsQueryHandlerInstance;
};

type ValidationStateReaderModule = {
  StoreValidationStateReader: new (deps: {
    messageStore: MessageStore;
    dataStore: DataStore;
    coreProtocols?: CoreProtocolRegistry;
  }) => ValidationStateReader;
};

type ValidationStateReader = unknown;

type CoreProtocolRegistryModule = {
  CoreProtocolRegistry: new () => CoreProtocolRegistry;
};

type DidResolverModule = {
  DidKey: unknown;
  UniversalResolver: new (config: { didResolvers: unknown[] }) => DidResolver;
};

type TestStubGeneratorModule = {
  TestStubGenerator: {
    stubDidResolver(didResolver: DidResolver, personas: unknown[]): void;
  };
};

type DidResolver = unknown;
type CoreProtocolRegistry = unknown;

type MessageStore = {
  open(): Promise<void>;
  close(): Promise<void>;
  clear(): Promise<void>;
  put(
    tenant: string,
    message: Record<string, unknown>,
    indexes: Record<string, unknown>,
  ): Promise<void>;
};

type DataStore = {
  open(): Promise<void>;
  close(): Promise<void>;
  clear(): Promise<void>;
};

type RecordsQueryHandlerInstance = {
  handle(input: {
    tenant: string;
    message: Record<string, unknown>;
  }): Promise<unknown>;
};

const recordsTagsQueryAssertion = 'records.tags.query';
const permissionsGrantQueryAssertion = 'permissions.grant-query';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const messageStoreLevelModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/store/message-store-level.ts');
const dataStoreLevelModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/store/data-store-level.ts');
const recordsQueryHandlerModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/handlers/records-query.ts');
const coreProtocolModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/core/core-protocol.ts');
const validationStateReaderModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/core/validation-state-reader.ts');
const testStubGeneratorModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/tests/utils/test-stub-generator.ts');
const didResolverModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/node_modules/@enbox/dids/src/index.ts');

for (const modulePath of [
  messageStoreLevelModulePath,
  dataStoreLevelModulePath,
  recordsQueryHandlerModulePath,
  coreProtocolModulePath,
  validationStateReaderModulePath,
  testStubGeneratorModulePath,
]) {
  if (!existsSync(modulePath)) {
    throw new Error(
      `Unable to find TypeScript DWN SDK at ${modulePath}. ` +
      'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
    );
  }
}

const { MessageStoreLevel } = await import(pathToFileURL(messageStoreLevelModulePath).href) as MessageStoreLevelModule;
const { DataStoreLevel } = await import(pathToFileURL(dataStoreLevelModulePath).href) as DataStoreLevelModule;
const { RecordsQueryHandler } = await import(pathToFileURL(recordsQueryHandlerModulePath).href) as RecordsQueryHandlerModule;
const { CoreProtocolRegistry } = await import(pathToFileURL(coreProtocolModulePath).href) as CoreProtocolRegistryModule;
const { StoreValidationStateReader } = await import(pathToFileURL(validationStateReaderModulePath).href) as ValidationStateReaderModule;
const { TestStubGenerator } = await import(pathToFileURL(testStubGeneratorModulePath).href) as TestStubGeneratorModule;
const { DidKey, UniversalResolver } = await import(
  existsSync(didResolverModulePath)
    ? pathToFileURL(didResolverModulePath).href
    : pathToFileURL(resolve(enboxTsRoot, 'packages/dids/src/index.ts')).href
) as DidResolverModule;

const manifest = await readJson<FixtureManifest>(resolve(fixturesRoot, 'manifest.json'));
const fixtureSuites = await Promise.all(
  manifest.suites.map(async (suite): Promise<{ fixtureSet: FixtureSet; suite: FixtureSuiteRef }> => ({
    suite,
    fixtureSet: await readJson<FixtureSet>(resolve(fixturesRoot, suite.path)),
  }))
);

describe('TypeScript RecordsQuery conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    const recordsTagsQuery = suite.assertions.includes(recordsTagsQueryAssertion);
    const permissionsGrantQuery = suite.assertions.includes(permissionsGrantQueryAssertion);
    if (!recordsTagsQuery && !permissionsGrantQuery) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        const query = recordsTagsQuery
          ? fixtureCase.recordsTagsQuery
          : fixtureCase.permissionsGrantQuery;
        if (query === undefined) {
          continue;
        }

        test(`${fixtureCase.id} reply`, async () => {
          await assertRecordsQueryReply(fixtureSet, fixtureCase.id, query);
        });
      }
    });
  }
});

async function assertRecordsQueryReply(
  fixtureSet: FixtureSet,
  caseId: string,
  query: RecordsQueryFixture,
): Promise<void> {
  const temporaryRoot = await mkdtemp(join(tmpdir(), `records-query-conformance-${process.pid}-${caseId}-`));
  const messageStore = new MessageStoreLevel({
    location: resolve(temporaryRoot, 'message-store'),
  });
  const dataStore = new DataStoreLevel({
    blockstoreLocation: resolve(temporaryRoot, 'data-store'),
  });
  const didResolver = new UniversalResolver({ didResolvers: [DidKey] });
  const alice = await getConformanceAlicePersona();
  TestStubGenerator.stubDidResolver(didResolver, [alice]);
  const coreProtocols = new CoreProtocolRegistry();
  const handler = new RecordsQueryHandler({
    didResolver,
    messageStore,
    coreProtocols,
    validationStateReader: new StoreValidationStateReader({
      messageStore,
      dataStore,
      coreProtocols,
    }),
  });

  try {
    await Promise.all([messageStore.open(), dataStore.open()]);
    const seed = recordsQuerySeed(fixtureSet, query.seedSet);
    for (const entry of seed) {
      const message = structuredClone(entry.message);
      if (entry.encodedData !== undefined) {
        message.encodedData = entry.encodedData;
      }
      await messageStore.put(query.tenant, message, entry.indexes);
    }

    const actual = await handler.handle({
      tenant: query.tenant,
      message: query.request.message,
    });
    expect(normalizeRecordsQueryReply(actual)).toEqual(normalizeRecordsQueryReply(query.reply));
  } finally {
    await messageStore.clear();
    await dataStore.clear();
    await messageStore.close();
    await dataStore.close();
    await rm(temporaryRoot, { force: true, recursive: true });
    expect(existsSync(resolve(repoRoot, 'MESSAGESTORE'))).toBeFalse();
    expect(existsSync(resolve(repoRoot, 'DATASTORE'))).toBeFalse();
  }
}

function recordsQuerySeed(fixtureSet: FixtureSet, seedSet: string): RecordsQuerySeedEntry[] {
  const seed = fixtureSet.seedSets?.[seedSet];
  if (seed === undefined) {
    throw new Error(`RecordsQuery seed set ${seedSet} not found`);
  }

  return seed;
}

function normalizeRecordsQueryReply(reply: unknown): unknown {
  const value = reply as {
    status?: unknown;
    entries?: Array<{ recordId?: string }>;
    cursor?: unknown;
  };

  return {
    status: value.status,
    entries: (value.entries ?? []).map((entry) => ({ recordId: entry.recordId })),
    cursor: value.cursor ?? null,
  };
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}
