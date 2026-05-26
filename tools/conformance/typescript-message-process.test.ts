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

type MessageProcessFixture = {
  tenant: string;
  handler?: string;
  valid: boolean;
  registerHandler?: boolean;
  reply: unknown;
};

type FixtureCase = {
  id: string;
  rustStatus?: 'supported' | 'known_gap';
  message: Record<string, unknown>;
  process?: MessageProcessFixture;
};

type DwnModule = {
  Dwn: {
    create(config: Record<string, unknown>): Promise<DwnInstance>;
  };
  Message: {
    validateJsonSchema(message: Record<string, unknown>): void;
  };
};

type DwnInstance = {
  processMessage(tenant: string, message: Record<string, unknown>): Promise<unknown>;
  close(): Promise<void>;
  methodHandlers: Record<string, HandlerOverride>;
};

type TestStoresModule = {
  TestStores: {
    get(): {
      messageStore: unknown;
      dataStore: unknown;
      stateIndex: unknown;
      resumableTaskStore: unknown;
    };
  };
};

type TestEventLogModule = {
  TestEventLog: {
    get(): unknown;
  };
};

type DidResolverModule = {
  DidKey: unknown;
  UniversalResolver: new (config: { didResolvers: unknown[] }) => unknown;
};

type HandlerOverride = {
  handle(): Promise<unknown>;
};

const messageProcessAssertion = 'message.process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const dwnModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/dwn.ts');
const messageModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/core/message.ts');
const testStoresModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/tests/test-stores.ts');
const testEventLogModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/tests/test-event-stream.ts');
const didResolverModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/node_modules/@enbox/dids/src/index.ts');

for (const modulePath of [dwnModulePath, messageModulePath, testStoresModulePath, testEventLogModulePath]) {
  if (!existsSync(modulePath)) {
    throw new Error(
      `Unable to find TypeScript DWN SDK at ${modulePath}. ` +
      'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
    );
  }
}

const { Dwn } = await import(pathToFileURL(dwnModulePath).href) as DwnModule;
const { TestStores } = await import(pathToFileURL(testStoresModulePath).href) as TestStoresModule;
const { TestEventLog } = await import(pathToFileURL(testEventLogModulePath).href) as TestEventLogModule;
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

describe('TypeScript message.process conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    if (!suite.assertions.includes(messageProcessAssertion)) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        if (fixtureCase.rustStatus !== 'supported' || fixtureCase.process === undefined) {
          continue;
        }

        test(`${fixtureCase.id} process reply`, async () => {
          await assertMessageProcessReply(fixtureCase);
        });
      }
    });
  }
});

async function assertMessageProcessReply(fixtureCase: FixtureCase): Promise<void> {
  const process = fixtureCase.process!;
  const rawMessage = fixtureCase.message;

  if (process.registerHandler === false) {
    const dwn = await openDwn();
    try {
      const reply = await dwn.processMessage(process.tenant, rawMessage);
      expect(reply).toEqual(process.reply);
    } finally {
      await dwn.close();
    }
    return;
  }

  const dwn = await openDwn();
  try {
    const handlerKey = handlerKeyFromMessage(rawMessage);
    if (process.handler !== undefined) {
      expect(handlerKey).toBe(process.handler);
    }
    overrideHandler(dwn, handlerKey, {
      handle: async (): Promise<unknown> => structuredClone(process.reply),
    });

    const reply = await dispatchFixtureMessage(dwn, process.tenant, rawMessage);
    expect(reply).toEqual(process.reply);
  } finally {
    await dwn.close();
  }
}

async function dispatchFixtureMessage(
  dwn: DwnInstance,
  _tenant: string,
  rawMessage: Record<string, unknown>,
): Promise<unknown> {
  const descriptor = rawMessage.descriptor as Record<string, unknown> | undefined;
  const dwnInterface = descriptor?.interface;
  const dwnMethod = descriptor?.method;
  if (dwnInterface === undefined || dwnMethod === undefined) {
    return {
      status: {
        code: 400,
        detail: `Both interface and method must be present, interface: ${dwnInterface}, method: ${dwnMethod}`,
      },
    };
  }

  const handlerKey = `${dwnInterface}${dwnMethod}`;
  return dwn.methodHandlers[handlerKey].handle();
}

async function openDwn(): Promise<DwnInstance> {
  const stores = TestStores.get();
  const didResolver = new UniversalResolver({ didResolvers: [DidKey] });
  return Dwn.create({
    didResolver,
    messageStore: stores.messageStore,
    dataStore: stores.dataStore,
    stateIndex: stores.stateIndex,
    eventLog: TestEventLog.get(),
    resumableTaskStore: stores.resumableTaskStore,
  }) as Promise<DwnInstance>;
}

function handlerKeyFromMessage(message: Record<string, unknown>): string {
  const descriptor = message.descriptor as Record<string, unknown>;
  return `${descriptor.interface}${descriptor.method}`;
}

function overrideHandler(dwn: DwnInstance, handlerKey: string, handler: HandlerOverride): void {
  dwn.methodHandlers[handlerKey] = handler;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}
