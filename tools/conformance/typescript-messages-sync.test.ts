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
  seedSets?: Record<string, MessagesSyncSeedEntry[]>;
  cases: MessagesSyncFixtureCase[];
};

type MessagesSyncFixtureCase = {
  id: string;
  sync?: MessagesSyncFixture;
};

type MessagesSyncFixture = {
  tenant: string;
  seedSet: string;
  request: { descriptor: MessagesSyncDescriptor };
  reply: unknown;
};

type MessagesSyncDescriptor = {
  action: 'root' | 'subtree' | 'leaves' | 'diff';
  protocol?: string;
  prefix?: string;
  hashes?: Record<string, string>;
  depth?: number;
};

type MessagesSyncSeedEntry = {
  id: string;
  messageCid: string;
  indexes: Record<string, unknown>;
  message: Record<string, unknown>;
  encodedData?: string;
  data?: FixtureData;
};

type FixtureData =
  | { encoding: 'base64url'; value: string }
  | { encoding: 'hex'; value: string }
  | { encoding: 'repeatByte'; byte: number; length: number }
  | { encoding: 'utf8'; value: string };

type StateIndex = {
  open(): Promise<void>;
  close(): Promise<void>;
  clear(): Promise<void>;
  insert(tenant: string, messageCid: string, indexes: Record<string, unknown>): Promise<void>;
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
};

type MessagesSyncHandlerModule = {
  MessagesSyncHandler: new (deps: unknown) => unknown;
};

type DiffHandler = {
  handleDiff(tenant: string, message: { descriptor: MessagesSyncDescriptor }): Promise<unknown>;
};

const messagesSyncRepliesAssertion = 'messages-sync.replies';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const stateIndexModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/state-index/state-index-level.ts');
const smtUtilsModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/smt/smt-utils.ts');
const messagesSyncHandlerModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/handlers/messages-sync.ts');

for (const modulePath of [stateIndexModulePath, smtUtilsModulePath, messagesSyncHandlerModulePath]) {
  if (!existsSync(modulePath)) {
    throw new Error(
      `Unable to find TypeScript DWN SDK at ${modulePath}. ` +
      'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
    );
  }
}

const { StateIndexLevel } = await import(pathToFileURL(stateIndexModulePath).href) as StateIndexModule;
const { hashToHex } = await import(pathToFileURL(smtUtilsModulePath).href) as SmtUtilsModule;
const { MessagesSyncHandler } = await import(pathToFileURL(messagesSyncHandlerModulePath).href) as MessagesSyncHandlerModule;
const manifest = await readJson<FixtureManifest>(resolve(fixturesRoot, 'manifest.json'));
const fixtureSuites = await Promise.all(
  manifest.suites.map(async (suite): Promise<{ fixtureSet: FixtureSet; suite: FixtureSuiteRef }> => ({
    suite,
    fixtureSet: await readJson<FixtureSet>(resolve(fixturesRoot, suite.path)),
  }))
);

describe('TypeScript MessagesSync reply conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    if (!suite.assertions.includes(messagesSyncRepliesAssertion)) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        test(`${fixtureCase.id} reply`, async () => {
          const location = resolve('/tmp/opencode', `messages-sync-conformance-${process.pid}-${Date.now()}-${fixtureCase.id}`);
          const stateIndex = new StateIndexLevel({ location });
          const sync = messagesSync(fixtureCase);
          const seed = messagesSyncSeed(fixtureSet, sync.seedSet);

          await stateIndex.open();
          try {
            for (const entry of seed) {
              await stateIndex.insert(sync.tenant, entry.messageCid, entry.indexes);
            }

            const actual = await messagesSyncReply(sync, seed, stateIndex);
            expect(actual).toEqual(sync.reply);
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

async function messagesSyncReply(sync: MessagesSyncFixture, seed: MessagesSyncSeedEntry[], stateIndex: StateIndex): Promise<unknown> {
  const { action, protocol, prefix } = sync.request.descriptor;

  switch (action) {
  case 'root': {
    const root = protocol === undefined
      ? await stateIndex.getRoot(sync.tenant)
      : await stateIndex.getProtocolRoot(sync.tenant, protocol);
    return { status: { code: 200, detail: 'OK' }, root: hashToHex(root) };
  }
  case 'subtree': {
    const hash = protocol === undefined
      ? await stateIndex.getSubtreeHash(sync.tenant, bitStringToPrefix(prefix!))
      : await stateIndex.getProtocolSubtreeHash(sync.tenant, protocol, bitStringToPrefix(prefix!));
    return { status: { code: 200, detail: 'OK' }, hash: hashToHex(hash) };
  }
  case 'leaves': {
    const entries = protocol === undefined
      ? await stateIndex.getLeaves(sync.tenant, bitStringToPrefix(prefix!))
      : await stateIndex.getProtocolLeaves(sync.tenant, protocol, bitStringToPrefix(prefix!));
    return { status: { code: 200, detail: 'OK' }, entries };
  }
  case 'diff': {
    const handler = new MessagesSyncHandler({
      dataStore    : dataStore(seed),
      messageStore : messageStore(seed),
      stateIndex,
    }) as DiffHandler;
    return handler.handleDiff(sync.tenant, sync.request);
  }
  }
}

function messageStore(seed: MessagesSyncSeedEntry[]): { get(tenant: string, messageCid: string): Promise<Record<string, unknown> | undefined> } {
  return {
    async get(_tenant: string, messageCid: string): Promise<Record<string, unknown> | undefined> {
      const entry = seed.find((candidate): boolean => candidate.messageCid === messageCid);
      if (entry === undefined) {
        return undefined;
      }

      return entry.encodedData === undefined
        ? structuredClone(entry.message)
        : { ...structuredClone(entry.message), encodedData: entry.encodedData };
    }
  };
}

function dataStore(seed: MessagesSyncSeedEntry[]): { get(tenant: string, recordId: string, dataCid: string): Promise<{ dataStream: ReadableStream<Uint8Array> } | undefined> } {
  return {
    async get(_tenant: string, recordId: string, dataCid: string): Promise<{ dataStream: ReadableStream<Uint8Array> } | undefined> {
      const entry = seed.find((candidate): boolean => {
        const descriptor = candidate.message.descriptor as Record<string, unknown> | undefined;
        return candidate.data !== undefined &&
          candidate.message.recordId === recordId &&
          descriptor?.dataCid === dataCid;
      });
      if (entry?.data === undefined) {
        return undefined;
      }

      return { dataStream: streamFromBytes(fixtureDataBytes(entry.data)) };
    }
  };
}

function streamFromBytes(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller): void {
      controller.enqueue(bytes);
      controller.close();
    }
  });
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

function messagesSync(fixtureCase: MessagesSyncFixtureCase): MessagesSyncFixture {
  if (fixtureCase.sync === undefined) {
    throw new Error(`${fixtureCase.id} must include MessagesSync fixture data`);
  }

  return fixtureCase.sync;
}

function messagesSyncSeed(fixtureSet: FixtureSet, seedSet: string): MessagesSyncSeedEntry[] {
  const seed = fixtureSet.seedSets?.[seedSet];
  if (seed === undefined) {
    throw new Error(`MessagesSync seed set ${seedSet} not found`);
  }

  return seed;
}

function bitStringToPrefix(prefix: string): boolean[] {
  return [...prefix].map((bit): boolean => bit === '1');
}

function fixtureDataBytes(data: FixtureData): Uint8Array {
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
