import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { getLoopbackPersona, LOOPBACK_TENANT } from './interop-persona.ts';
import { startLoopbackServer } from './loopback-server.ts';

type HttpDwnRpcClientModule = {
  HttpDwnRpcClient: new () => HttpDwnRpcClient;
};

type HttpDwnRpcClient = {
  sendDwnRequest(input: {
    dwnUrl: string;
    targetDid: string;
    message: Record<string, unknown>;
    data?: Uint8Array | ReadableStream<Uint8Array>;
  }): Promise<{
    status: { code: number; detail: string };
    entries?: unknown[];
    entry?: { recordsWrite?: { recordId?: string }; messageCid?: string };
  }>;
};

type DwnSdkModule = {
  ProtocolsConfigure: {
    create(input: Record<string, unknown>): Promise<{ message: Record<string, unknown> }>;
  };
  RecordsRead: {
    create(input: Record<string, unknown>): Promise<{ message: Record<string, unknown> }>;
  };
  TestDataGenerator: {
    generateRecordsWrite(input: Record<string, unknown>): Promise<{
      message: Record<string, unknown> & { recordId?: string; contextId?: string };
      dataBytes: Uint8Array;
    }>;
    generateGrantCreate(input: Record<string, unknown>): Promise<{
      message: Record<string, unknown>;
      dataBytes: Uint8Array;
    }>;
  };
  defaultTestProtocolDefinition: {
    protocol: string;
    published: boolean;
    types: Record<string, Record<string, unknown>>;
    structure: Record<string, Record<string, unknown>>;
  };
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const httpClientModulePath = resolve(enboxTsRoot, 'packages/dwn-clients/src/http-dwn-rpc-client.ts');
const dwnSdkModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/index.ts');
const testDataGeneratorPath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/tests/utils/test-data-generator.ts');

if (!existsSync(httpClientModulePath)) {
  throw new Error(
    `Unable to find @enbox/dwn-clients at ${httpClientModulePath}. ` +
    'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
  );
}

const { HttpDwnRpcClient } = await import(httpClientModulePath) as HttpDwnRpcClientModule;
const { ProtocolsConfigure, RecordsRead } = await import(dwnSdkModulePath) as DwnSdkModule;
const { TestDataGenerator, defaultTestProtocolDefinition } = await import(testDataGeneratorPath) as {
  TestDataGenerator: DwnSdkModule['TestDataGenerator'];
  defaultTestProtocolDefinition: DwnSdkModule['defaultTestProtocolDefinition'];
};

const loopbackProtocolDefinition = {
  ...defaultTestProtocolDefinition,
  published: true,
};

let endpoint: string;
let stopServer: () => Promise<void>;

beforeAll(async () => {
  const server = await startLoopbackServer();
  endpoint = server.endpoint;
  stopServer = server.stop;
}, 120_000);

afterAll(async () => {
  await stopServer();
});

describe('Loopback RPC interop (Rust server, TS client)', () => {
  test('exposes /info', async () => {
    const response = await fetch(`${endpoint}/info`);
    expect(response.ok).toBe(true);
    const info = await response.json() as { server: string };
    expect(info.server).toBe('@enbox/dwn-server');
  });

  test('processes unsigned RecordsQuery over HTTP JSON-RPC', async () => {
    const client = new HttpDwnRpcClient();
    const reply = await client.sendDwnRequest({
      dwnUrl: endpoint,
      targetDid: LOOPBACK_TENANT,
      message: {
        descriptor: {
          interface: 'Records',
          method: 'Query',
          messageTimestamp: '2025-01-01T00:00:00.000000Z',
          filter: {
            schema: 'http://example.com/schema',
            published: true,
          },
        },
      },
    });

    expect(reply.status.code).toBe(200);
    expect(reply.entries ?? []).toEqual([]);
  });

  test('rejects messages missing interface or method', async () => {
    const client = new HttpDwnRpcClient();
    const reply = await client.sendDwnRequest({
      dwnUrl: endpoint,
      targetDid: LOOPBACK_TENANT,
      message: {
        descriptor: {
          interface: 'Records',
          messageTimestamp: '2025-01-01T00:00:22.000000Z',
        },
      },
    });

    expect(reply.status.code).toBe(400);
    expect(reply.status.detail).toContain('Both interface and method must be present');
  });

  test('ProtocolsConfigure installs a published protocol', async () => {
    const client = new HttpDwnRpcClient();
    const alice = await getLoopbackPersona();
    const { message } = await ProtocolsConfigure.create({
      definition: loopbackProtocolDefinition,
      signer: alice.signer,
    });

    const reply = await client.sendDwnRequest({
      dwnUrl: endpoint,
      targetDid: LOOPBACK_TENANT,
      message,
    });

    expect(reply.status.code).toBe(202);
  });

  test('RecordsWrite then RecordsRead round-trip signed record', async () => {
    const client = new HttpDwnRpcClient();
    const alice = await getLoopbackPersona();

    await installLoopbackProtocol(client);

    const { message: writeMessage, dataBytes } = await TestDataGenerator.generateRecordsWrite({
      author: alice,
      schema: 'foo/bar',
    });

    const writeReply = await client.sendDwnRequest({
      dwnUrl: endpoint,
      targetDid: LOOPBACK_TENANT,
      message: writeMessage,
      data: dataBytes,
    });
    expect(writeReply.status.code).toBe(202);

    const { message: readMessage } = await RecordsRead.create({
      signer: alice.signer,
      filter: {
        recordId: writeMessage.recordId,
      },
    });

    const readReply = await client.sendDwnRequest({
      dwnUrl: endpoint,
      targetDid: LOOPBACK_TENANT,
      message: readMessage,
    });

    expect(readReply.status.code).toBe(200);
    const readBody = (readReply as { body?: { entry?: Record<string, unknown> }; entry?: Record<string, unknown> }).body
      ?? readReply as { entry?: Record<string, unknown> };
    const entry = readBody.entry ?? (readReply as { entry?: Record<string, unknown> }).entry;
    expect(entry).toBeDefined();
    expect(entry?.encodedData).toBeDefined();
    expect(entry?.recordsWrite).toBeDefined();
  });

  test('writes a PermissionsProtocol grant over loopback', async () => {
    const client = new HttpDwnRpcClient();
    const alice = await getLoopbackPersona();

    const { message: grantMessage, dataBytes } = await TestDataGenerator.generateGrantCreate({
      author: alice,
      grantedTo: alice,
    });

    const grantReply = await client.sendDwnRequest({
      dwnUrl: endpoint,
      targetDid: LOOPBACK_TENANT,
      message: grantMessage,
      data: dataBytes,
    });

    expect(grantReply.status.code).toBe(202);
  });
});

async function installLoopbackProtocol(client: HttpDwnRpcClient): Promise<void> {
  const alice = await getLoopbackPersona();
  const { message } = await ProtocolsConfigure.create({
    definition: loopbackProtocolDefinition,
    signer: alice.signer,
  });
  const reply = await client.sendDwnRequest({
    dwnUrl: endpoint,
    targetDid: LOOPBACK_TENANT,
    message,
  });
  if (reply.status.code !== 202) {
    throw new Error(`Failed to install loopback protocol: ${reply.status.code} ${reply.status.detail}`);
  }
}
