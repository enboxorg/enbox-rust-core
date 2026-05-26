import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';

type HttpDwnRpcClientModule = {
  HttpDwnRpcClient: new () => HttpDwnRpcClient;
};

type HttpDwnRpcClient = {
  sendDwnRequest(input: {
    dwnUrl: string;
    targetDid: string;
    message: Record<string, unknown>;
  }): Promise<{ status: { code: number; detail: string }; entries?: unknown[] }>;
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const httpClientModulePath = resolve(enboxTsRoot, 'packages/dwn-clients/src/http-dwn-rpc-client.ts');

if (!existsSync(httpClientModulePath)) {
  throw new Error(
    `Unable to find @enbox/dwn-clients at ${httpClientModulePath}. ` +
    'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
  );
}

const { HttpDwnRpcClient } = await import(httpClientModulePath) as HttpDwnRpcClientModule;

const tenant = 'did:example:alice';
let serverProcess: ChildProcessWithoutNullStreams | undefined;
let endpoint: string | undefined;

beforeAll(async () => {
  endpoint = await startLoopbackServer();
}, 120_000);

afterAll(async () => {
  await stopLoopbackServer();
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
      dwnUrl: endpoint!,
      targetDid: tenant,
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
      dwnUrl: endpoint!,
      targetDid: tenant,
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
});

async function startLoopbackServer(): Promise<string> {
  serverProcess = spawn(
    'cargo',
    ['run', '--quiet', '-p', 'dwn-rs-stores', '--example', 'loopback_interop_server'],
    {
      cwd: repoRoot,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    },
  );

  const ready = await new Promise<string>((resolvePromise, reject) => {
    const timeout = setTimeout((): void => {
      reject(new Error('Timed out waiting for loopback interop server'));
    }, 120_000);

    const rl = createInterface({ input: serverProcess!.stdout! });
    rl.on('line', (line): void => {
      if (line.startsWith('READY ')) {
        clearTimeout(timeout);
        rl.close();
        resolvePromise(line.slice('READY '.length).trim());
      }
    });

    serverProcess!.stderr.on('data', (chunk: Buffer): void => {
      process.stderr.write(chunk);
    });

    serverProcess!.on('exit', (code): void => {
      if (code !== 0 && code !== null) {
        clearTimeout(timeout);
        reject(new Error(`loopback interop server exited early with code ${code}`));
      }
    });
  });

  return ready;
}

async function stopLoopbackServer(): Promise<void> {
  if (serverProcess === undefined) {
    return;
  }

  serverProcess.stdin.write('stop\n');
  await new Promise<void>((resolvePromise): void => {
    serverProcess!.once('exit', (): void => resolvePromise());
    setTimeout((): void => {
      serverProcess?.kill();
      resolvePromise();
    }, 10_000);
  });
  serverProcess = undefined;
}
