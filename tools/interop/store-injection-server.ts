import { createInterface } from 'node:readline';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

const repoRoot = resolve(import.meta.dir, '../..');

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
};

export type StoreInjectionClient = {
  call(method: string, params?: unknown): Promise<unknown>;
  stop(): Promise<void>;
};

export async function startStoreInjectionServer(): Promise<StoreInjectionClient> {
  const serverProcess = spawn(
    'cargo',
    ['run', '--quiet', '-p', 'dwn-rs-stores', '--example', 'store_injection_server'],
    {
      cwd: repoRoot,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    },
  );

  const pending = new Map<number, PendingRequest>();
  let nextId = 1;
  let ready = false;
  let readyResolve: (() => void) | undefined;
  const readyPromise = new Promise<void>((resolvePromise, reject) => {
    readyResolve = resolvePromise;
    const timeout = setTimeout((): void => {
      reject(new Error('Timed out waiting for store injection server'));
    }, 120_000);

    serverProcess.on('exit', (code): void => {
      if (!ready && code !== 0 && code !== null) {
        clearTimeout(timeout);
        reject(new Error(`store injection server exited early with code ${code}`));
      }
    });
  });

  const responseReader = createInterface({ input: serverProcess.stdout! });
  responseReader.on('line', (line): void => {
    if (!ready) {
      if (line.trim() === 'READY') {
        ready = true;
        readyResolve?.();
      }
      return;
    }

    let response: { id?: number; result?: unknown; error?: string };
    try {
      response = JSON.parse(line) as { id?: number; result?: unknown; error?: string };
    } catch {
      return;
    }

    if (response.id === undefined) {
      return;
    }

    const waiter = pending.get(response.id);
    if (waiter === undefined) {
      return;
    }
    pending.delete(response.id);

    if (response.error !== undefined) {
      waiter.reject(new Error(response.error));
      return;
    }

    waiter.resolve(response.result ?? null);
  });

  serverProcess.stderr.on('data', (chunk: Buffer): void => {
    process.stderr.write(chunk);
  });

  await readyPromise;

  const call = async (method: string, params: unknown = {}): Promise<unknown> => {
    const id = nextId++;
    return new Promise<unknown>((resolvePromise, reject) => {
      pending.set(id, { resolve: resolvePromise, reject });
      serverProcess.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
    });
  };

  const stop = async (): Promise<void> => {
    responseReader.close();
    serverProcess.stdin.write('stop\n');
    await new Promise<void>((resolvePromise): void => {
      serverProcess.once('exit', (): void => resolvePromise());
      setTimeout((): void => {
        serverProcess.kill();
        resolvePromise();
      }, 10_000);
    });
  };

  return { call, stop };
}
