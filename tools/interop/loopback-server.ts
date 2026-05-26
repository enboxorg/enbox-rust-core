import { createInterface } from 'node:readline';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { resolve } from 'node:path';

const repoRoot = resolve(import.meta.dir, '../..');

export async function startLoopbackServer(): Promise<{
  endpoint: string;
  stop: () => Promise<void>;
}> {
  const serverProcess = spawn(
    'cargo',
    ['run', '--quiet', '-p', 'dwn-rs-stores', '--example', 'loopback_interop_server'],
    {
      cwd: repoRoot,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    },
  );

  const endpoint = await new Promise<string>((resolvePromise, reject) => {
    const timeout = setTimeout((): void => {
      reject(new Error('Timed out waiting for loopback interop server'));
    }, 120_000);

    const rl = createInterface({ input: serverProcess.stdout! });
    rl.on('line', (line): void => {
      if (line.startsWith('READY ')) {
        clearTimeout(timeout);
        rl.close();
        resolvePromise(line.slice('READY '.length).trim());
      }
    });

    serverProcess.stderr.on('data', (chunk: Buffer): void => {
      process.stderr.write(chunk);
    });

    serverProcess.on('exit', (code): void => {
      if (code !== 0 && code !== null) {
        clearTimeout(timeout);
        reject(new Error(`loopback interop server exited early with code ${code}`));
      }
    });
  });

  const stop = async (): Promise<void> => {
    serverProcess.stdin.write('stop\n');
    await new Promise<void>((resolvePromise): void => {
      serverProcess.once('exit', (): void => resolvePromise());
      setTimeout((): void => {
        serverProcess.kill();
        resolvePromise();
      }, 10_000);
    });
  };

  return { endpoint, stop };
}
