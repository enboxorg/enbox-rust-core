import { afterAll, describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createRustSqliteMessageStore } from './rust-sqlite-message-store.ts';
import { startStoreInjectionServer } from './store-injection-server.ts';

/**
 * Layer 5 (issue #169): run the dwn-sdk-js message-store spec battery
 * against the Rust SQLite backend through the JSON-RPC injection server.
 *
 * Scope is deliberately the message-store spec only: DataStore, EventLog
 * and ResumableTaskStore adapters are future work tracked by the Layer 5
 * row in docs/TEST_COVERAGE.md.
 *
 * Requires ENBOX_TS_ROOT pointing at the pinned enbox checkout
 * (see .enbox-version; CI checks it out at ./enbox).
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const testSuiteModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/tests/test-suite.ts');
const messageStoreSpecPath = resolve(
  enboxTsRoot,
  'packages/dwn-sdk-js/tests/store/message-store.spec.ts',
);

if (!existsSync(testSuiteModulePath)) {
  throw new Error(
    `Unable to find dwn-sdk-js TestSuite at ${testSuiteModulePath}. ` +
    'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.',
  );
}

let client: Awaited<ReturnType<typeof startStoreInjectionServer>> | undefined;

try {
  client = await startStoreInjectionServer();
} catch (error) {
  // Fail fast with a clear message instead of a passing empty suite.
  test('store injection server starts', () => {
    throw error;
  });
}

afterAll(async () => {
  await client?.stop();
  client = undefined;
});

if (client !== undefined) {
  const messageStore = createRustSqliteMessageStore(client);

  const [{ TestStores }, { testMessageStore }] = await Promise.all([
    import(resolve(enboxTsRoot, 'packages/dwn-sdk-js/tests/test-stores.js')),
    import(messageStoreSpecPath),
  ]);

  TestStores.override({ messageStore });

  describe('Rust SQLite message store against dwn-sdk-js store specs', () => {
    test('TestSuite module is present for injected Rust store adapters', () => {
      expect(existsSync(testSuiteModulePath)).toBe(true);
    });

    testMessageStore();
  });
}
