import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Scaffold for running the full dwn-sdk-js injectable suite against Rust-backed stores.
 *
 * Target wiring:
 * - expose MessageStore/DataStore/StateIndex/EventLog/ResumableTaskStore via enbox-ffi or WASM
 * - call TestSuite.runInjectableDependentTests({ ...rustStores })
 *
 * See docs/TEST_COVERAGE.md (layer 5) for status.
 *
 * Do not import `test-suite.ts` here: many Enbox spec modules self-register tests at import time.
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const testSuiteModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/tests/test-suite.ts');

if (!existsSync(testSuiteModulePath)) {
  throw new Error(
    `Unable to find dwn-sdk-js TestSuite at ${testSuiteModulePath}. ` +
    'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
  );
}

describe('TestSuite store injection scaffold', () => {
  test('TestSuite module is present for future Rust store adapters', () => {
    expect(existsSync(testSuiteModulePath)).toBe(true);
  });

  test.skip('Rust-backed stores via FFI/WASM (wire enbox-ffi adapters here)', () => {
    // Future entry point (run from a dedicated harness, not this scaffold):
    // import { TestSuite } from '@enbox/dwn-sdk-js/tests/test-suite.js';
    // TestSuite.runInjectableDependentTests({
    //   messageStore: rustMessageStoreAdapter,
    //   dataStore: rustDataStoreAdapter,
    //   stateIndex: rustStateIndexAdapter,
    //   eventLog: rustEventLogAdapter,
    //   resumableTaskStore: rustResumableTaskStoreAdapter,
    // });
  });
});
