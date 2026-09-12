// Replays the grant-key coverage fixture against the TypeScript.
//
// The Rust side asserts the same fixture, so between them the two
// implementations are pinned to each other. This half is what stops the
// fixture drifting: if the TypeScript rule changes, the recorded expectations
// stop matching here and the fixture has to be regenerated deliberately rather
// than quietly carrying a stale answer that Rust then conforms to.

import { describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type CoverageCase = {
  id: string;
  grantKeyCoverage: {
    grantScope: Record<string, unknown>;
    deliveredScope: { protocol: string; protocolPath?: string };
    definition?: string;
    expectedEligible: boolean;
    expectedCovers: boolean;
  };
};

type CoverageFixture = {
  schemaVersion: number;
  source: { commit: string };
  definitions: Record<string, unknown>;
  cases: CoverageCase[];
};

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? resolve(repoRoot, '../enbox');

const fixture: CoverageFixture = JSON.parse(
  await readFile(resolve(repoRoot, 'fixtures/dwn/records/grant-key-coverage.json'), 'utf8'),
);

const { grantKeyScopeCoversDeliveredScope, isGrantKeyEligibleRecordsScope } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/utils/grant-key-coverage.ts')
);

describe('grant-key Read coverage', () => {
  test('the pinned commit is the one the fixture was generated from', async () => {
    const pin = (await readFile(resolve(repoRoot, '.enbox-version'), 'utf8'))
      .split('\n')
      .map((line) => line.trim())
      .find((line) => line.length > 0 && !line.startsWith('#'));
    expect(fixture.source.commit).toBe(pin);
  });

  for (const { id, grantKeyCoverage } of fixture.cases) {
    test(id, () => {
      const { grantScope, deliveredScope, definition, expectedEligible, expectedCovers } =
        grantKeyCoverage;

      const eligible = isGrantKeyEligibleRecordsScope(grantScope);
      expect(eligible).toBe(expectedEligible);

      const covers = eligible
        ? grantKeyScopeCoversDeliveredScope({
          grantScope,
          deliveredScope,
          protocolDefinition:
              definition === undefined ? undefined : fixture.definitions[definition],
        })
        : false;
      expect(covers).toBe(expectedCovers);
    });
  }
});
