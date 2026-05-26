import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONFORMANCE_ALICE_DID, getConformanceAlicePersona } from './conformance-persona.ts';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? resolve(repoRoot, '../enbox');

const { TestDataGenerator } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/tests/utils/test-data-generator.ts')
);
const { PermissionsProtocol } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/index.ts')
);

const tenant = CONFORMANCE_ALICE_DID;
const grantProtocol = 'https://example.com/protocol/notes';

const permissionsFixture = JSON.parse(
  readFileSync(resolve(repoRoot, 'fixtures/dwn/protocols/permissions-protocol-records.json'), 'utf8'),
) as { cases: Array<{ id: string; message: Record<string, unknown>; data?: { value: string } }> };

const grantCase = permissionsFixture.cases.find((entry) => entry.id === 'permissions-grant-records-write');
if (!grantCase) {
  throw new Error('permissions-grant-records-write fixture case not found');
}

function indexesForGrant(message: Record<string, unknown>) {
  const descriptor = message.descriptor as Record<string, unknown>;
  const tags = descriptor.tags as Record<string, unknown> | undefined;
  return {
    interface: 'Records',
    method: 'Write',
    published: false,
    isLatestBaseState: true,
    squash: false,
    author: tenant,
    recordId: message.recordId,
    entryId: `${tenant}/${message.recordId}`,
    protocol: descriptor.protocol,
    protocolPath: descriptor.protocolPath,
    recipient: descriptor.recipient,
    dateCreated: descriptor.dateCreated,
    messageTimestamp: descriptor.messageTimestamp,
    contextId: message.contextId,
    ...(tags ? Object.fromEntries(Object.entries(tags).map(([key, value]) => [`tag.${key}`, value])) : {}),
  };
}

const seedSets = {
  'permissions-grants': [
    {
      id: 'permissions-grant-records-write',
      messageCid: 'bafyreibt53orcpk6vituo7sm2s7etwaa3x7hhfkjx6hwlpqixk7wglef3i',
      indexes: indexesForGrant(grantCase.message),
      message: grantCase.message,
      encodedData: Buffer.from(grantCase.data!.value, 'utf8').toString('base64url'),
    },
  ],
};

async function grantQueryCase(id: string, filter: Record<string, unknown>, expectedCount: number) {
  const alice = await getConformanceAlicePersona();
  const { message } = await TestDataGenerator.generateRecordsQuery({
    author: alice,
    filter: {
      protocol: PermissionsProtocol.uri,
      protocolPath: PermissionsProtocol.grantPath,
      ...filter,
    },
  });
  return {
    id,
    rustStatus: 'supported' as const,
    permissionsGrantQuery: {
      tenant,
      seedSet: 'permissions-grants',
      request: { message },
      reply: {
        status: { code: 200, detail: 'OK' },
        entries: expectedCount === 1 ? [{ recordId: grantCase.message.recordId }] : [],
        cursor: null,
      },
    },
  };
}

const cases = [
  await grantQueryCase('query-permissions-grant-by-path', {}, 1),
  await grantQueryCase(
    'query-permissions-grant-by-protocol-tag',
    { tags: { protocol: grantProtocol } },
    1,
  ),
  await grantQueryCase(
    'query-permissions-grant-tag-no-match',
    { tags: { protocol: 'https://example.com/other' } },
    0,
  ),
];

const fixture = {
  schemaVersion: 1,
  source: {
    package: '@enbox/dwn-sdk-js',
    repository: 'enboxorg/enbox',
    commit: '1a227b0179f33e5d9ce3d68ba6275533ae306e2d',
    functions: [
      'PermissionsProtocol.createGrant',
      'RecordsQuery.create',
      'PermissionsProtocol.grantPath',
    ],
  },
  seedSets,
  cases,
};

const outPath = resolve(repoRoot, 'fixtures/dwn/protocols/permissions-grant-query.json');
writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`Wrote ${outPath}`);
