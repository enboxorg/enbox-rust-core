import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONFORMANCE_ALICE_DID, CONFORMANCE_ALICE_KEY_ID, getConformanceAlicePersona } from './conformance-persona.ts';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? resolve(repoRoot, '../enbox');

const { TestDataGenerator } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/tests/utils/test-data-generator.ts')
);
const { Message } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/core/message.ts')
);

const tenant = CONFORMANCE_ALICE_DID;

async function buildTaggedWrite(options: {
  id: string;
  stringTag?: string;
  numberTag?: number;
  booleanTag?: boolean;
}) {
  const alice = await getConformanceAlicePersona();
  const tags: Record<string, unknown> = {};
  if (options.stringTag !== undefined) tags.stringTag = options.stringTag;
  if (options.numberTag !== undefined) tags.numberTag = options.numberTag;
  if (options.booleanTag !== undefined) tags.booleanTag = options.booleanTag;

  const { message, dataBytes } = await TestDataGenerator.generateRecordsWrite({
    author: alice,
    published: true,
    schema: 'http://example.com/post',
    tags,
  });
  const messageCid = await Message.getCid(message);
  return { ...options, message, messageCid, dataBytes };
}

function indexesFor(message: Record<string, unknown>) {
  const descriptor = message.descriptor as Record<string, unknown>;
  const tags = descriptor.tags as Record<string, unknown> | undefined;
  const indexes: Record<string, unknown> = {
    interface: 'Records',
    method: 'Write',
    published: true,
    isLatestBaseState: true,
    squash: false,
    author: tenant,
    recordId: message.recordId,
    entryId: `${tenant}/${message.recordId}`,
    schema: descriptor.schema,
    dateCreated: descriptor.dateCreated,
    messageTimestamp: descriptor.messageTimestamp,
  };
  if (message.contextId) {
    indexes.contextId = message.contextId;
  }
  for (const [key, value] of Object.entries(tags ?? {})) {
    indexes[`tag.${key}`] = value;
  }
  return indexes;
}

const writes = await Promise.all([
  buildTaggedWrite({ id: 'post-string-tag', stringTag: 'string-value' }),
  buildTaggedWrite({ id: 'post-number-tag', numberTag: 54566975 }),
  buildTaggedWrite({ id: 'post-boolean-tag-true', booleanTag: true }),
  buildTaggedWrite({ id: 'post-boolean-tag-false', booleanTag: false }),
]);

const seedSets = {
  'tagged-published-records': writes.map((write) => ({
    id: write.id,
    messageCid: write.messageCid,
    indexes: indexesFor(write.message as Record<string, unknown>),
    message: write.message,
    encodedData: Buffer.from(write.dataBytes).toString('base64url'),
  })),
};

async function queryCase(
  id: string,
  filter: Record<string, unknown>,
  expectedRecordIds: string[],
) {
  const alice = await getConformanceAlicePersona();
  const { message } = await TestDataGenerator.generateRecordsQuery({
    author: alice,
    filter: { published: true, ...filter },
  });
  return {
    id,
    rustStatus: 'supported' as const,
    recordsTagsQuery: {
      tenant,
      seedSet: 'tagged-published-records',
      request: { message },
      reply: {
        status: { code: 200, detail: 'OK' },
        entries: expectedRecordIds.map((recordId) => ({ recordId })),
        cursor: null,
      },
    },
  };
}

const byId = Object.fromEntries(writes.map((write) => [write.id, write]));

const cases = [
  await queryCase('query-string-tag-match', { tags: { stringTag: 'string-value' } }, [byId['post-string-tag'].message.recordId!]),
  await queryCase('query-string-tag-no-match', { tags: { stringTag: 'other-value' } }, []),
  await queryCase('query-number-tag-match', { tags: { numberTag: 54566975 } }, [byId['post-number-tag'].message.recordId!]),
  await queryCase('query-boolean-tag-true-match', { tags: { booleanTag: true } }, [byId['post-boolean-tag-true'].message.recordId!]),
  await queryCase('query-boolean-tag-false-match', { tags: { booleanTag: false } }, [byId['post-boolean-tag-false'].message.recordId!]),
];

const fixture = {
  schemaVersion: 1,
  source: {
    package: '@enbox/dwn-sdk-js',
    repository: 'enboxorg/enbox',
    commit: '1a227b0179f33e5d9ce3d68ba6275533ae306e2d',
    functions: ['RecordsWrite.create', 'RecordsQuery.create', 'Message.getCid'],
  },
  seedSets,
  cases,
};

const outPath = resolve(repoRoot, 'fixtures/dwn/records/tag-query-filters.json');
writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`Wrote ${outPath}`);
