import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? resolve(repoRoot, '../enbox');

const { getConformanceAlicePersona } = await import('./conformance-persona.ts');

const { RecordsCount } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/interfaces/records-count.ts')
);
const { RecordsDelete } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/interfaces/records-delete.ts')
);
const { RecordsQuery } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/interfaces/records-query.ts')
);
const { RecordsRead } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/interfaces/records-read.ts')
);
const { RecordsSubscribe } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/interfaces/records-subscribe.ts')
);
const { Message } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/core/message.ts')
);
const { Cid } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/utils/cid.ts')
);

// Provenance pin: generated vectors must match .enbox-version.
const pin = readFileSync(resolve(repoRoot, '.enbox-version'), 'utf8')
  .split('\n')
  .map((line) => line.trim())
  .find((line) => line !== '' && !line.startsWith('#'))!;

// Synthetic grant ids: these vectors prove the descriptor wire shape and its
// CID binding, not grant authorization (see the Rust handler tests for that).
async function grantCase(
  id: string,
  description: string,
  message: { descriptor: unknown; authorization?: unknown },
) {
  // Unsigned creates leave `authorization: undefined`, which IPLD cannot
  // encode; the wire shape carries no authorization key at all.
  const wireMessage =
    message.authorization === undefined ? { descriptor: message.descriptor } : message;
  const descriptorCid = await Cid.computeCid(wireMessage.descriptor);
  const messageCid = await Message.getCid(wireMessage as never);
  return {
    id,
    description,
    rustStatus: 'supported' as const,
    descriptorCid,
    messageCid,
    message: wireMessage,
  };
}

const cases = [
  await grantCase(
    'records-query-permission-grant',
    'Current TypeScript RecordsQuery includes permissionGrantId in the descriptor when provided.',
    (
      await RecordsQuery.create({
        messageTimestamp: '2025-01-01T00:00:12.000000Z',
        filter: { protocol: 'https://example.com/protocol' },
        permissionGrantId: 'grant-query-123',
      })
    ).message,
  ),
  await grantCase(
    'records-count-permission-grant',
    'Current TypeScript RecordsCount includes permissionGrantId in the descriptor when provided.',
    (
      await RecordsCount.create({
        messageTimestamp: '2025-01-01T00:00:13.000000Z',
        filter: { protocol: 'https://example.com/protocol' },
        permissionGrantId: 'grant-count-123',
      })
    ).message,
  ),
  await grantCase(
    'records-subscribe-permission-grant',
    'Current TypeScript RecordsSubscribe includes permissionGrantId in the descriptor when provided.',
    (
      await RecordsSubscribe.create({
        messageTimestamp: '2025-01-01T00:00:14.000000Z',
        filter: { protocol: 'https://example.com/protocol' },
        permissionGrantId: 'grant-subscribe-123',
      })
    ).message,
  ),
  await grantCase(
    'records-delete-permission-grant',
    'Current TypeScript RecordsDelete includes permissionGrantId in the descriptor when provided.',
    (
      await RecordsDelete.create({
        recordId: 'record-1',
        messageTimestamp: '2025-01-01T00:00:15.000000Z',
        permissionGrantId: 'grant-delete-123',
        signer: (await getConformanceAlicePersona()).signer as never,
      })
    ).message,
  ),
  await grantCase(
    'records-read-permission-grant',
    'Current TypeScript RecordsRead includes permissionGrantId in the descriptor when provided.',
    (
      await RecordsRead.create({
        messageTimestamp: '2025-01-01T00:00:16.000000Z',
        filter: { recordId: 'record-2' },
        permissionGrantId: 'grant-read-123',
      })
    ).message,
  ),
];

const fixture = {
  schemaVersion: 1,
  source: {
    package: '@enbox/dwn-sdk-js',
    repository: 'enboxorg/enbox',
    commit: pin,
    functions: [
      'RecordsQuery.create',
      'RecordsCount.create',
      'RecordsSubscribe.create',
      'RecordsDelete.create',
      'RecordsRead.create',
    ],
    cidFunction: 'Cid.computeCid',
  },
  cases,
};

const outPath = resolve(repoRoot, 'fixtures/dwn/records/collection-grant-invocation.json');
writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`Wrote ${outPath}`);
