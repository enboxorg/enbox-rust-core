// Generates fixtures/dwn/protocols/permissions-protocol-records.json from the
// pinned Permissions module at ENBOX_TS_ROOT.
//
// Run with:
//   ENBOX_TS_ROOT=/path/to/enbox bun tools/conformance/generate-permissions-records-fixtures.ts

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONFORMANCE_ALICE_DID, getConformanceAlicePersona } from './conformance-persona.ts';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? resolve(repoRoot, '../enbox');

const { PermissionsModule, RecordsWrite } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/index.ts')
);
const { Cid } = await import(resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/utils/cid.ts'));
const { Message } = await import(resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/core/message.ts'));
const { Encoder } = await import(resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/utils/encoder.ts'));

const pin = readFileSync(resolve(repoRoot, '.enbox-version'), 'utf8')
  .split('\n')
  .map((line) => line.trim())
  .find((line) => line !== '' && !line.startsWith('#'))!;

const alice = await getConformanceAlicePersona();
const scope = {
  interface: 'Records',
  method: 'Write',
  module: 'https://example.com/protocol/notes',
  modulePath: 'note',
};
const conditions = { publication: 'Required' };

const request = await PermissionsModule.createRequest({
  signer: alice.signer as never,
  dateRequested: '2025-01-01T00:02:00.000000Z',
  description: 'Request write access to protocol notes.',
  delegated: false,
  scope,
  conditions,
});

const grant = await PermissionsModule.createGrant({
  signer: alice.signer as never,
  grantedTo: 'did:example:bob',
  dateGranted: '2025-01-01T00:02:01.000000Z',
  dateExpires: '2025-02-01T00:00:00.000000Z',
  requestId: request.recordsWrite.message.recordId,
  description: 'Grant write access to protocol notes.',
  delegated: true,
  scope,
  conditions,
});

const revocationBytes = Encoder.objectToBytes({ description: 'Revoke delegated note write access.' });
const revocationWrite = await RecordsWrite.create({
  signer: alice.signer as never,
  messageTimestamp: '2025-01-01T00:02:02.000000Z',
  parentContextId: grant.recordsWrite.message.recordId,
  module: PermissionsModule.uri,
  modulePath: PermissionsModule.revocationPath,
  dataFormat: 'application/json',
  data: revocationBytes,
  tags: { module: 'https://example.com/protocol/notes' },
});

async function caseFor(
  id: string,
  permissionKind: 'request' | 'grant' | 'revocation',
  dataEncodedMessage: Record<string, any>,
  dataBytes: Uint8Array,
  permissionData: Record<string, unknown>,
) {
  const { encodedData: _encodedData, ...message } = dataEncodedMessage;
  const descriptor = message.descriptor as Record<string, unknown>;
  return {
    id,
    description: `${permissionKind} permission record written to the Permissions module.`,
    rustStatus: 'supported' as const,
    permissionKind,
    permissionData,
    expected: { statusCode: 202 },
    cid: await Cid.computeDagPbCidFromBytes(dataBytes),
    dataCid: await Cid.computeDagPbCidFromBytes(dataBytes),
    dataSize: dataBytes.byteLength,
    data: { encoding: 'utf8' as const, value: Encoder.bytesToString(dataBytes) },
    descriptorCid: await Cid.computeCid(descriptor),
    messageCid: await Message.getCid(message as never),
    message,
  };
}

const cases = [
  await caseFor(
    'permissions-request-records-write',
    'request',
    request.dataEncodedMessage,
    request.permissionRequestBytes,
    request.permissionRequestData as unknown as Record<string, unknown>,
  ),
  await caseFor(
    'permissions-grant-records-write',
    'grant',
    grant.dataEncodedMessage,
    grant.permissionGrantBytes,
    grant.permissionGrantData as unknown as Record<string, unknown>,
  ),
  await caseFor(
    'permissions-revocation-records-write',
    'revocation',
    { ...revocationWrite.message, encodedData: Encoder.bytesToBase64Url(revocationBytes) },
    revocationBytes,
    { description: 'Revoke delegated note write access.' },
  ),
];

const fixture = {
  schemaVersion: 1,
  source: {
    package: '@enbox/dwn-sdk-js',
    repository: 'enboxorg/enbox',
    commit: pin,
    functions: [
      'RecordsWrite.create',
      'PermissionsModule.requestPath',
      'PermissionsModule.grantPath',
      'PermissionsModule.revocationPath',
      'Encoder.objectToBytes',
      'Cid.computeCid',
      'Cid.computeDagPbCidFromBytes',
    ],
  },
  cases,
};

const outPath = resolve(repoRoot, 'fixtures/dwn/protocols/permissions-protocol-records.json');
writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`Wrote ${outPath}`);
void CONFORMANCE_ALICE_DID;
