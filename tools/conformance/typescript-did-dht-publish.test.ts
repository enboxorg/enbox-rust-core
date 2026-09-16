import { describe, expect, test } from 'bun:test';
import { Buffer } from 'node:buffer';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures/interop');
const rustBlobPath = resolve(repoRoot, 'crates/did-dht/tests/fixtures/rust-publish-bytes.json');
const tsFixturePath = resolve(fixturesRoot, 'did-dht-publish.json');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? resolve(repoRoot, '../enbox');
const didDhtDnsPath = resolve(enboxTsRoot, 'packages/dids/src/methods/did-dht-dns.ts');
const dnsPacketPath = resolve(
  enboxTsRoot,
  'packages/dids/node_modules/@dnsquery/dns-packet/index.mjs'
);

for (const modulePath of [didDhtDnsPath, dnsPacketPath, rustBlobPath, tsFixturePath]) {
  if (!existsSync(modulePath)) {
    throw new Error(
      `Unable to find ${modulePath}. ` +
      'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
    );
  }
}

const { fromDnsPacket } = await import(didDhtDnsPath);
const { decode: dnsPacketDecode } = await import(dnsPacketPath);

async function decodeFixtureBytes(dnsBytesBase64Url: string, didUri: string) {
  const dnsPacket = dnsPacketDecode(Buffer.from(dnsBytesBase64Url, 'base64url'));
  return fromDnsPacket({ didUri, dnsPacket });
}

describe('did:dht publish interop', () => {
  test('pinned TypeScript decoder accepts Rust DNS bytes', async () => {
    const blob = JSON.parse(await readFile(rustBlobPath, 'utf8'));
    const { didDocument, didDocumentMetadata } = await decodeFixtureBytes(
      blob.dnsBytes,
      blob.didDocument.id
    );

    expect(didDocument).toEqual(blob.didDocument);
    expect(didDocumentMetadata.types).toEqual(blob.types);
  });

  test('TypeScript fixture decodes to its own document', async () => {
    const fixture = JSON.parse(await readFile(tsFixturePath, 'utf8'));
    const { didDocument, didDocumentMetadata } = await decodeFixtureBytes(
      fixture.vector.dnsBytes,
      fixture.vector.didDocument.id
    );

    expect(didDocument).toEqual(fixture.vector.didDocument);
    expect(didDocumentMetadata.types).toEqual(fixture.vector.didMetadata.types);
  });
});
