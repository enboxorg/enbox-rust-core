import { describe, expect, test } from 'bun:test';
import { Buffer } from 'node:buffer';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type FixtureManifest = {
  schemaVersion: number;
  suites: FixtureSuiteRef[];
};

type FixtureSuiteRef = {
  id: string;
  path: string;
  assertions: string[];
};

type FixtureSet = {
  schemaVersion: number;
  cases: FixtureCase[];
};

type FixtureCase = {
  id: string;
  cek?: FixtureData;
  ciphertext?: FixtureData;
  contentEncryptionAlgorithm?: string;
  derivedPrivateJwk?: Record<string, unknown>;
  ephemeralPrivateJwk?: Record<string, unknown>;
  expectedErrorCode?: string;
  iv?: FixtureData;
  jwe?: JweEncryption;
  keyAgreementAlgorithm?: string;
  plaintext?: FixtureData;
  recipientPrivateJwk?: Record<string, unknown>;
  recipientPublicJwk?: Record<string, unknown>;
  record?: Record<string, unknown>;
  tag?: FixtureData;
};

type FixtureData =
  | { encoding: 'base64url'; value: string }
  | { encoding: 'hex'; value: string }
  | { encoding: 'repeatByte'; byte: number; length: number }
  | { encoding: 'utf8'; value: string };

type JweEncryption = {
  protected: string;
  iv: string;
  tag: string;
  recipients: Array<{
    encrypted_key: string;
    header: {
      derivationScheme: string;
      epk: Record<string, unknown>;
      kid: string;
      derivedPublicKey?: Record<string, unknown>;
    };
  }>;
};

type EncryptionModule = {
  Encryption: {
    aeadDecrypt(
      algorithm: string,
      keyBytes: Uint8Array,
      iv: Uint8Array,
      ciphertext: Uint8Array,
      tag: Uint8Array
    ): Promise<Uint8Array>;
    aeadEncrypt(
      algorithm: string,
      keyBytes: Uint8Array,
      iv: Uint8Array,
      plaintext: Uint8Array
    ): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }>;
    ecdhEsUnwrapKey(recipientPrivateKey: Record<string, unknown>, ephemeralPublicKey: Record<string, unknown>, wrappedKey: Uint8Array): Promise<Uint8Array>;
    ecdhEsWrapKey(ephemeralPrivateKey: Record<string, unknown>, recipientPublicKey: Record<string, unknown>, cek: Uint8Array): Promise<Uint8Array>;
    parseProtectedHeader(protectedBase64url: string): Record<string, unknown>;
  };
};

type RecordsModule = {
  Records: {
    decrypt(
      recordsWrite: Record<string, unknown>,
      ancestorPrivateKey: Record<string, unknown>,
      cipherStream: ReadableStream<Uint8Array>
    ): Promise<ReadableStream<Uint8Array>>;
  };
};

const jweProtectedAssertion = 'jwe.protected';
const jweAeadAssertion = 'jwe.aead';
const jweKeywrapAssertion = 'jwe.keywrap';
const jweDecryptAssertion = 'jwe.decrypt';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const encryptionModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/utils/encryption.ts');
const recordsModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/utils/records.ts');

for (const modulePath of [encryptionModulePath, recordsModulePath]) {
  if (!existsSync(modulePath)) {
    throw new Error(
      `Unable to find TypeScript DWN SDK at ${modulePath}. ` +
      'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
    );
  }
}

const { Encryption } = await import(pathToFileURL(encryptionModulePath).href) as EncryptionModule;
const { Records } = await import(pathToFileURL(recordsModulePath).href) as RecordsModule;
const manifest = await readJson<FixtureManifest>(resolve(fixturesRoot, 'manifest.json'));
const fixtureSuites = await Promise.all(
  manifest.suites.map(async (suite): Promise<{ fixtureSet: FixtureSet; suite: FixtureSuiteRef }> => ({
    suite,
    fixtureSet: await readJson<FixtureSet>(resolve(fixturesRoot, suite.path)),
  }))
);

describe('TypeScript JWE conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    if (
      !suite.assertions.includes(jweProtectedAssertion) &&
      !suite.assertions.includes(jweAeadAssertion) &&
      !suite.assertions.includes(jweKeywrapAssertion) &&
      !suite.assertions.includes(jweDecryptAssertion)
    ) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        if (suite.assertions.includes(jweProtectedAssertion)) {
          test(`${fixtureCase.id} protected header`, () => {
            const expectedProtectedHeader = {
              alg : keyAgreementAlgorithm(fixtureCase),
              enc : contentEncryptionAlgorithm(fixtureCase),
            };

            expect(Encryption.parseProtectedHeader(jwe(fixtureCase).protected)).toEqual(expectedProtectedHeader);
            expect(jwe(fixtureCase).protected).toBe(Buffer.from(JSON.stringify(expectedProtectedHeader)).toString('base64url'));
          });
        }

        if (suite.assertions.includes(jweAeadAssertion) && fixtureCase.expectedErrorCode === undefined) {
          test(`${fixtureCase.id} AEAD`, async () => {
            const encrypted = await Encryption.aeadEncrypt(
              contentEncryptionAlgorithm(fixtureCase),
              bytes(fixtureCase, fixtureCase.cek, 'CEK'),
              bytes(fixtureCase, fixtureCase.iv, 'IV'),
              bytes(fixtureCase, fixtureCase.plaintext, 'plaintext'),
            );

            expect(toBase64Url(encrypted.ciphertext)).toBe(base64UrlValue(fixtureCase, fixtureCase.ciphertext, 'ciphertext'));
            expect(toBase64Url(encrypted.tag)).toBe(base64UrlValue(fixtureCase, fixtureCase.tag, 'tag'));

            await expect(Encryption.aeadDecrypt(
              contentEncryptionAlgorithm(fixtureCase),
              bytes(fixtureCase, fixtureCase.cek, 'CEK'),
              bytes(fixtureCase, fixtureCase.iv, 'IV'),
              bytes(fixtureCase, fixtureCase.ciphertext, 'ciphertext'),
              bytes(fixtureCase, fixtureCase.tag, 'tag'),
            )).resolves.toEqual(bytes(fixtureCase, fixtureCase.plaintext, 'plaintext'));
          });
        }

        if (suite.assertions.includes(jweKeywrapAssertion)) {
          test(`${fixtureCase.id} key wrap`, async () => {
            const recipient = singleRecipient(fixtureCase);
            const wrappedKey = await Encryption.ecdhEsWrapKey(
              jwk(fixtureCase, fixtureCase.ephemeralPrivateJwk, 'ephemeralPrivateJwk'),
              jwk(fixtureCase, fixtureCase.recipientPublicJwk, 'recipientPublicJwk'),
              bytes(fixtureCase, fixtureCase.cek, 'CEK'),
            );

            expect(toBase64Url(wrappedKey)).toBe(recipient.encrypted_key);

            await expect(Encryption.ecdhEsUnwrapKey(
              jwk(fixtureCase, fixtureCase.recipientPrivateJwk, 'recipientPrivateJwk'),
              recipient.header.epk,
              wrappedKey,
            )).resolves.toEqual(bytes(fixtureCase, fixtureCase.cek, 'CEK'));
          });
        }

        if (suite.assertions.includes(jweDecryptAssertion)) {
          test(`${fixtureCase.id} decrypt`, async () => {
            const decrypted = decryptFixture(fixtureCase);

            if (fixtureCase.expectedErrorCode !== undefined) {
              await expect(decrypted).rejects.toThrow();
            } else {
              await expect(decrypted).resolves.toEqual(bytes(fixtureCase, fixtureCase.plaintext, 'plaintext'));
            }
          });
        }
      }
    });
  }
});

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

async function decryptFixture(fixtureCase: FixtureCase): Promise<Uint8Array> {
  const plaintextStream = await Records.decrypt(
    record(fixtureCase),
    jwk(fixtureCase, fixtureCase.derivedPrivateJwk, 'derivedPrivateJwk'),
    byteStream(bytes(fixtureCase, fixtureCase.ciphertext, 'ciphertext')),
  );

  return readStream(plaintextStream);
}

async function readStream(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];

  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    chunks.push(value);
  }

  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
}

function bytes(fixtureCase: FixtureCase, data: FixtureData | undefined, label: string): Uint8Array {
  if (data === undefined) {
    throw new Error(`${fixtureCase.id} must include ${label}`);
  }

  switch (data.encoding) {
  case 'base64url':
    return Uint8Array.from(Buffer.from(data.value, 'base64url'));
  case 'hex':
    return Uint8Array.from(Buffer.from(data.value, 'hex'));
  case 'repeatByte':
    return new Uint8Array(data.length).fill(data.byte);
  case 'utf8':
    return new TextEncoder().encode(data.value);
  }
}

function base64UrlValue(fixtureCase: FixtureCase, data: FixtureData | undefined, label: string): string {
  return toBase64Url(bytes(fixtureCase, data, label));
}

function toBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

function byteStream(payload: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller): void {
      controller.enqueue(payload);
      controller.close();
    },
  });
}

function jwe(fixtureCase: FixtureCase): JweEncryption {
  if (fixtureCase.jwe === undefined) {
    throw new Error(`${fixtureCase.id} must include a JWE`);
  }

  return fixtureCase.jwe;
}

function singleRecipient(fixtureCase: FixtureCase): JweEncryption['recipients'][number] {
  const recipients = jwe(fixtureCase).recipients;
  expect(recipients.length).toBe(1);

  return recipients[0];
}

function keyAgreementAlgorithm(fixtureCase: FixtureCase): string {
  if (fixtureCase.keyAgreementAlgorithm === undefined) {
    throw new Error(`${fixtureCase.id} must include keyAgreementAlgorithm`);
  }

  return fixtureCase.keyAgreementAlgorithm;
}

function contentEncryptionAlgorithm(fixtureCase: FixtureCase): string {
  if (fixtureCase.contentEncryptionAlgorithm === undefined) {
    throw new Error(`${fixtureCase.id} must include contentEncryptionAlgorithm`);
  }

  return fixtureCase.contentEncryptionAlgorithm;
}

function jwk(fixtureCase: FixtureCase, value: Record<string, unknown> | undefined, label: string): Record<string, unknown> {
  if (value === undefined) {
    throw new Error(`${fixtureCase.id} must include ${label}`);
  }

  return value;
}

function record(fixtureCase: FixtureCase): Record<string, unknown> {
  if (fixtureCase.record === undefined) {
    throw new Error(`${fixtureCase.id} must include record`);
  }

  return fixtureCase.record;
}
