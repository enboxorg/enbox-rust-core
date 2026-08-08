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
  derivationScheme?: string;
  encryption?: DwnEncryption;
  expectedErrorCode?: string;
  iv?: FixtureData;
  keyAgreementAlgorithm?: string;
  keyId?: string;
  plaintext?: FixtureData;
  recipientPrivateJwk?: Record<string, unknown>;
  recipientPublicJwk?: Record<string, unknown>;
  record?: Record<string, unknown>;
  derivedPrivateJwk?: DerivedPrivateJwk;
  ephemeralPublicJwk?: Record<string, unknown>;
};

type DerivedPrivateJwk = {
  rootKeyId: string;
  derivationScheme: string;
  derivationPath?: string[];
  derivedPrivateKey: Record<string, unknown>;
};

type FixtureData =
  | { encoding: 'base64url'; value: string }
  | { encoding: 'hex'; value: string }
  | { encoding: 'repeatByte'; byte: number; length: number }
  | { encoding: 'utf8'; value: string };

type DwnEncryption = {
  algorithm: string;
  initializationVector: string;
  keyEncryption: Array<{
    algorithm: string;
    keyId: string;
    ephemeralPublicKey: Record<string, unknown>;
    encryptedKey: string;
    derivationScheme: string;
  }>;
};

type EncryptionModule = {
  Encryption: {
    decrypt(
      algorithm: string,
      keyBytes: Uint8Array,
      iv: Uint8Array,
      ciphertext: Uint8Array,
    ): Promise<Uint8Array>;
    encrypt(
      algorithm: string,
      keyBytes: Uint8Array,
      iv: Uint8Array,
      plaintext: Uint8Array,
    ): Promise<Uint8Array>;
    unwrapKey(
      recipientPrivateKey: Record<string, unknown>,
      keyEncryption: DwnEncryption['keyEncryption'][number],
    ): Promise<Uint8Array>;
  };
};

type RecordsModule = {
  Records: {
    decrypt(
      recordsWrite: Record<string, unknown>,
      keyDecrypter: KeyDecrypter,
      cipherStream: ReadableStream<Uint8Array>,
    ): Promise<ReadableStream<Uint8Array>>;
  };
};

type KeyDecrypter = {
  rootKeyId: string;
  derivationScheme: string;
  derivePublicKey(fullDerivationPath: string[]): Promise<Record<string, unknown>>;
  decrypt(
    fullDerivationPath: string[],
    keyUnwrapPayload: { encryptedKey: Uint8Array; ephemeralPublicKey: Record<string, unknown>; keyEncryption: DwnEncryption['keyEncryption'][number] },
  ): Promise<Uint8Array>;
};

const jweEnvelopeAssertion = 'jwe.envelope';
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

describe('TypeScript A256CTR JWE conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    if (
      !suite.assertions.includes(jweEnvelopeAssertion) &&
      !suite.assertions.includes(jweAeadAssertion) &&
      !suite.assertions.includes(jweKeywrapAssertion) &&
      !suite.assertions.includes(jweDecryptAssertion)
    ) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        if (fixtureCase.expectedErrorCode !== undefined) {
          continue;
        }

        if (suite.assertions.includes(jweEnvelopeAssertion) && fixtureCase.expectedErrorCode === undefined) {
          test(`${fixtureCase.id} envelope`, async () => {
            await assertEnvelope(fixtureCase);
          });
        }

        if (suite.assertions.includes(jweAeadAssertion) && fixtureCase.expectedErrorCode === undefined) {
          test(`${fixtureCase.id} A256CTR`, async () => {
            await assertAead(fixtureCase);
          });
        }

        if (suite.assertions.includes(jweKeywrapAssertion) && fixtureCase.expectedErrorCode === undefined) {
          test(`${fixtureCase.id} key wrap`, async () => {
            await assertKeywrap(fixtureCase);
          });
        }

        if (suite.assertions.includes(jweDecryptAssertion)) {
          test(`${fixtureCase.id} decrypt`, async () => {
            const decrypt = assertDecrypt(fixtureCase);
            if (fixtureCase.expectedErrorCode !== undefined) {
              await expect(decrypt).rejects.toMatchObject({ code: fixtureCase.expectedErrorCode });
            } else {
              await decrypt;
            }
          });
        }
      }
    });
  }
});

async function assertEnvelope(fixtureCase: FixtureCase): Promise<void> {
  const encryption = dwnEncryption(fixtureCase);
  expect(encryption.algorithm).toBe(fixtureCase.contentEncryptionAlgorithm);
  expect(encryption.initializationVector).toBe(base64UrlValue(fixtureCase, fixtureCase.iv, 'IV'));

  const entry = singleKeyEncryption(fixtureCase);
  expect(entry.algorithm).toBe(fixtureCase.keyAgreementAlgorithm);
  expect(entry.keyId).toBe(fixtureCase.keyId);
  expect(entry.derivationScheme).toBe(fixtureCase.derivationScheme);
  expect(entry.encryptedKey).not.toBe('');
  if (fixtureCase.ephemeralPublicJwk !== undefined) {
    expect(entry.ephemeralPublicKey).toMatchObject(fixtureCase.ephemeralPublicJwk);
  }

  const record = fixtureCase.record!;
  const recordEncryption = record.encryption as DwnEncryption;
  expect(recordEncryption).toEqual(encryption);
}

async function assertAead(fixtureCase: FixtureCase): Promise<void> {
  const encrypted = await Encryption.encrypt(
    contentEncryptionAlgorithm(fixtureCase),
    bytes(fixtureCase, fixtureCase.cek, 'CEK'),
    bytes(fixtureCase, fixtureCase.iv, 'IV'),
    bytes(fixtureCase, fixtureCase.plaintext, 'plaintext'),
  );

  expect(toBase64Url(encrypted)).toBe(base64UrlValue(fixtureCase, fixtureCase.ciphertext, 'ciphertext'));

  await expect(Encryption.decrypt(
    contentEncryptionAlgorithm(fixtureCase),
    bytes(fixtureCase, fixtureCase.cek, 'CEK'),
    bytes(fixtureCase, fixtureCase.iv, 'IV'),
    bytes(fixtureCase, fixtureCase.ciphertext, 'ciphertext'),
  )).resolves.toEqual(bytes(fixtureCase, fixtureCase.plaintext, 'plaintext'));
}

async function assertKeywrap(fixtureCase: FixtureCase): Promise<void> {
  const entry = singleKeyEncryption(fixtureCase);
  const unwrapped = await Encryption.unwrapKey(
    fixtureJwk(fixtureCase, fixtureCase.recipientPrivateJwk, 'recipientPrivateJwk'),
    entry,
  );

  expect(toBase64Url(unwrapped)).toBe(toBase64Url(bytes(fixtureCase, fixtureCase.cek, 'CEK')));
}

async function assertDecrypt(fixtureCase: FixtureCase): Promise<void> {
  const decrypt = Records.decrypt(
    fixtureCase.record!,
    keyDecrypter(fixtureCase),
    byteStream(bytes(fixtureCase, fixtureCase.ciphertext, 'ciphertext')),
  );

  const plaintextStream = await decrypt;
  const plaintext = await readStream(plaintextStream);
  expect(toBase64Url(plaintext)).toBe(base64UrlValue(fixtureCase, fixtureCase.plaintext, 'plaintext'));
}

function keyDecrypter(fixtureCase: FixtureCase): KeyDecrypter {
  const derived = fixtureCase.derivedPrivateJwk!;
  const derivationPath = derived.derivationPath ?? [];
  return {
    rootKeyId        : derived.rootKeyId,
    derivationScheme : derived.derivationScheme,
    async derivePublicKey(_fullDerivationPath: string[]): Promise<Record<string, unknown>> {
      return fixtureJwk(fixtureCase, fixtureCase.recipientPublicJwk, 'recipientPublicJwk');
    },
    async decrypt(_fullDerivationPath: string[], payload): Promise<Uint8Array> {
      return Encryption.unwrapKey(derived.derivedPrivateKey, payload.keyEncryption);
    },
  };
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

function dwnEncryption(fixtureCase: FixtureCase): DwnEncryption {
  if (fixtureCase.encryption === undefined) {
    throw new Error(`${fixtureCase.id} must include an encryption envelope`);
  }

  return fixtureCase.encryption;
}

function singleKeyEncryption(fixtureCase: FixtureCase): DwnEncryption['keyEncryption'][number] {
  const keyEncryption = dwnEncryption(fixtureCase).keyEncryption;
  expect(keyEncryption.length).toBe(1);

  return keyEncryption[0];
}

function contentEncryptionAlgorithm(fixtureCase: FixtureCase): string {
  if (fixtureCase.contentEncryptionAlgorithm === undefined) {
    throw new Error(`${fixtureCase.id} must include contentEncryptionAlgorithm`);
  }

  return fixtureCase.contentEncryptionAlgorithm;
}

function fixtureJwk(fixtureCase: FixtureCase, value: Record<string, unknown> | undefined, label: string): Record<string, unknown> {
  if (value === undefined) {
    throw new Error(`${fixtureCase.id} must include ${label}`);
  }

  return value;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}
