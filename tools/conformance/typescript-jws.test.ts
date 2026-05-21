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
  keys?: Record<string, FixtureKey>;
  cases: FixtureCase[];
};

type FixtureCase = {
  id: string;
  expectedErrorCode?: string;
  expectedSigners?: string[];
  jws?: GeneralJws;
  payload?: FixturePayload;
  signerIds?: string[];
};

type FixtureKey = {
  kid: string;
  algorithm: string;
  publicJwk: Record<string, unknown>;
  privateJwk?: Record<string, unknown>;
};

type FixturePayload =
  | { encoding: 'base64url'; value: string }
  | { encoding: 'json'; value: unknown }
  | { encoding: 'utf8'; value: string };

type GeneralJws = {
  payload: string;
  signatures: Array<{
    protected: string;
    signature: string;
  }>;
};

type MessageSigner = {
  algorithm: string;
  keyId: string;
  sign(content: Uint8Array): Promise<Uint8Array>;
};

type GeneralJwsBuilderModule = {
  GeneralJwsBuilder: {
    create(payload: Uint8Array, signers: MessageSigner[]): Promise<{ getJws(): GeneralJws }>;
  };
};

type GeneralJwsVerifierModule = {
  GeneralJwsVerifier: {
    verifySignatures(jws: GeneralJws, didResolver: DidResolver): Promise<{ signers: string[] }>;
  };
};

type PrivateKeySignerModule = {
  PrivateKeySigner: new (options: { algorithm?: string; keyId: string; privateJwk: Record<string, unknown> }) => MessageSigner;
};

type DidResolver = {
  resolve(did: string): Promise<{
    didDocument: {
      verificationMethod: Array<{
        controller: string;
        id: string;
        publicKeyJwk: Record<string, unknown>;
        type: string;
      }>;
    };
    didDocumentMetadata: Record<string, unknown>;
    didResolutionMetadata: Record<string, unknown>;
  }>;
};

const jwsGeneralSignAssertion = 'jws.general.sign';
const jwsGeneralVerifyAssertion = 'jws.general.verify';
const jwsGeneralPayloadAssertion = 'jws.general.payload';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const builderModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/jose/jws/general/builder.ts');
const verifierModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/jose/jws/general/verifier.ts');
const signerModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/utils/private-key-signer.ts');

for (const modulePath of [builderModulePath, verifierModulePath, signerModulePath]) {
  if (!existsSync(modulePath)) {
    throw new Error(
      `Unable to find TypeScript DWN SDK at ${modulePath}. ` +
      'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
    );
  }
}

const { GeneralJwsBuilder } = await import(pathToFileURL(builderModulePath).href) as GeneralJwsBuilderModule;
const { GeneralJwsVerifier } = await import(pathToFileURL(verifierModulePath).href) as GeneralJwsVerifierModule;
const { PrivateKeySigner } = await import(pathToFileURL(signerModulePath).href) as PrivateKeySignerModule;
const manifest = await readJson<FixtureManifest>(resolve(fixturesRoot, 'manifest.json'));
const fixtureSuites = await Promise.all(
  manifest.suites.map(async (suite): Promise<{ fixtureSet: FixtureSet; suite: FixtureSuiteRef }> => ({
    suite,
    fixtureSet: await readJson<FixtureSet>(resolve(fixturesRoot, suite.path)),
  }))
);

describe('TypeScript JWS conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    if (
      !suite.assertions.includes(jwsGeneralSignAssertion) &&
      !suite.assertions.includes(jwsGeneralVerifyAssertion) &&
      !suite.assertions.includes(jwsGeneralPayloadAssertion)
    ) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        if (suite.assertions.includes(jwsGeneralPayloadAssertion)) {
          test(`${fixtureCase.id} payload`, () => {
            expect(Buffer.from(payloadBytes(fixtureCase)).toString('base64url')).toBe(jws(fixtureCase).payload);
          });
        }

        if (suite.assertions.includes(jwsGeneralSignAssertion) && fixtureCase.expectedErrorCode === undefined) {
          test(`${fixtureCase.id} signing`, async () => {
            const builder = await GeneralJwsBuilder.create(payloadBytes(fixtureCase), signingKeys(fixtureSet, fixtureCase));
            expect(builder.getJws()).toEqual(jws(fixtureCase));
          });
        }

        if (suite.assertions.includes(jwsGeneralVerifyAssertion)) {
          test(`${fixtureCase.id} verification`, async () => {
            const verification = GeneralJwsVerifier.verifySignatures(jws(fixtureCase), didResolver(fixtureSet, fixtureCase));

            if (fixtureCase.expectedErrorCode !== undefined) {
              await expect(verification).rejects.toMatchObject({ code: fixtureCase.expectedErrorCode });
            } else {
              await expect(verification).resolves.toEqual({ signers: expectedSigners(fixtureCase) });
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

function payloadBytes(fixtureCase: FixtureCase): Uint8Array {
  const payload = fixtureCase.payload;
  if (payload === undefined) {
    throw new Error(`${fixtureCase.id} must include a payload`);
  }

  switch (payload.encoding) {
  case 'base64url':
    return Uint8Array.from(Buffer.from(payload.value, 'base64url'));
  case 'json':
    return new TextEncoder().encode(JSON.stringify(payload.value));
  case 'utf8':
    return new TextEncoder().encode(payload.value);
  }
}

function signingKeys(fixtureSet: FixtureSet, fixtureCase: FixtureCase): MessageSigner[] {
  return signerIds(fixtureCase).map((signerId) => {
    const key = fixtureKey(fixtureSet, fixtureCase, signerId);
    if (key.privateJwk === undefined) {
      throw new Error(`${fixtureCase.id} signer ${signerId} must include a privateJwk`);
    }

    return new PrivateKeySigner({
      algorithm  : key.algorithm,
      keyId      : key.kid,
      privateJwk : key.privateJwk,
    });
  });
}

function didResolver(fixtureSet: FixtureSet, fixtureCase: FixtureCase): DidResolver {
  const methodsByDid = new Map<string, DidResolverMethod[]>();

  for (const signerId of signerIds(fixtureCase)) {
    const key = fixtureKey(fixtureSet, fixtureCase, signerId);
    const did = didFromKid(key.kid);
    const methods = methodsByDid.get(did) ?? [];
    methods.push({
      controller   : did,
      id           : key.kid,
      publicKeyJwk : key.publicJwk,
      type         : 'JsonWebKey2020',
    });
    methodsByDid.set(did, methods);
  }

  return {
    async resolve(did: string) {
      return {
        didDocument: {
          verificationMethod: methodsByDid.get(did) ?? [],
        },
        didDocumentMetadata   : {},
        didResolutionMetadata : {},
      };
    },
  };
}

type DidResolverMethod = Awaited<ReturnType<DidResolver['resolve']>>['didDocument']['verificationMethod'][number];

function fixtureKey(fixtureSet: FixtureSet, fixtureCase: FixtureCase, signerId: string): FixtureKey {
  const key = fixtureSet.keys?.[signerId];
  if (key === undefined) {
    throw new Error(`${fixtureCase.id} references missing signer ${signerId}`);
  }

  return key;
}

function signerIds(fixtureCase: FixtureCase): string[] {
  if (fixtureCase.signerIds === undefined) {
    throw new Error(`${fixtureCase.id} must include signerIds`);
  }

  return fixtureCase.signerIds;
}

function jws(fixtureCase: FixtureCase): GeneralJws {
  if (fixtureCase.jws === undefined) {
    throw new Error(`${fixtureCase.id} must include a JWS`);
  }

  return fixtureCase.jws;
}

function expectedSigners(fixtureCase: FixtureCase): string[] {
  if (fixtureCase.expectedSigners === undefined) {
    throw new Error(`${fixtureCase.id} must include expectedSigners`);
  }

  return fixtureCase.expectedSigners;
}

function didFromKid(kid: string): string {
  return kid.split('#')[0];
}
