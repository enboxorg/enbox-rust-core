/**
 * Fixed personas matching `fixtures/crypto/jws-general.json` for deterministic fixtures.
 */
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const repoRoot = resolve(import.meta.dir, '../..');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const dwnSdkModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/index.ts');

if (!existsSync(dwnSdkModulePath)) {
  throw new Error(
    `Unable to find @enbox/dwn-sdk-js at ${dwnSdkModulePath}. Set ENBOX_TS_ROOT before generating fixtures.`
  );
}

type Persona = {
  did: string;
  keyId: string;
  keyPair: {
    publicJwk: Record<string, unknown>;
    privateJwk: Record<string, unknown>;
  };
  encryptionKeyPair: {
    publicJwk: Record<string, unknown>;
    privateJwk: Record<string, unknown>;
  };
  signer: unknown;
};

type DwnSdkModule = {
  PrivateKeySigner: new (input: Record<string, unknown>) => Persona['signer'];
};

const { PrivateKeySigner } = await import(dwnSdkModulePath) as DwnSdkModule;

export const CONFORMANCE_ALICE_DID = 'did:example:alice';
export const CONFORMANCE_ALICE_KEY_ID = 'did:example:alice#key1';

const SIGNING_PUBLIC_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg',
  alg: 'EdDSA',
  kid: CONFORMANCE_ALICE_KEY_ID,
} as const;

const SIGNING_PRIVATE_JWK = {
  ...SIGNING_PUBLIC_JWK,
  d: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
} as const;

const PLACEHOLDER_ENCRYPTION_KEY_PAIR = {
  publicJwk: { kty: 'OKP', crv: 'X25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  privateJwk: { kty: 'OKP', crv: 'X25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
};

let cachedAlice: Persona | undefined;

export async function getConformanceAlicePersona(): Promise<Persona> {
  if (cachedAlice !== undefined) {
    return cachedAlice;
  }

  cachedAlice = {
    did: CONFORMANCE_ALICE_DID,
    keyId: CONFORMANCE_ALICE_KEY_ID,
    keyPair: {
      publicJwk: { ...SIGNING_PUBLIC_JWK },
      privateJwk: { ...SIGNING_PRIVATE_JWK },
    },
    encryptionKeyPair: PLACEHOLDER_ENCRYPTION_KEY_PAIR,
    signer: new PrivateKeySigner({
      privateJwk: SIGNING_PRIVATE_JWK,
      algorithm: 'EdDSA',
      keyId: CONFORMANCE_ALICE_KEY_ID,
    }),
  };

  return cachedAlice;
}
