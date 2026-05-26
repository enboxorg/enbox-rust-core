/**
 * Fixed test persona matching `loopback_interop_server.rs` resolver keys.
 * Keeps loopback interop deterministic without registering dynamic did:key tenants.
 */
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const repoRoot = resolve(import.meta.dir, '../..');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const dwnSdkModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/index.ts');
const cryptoModulePath = resolve(enboxTsRoot, 'packages/crypto/src/index.ts');

if (!existsSync(dwnSdkModulePath)) {
  throw new Error(
    `Unable to find @enbox/dwn-sdk-js at ${dwnSdkModulePath}. Set ENBOX_TS_ROOT before running interop tests.`
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
  signer: { sign: (input: unknown) => Promise<unknown> };
};

type DwnSdkModule = {
  PrivateKeySigner: new (input: Record<string, unknown>) => Persona['signer'];
};

type CryptoModule = {
  X25519: {
    generateKey(): Promise<Record<string, unknown>>;
    getPublicKey(input: { key: Record<string, unknown> }): Promise<Record<string, unknown>>;
  };
};

const { PrivateKeySigner } = await import(dwnSdkModulePath) as DwnSdkModule;
const { X25519 } = await import(cryptoModulePath) as CryptoModule;

export type { Persona };

export const LOOPBACK_TENANT = 'did:example:alice';
export const LOOPBACK_KEY_ID = 'did:example:alice#key1';

const SIGNING_PUBLIC_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg',
  alg: 'EdDSA',
  kid: LOOPBACK_KEY_ID,
} as const;

const SIGNING_PRIVATE_JWK = {
  ...SIGNING_PUBLIC_JWK,
  d: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
} as const;

let cachedPersona: Persona | undefined;

/** Lazily builds the loopback Alice persona with a fresh X25519 encryption key pair. */
export async function getLoopbackPersona(): Promise<Persona> {
  if (cachedPersona !== undefined) {
    return cachedPersona;
  }

  const encPrivateKey = await X25519.generateKey();
  const encPublicKey = await X25519.getPublicKey({ key: encPrivateKey });

  cachedPersona = {
    did: LOOPBACK_TENANT,
    keyId: LOOPBACK_KEY_ID,
    keyPair: {
      publicJwk: { ...SIGNING_PUBLIC_JWK },
      privateJwk: { ...SIGNING_PRIVATE_JWK },
    },
    encryptionKeyPair: {
      publicJwk: encPublicKey,
      privateJwk: encPrivateKey,
    },
    signer: new PrivateKeySigner({
      privateJwk: SIGNING_PRIVATE_JWK,
      algorithm: 'EdDSA',
      keyId: LOOPBACK_KEY_ID,
    }),
  };

  return cachedPersona;
}
