import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import type { ModuleDefinition } from '@enbox/dwn-sdk-js';

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

type ProtocolAuthorizationFixture = {
  directives: string[];
  definition: ModuleDefinition;
  expectedStatusCode: number;
  expectedErrorCode?: string;
};

type GrantScopeFixture = {
  interface: string;
  method: string;
  module?: string;
  modulePath?: string;
};

type GrantAuthorizationFixture = {
  grantId: string;
  grantor: string;
  grantee: string;
  delegated: boolean;
  revoked?: boolean;
  revocationId?: string;
  revokedAt?: string;
  dateGranted?: string;
  dateExpires?: string;
  messageTimestamp?: string;
  scope: GrantScopeFixture;
  conditions?: Record<string, unknown>;
  incomingMessage: Record<string, unknown>;
  expectedStatusCode: number;
  expectedErrorCode?: string;
};

type FixtureCase = {
  id: string;
  rustStatus?: 'supported' | 'known_gap';
  protocolAuthorization?: ProtocolAuthorizationFixture;
  grantAuthorization?: GrantAuthorizationFixture;
};

type SdkModule = {
  ModulesConfigure: {
    validateModuleDefinition(definition: ModuleDefinition): void;
  };
};

const protocolAuthorizationAssertion = 'protocol.authorization-corpus';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../..');
const fixturesRoot = resolve(repoRoot, 'fixtures');
const defaultEnboxTsRoot = resolve(repoRoot, '../enbox');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? defaultEnboxTsRoot;
const sdkModulePath = resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/interfaces/modules-configure.ts');

if (!existsSync(sdkModulePath)) {
  throw new Error(
    `Unable to find TypeScript DWN SDK at ${sdkModulePath}. ` +
    'Set ENBOX_TS_ROOT to the enbox monorepo root before running this Bun test.'
  );
}

const { ModulesConfigure } = await import(pathToFileURL(sdkModulePath).href) as {
  ModulesConfigure: SdkModule['ModulesConfigure'];
};
const manifest = await readJson<FixtureManifest>(resolve(fixturesRoot, 'manifest.json'));
const fixtureSuites = await Promise.all(
  manifest.suites.map(async (suite): Promise<{ fixtureSet: FixtureSet; suite: FixtureSuiteRef }> => ({
    suite,
    fixtureSet: await readJson<FixtureSet>(resolve(fixturesRoot, suite.path)),
  }))
);


describe('TypeScript protocol.authorization-corpus conformance fixtures', () => {
  for (const { fixtureSet, suite } of fixtureSuites) {
    if (!suite.assertions.includes(protocolAuthorizationAssertion)) {
      continue;
    }

    describe(suite.id, () => {
      for (const fixtureCase of fixtureSet.cases) {
        if (fixtureCase.rustStatus !== 'supported') {
          continue;
        }

        if (fixtureCase.protocolAuthorization !== undefined) {
          test(`${fixtureCase.id} protocol definition`, async () => {
            await assertProtocolAuthorizationFixture(fixtureCase.id, fixtureCase.protocolAuthorization);
          });
        }

        if (fixtureCase.grantAuthorization !== undefined) {
          test(`${fixtureCase.id} grant authorization`, () => {
            assertGrantAuthorizationFixture(fixtureCase.id, fixtureCase.grantAuthorization);
          });
        }
      }
    });
  }
});

async function assertProtocolAuthorizationFixture(
  caseId: string,
  protocol: ProtocolAuthorizationFixture,
): Promise<void> {
  expect(protocol.directives.length).toBeGreaterThan(0);

  try {
    (ModulesConfigure as unknown as { validateModuleDefinition(definition: ModuleDefinition): void })
      .validateModuleDefinition(protocol.definition);
    expect(protocol.expectedStatusCode).toBeLessThan(400);
  } catch (error) {
    expect(protocol.expectedStatusCode).toBeGreaterThanOrEqual(400);
    if (protocol.expectedErrorCode !== undefined) {
      expect((error as { code?: string }).code).toBe(protocol.expectedErrorCode);
    }
  }
}

function assertGrantAuthorizationFixture(caseId: string, grant: GrantAuthorizationFixture): void {
  const result = evaluateGrantAuthorizationFixture(caseId, grant);
  if (grant.expectedStatusCode < 400) {
    expect(result).toBeUndefined();
  } else {
    expect(result).toBe(grant.expectedErrorCode);
  }
}

function evaluateGrantAuthorizationFixture(caseId: string, grant: GrantAuthorizationFixture): string | undefined {
  const incomingTimestamp = grantTimestamp(
    caseId,
    grant.messageTimestamp ?? '2025-01-01T12:00:00.000000Z',
    'messageTimestamp',
  );
  const dateGranted = grantTimestamp(
    caseId,
    grant.dateGranted ?? '2025-01-01T00:00:00.000000Z',
    'dateGranted',
  );
  const dateExpires = grantTimestamp(
    caseId,
    grant.dateExpires ?? '2026-01-01T00:00:00.000000Z',
    'dateExpires',
  );

  if (incomingTimestamp < dateGranted) {
    return 'GrantAuthorizationGrantNotYetActive';
  }
  if (incomingTimestamp >= dateExpires) {
    return 'GrantAuthorizationGrantExpired';
  }
  if (grant.revoked === true) {
    const revokedAt = grantTimestamp(caseId, grant.revokedAt ?? '', 'revokedAt');
    if (revokedAt <= incomingTimestamp) {
      return 'GrantAuthorizationGrantRevoked';
    }
  }

  const incomingInterface = incomingMessageStr(caseId, grant, 'interface');
  const incomingMethod = incomingMessageStr(caseId, grant, 'method');
  if (incomingInterface !== grant.scope.interface) {
    return 'GrantAuthorizationInterfaceMismatch';
  }
  if (grant.scope.interface === 'Messages') {
    if (grant.scope.method !== 'Read' || !['Read', 'Subscribe', 'Sync'].includes(incomingMethod)) {
      return 'GrantAuthorizationMethodMismatch';
    }
  } else if (incomingMethod !== grant.scope.method) {
    return 'GrantAuthorizationMethodMismatch';
  }

  switch (grant.scope.interface) {
  case 'Records':
    return evaluateRecordsGrantAuthorization(grant);
  case 'Modules':
    return evaluateModulesGrantAuthorization(grant);
  case 'Messages':
    return evaluateMessagesGrantAuthorization(grant);
  default:
    return undefined;
  }
}

function evaluateRecordsGrantAuthorization(grant: GrantAuthorizationFixture): string | undefined {
  if (grant.scope.module !== incomingMessageStrOptional(grant, 'module')) {
    return 'RecordsGrantAuthorizationScopeModuleMismatch';
  }
  if (grant.scope.modulePath !== undefined &&
    incomingMessageStrOptional(grant, 'modulePath') !== grant.scope.modulePath) {
    return 'RecordsGrantAuthorizationScopeModulePathMismatch';
  }

  const publication = grant.conditions?.publication;
  if (publication === 'Required' && incomingMessageBool(grant, 'published') !== true) {
    return 'RecordsGrantAuthorizationConditionPublicationRequired';
  }
  if (publication === 'Prohibited' && incomingMessageBool(grant, 'published') === true) {
    return 'RecordsGrantAuthorizationConditionPublicationProhibited';
  }
  return undefined;
}

function evaluateModulesGrantAuthorization(grant: GrantAuthorizationFixture): string | undefined {
  const scopeModule = grant.scope.module;
  if (scopeModule === undefined) {
    return undefined;
  }
  const incomingModule = incomingMessageStrOptional(grant, 'module');
  if (incomingModule !== undefined && incomingModule !== scopeModule) {
    return 'ModulesGrantAuthorizationQueryModuleScopeMismatch';
  }
  return undefined;
}

function evaluateMessagesGrantAuthorization(grant: GrantAuthorizationFixture): string | undefined {
  const scopeModule = grant.scope.module;
  if (scopeModule === undefined) {
    return undefined;
  }
  const incomingModules = incomingMessageModules(grant);
  if (incomingModules.length === 0 || incomingModules.some((module): boolean => module !== scopeModule)) {
    return 'MessagesGrantAuthorizationMismatchedModule';
  }
  return undefined;
}

function incomingMessageStr(caseId: string, grant: GrantAuthorizationFixture, field: string): string {
  const value = incomingMessageStrOptional(grant, field);
  if (value === undefined) {
    throw new Error(`${caseId} incomingMessage.${field} must be a string`);
  }
  return value;
}

function incomingMessageStrOptional(grant: GrantAuthorizationFixture, field: string): string | undefined {
  const value = grant.incomingMessage[field];
  return typeof value === 'string' ? value : undefined;
}

function incomingMessageBool(grant: GrantAuthorizationFixture, field: string): boolean | undefined {
  const value = grant.incomingMessage[field];
  return typeof value === 'boolean' ? value : undefined;
}

function incomingMessageModules(grant: GrantAuthorizationFixture): string[] {
  const modules: string[] = [];
  const direct = incomingMessageStrOptional(grant, 'module');
  if (direct !== undefined) {
    modules.push(direct);
  }
  const filters = grant.incomingMessage.filters;
  if (Array.isArray(filters)) {
    for (const filter of filters) {
      if (filter !== null && typeof filter === 'object' && typeof (filter as Record<string, unknown>).module === 'string') {
        modules.push((filter as Record<string, unknown>).module as string);
      }
    }
  }
  return modules;
}

function grantTimestamp(caseId: string, value: string, field: string): string {
  if (value.length === 0) {
    throw new Error(`${caseId} grant ${field} must not be empty`);
  }
  return value;
}


async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}
