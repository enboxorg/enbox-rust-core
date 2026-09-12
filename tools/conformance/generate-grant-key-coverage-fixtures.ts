// Generates the grant-key Read coverage fixture from the TypeScript.
//
// `grantKeyScopeCoversDeliveredScope` decides whether a permission grant is
// reason enough to reach a delivered encryption key. It is the most
// security-sensitive rule in the encryption work, it is a pure function of a
// grant scope, a delivered scope and a protocol definition, and it has to give
// the same answer in both implementations. That makes it ideal conformance
// material: no store, no handler, no clock — just a truth table whose expected
// values come from running the TypeScript rather than from reading it.
//
// Run with:
//   ENBOX_TS_ROOT=../enbox bun tools/conformance/generate-grant-key-coverage-fixtures.ts
//
// The commit recorded in source.commit must match .enbox-version, which the
// provenance gate enforces.

import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const enboxTsRoot = process.env.ENBOX_TS_ROOT ?? resolve(repoRoot, '../enbox');

const { grantKeyScopeCoversDeliveredScope, isGrantKeyEligibleRecordsScope } = await import(
  resolve(enboxTsRoot, 'packages/dwn-sdk-js/src/utils/grant-key-coverage.ts')
);

const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: enboxTsRoot,
  encoding: 'utf8',
}).trim();

const PROTOCOL = 'http://example.com/threads';
const KEY = {
  publicKeyJwk: {
    kty: 'OKP',
    crv: 'X25519',
    x: 'Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI',
  },
};

// `thread` reads through `member`; `thread/notes` reads through `archivist`,
// declared at the root; `plain` reads through nothing; `unkeyed` is a role the
// configuration deliberately does not key; `other:reader` is a cross-protocol
// reference.
const definition = {
  protocol: PROTOCOL,
  published: true,
  types: {
    member: {},
    archivist: {},
    unkeyed: {},
    thread: {},
    notes: {},
    plain: {},
    leaf: {},
  },
  structure: {
    member: { $role: true, $keyAgreement: KEY },
    archivist: { $role: true, $keyAgreement: KEY },
    unkeyed: { $role: true },
    plain: {},
    thread: {
      $actions: [{ role: 'member', can: ['read'] }],
      notes: {
        $actions: [
          { role: 'archivist', can: ['read'] },
          { role: 'unkeyed', can: ['read'] },
          { role: 'other:reader', can: ['read'] },
        ],
        leaf: {},
      },
    },
  },
};

type CaseInput = {
  id: string;
  method: 'Read' | 'Write';
  grantProtocolPath?: string;
  grantContextId?: string;
  deliveredProtocolPath?: string;
  withDefinition: boolean;
};

const inputs: CaseInput[] = [
  // A grant over the whole protocol covers everything in it, definition or not.
  { id: 'protocol-grant-covers-protocol-key', method: 'Read', withDefinition: false },
  { id: 'protocol-grant-covers-path', method: 'Read', deliveredProtocolPath: 'member', withDefinition: false },
  { id: 'protocol-grant-covers-nested-path', method: 'Read', deliveredProtocolPath: 'thread/notes', withDefinition: false },
  // A path-scoped grant covers its own path and its descendants.
  { id: 'path-grant-covers-itself', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'thread', withDefinition: false },
  { id: 'path-grant-covers-descendant', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'thread/notes', withDefinition: false },
  { id: 'path-grant-covers-deep-descendant', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'thread/notes/leaf', withDefinition: false },
  // But never the protocol-scoped key.
  { id: 'path-grant-excludes-protocol-key', method: 'Read', grantProtocolPath: 'thread', withDefinition: false },
  { id: 'path-grant-excludes-protocol-key-with-definition', method: 'Read', grantProtocolPath: 'thread', withDefinition: true },
  // Path boundaries, so no prefix collisions.
  { id: 'path-boundary-is-respected', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'threading', withDefinition: true },
  // The keyed-role exception, and its dependence on the definition.
  { id: 'subtree-reaches-role-it-reads-through', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'member', withDefinition: true },
  { id: 'role-exception-undecidable-without-definition', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'member', withDefinition: false },
  { id: 'role-reached-from-deeper-in-subtree', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'archivist', withDefinition: true },
  // A subtree that reads through nothing reaches nothing.
  { id: 'subtree-without-read-actions-reaches-nothing', method: 'Read', grantProtocolPath: 'plain', deliveredProtocolPath: 'member', withDefinition: true },
  // A role the configuration does not key conveys no key material.
  { id: 'unkeyed-role-is-not-reachable', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'unkeyed', withDefinition: true },
  // Cross-protocol references name membership this protocol does not define.
  { id: 'cross-protocol-role-ref-excluded', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'other:reader', withDefinition: true },
  // Referencing a role reaches the role, not its subtree.
  { id: 'referenced-role-is-not-a-subtree', method: 'Read', grantProtocolPath: 'thread', deliveredProtocolPath: 'member/child', withDefinition: true },
];

function grantScopeFor(input: CaseInput) {
  const scope: Record<string, unknown> = {
    interface: 'Records',
    method: input.method,
    protocol: PROTOCOL,
  };
  if (input.grantProtocolPath !== undefined) scope.protocolPath = input.grantProtocolPath;
  if (input.grantContextId !== undefined) scope.contextId = input.grantContextId;
  return scope;
}

const cases = inputs.map((input) => {
  const grantScope = grantScopeFor(input);
  const eligible = isGrantKeyEligibleRecordsScope(grantScope);
  const covers = eligible
    ? grantKeyScopeCoversDeliveredScope({
      grantScope,
      deliveredScope: { protocol: PROTOCOL, protocolPath: input.deliveredProtocolPath },
      protocolDefinition: input.withDefinition ? definition : undefined,
    })
    : false;

  return {
    id: input.id,
    rustStatus: 'supported',
    grantKeyCoverage: {
      grantScope,
      deliveredScope: { protocol: PROTOCOL, protocolPath: input.deliveredProtocolPath },
      // The definition this case is evaluated against, by name, or absent when
      // the case is about staying decidable without one.
      definition: input.withDefinition ? 'threads' : undefined,
      expectedEligible: eligible,
      expectedCovers: covers,
    },
  };
});

// Ineligible scopes, which must deliver nothing however they are scoped.
const ineligible: CaseInput[] = [
  { id: 'context-scoped-grant-is-ineligible', method: 'Read', grantContextId: 'thread-1', deliveredProtocolPath: 'thread', withDefinition: true },
];
for (const input of ineligible) {
  const grantScope = grantScopeFor(input);
  cases.push({
    id: input.id,
    rustStatus: 'supported',
    grantKeyCoverage: {
      grantScope,
      deliveredScope: { protocol: PROTOCOL, protocolPath: input.deliveredProtocolPath },
      definition: input.withDefinition ? 'threads' : undefined,
      expectedEligible: isGrantKeyEligibleRecordsScope(grantScope),
      expectedCovers: false,
    },
  });
}

const fixture = {
  schemaVersion: 1,
  source: {
    package: '@enbox/dwn-sdk-js',
    repository: 'enboxorg/enbox',
    commit,
    functions: ['grantKeyScopeCoversDeliveredScope', 'isGrantKeyEligibleRecordsScope'],
  },
  definitions: { threads: definition },
  cases,
};

const target = resolve(repoRoot, 'fixtures/dwn/records/grant-key-coverage.json');
writeFileSync(target, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`wrote ${cases.length} cases to ${target} at ${commit}`);
