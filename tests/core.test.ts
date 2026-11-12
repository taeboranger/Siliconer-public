import test from 'node:test';
import assert from 'node:assert/strict';
import { advisorySchema, AppError } from '../packages/core/src/types.js';
import { matchVersion, aggregate } from '../packages/core/src/matcher.js';
import { parseSbom, parsePurl } from '../packages/core/src/sbom.js';
import { renderGitops } from '../packages/connectors/src/gitops.js';
import { cleanText, canonical } from '../packages/core/src/util.js';

const advisory = advisorySchema.parse({ id: 'TEST-1', modified: '2026-11-10T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: 'example' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.0' }, { introduced: '2.0.0' }, { last_affected: '2.1.0' }] }] }] });
test('npm ranges respect fixed/last_affected boundaries and disjoint ranges', () => {
  for (const [version, expected] of [['0.1.0','affected'],['1.2.0','not_affected'],['1.9.0','not_affected'],['2.0.0','affected'],['2.1.0','affected'],['2.1.1','not_affected'],['not-version','unknown']])
    assert.equal(matchVersion(advisory, { purl: '', ecosystem: 'npm', name: 'example', version }).match, expected, version);
});
test('prereleases are compared without coercion; unsupported ranges remain unknown', () => {
  assert.equal(matchVersion(advisory, { purl: '', ecosystem: 'npm', name: 'example', version: '1.2.0-beta.1' }).match, 'affected');
  const other = structuredClone(advisory); other.affected[0].ranges[0].type = 'ECOSYSTEM';
  assert.equal(matchVersion(other, { purl: '', ecosystem: 'npm', name: 'example', version: '1.2.0' }).match, 'unknown');
});
test('malformed reversed vulnerability intervals never produce a negative finding', () => {
  const invalid=structuredClone(advisory); invalid.affected[0].ranges[0].events=[{introduced:'2.0.0'},{fixed:'1.0.0'}];
  assert.equal(matchVersion(invalid,{purl:'',ecosystem:'npm',name:'example',version:'3.0.0'}).match,'unknown');
});
test('SBOM parsing preserves scoped npm names, rejects unknown formats, marks incomplete scope', () => {
  assert.equal(parsePurl('pkg:npm/%40scope/name@1.0.0')?.name, '@scope/name');
  assert.equal(parsePurl('pkg:npm/%E0%A4%A@1.0.0'), undefined);
  const cyclonedx = parseSbom({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ purl: 'pkg:npm/a@1.0.0' }, { purl: 'pkg:deb/debian/libc6@2.0' }] }, true);
  assert.equal(cyclonedx.components.length, 1); assert.equal(cyclonedx.complete, false); assert.equal(cyclonedx.unsupported, 1);
  const spdx = parseSbom({ spdxVersion: 'SPDX-2.3', packages: [{ externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/a@1.0.0' }] }] }, true);
  assert.equal(spdx.complete, true); assert.throws(() => parseSbom({ anything: true }));
});
test('mixed rollout, zero replicas, partial coverage and stale evidence cannot become fixed', () => {
  const fixed = { status: 'fixed' as const, reason: '', evidenceIds: [], fixedVersions: [] };
  assert.equal(aggregate([fixed,{ ...fixed, status: 'affected' }], true, true), 'affected');
  assert.equal(aggregate([fixed], false, true), 'under_investigation');
  assert.equal(aggregate([], true, true), 'under_investigation');
  assert.equal(aggregate([fixed], true, false), 'under_investigation');
  assert.equal(aggregate([fixed], true, true), 'fixed');
});
test('Kustomize nested overlay image replacement and registry ports are resolved', async () => {
  const files: Record<string,string> = {
    'overlays/prod/kustomization.yaml': 'resources:\n- ../../base\nimages:\n- name: localhost:5000/app\n  newTag: commit123\n',
    'base/kustomization.yaml': 'resources:\n- deploy.yaml\n',
    'base/deploy.yaml': 'apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: localhost:5000/app:latest\n',
  };
  const rendered = await renderGitops('overlays/prod', async p => { if (!files[p]) throw new AppError('upstream_404'); return files[p]; });
  assert.deepEqual(rendered.images, ['localhost:5000/app:commit123']); assert.equal(rendered.state, 'resolved');
  files['overlays/prod/kustomization.yaml'] += 'patches: []\n';
  assert.equal((await renderGitops('overlays/prod', async p => files[p])).state, 'render_incomplete');
});
test('GitOps remote paths and YAML aliases cannot access local files or trigger code', async () => {
  await assert.rejects(renderGitops('.', async () => 'resources:\n- https://evil.invalid/base\n'), /remote_or_unsafe/);
  await assert.rejects(renderGitops('../outside', async () => ''), /remote_or_unsafe/);
});
test('context redaction and canonical hashes are stable', () => {
  assert.equal(canonical({ b: 2, a: 1 }), canonical({ a: 1, b: 2 }));
  assert.notEqual(canonical(new Date('2026-11-10T00:00:00Z')),canonical(new Date('2026-11-10T00:01:00Z')));
  assert(!cleanText('secret=do-not-leak Bearer token-goes-here').includes('do-not-leak'));
});
