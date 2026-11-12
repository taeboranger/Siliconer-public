import { randomUUID } from 'node:crypto';
import semver from 'semver';
import { ORG, type Database } from '../../../packages/storage/src/db.js';
import { aggregate, matchVersion, type ContainerAssessment } from '../../../packages/core/src/matcher.js';
import { hash, normalizeImageId } from '../../../packages/core/src/util.js';
import type { Advisory, Component, Observation } from '../../../packages/core/src/types.js';
import { enqueue } from '../../../packages/storage/src/jobs.js';

export const EVALUATOR_VERSION = 'npm-evidence-1';
export interface Evidence { id: string; kind: string; source: string; observedAt: string; expiresAt?: string; details: Record<string, unknown> }
export async function assessAll(db: Database, ttlSeconds: number) {
  const [apps, advisories, sboms] = await Promise.all([
    db.query('SELECT * FROM applications WHERE organization_id=$1', [ORG]),
    db.query('SELECT * FROM advisories WHERE organization_id=$1', [ORG]),
    db.query('SELECT * FROM sboms WHERE organization_id=$1', [ORG]),
  ]);
  let assessed = 0;
  for (const app of apps) {
    const [snapshot] = await db.query('SELECT * FROM snapshots WHERE organization_id=$1 AND application_id=$2 ORDER BY observed_at DESC,created_at DESC LIMIT 1', [ORG, app.id]);
    const observations: Observation[] = snapshot?.containers ?? [];
    const active = observations.filter(c => c.running || c.kind === 'init');
    const desiredSboms = sboms.filter(s => app.desired_images.some((ref: string) => ref === s.image || ref.endsWith(`@${s.digest}`)));
    const observedSboms = sboms.filter(s => active.some(c => (c.digest ?? normalizeImageId(c.imageId)) === s.digest));
    const candidates = [...new Map([...desiredSboms, ...observedSboms].map(s => [s.id, s])).values()];
    for (const advisoryRow of advisories) {
      const advisory = advisoryRow.document as Advisory;
      const [previous] = await db.query('SELECT * FROM findings WHERE organization_id=$1 AND application_id=$2 AND advisory_id=$3', [ORG, app.id, advisoryRow.id]);
      const relevant = candidates.some(s => (s.components as Component[]).some(c => advisory.affected.some(a => a.package.ecosystem.toLowerCase() === c.ecosystem && a.package.name === c.name)));
      const inventoryUnknown=app.render_state!=='resolved' || candidates.length===0;
      if (!relevant && !previous && !inventoryUnknown) continue;
      const expiresAt = new Date(Math.min(new Date(app.observed_at).getTime() + ttlSeconds * 1000, snapshot ? new Date(snapshot.expires_at).getTime() : Infinity));
      const fresh = expiresAt.getTime() > Date.now();
      const evidence: Evidence[] = [{ id: `app:${app.id}`, kind: 'deployment_desired', source: `${app.integration_id}/${app.application_namespace}/${app.name}`, observedAt: new Date(app.observed_at).toISOString(), expiresAt: expiresAt.toISOString(), details: { sync: app.sync_state, health: app.health_state, renderState: app.render_state, images: app.desired_images, sources: app.source_refs } }];
      if (snapshot) evidence.push({ id: `snapshot:${snapshot.id}`, kind: 'deployment_observed', source: `${snapshot.cluster_id}/${app.namespace}`, observedAt: new Date(snapshot.observed_at).toISOString(), expiresAt: new Date(snapshot.expires_at).toISOString(), details: { complete: snapshot.complete, containers: active.length, contentHash: snapshot.content_hash } });
      for (const sbom of candidates) evidence.push({ id: `sbom:${sbom.id}`, kind: 'build_observed', source: `https://github.com/${sbom.repository}/commit/${sbom.commit_sha}`, observedAt: new Date(sbom.collected_at).toISOString(), details: { digest: sbom.digest, image: sbom.image, commit: sbom.commit_sha, provenance: sbom.provenance, hash: sbom.content_hash, complete: sbom.complete, components: (sbom.components as Component[]).filter(c => advisory.affected.some(a => a.package.name === c.name && a.package.ecosystem.toLowerCase() === c.ecosystem)).slice(0,100) } });
      const results: ContainerAssessment[] = [];
      const fixes = new Set<string>();
      for (const container of active) {
        const digest = container.digest ?? normalizeImageId(container.imageId);
        // Conflicting verified SBOMs are not arbitrarily collapsed into a single truth.
        const matching = sboms.filter(s => s.digest === digest && s.provenance === 'verified');
        const inventories = new Set(matching.map(s => hash(s.components)));
        if (!digest || matching.length === 0 || inventories.size !== 1) {
          results.push({ status: 'under_investigation', reason: `${container.container}: 실행 digest에 연결된 검증된 SBOM이 없거나 충돌합니다.`, evidenceIds: [], fixedVersions: [] }); continue;
        }
        const sbom = matching[0];
        const components = (sbom.components as Component[]).filter(c => advisory.affected.some(a => a.package.ecosystem.toLowerCase() === c.ecosystem && a.package.name === c.name));
        if (!components.length) {
          results.push({ status: sbom.complete && !advisory.withdrawn ? 'not_affected' : 'under_investigation', reason: sbom.complete ? `${container.container}: 검증된 완전한 SBOM에 대상 npm 패키지가 없습니다.` : `${container.container}: 구성요소 목록의 수집 범위가 불완전합니다.`, evidenceIds: [`sbom:${sbom.id}`], fixedVersions: [] }); continue;
        }
        for (const component of components) {
          const match = matchVersion(advisory, component);
          match.fixedVersions.forEach(f => fixes.add(f));
          const requiresEnvironment = advisory.affected.some(a => a.package.name === component.name && a.database_specific?.siliconer_requires_environment === true);
          const fixed = match.match === 'not_affected' && match.fixedVersions.some(f => semver.valid(component.version) && semver.gte(component.version, f));
          results.push({ status: requiresEnvironment || match.match === 'unknown' ? 'under_investigation' : match.match === 'affected' ? 'affected' : fixed ? 'fixed' : 'not_affected', reason: `${container.container} / ${component.name}@${component.version}: ${requiresEnvironment ? '추가 환경 조건을 확인할 근거가 필요합니다.' : match.reason}`, evidenceIds: [`sbom:${sbom.id}`], fixedVersions: match.fixedVersions });
        }
      }
      for (const sbom of desiredSboms) for (const component of sbom.components as Component[]) matchVersion(advisory, component).fixedVersions.forEach(f => fixes.add(f));
      const complete = Boolean(snapshot?.complete && snapshot.namespaces.includes(app.namespace) && active.length > 0 && observations.every(c => c.kind === 'init' || c.running));
      const status = aggregate(results, complete, fresh);
      const summary = !fresh ? '배포 근거가 만료되어 재수집이 필요합니다.' : !snapshot ? '배포 선언만 확인했습니다. 실제 실행 digest를 수집해야 합니다.' : results.length ? [...new Set(results.map(r => r.reason))].join('\n') : '실행 컨테이너가 없거나 수집 범위를 확인할 수 없습니다.';
      const inputHash = hash({ evaluator: EVALUATOR_VERSION, advisory: advisoryRow.content_hash, app: { sources: app.source_refs, images: app.desired_images, observedAt: app.observed_at }, snapshot: snapshot?.content_hash, sboms: candidates.map(s => [s.id, s.content_hash, s.provenance]), results, fresh, complete });
      if (previous?.input_hash === inputHash && !previous.stale) continue;
      await db.transaction(async tx => {
        const id = previous?.id ?? randomUUID();
        const priority = advisoryRow.severity === 'critical' || advisoryRow.severity === 'high' ? 'high' : 'medium';
        await tx.query(`INSERT INTO findings(id,organization_id,advisory_id,application_id,status,priority,summary,evidence,fixed_versions,input_hash,expires_at,stale,relevance)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(organization_id,advisory_id,application_id)
          DO UPDATE SET status=$5,priority=$6,summary=$7,evidence=$8,fixed_versions=$9,input_hash=$10,expires_at=$11,stale=$12,relevance=$13,assessed_at=now()`,
        [id, ORG, advisoryRow.id, app.id, status, priority, summary, JSON.stringify(evidence), JSON.stringify([...fixes].sort(semver.compare)), inputHash, expiresAt, !fresh,relevant?'relevant':'unknown']);
        await tx.query('INSERT INTO assessments(id,organization_id,finding_id,status,evidence,input_hash,evaluator_version) VALUES($1,$2,$3,$4,$5,$6,$7)', [randomUUID(), ORG, id, status, JSON.stringify(evidence), inputHash, EVALUATOR_VERSION]);
        if (!previous || previous.status !== status) {
          if (status === 'affected') await tx.query('INSERT INTO tickets(id,organization_id,finding_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [randomUUID(), ORG, id]);
          await enqueue(tx, 'notify', { findingId: id, status, advisory: advisoryRow.canonical_id, application: app.name, priority, eventHash: hash({ id, status, inputHash }) }, `notify:${id}:${inputHash}`);
        }
      });
      assessed++;
    }
  }
  return assessed;
}
