import { randomUUID } from 'node:crypto';
import { ORG, type Database } from '../../../packages/storage/src/db.js';
import { hash } from '../../../packages/core/src/util.js';
import { parseSbom } from '../../../packages/core/src/sbom.js';
import { createUser } from './auth.js';
import { saveAdvisory } from './inventory.js';
import { assessAll } from './assessment.js';
export const DEMO_EMAIL = 'admin@siliconer.local';
export const DEMO_PASSWORD = 'siliconer-demo-2026';
export async function seedDemo(db: Database, enabled: boolean) {
  if (!enabled || process.env.NODE_ENV === 'production') throw new Error('Demo seed is restricted to explicit non-production mode');
  if ((await db.query('SELECT id FROM users WHERE email=$1', [DEMO_EMAIL])).length) return;
  await createUser(db, DEMO_EMAIL, DEMO_PASSWORD);
  await db.query("INSERT INTO integrations(id,organization_id,kind,name,scope,state,last_success_at) VALUES('demo-argocd',$1,'argocd','데모 Argo CD · 실제 연동 아님','demo-project','demo',now())", [ORG]);
  const vulnerable = `sha256:${'a'.repeat(64)}`; const patched = `sha256:${'b'.repeat(64)}`;
  for (const [version, digest, tag] of [['4.17.20', vulnerable, 'old'], ['4.17.21', patched, 'patched']]) {
    const raw = { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [{ type: 'library', name: 'lodash', version, purl: `pkg:npm/lodash@${version}` }] };
    const sbom = parseSbom(raw, true);
    await db.query(`INSERT INTO sboms(id,organization_id,repository,commit_sha,image,digest,workflow_run_id,run_attempt,format,content_hash,raw_document,components,complete,unsupported,provenance)
      VALUES($1,$2,'demo/portal',$3,$4,$5,'1',1,'CycloneDX',$6,$7,$8,true,0,'verified')`, [randomUUID(), ORG, (tag === 'old' ? '1' : '2').repeat(40), `demo/portal:${tag}`, digest, sbom.hash, JSON.stringify(raw), JSON.stringify(sbom.components)]);
  }
  for (const [name, desired, observed] of [
    ['portal-prod','demo/portal:old',vulnerable], ['club-api-prod','demo/portal:patched',vulnerable],
    ['archive-worker','demo/portal:old',null], ['docs-service','demo/portal:patched',patched],
  ]) {
    const id = randomUUID(); const namespace = String(name);
    await db.query(`INSERT INTO applications(id,organization_id,integration_id,external_uid,name,application_namespace,project,cluster_id,namespace,environment,source_refs,desired_images,sync_state,health_state,render_state,observed_at)
      VALUES($1,$2,'demo-argocd',$3,$4,'argocd','demo-project','demo-cluster',$5,'prod',$6,$7,'Synced','Healthy','resolved',now())`,
    [id, ORG, `demo-${name}`, name, namespace, JSON.stringify([{ repository: 'demo/portal-config', path: 'overlays/prod', resolvedRevision: '3'.repeat(40), state: 'resolved' }]), JSON.stringify([desired])]);
    if (observed) {
      const containers = [{ podUid: `pod-${name}`, workloadUid: `workload-${name}`, workloadName: name, namespace, container: 'app', kind: 'regular', desiredImage: desired, imageId: `docker-pullable://demo/portal@${observed}`, digest: observed, running: true }];
      await db.query(`INSERT INTO snapshots(id,organization_id,application_id,cluster_id,observed_at,expires_at,complete,namespaces,containers,content_hash)
        VALUES($1,$2,$3,'demo-cluster',now(),now()+interval '1 day',true,$4,$5,$6)`, [randomUUID(), ORG, id, JSON.stringify([namespace]), JSON.stringify(containers), hash(containers)]);
    }
  }
  await saveAdvisory(db, { id: 'DEMO-2026-0001', aliases: [], modified: new Date().toISOString(), summary: '데모: lodash 취약 버전과 실제 실행 이미지 비교',
    details: '기능 검증을 위한 가상 권고문입니다. 실제 보안 공지가 아닙니다. 수정 버전 배포 선언과 실제 실행 이미지가 다른 경우를 보여줍니다.',
    affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
    database_specific: { severity: 'HIGH' }, references: [] });
  await assessAll(db, 86400);
}
