import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHmac } from 'node:crypto';
import { createApp } from '../apps/api/src/app.js';
import { readSettings } from '../apps/api/src/config.js';
import { seedDemo, DEMO_EMAIL, DEMO_PASSWORD } from '../apps/api/src/seed.js';
import { configSchema } from '../packages/connectors/src/config.js';
import { registerIntegrations, saveAdvisory, ingestSnapshot } from '../apps/api/src/inventory.js';
import { createUser } from '../apps/api/src/auth.js';
import { ORG, migrate } from '../packages/storage/src/db.js';
import { assessAll } from '../apps/api/src/assessment.js';
import {InspectionTools,inspectionStamp} from '../apps/api/src/inspection-tools.js';
import { testDatabase } from './helpers.js';
const origin = 'http://localhost:3000';
test('authenticated evidence workflow, authorization and adversarial inputs', async t => {
  const db = await testDatabase(); await migrate(db); await seedDemo(db, true);
  process.env.SILICONER_TEST_INGEST = 'test-ingest-credential-32-characters'; process.env.SILICONER_TEST_WEBHOOK = 'test-webhook-credential-32-characters';
  const config = configSchema.parse({ integrations: [
    { id: 'github-test', name: 'Test GitHub', kind: 'github', appId: '1', installationId: 1, privateKeyFileEnv: 'TEST_KEY_FILE', webhookSecretEnv: 'SILICONER_TEST_WEBHOOK', repositories: [{ name: 'test/source', kind: 'source' }] },
    { id: 'ingest-test', name: 'Test ingest', kind: 'ingest', tokenEnv: 'SILICONER_TEST_INGEST', repositories: ['test/source'] },
  ] });
  await registerIntegrations(db, config);
  const app = await createApp(db, config, readSettings({ SILICONER_DATABASE_URL: 'pglite:memory', SILICONER_BASE_URL: origin }));
  let client = 0;
  async function login(email: string, password: string) {
    const r = await app.inject({ method: 'POST', url: '/api/v1/auth/login', headers: { origin }, payload: { email, password }, remoteAddress: `127.0.0.${++client}` });
    assert.equal(r.statusCode, 200, r.body);
    const values = r.headers['set-cookie']; const all = Array.isArray(values) ? values : [String(values)];
    return { cookie: all.map(c => c.split(';')[0]).join('; '), origin, 'x-csrf-token': r.json().csrf };
  }
  const admin = await login(DEMO_EMAIL, DEMO_PASSWORD);
  try {
    await t.test('health works without auth; data endpoints require sessions', async () => {
      assert.equal((await app.inject('/health/ready')).statusCode, 200);
      assert.equal((await app.inject('/api/v1/findings')).statusCode, 401);
      const session = await app.inject({ url: '/api/v1/auth/session', headers: admin }); assert.equal(session.json().user.role, 'admin');
      assert(!JSON.stringify(session.json()).includes('password_hash'));
    });
    await t.test('only admins can change the persisted Codex budget',async()=>{
      const codex=await createApp(db,config,readSettings({SILICONER_DATABASE_URL:'pglite:memory',SILICONER_BASE_URL:origin,SILICONER_LLM_PROVIDER:'codex'}));
      try{
        const id=await createUser(db,'budget-reviewer@test.local','budget-reviewer-password','reviewer');
        const reviewer=await login('budget-reviewer@test.local','budget-reviewer-password');
        assert.ok(id);
        const url='/api/v1/usage/llm/budget';
        const budget={dailyCalls:135,subscriptionPercent:90};
        assert.equal((await codex.inject({method:'PATCH',url,headers:reviewer,payload:budget})).statusCode,403);
        assert.equal((await codex.inject({method:'PATCH',url,headers:admin,payload:{...budget,dailyCalls:1001}})).statusCode,400);
        assert.equal((await codex.inject({method:'PATCH',url,headers:admin,payload:budget})).statusCode,200);
        const usage=(await codex.inject({url:'/api/v1/usage/llm',headers:admin})).json();
        assert.deepEqual(usage.budget,budget);
        assert.equal(usage.appDaily.limit,budget.dailyCalls);
      }finally{await codex.close();}
    });
    await t.test('Codex device codes are visible only to the administrator who requested them',async()=>{
      const codex=await createApp(db,config,readSettings({
        SILICONER_DATABASE_URL:'pglite:memory',SILICONER_BASE_URL:origin,SILICONER_LLM_PROVIDER:'codex',SILICONER_LLM_ENABLED:'true',
      }));
      try{
        await createUser(db,'switch-admin@test.local','switch-admin-password','admin');
        const other=await login('switch-admin@test.local','switch-admin-password');
        const reviewer=await login('budget-reviewer@test.local','budget-reviewer-password');
        const url='/api/v1/codex/account';
        assert.equal((await codex.inject({url,headers:reviewer})).statusCode,403);
        const begin=(headers:typeof admin)=>codex.inject({method:'POST',url:url+'/switch',headers,payload:{}});
        const started=await begin(admin);
        assert.equal(started.statusCode,202);
        assert.equal((await begin(other)).statusCode,409);
        const id=started.json().id;
        await db.query("UPDATE codex_account_switches SET state='waiting',user_code='TEST-1234' WHERE id=$1",[id]);
        assert.equal((await codex.inject({url,headers:admin})).json().attempt.code,'TEST-1234');
        assert.equal((await codex.inject({url,headers:other})).json().attempt.code,null);
        const cancel=(headers:typeof admin)=>codex.inject({method:'DELETE',url:url+'/switch/'+id,headers,payload:{}});
        assert.equal((await cancel(other)).statusCode,409);
        assert.equal((await cancel(admin)).statusCode,200);
        const ended=(await codex.inject({url,headers:admin})).json().attempt;
        assert.equal(ended.state,'cancelled');
        assert.equal(ended.code,null);
      }finally{await codex.close();}
    });
    await t.test('demo pipeline yields affected, desired-only unknown and runtime-fixed', async () => {
      const r = await app.inject({ url: '/api/v1/findings', headers: admin }); assert.equal(r.statusCode, 200, r.body);
      const rows = r.json().items; assert.equal(rows.length, 4);
      assert.equal(rows.find((f: any) => f.application === 'club-api-prod').status, 'affected');
      assert.equal(rows.find((f: any) => f.application === 'archive-worker').status, 'under_investigation');
      assert.equal(rows.find((f: any) => f.application === 'docs-service').status, 'fixed');
      const filtered = await app.inject({ url: '/api/v1/findings?status=fixed', headers: admin }); assert.equal(filtered.json().items.length, 1);
      const first = await app.inject({ url: '/api/v1/findings?limit=1', headers: admin });
      const next = await app.inject({ url: `/api/v1/findings?limit=1&cursor=${first.json().nextCursor}`, headers: admin });
      assert.notEqual(first.json().items[0].id, next.json().items[0].id);
    });
    await t.test('viewer cannot mutate or access integrations; CSRF is enforced', async () => {
      await createUser(db, 'viewer@test.local', 'viewer-password-2026', 'viewer');
      const viewer = await login('viewer@test.local', 'viewer-password-2026');
      assert.equal((await app.inject({ method: 'POST', url: '/api/v1/sync', headers: viewer, payload: {} })).statusCode, 403);
      assert.equal((await app.inject({ url: '/api/v1/integrations', headers: viewer })).statusCode, 403);
      assert.equal((await app.inject({ method: 'POST', url: '/api/v1/sync', headers: { cookie: admin.cookie, origin }, payload: {} })).statusCode, 403);
      assert.equal((await app.inject({ method: 'POST', url: '/api/v1/sync', headers: { ...admin, origin: 'https://evil.invalid' }, payload: {} })).statusCode, 403);
    });
    await t.test('service owners cannot read or change other services', async () => {
      const userId = await createUser(db, 'owner@test.local', 'owner-password-2026', 'developer');
      const [owned, other] = await db.query('SELECT id FROM applications ORDER BY id LIMIT 2');
      await db.query('INSERT INTO service_owners(organization_id,user_id,application_id) VALUES($1,$2,$3)', [ORG, userId, owned.id]);
      const owner = await login('owner@test.local', 'owner-password-2026');
      assert.equal((await app.inject({ url: '/api/v1/assets', headers: owner })).json().items.length, 1);
      assert.equal((await app.inject({ url: `/api/v1/assets/${other.id}`, headers: owner })).statusCode, 403);
      const [finding] = await db.query('SELECT id FROM findings WHERE application_id=$1', [other.id]);
      assert.equal((await app.inject({ method: 'POST', url: '/api/v1/tickets', headers: owner, payload: { findingId: finding.id } })).statusCode, 403);
    });
    await t.test('only active admins manage other accounts, and account changes revoke sessions', async () => {
      const users = '/api/v1/users';
      const payload = { email: 'New-Reviewer@test.local', password: 'reviewer-password-2026', role: 'reviewer' };
      const created = await app.inject({ method: 'POST', url: users, headers: admin, payload });
      assert.equal(created.statusCode, 200, created.body);
      const id = created.json().id;
      const target = `${users}/${id}`;
      assert.equal((await app.inject({ method: 'POST', url: users, headers: admin, payload: { ...payload, email: payload.email.toLowerCase() } })).statusCode, 409);
      const listing = await app.inject({ url: `${users}?q=NEW-REVIEWER`, headers: admin });
      assert.equal(listing.statusCode, 200, listing.body);
      assert.deepEqual(listing.json().items.map((row: Record<string, unknown>) => [row.id, row.email, row.role, row.disabled_at]), [[id, payload.email.toLowerCase(), 'reviewer', null]]);
      assert(!listing.body.includes('password_hash'));
      const reviewer = await login(payload.email, payload.password);
      assert.equal((await app.inject({ url: users, headers: reviewer })).statusCode, 403);
      assert.equal((await app.inject({ method: 'POST', url: users, headers: reviewer, payload })).statusCode, 403);
      assert.equal((await app.inject({ method: 'PATCH', url: target, headers: reviewer, payload: { role: 'admin' } })).statusCode, 403);
      const me = (await app.inject({ url: '/api/v1/auth/session', headers: admin })).json().user.id;
      for (const change of [{ enabled: false }, { role: 'viewer' }]) {
        assert.equal((await app.inject({ method: 'PATCH', url: `${users}/${me}`, headers: admin, payload: change })).statusCode, 403);
      }
      const change = async (payload: object) => {
        const response = await app.inject({ method: 'PATCH', url: target, headers: admin, payload });
        assert.equal(response.statusCode, 200, response.body);
      };
      await change({ role: 'viewer' });
      assert.equal((await app.inject({ url: '/api/v1/auth/session', headers: reviewer })).statusCode, 401);
      const viewer = await login(payload.email, payload.password);
      assert.equal((await app.inject({ url: '/api/v1/auth/session', headers: viewer })).json().user.role, 'viewer');
      await change({ enabled: false });
      assert.equal((await app.inject({ url: '/api/v1/auth/session', headers: viewer })).statusCode, 401);
      assert.equal((await app.inject({ method: 'POST', url: '/api/v1/auth/login', headers: { origin }, payload, remoteAddress: '127.0.0.100' })).statusCode, 401);
      await change({ enabled: true });
      await login(payload.email, payload.password);
      assert.equal((await app.inject({ url: '/api/v1/auth/session', headers: viewer })).statusCode, 401);
      const audit = (await app.inject({ url: '/api/v1/audit', headers: admin })).json().items;
      assert.equal(audit.filter((row: Record<string, unknown>) => row.action === 'user.update' && row.target === id).length, 3);
    });
    await t.test('tickets update internally and manual decisions preserve automated assessments', async () => {
      const [finding] = await db.query("SELECT * FROM findings WHERE status='affected' LIMIT 1");
      const r = await app.inject({ method: 'POST', url: '/api/v1/tickets', headers: admin, payload: { findingId: finding.id } });
      assert.equal(r.statusCode,200,r.body);
      const [clean]=await db.query("SELECT id FROM findings WHERE status IN ('fixed','not_affected') LIMIT 1");
      assert.equal((await app.inject({method:'POST',url:'/api/v1/tickets',headers:admin,payload:{findingId:clean.id}})).statusCode,409);
      const update = await app.inject({ method: 'PATCH', url: `/api/v1/tickets/${r.json().id}`, headers: admin, payload: { status: 'in_progress', notes: '패치 테스트를 진행합니다.' } }); assert.equal(update.statusCode, 200, update.body);
      const decision = await app.inject({ method: 'POST', url: `/api/v1/findings/${finding.id}/decision`, headers: admin, payload: { status: 'not_affected', rationale: '운영 조건을 추가로 검토한 수동 기록입니다.', expiresAt: new Date(Date.now()+86400000).toISOString() } }); assert.equal(decision.statusCode, 200);
      const detail = await app.inject({ url: `/api/v1/findings/${finding.id}`, headers: admin }); assert.equal(detail.json().automated_status, 'affected'); assert.equal(detail.json().decisions[0].status, 'not_affected');
    });
    await t.test('webhooks require raw-body HMAC and deduplicate delivery IDs', async () => {
      const payload = JSON.stringify({ repository: { full_name: 'test/source' } });
      const headers = { 'content-type': 'application/json', 'x-github-delivery': 'delivery-1', 'x-hub-signature-256': `sha256=${createHmac('sha256', process.env.SILICONER_TEST_WEBHOOK!).update(payload).digest('hex')}` };
      assert.equal((await app.inject({ method: 'POST', url: '/api/v1/webhooks/github/github-test', headers: { ...headers, 'x-hub-signature-256': `sha256=${'0'.repeat(64)}` }, payload })).statusCode, 401);
      const first = await app.inject({ method: 'POST', url: '/api/v1/webhooks/github/github-test', headers, payload }); assert.equal(first.statusCode, 202, first.body); assert.equal(first.json().duplicate, false);
      const second = await app.inject({ method: 'POST', url: '/api/v1/webhooks/github/github-test', headers, payload }); assert.equal(second.json().duplicate, true);
    });
    await t.test('ingest scope prevents cross-repo uploads and cannot assert verified provenance', async () => {
      const payload = { repository: 'test/source', commitSha: 'f'.repeat(40), image: 'test/source:v1', digest: `sha256:${'f'.repeat(64)}`, workflowRunId: '42', complete: true,
        sbom: { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ purl: 'pkg:npm/test@1.0.0' }] }, provenance: 'verified' };
      const headers = { authorization: `Bearer ${process.env.SILICONER_TEST_INGEST}` };
      const r = await app.inject({ method: 'POST', url: '/api/v1/ingest/sbom', headers, payload }); assert.equal(r.statusCode, 202, r.body); assert.equal(r.json().provenance, 'unverified');
      assert.equal((await app.inject({ method: 'POST', url: '/api/v1/ingest/sbom', headers, payload: { ...payload, repository: 'unauthorized/repo' } })).statusCode, 403);
      assert.equal((await app.inject({ method: 'POST', url: '/api/v1/ingest/sbom', payload })).statusCode, 401);
    });
    await t.test('expired evidence immediately reads as unknown, with historical state intact', async () => {
      const [finding] = await db.query("SELECT id FROM findings WHERE status='fixed' LIMIT 1");
      await db.query("UPDATE findings SET expires_at=now()-interval '1 second' WHERE id=$1", [finding.id]);
      const r = await app.inject({ url: `/api/v1/findings/${finding.id}`, headers: admin }); assert.equal(r.json().status, 'under_investigation'); assert.equal(r.json().automated_status, 'fixed');
    });
    await t.test('mixed rollout remains affected and snapshot namespace scope is enforced', async () => {
      const [asset] = await db.query("SELECT * FROM applications WHERE name='docs-service'");
      const config = { id: 'collector', kind: 'collector' as const, name: 'Collector', tokenEnv: 'TEST_TOKEN', clusterId: 'demo-cluster', namespaces: [asset.namespace], applicationIds: [asset.id] };
      const containers = ['a','b'].map((d,i) => ({ podUid: `mixed-${i}`, workloadUid: 'demo-workload', workloadName: 'docs', namespace: asset.namespace, container: 'app', kind: 'regular' as const, desiredImage: 'demo/portal:patched', digest: `sha256:${d.repeat(64)}`, running: true }));
      const snapshot = { applicationId: asset.id, clusterId: 'demo-cluster', observedAt: new Date(Date.now()+1000).toISOString(), complete: true, namespaces: [asset.namespace], containers };
      await ingestSnapshot(db, snapshot, config, 900); await assessAll(db, 86400);
      const [finding] = await db.query('SELECT status FROM findings WHERE application_id=$1', [asset.id]); assert.equal(finding.status, 'affected');
      await assert.rejects(ingestSnapshot(db, { ...snapshot, namespaces: ['other'] }, config, 900), /collector_scope_denied/);
      const scope={applicationIds:[asset.id],repositories:[],factAssetIds:[],userId:'test'};
      const oldStamp=await inspectionStamp(db,scope,{integrations:[],osv:false,pollSeconds:300,evidenceTtlSeconds:900});
      const collected={...containers[0],imageId:`docker.io/demo/portal@${containers[0].digest}`,
        runtimeVersions:[{product:'python',version:'3.12.12'},{product:'postgresql',version:'17.8'}]};
      const measurement={...snapshot,observedAt:new Date(Date.now()+2000).toISOString(),containers:[collected]};
      await assert.rejects(ingestSnapshot(db,measurement,config,900),/collector_runtime_probe_scope_denied/);
      const enabled={...config,runtimeVersionProbe:true};
      await assert.rejects(ingestSnapshot(db,{...measurement,containers:[{...collected,running:false}]},enabled,900),/collector_runtime_probe_scope_denied/);
      await ingestSnapshot(db,measurement,enabled,900);
      const evidenceConfig={integrations:[],osv:false,pollSeconds:300,evidenceTtlSeconds:900};
      assert.notEqual(await inspectionStamp(db,scope,evidenceConfig),oldStamp);
      const tools=new InspectionTools(db,evidenceConfig,scope);await tools.init();
      const {evidence}=await tools.call('asset_evidence',{target_id:asset.id});
      assert.deepEqual(evidence.filter((item:any)=>item.source==='collector:runtime-binary-version')
        .map((item:any)=>[item.facts.product,item.facts.version,item.facts.digest]),
        [['python','3.12.12',collected.digest],['postgresql','17.8',collected.digest]]);
    });
    await t.test('advisory alias collisions are visible; no SQL or secrets leak in errors', async () => {
      const doc = { id: 'TEST-ALIASED', aliases: ['TEST-ALIAS'], modified: new Date().toISOString(), affected: [] };
      const id = await saveAdvisory(db, doc); assert.equal(await saveAdvisory(db, doc), id);
      await saveAdvisory(db,{...doc,id:'TEST-SECOND',aliases:['TEST-ALIAS-SECOND']});
      await assert.rejects(saveAdvisory(db,{...doc,id:'TEST-CONFLICT',aliases:['TEST-ALIAS','TEST-ALIAS-SECOND']}),/advisory_alias_conflict/);
      const bad = await app.inject({ url: '/api/v1/findings?cursor=not-a-uuid', headers: admin }); assert.equal(bad.statusCode, 400); assert(!bad.body.includes('SELECT'));
      const invalid = await app.inject({ url: `/api/v1/assets/${randomUUID()}`, headers: admin }); assert.equal(invalid.statusCode, 404);
    });
  } finally { await app.close(); await db.close(); }
});
