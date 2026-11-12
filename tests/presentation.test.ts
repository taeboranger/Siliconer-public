import test from 'node:test';
import assert from 'node:assert/strict';
import {collectionSummary,responseSummary,threatSummary,observedVersions,targetName,inspectionFailureMessage} from '../packages/core/src/presentation.js';
import {testDatabase} from './helpers.js';
import {configSchema} from '../packages/connectors/src/config.js';
import {registerIntegrations,syncIntegration} from '../apps/api/src/inventory.js';

test('threat level, service applicability and resolved workflow are independent',()=>{
  assert.equal(threatSummary({threat:{severity:'critical'}}).severity,'critical');
  assert.equal(responseSummary('not_affected').tone,'not_affected');
  assert.equal(responseSummary('affected','resolved').label,'처리 완료');
  assert.equal(responseSummary('under_investigation').label,'확인 후 대응 판단');
  assert.equal(threatSummary({products:[{name:'nginx'}]}).severity,'unknown');
  const evidence=[{target_id:'id',kind:'deployment_desired',source:'home/test-app',facts:{images:['nginx:1.26.1-alpine']}}];
  assert.deepEqual(observedVersions(evidence),['nginx:1.26.1-alpine']);assert.equal(targetName({target_id:'id'},evidence),'test-app');
  assert.equal(collectionSummary({render_state:'render_incomplete',desired_images:['nginx:1.26.1'],source_refs:[{state:'argo_summary'}]}).level,'summary');
  assert.equal(collectionSummary({render_state:'render_incomplete',desired_images:[]}).level,'missing');
  assert.match(inspectionFailureMessage('codex_request_timeout'),/대기 시간이 초과/);assert.match(inspectionFailureMessage('codex_usage_limit'),/사용 한도/);assert.match(inspectionFailureMessage('codex_login_required'),/로그인이 필요/);
  assert(!inspectionFailureMessage('codex_request_uncertain').includes('로그인'));assert(!inspectionFailureMessage('codex_request_uncertain').includes('사용 한도'));
});

test('Argo-only collection is an explicit image summary mode, with version evidence preserved',async()=>{
  const db=await testDatabase();const config=configSchema.parse({integrations:[{id:'argo',name:'Home Argo',kind:'argocd',url:'https://argo.example.internal',tokenEnv:'PRESENTATION_ARGO_TOKEN',projects:['default'],clusterId:'home'}]});
  process.env.PRESENTATION_ARGO_TOKEN='test-readonly-token';
  try{
    await registerIntegrations(db,config);
    await syncIntegration(db,config,'argo',async()=>Response.json({items:[{metadata:{uid:'uid-home',name:'spring-service'},spec:{project:'default',source:{repoURL:'git@github.com:example/config.git',path:'prod'},destination:{namespace:'service'}},status:{sync:{status:'Synced',revision:'a'.repeat(40)},health:{status:'Healthy'},summary:{images:['example/spring:3.2.1']}}}]}));
    const [asset]=await db.query('SELECT * FROM applications');assert.equal(asset.render_state,'summary_only');assert.equal(asset.sync_state,'Synced');assert.deepEqual(asset.desired_images,['example/spring:3.2.1']);assert.equal(asset.source_refs[0].reason,'github_not_configured');assert.equal(collectionSummary(asset).label,'Argo CD 이미지 목록 확인');
  }finally{delete process.env.PRESENTATION_ARGO_TOKEN;await db.close();}
});
