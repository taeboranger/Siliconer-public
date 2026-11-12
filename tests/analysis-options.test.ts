import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {predictAnalysis} from '../apps/api/src/analysis-usage.js';
import {settingsForAnalysis} from '../apps/api/src/model-account.js';
import {readSettings} from '../apps/api/src/config.js';
import {testDatabase} from './helpers.js';
import {createUser,newSession} from '../apps/api/src/auth.js';
import {createApp} from '../apps/api/src/app.js';
import {configSchema} from '../packages/connectors/src/config.js';
import {registerIntegrations} from '../apps/api/src/inventory.js';
import {ORG} from '../packages/storage/src/db.js';

test('usage predictions preserve unknown allowances and calibrate matching model, effort and quota windows',()=>{
  const window={id:'codex',name:'Codex',minutes:300,usedPercent:40,resetsAt:1000,plan:'plus'};
  const sample={model:'model-a',effort:'low',type:'investigate',state:'succeeded',input:1000,output:200,calls:3,targets:2,
    before:[{...window,usedPercent:30}],after:[{...window,usedPercent:32}]};
  const predicted=predictAnalysis([sample,{...sample,model:'other',input:99999}],sample.model,'low','investigate',4,[window]);
  assert.equal(predicted.sampleCount,1);assert.equal(predicted.tokens?.median,2400);
  assert.equal(predicted.windows[0].predictedIncrease?.median,4);
  assert.equal(predicted.windows[0].usedPercent,40);
  assert.equal(predictAnalysis([sample],sample.model,'high','investigate',2,[window]).tokens,null);
  assert.equal(predictAnalysis([{...sample,state:'blocked'}],sample.model,'low','investigate',2,[window]).sampleCount,0);
  const unchanged=predictAnalysis([{...sample,after:sample.before}],sample.model,'low','investigate',2,[window]);
  assert.equal(unchanged.windows[0].predictedIncrease,null,'Rounded zero quota changes cannot establish zero consumption');
  const reset=predictAnalysis([{...sample,after:[{...window,resetsAt:2000}]}],sample.model,'low','investigate',2,[window]);
  assert.equal(reset.windows[0].predictedIncrease,null,'Never compare usage across a reset');
});

test('reports are saved independently and per-analysis model settings survive result deletion and reuse',async()=>{
  const db=await testDatabase();
  const user=await createUser(db,'report-owner@test.local','report-owner-password');
  const dev=await createUser(db,'other-developer@test.local','report-other-password','developer');
  const reviewer=await createUser(db,'reviewer@test.local','report-reviewer-password','reviewer');
  const settings=readSettings({SILICONER_DATABASE_URL:'pglite:memory',SILICONER_LLM_PROVIDER:'codex',SILICONER_LLM_ENABLED:'true'});
  const config=configSchema.parse({integrations:[{id:'host',kind:'facts',name:'Host',tokenEnv:'TEST_HOST_TOKEN',assetIds:['host:test'],allowedFactKeys:['version']}]});
  await registerIntegrations(db,config);
  await db.query(`INSERT INTO model_accounts(organization_id,provider,models,limits,observed_at) VALUES($1,'codex',$2,'[]',now())`,
    [ORG,JSON.stringify([{id:'custom-model',name:'Custom',efforts:['low','high'],defaultEffort:'low'}])]);
  const app=await createApp(db,config,settings);
  const sessionHeaders=async(id:string)=>{
    const session=await newSession(db,id);
    return {cookie:`siliconer_session=${session.token}; siliconer_csrf=${session.csrf}`,origin:settings.baseUrl,'x-csrf-token':session.csrf};
  };
  const [headers,devHeaders,reviewerHeaders]=await Promise.all([sessionHeaders(user),sessionHeaders(dev),sessionHeaders(reviewer)]);
  const report={title:'Saved host report',reportText:'A user-provided security report.\nIt lists an affected product and version range.',referenceUrl:'https://example.test/first',analysisSettings:{model:'custom-model',effort:'high' as const}};
  try{
    const created=await app.inject({method:'POST',url:'/api/v1/investigations',headers,payload:report});
    assert.equal(created.statusCode,202,created.body);
    const id=created.json().id;
    const [saved]=await db.query('SELECT report_id,analysis_settings FROM investigations WHERE id=$1',[id]);
    assert.deepEqual(saved.analysis_settings,report.analysisSettings);
    assert.equal(settingsForAnalysis(settings,saved.analysis_settings).reasoningEffort,'high');
    const library=await app.inject({url:'/api/v1/security-reports',headers});
    assert.equal(library.json().items.length,1);assert.equal(library.json().items[0].analysis_count,1);
    const source=await app.inject({url:`/api/v1/security-reports/${saved.report_id}`,headers});
    assert.equal(source.json().body,report.reportText);assert.equal(source.json().analyses[0].id,id);
    assert.equal((await app.inject({url:`/api/v1/security-reports/${saved.report_id}`,headers:devHeaders})).statusCode,404);
    const appId=randomUUID();
    await db.query(`INSERT INTO applications(id,organization_id,integration_id,external_uid,name,application_namespace,project,cluster_id,namespace,observed_at)
      VALUES($1,$2,'host','dedup-app','dedup-app','argocd','default','test','test',now())`,[appId,ORG]);
    await db.query('INSERT INTO service_owners(organization_id,user_id,application_id) VALUES($1,$2,$3)',[ORG,dev,appId]);
    const duplicate={...report,title:'Same body, different title',reportText:report.reportText.replace(/\n/g,'\r\n'),referenceUrl:'https://example.test/duplicate'};
    const [devRun,reviewerRun]=await Promise.all([devHeaders,reviewerHeaders].map(headers=>app.inject({method:'POST',url:'/api/v1/investigations',headers,payload:duplicate})));
    for(const run of [devRun,reviewerRun]){
      assert.equal(run.statusCode,202,run.body);
      const [record]=await db.query('SELECT report_id,report_text,reference_url FROM investigations WHERE id=$1',[run.json().id]);
      assert.equal(record.report_id,saved.report_id);assert.equal(record.report_text,report.reportText);assert.equal(record.reference_url,report.referenceUrl);
    }
    const shared=await app.inject({url:`/api/v1/security-reports/${saved.report_id}`,headers:devHeaders});
    assert.equal(shared.statusCode,200);assert.equal(shared.json().title,report.title);assert.deepEqual(shared.json().analyses.map((analysis:any)=>analysis.id),[devRun.json().id]);
    for(const [run,headers] of [[devRun,devHeaders],[reviewerRun,reviewerHeaders]] as const){
      const id=run.json().id;
      await db.query("UPDATE jobs SET state='succeeded' WHERE payload->>'investigationId'=$1",[id]);
      await db.query("UPDATE investigations SET state='blocked' WHERE id=$1",[id]);
      assert.equal((await app.inject({method:'DELETE',url:`/api/v1/investigations/${id}`,headers})).statusCode,403);
    }
    const unavailable=await app.inject({method:'POST',url:'/api/v1/investigations',headers,payload:{...report,analysisSettings:{model:'unavailable',effort:'low'}}});
    assert.equal(unavailable.statusCode,400);assert.equal(unavailable.json().error.code,'model_not_available');
    await db.query("UPDATE jobs SET state='succeeded' WHERE type='investigate' AND payload->>'investigationId'=$1",[id]);
    await db.query("UPDATE investigations SET state='blocked' WHERE id=$1",[id]);
    assert.equal((await app.inject({method:'DELETE',url:`/api/v1/investigations/${id}`,headers})).statusCode,200);
    assert.equal((await app.inject({url:`/api/v1/security-reports/${saved.report_id}`,headers})).json().body,report.reportText);
    const reused=await app.inject({method:'POST',url:'/api/v1/investigations',headers,payload:{title:'Recheck saved report',reportId:saved.report_id,analysisSettings:{model:'custom-model',effort:'low'}}});
    assert.equal(reused.statusCode,202,reused.body);
    assert.equal((await db.query('SELECT count(*)::integer AS n FROM security_reports'))[0].n,1);
    const [rerun]=await db.query('SELECT report_text,analysis_settings FROM investigations WHERE id=$1',[reused.json().id]);
    assert.equal(rerun.report_text,report.reportText);assert.equal(rerun.analysis_settings.effort,'low');
    const options=await app.inject({url:'/api/v1/analysis/options?model=custom-model&effort=low&targetCount=1',headers});
    assert.equal(options.statusCode,200,options.body);assert.equal(options.json().tokenAllowance,null);assert.equal(options.json().forecast.tokens,null);
  }finally{await app.close();await db.close();}
});
