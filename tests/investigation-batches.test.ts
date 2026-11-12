import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {testDatabase} from './helpers.js';
import {ORG} from '../packages/storage/src/db.js';
import {createUser} from '../apps/api/src/auth.js';
import {readSettings} from '../apps/api/src/config.js';
import {configSchema} from '../packages/connectors/src/config.js';
import {registerIntegrations} from '../apps/api/src/inventory.js';
import {createInvestigation,runInvestigation} from '../apps/api/src/investigations.js';
import type {Transport} from '../packages/connectors/src/http.js';

test('large inspections use bounded target batches and save tickets only after every batch validates',async()=>{
  const db=await testDatabase(),user=await createUser(db,'batch@test.local','batch-test-password');
  const config=configSchema.parse({integrations:[{id:'argo',kind:'argocd',name:'Test',url:'https://argo.test',tokenEnv:'UNUSED_TEST_TOKEN',projects:['default'],clusterId:'home'}]});
  await registerIntegrations(db,config);
  for(let i=0;i<6;i++){const id=randomUUID();await db.query("INSERT INTO applications(id,organization_id,integration_id,external_uid,name,application_namespace,project,cluster_id,namespace,desired_images,observed_at) VALUES($1,$2,'argo',$3,$3,'argocd','default','home','test',$4,now())",[id,ORG,'batch-'+i,JSON.stringify([i%2?'nginx:1.26.2':'nginx:1.26.1'])]);}
  const settings=readSettings({SILICONER_DATABASE_URL:'pglite:memory',SILICONER_LLM_ENABLED:'true',OPENAI_MODEL:'test-model',OPENAI_INPUT_USD_PER_MILLION:'1',OPENAI_OUTPUT_USD_PER_MILLION:'2',OPENAI_DAILY_BUDGET_USD:'10'});
  const plan={threat:{severity:'unknown',basis:'unknown',headline:'Test',impact:'Test',severity_reason:'Test',cvss_score:null},summary:'Version check',products:[],checks:[{id:'version',kind:'version',question:'Affected?',required_evidence:'Image tag'}]};
  const report={title:'Batch test',reportText:'Test report for declared nginx image versions: 1.26.1 is affected; 1.26.2 is fixed.',force:true};
  let batchCalls=0;
  function transport(fail=false,otherUnknown=false,repeat=false,changeEvidence=false):Transport{return async(_url,init)=>{
    const payload=JSON.parse(String(init?.body)),format=payload.text.format.name;
    const respond=(output:any[])=>Response.json({status:'completed',usage:{input_tokens:10,output_tokens:10},output});
    const result=(r:unknown)=>respond([{content:[{type:'output_text',text:JSON.stringify(r)}]}]);
    if(format==='security_inspection_plan')return result(otherUnknown?{...plan,checks:[...plan.checks,{id:'other-version',kind:'version',question:'Unrelated product affected?',required_evidence:'Other product version'}]}:plan);
    const request=JSON.parse(payload.input.find((i:any)=>i.role==='user').content),targets=request.allowed_targets;
    assert.equal(targets.length,2);assert.equal(request.target_count,2);
    assert.equal(request.initial_evidence.length,2);assert(request.initial_evidence.every((item:any)=>item.evidence.some((e:any)=>targets.some((t:any)=>t.id===e.target_id))),'Host must provide real scoped evidence before asking the model');
    if(repeat){
      if(payload.tools?.length)return respond(targets.map((t:any)=>({type:'function_call',name:'asset_evidence',call_id:randomUUID(),arguments:JSON.stringify({target_id:t.id})})));
      return result({summary:'Evidence collection exhausted',targets:targets.map((t:any)=>({target_id:t.id,status:'under_investigation',confidence:'low',response_summary:'Insufficient evidence',explanation:'Cannot conclude',version_comparison:[],checks:[{check_id:'version',result:'unknown',evidence_ids:[],explanation:'Missing conclusion'}],recommended_actions:[]})),limitations:['No runtime verification']});
    }
    const outputs=payload.input.filter((i:any)=>i.type==='function_call_output');
    if(!outputs.length){batchCalls++;if(fail&&batchCalls===2)throw new Error('Simulated second-batch failure');return respond(targets.map((t:any)=>({type:'function_call',name:'asset_evidence',call_id:t.id,arguments:JSON.stringify({target_id:t.id})})));}
    const evidence=outputs.flatMap((o:any)=>JSON.parse(o.output).evidence??[]);
    if(changeEvidence&&batchCalls===3)await db.query("UPDATE applications SET desired_images='[\"nginx:1.27.0\"]' WHERE name='batch-0'");
    return result({summary:'Checked two services',targets:targets.map((t:any)=>{const e=evidence.find((e:any)=>e.target_id===t.id),affected=e.facts.images.includes('nginx:1.26.1');return {target_id:t.id,status:affected?'affected':'not_affected',confidence:'high',response_summary:'Declared version compared',explanation:'Image evidence',version_comparison:otherUnknown?[{product:'nginx',observed_version:affected?'1.26.1':'1.26.2',affected_range:'<1.26.2',fixed_version:'1.26.2',result:affected?'affected':'outside_range',evidence_ids:[e.id]}]:[],checks:[{check_id:'version',result:affected?'met':'not_met',evidence_ids:[e.id],explanation:'Version comparison'},...(otherUnknown?[{check_id:'other-version',result:'unknown',evidence_ids:[],explanation:'Unrelated version unavailable'}]:[])],recommended_actions:[]}}),limitations:['Declared versions only']});
  };}
  process.env.OPENAI_API_KEY='test-only-batch-key';
  try{
    const failed=await createInvestigation(db,config,settings,user,report);
    await assert.rejects(runInvestigation(db,failed.id,settings,config,undefined,transport(true)),/llm_request_uncertain/);
    assert.equal((await db.query('SELECT count(*)::int AS n FROM tickets'))[0].n,0);
    assert.equal((await db.query('SELECT state FROM investigations WHERE id=$1',[failed.id]))[0].state,'blocked');
    batchCalls=0;const created=await createInvestigation(db,config,settings,user,report),result=await runInvestigation(db,created.id,settings,config,undefined,transport());
    assert.equal(batchCalls,3);assert.equal(result.targets.length,6);assert.equal(new Set(result.targets.map(t=>t.target_id)).size,6);assert.equal(result.ticket_ids.length,3);assert.equal(result.tool_calls,6);
    assert.equal((await db.query('SELECT state FROM investigations WHERE id=$1',[created.id]))[0].state,'completed');
    // A confirmed vulnerable product still needs action when another product is unknown.
    // A safe version for one product must not prove the whole multi-product report safe.
    const multi=await createInvestigation(db,config,settings,user,{...report,reportText:report.reportText+' Also inspect an unrelated product.'});
    const mixed=await runInvestigation(db,multi.id,settings,config,undefined,transport(false,true));
    assert.equal(mixed.targets.filter(t=>t.status==='affected').length,3);assert.equal(mixed.targets.filter(t=>t.status==='under_investigation').length,3);
    assert(mixed.targets.filter(t=>t.status==='under_investigation').every(t=>
      t.version_comparison.some(version=>version.product==='nginx'&&version.result==='outside_range')&&
      t.response_summary.includes('nginx')&&t.response_summary.includes('나머지 조건은 확인')));
    const exhausted=await createInvestigation(db,config,settings,user,{...report,reportText:report.reportText+' Collection exhaustion test.'});
    const bounded=await runInvestigation(db,exhausted.id,settings,config,undefined,transport(false,false,true));assert(bounded.targets.every(t=>t.status==='under_investigation'));assert.equal(bounded.tool_calls,24);
    batchCalls=0;
    const changed=await createInvestigation(db,config,settings,user,report);
    const historical=await runInvestigation(db,changed.id,settings,config,undefined,transport(false,false,false,true));
    assert.equal(historical.evidence_changed,true);
    assert.equal(historical.targets.length,6);
    const changedTarget=historical.targets.find(target=>target.target_name==='batch-0')!;
    assert.deepEqual(historical.changed_target_ids,[changedTarget.target_id]);
    assert.equal(historical.ticket_ids.length,2);
    assert.deepEqual(await db.query('SELECT target_id FROM investigation_tickets WHERE investigation_id=$1 AND target_id=$2',[changed.id,changedTarget.target_id]),[]);
    const [stored]=await db.query('SELECT state,expires_at FROM investigations WHERE id=$1',[changed.id]);
    assert.equal(stored.state,'completed');
    assert(Date.parse(stored.expires_at)<=Date.now());
  }finally{delete process.env.OPENAI_API_KEY;await db.close();}
});
