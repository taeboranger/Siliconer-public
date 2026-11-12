import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {testDatabase} from './helpers.js';
import {readSettings} from '../apps/api/src/config.js';
import {codexInspectionModel} from '../apps/api/src/codex-model.js';
import {configSchema} from '../packages/connectors/src/config.js';
import {ORG} from '../packages/storage/src/db.js';
import {reserveCodexCall} from '../apps/api/src/llm-budget.js';

test('subscription inference isolates secrets, validates tool calls and caps daily calls without USD charges',async()=>{
  const db=await testDatabase();const directory=await mkdtemp(join(tmpdir(),'siliconer-codex-test-'));
  const settings=readSettings({SILICONER_DATABASE_URL:'pglite:memory',SILICONER_LLM_ENABLED:'true',SILICONER_LLM_PROVIDER:'codex',SILICONER_CODEX_HOME:directory,SILICONER_LLM_DAILY_CALLS:'2',SILICONER_REASONING_EFFORT:'medium'});
  const format={schema:{type:'object',properties:{summary:{type:'string'}},required:['summary'],additionalProperties:false}};
  const tools=[{type:'function',name:'asset_evidence',parameters:{type:'object'}}];
  try{
    await assert.rejects(codexInspectionModel(db,settings,undefined,[],format,tools),/codex_login_required/);
    await writeFile(join(directory,'auth.json'),'{}');
    const first=await codexInspectionModel(db,settings,undefined,[],format,tools,async(options,thread)=>{
      assert.equal(options.env?.CODEX_HOME,directory);assert(!('SILICONER_DATABASE_URL' in options.env!));assert(!('ARGOCD_AUTH_TOKEN' in options.env!));assert(!('OPENAI_API_KEY' in options.env!));
      assert.equal((options.config?.features as any).shell_tool,false);assert.equal(thread.approvalPolicy,'never');assert.equal(thread.webSearchMode,'disabled');assert.equal(thread.sandboxMode,'read-only');
      assert.equal(thread.modelReasoningEffort,'medium');assert.equal(thread.model,settings.model);
      return {items:[],finalResponse:JSON.stringify({tool_calls:[{name:'asset_evidence',arguments:'{"target_id":"test"}'}],result:null}),usage:{input_tokens:50,output_tokens:20,cached_input_tokens:0,cache_write_input_tokens:0,reasoning_output_tokens:0}};
    });
    assert.equal(first.output[0].name,'asset_evidence');
    await assert.rejects(codexInspectionModel(db,settings,undefined,[],format,tools,async()=>({items:[],finalResponse:JSON.stringify({tool_calls:[{name:'run_shell',arguments:'{}'}],result:null}),usage:{input_tokens:50,output_tokens:20,cached_input_tokens:0,cache_write_input_tokens:0,reasoning_output_tokens:0}})),/llm_invalid_output/);
    await assert.rejects(codexInspectionModel(db,settings,undefined,[],format,tools),/llm_call_limit/);
    const usage=await db.query('SELECT provider,state,actual_usd,reserved_usd FROM llm_usage ORDER BY created_at');
    assert.equal(usage.length,2);assert.equal(usage[0].provider,'codex');assert.equal(usage[0].actual_usd,null);assert.equal(Number(usage[0].reserved_usd),0);assert.equal(usage[1].state,'uncertain');
  }finally{await db.close();await rm(directory,{recursive:true,force:true});}
});

test('Argo-only configuration allows explicit cluster service HTTP but rejects arbitrary plaintext endpoints',()=>{
  const argo={id:'argo',name:'Home Argo',kind:'argocd',url:'http://argocd-server.argocd.svc',tokenEnv:'ARGO_TOKEN',projects:['default'],clusterId:'home'};
  assert.throws(()=>configSchema.parse({integrations:[argo]}));
  assert.equal(configSchema.parse({integrations:[{...argo,allowInsecureClusterHttp:true}]}).integrations.length,1);
  assert.throws(()=>configSchema.parse({integrations:[{...argo,url:'http://example.com',allowInsecureClusterHttp:true}]}));
});

test('saved budgets take effect on the next reservation without resetting daily usage',async()=>{
  const db=await testDatabase();
  try{
    const reserve=()=>db.transaction(tx=>reserveCodexCall(tx,1));
    await reserve();
    await assert.rejects(reserve,/llm_call_limit/);
    await db.query('INSERT INTO llm_budget_settings VALUES($1,2,80)',[ORG]);
    await db.query("INSERT INTO model_accounts(organization_id,provider,limits) VALUES($1,'codex',$2)",[ORG,
      JSON.stringify([{usedPercent:20,resetsAt:Math.floor(Date.now()/1000)+3600},{usedPercent:80,resetsAt:Math.floor(Date.now()/1000)+86400}])]);
    await assert.rejects(reserve,/llm_subscription_budget_reached/);
    await db.query('UPDATE llm_budget_settings SET subscription_percent=100 WHERE organization_id=$1',[ORG]);
    await reserve();
    await assert.rejects(reserve,/llm_call_limit/);
    assert.equal((await db.query('SELECT calls FROM llm_call_budgets WHERE organization_id=$1',[ORG]))[0].calls,2);
  }finally{await db.close();}
});

test('Codex failures distinguish an actual timeout from auth, quota and invalid output without storing raw errors or retrying',async()=>{
  const db=await testDatabase(),directory=await mkdtemp(join(tmpdir(),'siliconer-codex-errors-'));
  const settings=readSettings({SILICONER_DATABASE_URL:'pglite:memory',SILICONER_LLM_ENABLED:'true',SILICONER_LLM_PROVIDER:'codex',SILICONER_CODEX_HOME:directory});
  assert.equal(settings.codexTimeoutSeconds,300);
  assert.throws(()=>readSettings({SILICONER_DEMO:'true',SILICONER_CODEX_TIMEOUT_SECONDS:'0'}));
  const cases=[['codex_usage_limit','You have reached your usage limit'],['codex_login_required','authentication failed'],['codex_connection_failed','stream disconnected before completion'],['codex_request_uncertain','unexpected private source content: SECRET-SENTINEL']];
  const format={schema:{type:'object',properties:{summary:{type:'string'}},required:['summary'],additionalProperties:false}};
  let calls=0;
  try{
    await writeFile(join(directory,'auth.json'),'{}');
    for(const [code,message] of cases)await assert.rejects(codexInspectionModel(db,settings,undefined,[],format,[],async()=>{calls++;throw new Error(message)}),new RegExp(code));
    await assert.rejects(codexInspectionModel(db,{...settings,codexTimeoutSeconds:0.001},undefined,[],format,[],async(_o,_t,_p,_s,signal)=>{
      calls++;await new Promise<never>((_resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Test signal did not abort')),1000);signal.addEventListener('abort',()=>{clearTimeout(timer);reject(signal.reason)},{once:true});});throw new Error('Unreachable');
    }),/codex_request_timeout/);
    await assert.rejects(codexInspectionModel(db,settings,undefined,[],format,[],async()=>{calls++;return {items:[],finalResponse:'invalid JSON SECRET-SENTINEL',usage:{input_tokens:1,output_tokens:1,cached_input_tokens:0,cache_write_input_tokens:0,reasoning_output_tokens:0}}}),/llm_invalid_output/);
    assert.equal(calls,6,'Failed paid/subscription calls must not automatically retry');
    const events=await db.query("SELECT details FROM audit_events WHERE action='llm.codex_failed'");assert.equal(events.length,6);assert(!JSON.stringify(events).includes('SECRET-SENTINEL'));assert(events.some(e=>e.details.code==='codex_request_timeout'));
    assert((await db.query('SELECT state FROM llm_usage')).every(u=>u.state==='uncertain'));
  }finally{await db.close();await rm(directory,{recursive:true,force:true});}
});
