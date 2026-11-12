import test from 'node:test';
import assert from 'node:assert/strict';
import { seedDemo } from '../apps/api/src/seed.js';
import { generateReport } from '../apps/api/src/reports.js';
import { readSettings } from '../apps/api/src/config.js';
import type { Transport } from '../packages/connectors/src/http.js';
import { testDatabase } from './helpers.js';
test('report evidence validation, metadata-only context, budget reservation and cache invalidation', async () => {
  const db = await testDatabase(); await seedDemo(db,true); process.env.OPENAI_API_KEY='test-not-a-real-api-key';
  const settings=readSettings({SILICONER_DATABASE_URL:'pglite:memory',SILICONER_LLM_ENABLED:'true',OPENAI_MODEL:'test-model',OPENAI_INPUT_USD_PER_MILLION:'1',OPENAI_OUTPUT_USD_PER_MILLION:'2',OPENAI_DAILY_BUDGET_USD:'1'});
  const [finding]=await db.query("SELECT * FROM findings WHERE status='affected' LIMIT 1"); let calls=0;
  const transport=(async (_url:any,init:any)=>{ calls++; const body=JSON.parse(init.body); assert.equal(body.store,false); assert(!body.tools); const context=JSON.parse(body.input[1].content); assert.equal(context.codePolicy,'deny'); assert(!JSON.stringify(context).includes('config.git'));
    return Response.json({status:'completed',usage:{input_tokens:100,output_tokens:50,input_tokens_details:{cached_tokens:0}},output:[{content:[{type:'output_text',text:JSON.stringify({summary:'검증된 메타데이터 기반 보고서',verified_facts:[{description:'수집된 실행 근거가 있습니다.',evidence_ids:[finding.evidence[0].id]}],potential_impact:[],unknowns:['코드와 릴리스 노트가 제공되지 않았습니다.'],recommended_checks:['업그레이드 후 통합 테스트를 수행하세요.']})}]}]});}) as Transport;
  try {
    const first=await generateReport(db,finding.id,'4.17.21',settings,undefined,transport); const cached=await generateReport(db,finding.id,'4.17.21',settings,undefined,transport);
    assert.equal(first.id,cached.id); assert.equal(calls,1);
    const [budget]=await db.query('SELECT * FROM llm_budgets'); assert.equal(Number(budget.reserved_usd),0); assert(Number(budget.spent_usd)>0);
    await db.query('UPDATE findings SET input_hash=$2 WHERE id=$1',[finding.id,'new-environment-evidence']);
    assert.notEqual((await generateReport(db,finding.id,'4.17.21',settings,undefined,transport)).id,first.id); assert.equal(calls,2);
    await assert.rejects(generateReport(db,finding.id,'5.0.0',{...settings,llmDailyBudget:0.0000001},undefined,transport),/llm_budget_exceeded/);
    const invalid=(async()=>Response.json({status:'completed',usage:{input_tokens:10,output_tokens:10},output:[{content:[{type:'output_text',text:JSON.stringify({summary:'Invalid',verified_facts:[{description:'Unsupported',evidence_ids:['invented-id']}],potential_impact:[],unknowns:[],recommended_checks:[]})}]}]})) as Transport;
    await assert.rejects(generateReport(db,finding.id,'5.0.1',settings,undefined,invalid),/llm_invalid_evidence/);
    const timeout=(async()=>{throw new Error('timeout');}) as Transport;
    await assert.rejects(generateReport(db,finding.id,'5.0.2',settings,undefined,timeout),/llm_request_uncertain/);
    assert.equal((await db.query("SELECT count(*)::integer AS n FROM llm_usage WHERE state='uncertain'"))[0].n,1);
    assert(Number((await db.query('SELECT reserved_usd FROM llm_budgets'))[0].reserved_usd)>0);
  } finally { delete process.env.OPENAI_API_KEY; await db.close(); }
});
