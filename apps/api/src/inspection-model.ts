import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {ORG,type Database} from '../../../packages/storage/src/db.js';
import {AppError} from '../../../packages/core/src/types.js';
import {jsonRequest,type Transport} from '../../../packages/connectors/src/http.js';
import type {Settings} from './config.js';
import {codexInspectionModel} from './codex-model.js';

export function outputFormat(name:string,schema:z.ZodType){const json=z.toJSONSchema(schema);delete json.$schema;return {type:'json_schema',name,strict:true,schema:json};}
export async function inspectionModel(db:Database,settings:Settings,jobId:string|undefined,input:any[],format:unknown,tools:any[]=[],transport:Transport=fetch){
  if(!settings.llm)throw new AppError('llm_disabled',409);
  if(settings.llmProvider==='codex')return codexInspectionModel(db,settings,jobId,input,format,tools);
  if(!process.env.OPENAI_API_KEY)throw new AppError('llm_credential_missing',409);
  const payload={model:settings.model,store:false,max_output_tokens:settings.llmMaxOutput,input,text:{format},...(tools.length?{tools,parallel_tool_calls:false}:{})};
  const size=Buffer.byteLength(JSON.stringify(payload));if(size>180000)throw new AppError('inspection_context_limit',409);
  const reserve=((size+2048)*settings.llmInputPrice+settings.llmMaxOutput*settings.llmOutputPrice)/1e6;
  const id=randomUUID();
  await db.transaction(async tx=>{
    await tx.query('INSERT INTO llm_budgets(organization_id,day) VALUES($1,current_date) ON CONFLICT DO NOTHING',[ORG]);
    if(!(await tx.query('UPDATE llm_budgets SET reserved_usd=reserved_usd+$2 WHERE organization_id=$1 AND day=current_date AND reserved_usd+spent_usd+$2<=$3 RETURNING day',[ORG,reserve,settings.llmDailyBudget])).length)throw new AppError('llm_budget_exceeded',409);
    await tx.query('INSERT INTO llm_usage(id,organization_id,job_id,model,state,reserved_usd,effort) VALUES($1,$2,$3,$4,$5,$6,$7)',[id,ORG,jobId??null,settings.model,'reserved',reserve,settings.reasoningEffort]);
  });
  let response:any;
  try{response=await jsonRequest('https://api.openai.com/v1/responses',{method:'POST',headers:{Authorization:`Bearer ${process.env.OPENAI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(payload),signal:AbortSignal.timeout(60000)},transport);}
  catch{await db.query("UPDATE llm_usage SET state='uncertain' WHERE id=$1",[id]);throw new AppError('llm_request_uncertain',409);}
  const usage=response.usage;
  if(!usage || !Number.isInteger(usage.input_tokens) || usage.input_tokens<0 || !Number.isInteger(usage.output_tokens) || usage.output_tokens<0){await db.query("UPDATE llm_usage SET state='uncertain' WHERE id=$1",[id]);throw new AppError('llm_usage_missing',409);}
  const cost=(usage.input_tokens*settings.llmInputPrice+usage.output_tokens*settings.llmOutputPrice)/1e6;
  await db.transaction(async tx=>{
    await tx.query('UPDATE llm_budgets SET reserved_usd=GREATEST(0,reserved_usd-$2),spent_usd=spent_usd+$3 WHERE organization_id=$1 AND day=(SELECT created_at::date FROM llm_usage WHERE id=$4)',[ORG,reserve,cost,id]);
    await tx.query("UPDATE llm_usage SET state='completed',actual_usd=$2,input_tokens=$3,output_tokens=$4,cached_tokens=$5 WHERE id=$1",[id,cost,usage.input_tokens,usage.output_tokens,usage.input_tokens_details?.cached_tokens??0]);
  });
  if(response.status!=='completed')throw new AppError('llm_incomplete',409);
  return response;
}
export function responseObject(response:any){
  try{return JSON.parse((response.output??[]).flatMap((r:any)=>r.content??[]).filter((c:any)=>c.type==='output_text').map((c:any)=>c.text).join(''));}
  catch{throw new AppError('llm_invalid_output',409);}
}
