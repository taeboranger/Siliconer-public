import {z} from 'zod';
import type {FastifyInstance} from 'fastify';
import {ORG,type Database} from '../../../packages/storage/src/db.js';
import {enqueue} from '../../../packages/storage/src/jobs.js';
import {AppError,roleLevel} from '../../../packages/core/src/types.js';
import {analysisSettingsSchema,type ModelOption,type QuotaWindow} from './model-account.js';
import type {Settings} from './config.js';
import type {ConnectorConfig} from '../../../packages/connectors/src/config.js';
import {allowedScope,InspectionTools} from './inspection-tools.js';
import {budgetSettings,readLlmBudget} from './llm-budget.js';
import {audit} from './inventory.js';

interface Sample {model:string;effort:string;type:string;state?:string;input:number;output:number;calls:number;targets:number;before:QuotaWindow[];after:QuotaWindow[]}
function percentile(values:number[],position:number){
  const sorted=values.toSorted((a,b)=>a-b);
  return sorted[Math.min(sorted.length-1,Math.floor((sorted.length-1)*position))];
}

export function predictAnalysis(samples:Sample[],model:string,effort:string,operation:string,targetCount:number,windows:QuotaWindow[]){
  const matching=samples.filter(sample=>(!sample.state||sample.state==='succeeded')&&sample.model===model&&sample.effort===effort&&sample.type===operation);
  const scaled=matching.map(sample=>{
    const factor=operation==='investigate'?Math.max(1,targetCount)/Math.max(1,sample.targets):1;
    return {sample,factor,input:sample.input*factor,output:sample.output*factor,calls:sample.calls*factor};
  });
  if(!scaled.length)return {sampleCount:0,tokens:null,calls:null,windows:windows.map(window=>({...window,predictedIncrease:null}))};
  const range=(values:number[])=>({low:Math.round(percentile(values,.2)),median:Math.round(percentile(values,.5)),high:Math.round(percentile(values,.8))});
  const tokens=range(scaled.map(sample=>sample.input+sample.output));
  const quotas=windows.map(window=>{
    const changes=scaled.flatMap(({sample,factor})=>{
      const before=sample.before.find(value=>value.id===window.id&&value.minutes===window.minutes);
      const after=sample.after.find(value=>value.id===window.id&&value.minutes===window.minutes);
      if(!before||!after||before.resetsAt!==after.resetsAt||after.usedPercent<=before.usedPercent)return [];
      return [(after.usedPercent-before.usedPercent)*factor];
    });
    const predictedIncrease=changes.length?{
      low:Number(percentile(changes,.2).toFixed(2)),median:Number(percentile(changes,.5).toFixed(2)),
      high:Number(percentile(changes,.8).toFixed(2)),sampleCount:changes.length,
    }:null;
    return {...window,predictedIncrease};
  });
  return {sampleCount:scaled.length,tokens,inputTokens:range(scaled.map(sample=>sample.input)),outputTokens:range(scaled.map(sample=>sample.output)),
    calls:range(scaled.map(sample=>sample.calls)),windows:quotas};
}

export async function analysisUsage(db:Database,settings:Settings,userId:string,all:boolean,query?:{model:string;effort:string;operation:string;targetCount:number}){
  const [accounts,usage,budgets,budget]=await Promise.all([
    db.query('SELECT * FROM model_accounts WHERE organization_id=$1 AND provider=$2',[ORG,settings.llmProvider]),
    db.query(`SELECT u.job_id,u.model,u.effort,u.input_tokens,u.output_tokens,j.type,j.state,j.usage_context,
        COALESCE(jsonb_array_length(i.result->'targets'),jsonb_array_length(i.scope->'applicationIds'),1) AS targets
      FROM llm_usage u JOIN jobs j ON j.id=u.job_id AND j.organization_id=u.organization_id
      LEFT JOIN investigations i ON i.organization_id=j.organization_id AND i.id::text=j.payload->>'investigationId'
      WHERE u.organization_id=$1 AND u.provider=$2 AND u.state='completed'
        AND j.type IN ('investigate','investigation-detail')
        AND ($3::boolean OR i.created_by=$4 OR j.payload->>'requestedBy'=$4::text)
      ORDER BY u.created_at DESC LIMIT 3000`,[ORG,settings.llmProvider,all,userId]),
    db.query("SELECT calls FROM llm_call_budgets WHERE organization_id=$1 AND provider=$2 AND day=current_date",[ORG,settings.llmProvider]),
    readLlmBudget(db,settings.llmDailyCalls),
  ]);
  const account=accounts[0];
  const models:ModelOption[]=account?.models?.length?account.models:[{id:settings.model,name:settings.model,efforts:[settings.reasoningEffort],defaultEffort:settings.reasoningEffort}];
  const limits:QuotaWindow[]=account?.limits??[];
  const samples=new Map<string,Sample>();
  for(const row of usage){
    if(row.input_tokens===null||row.output_tokens===null)continue;
    let sample=samples.get(row.job_id);
    if(!sample){sample={model:row.model,effort:row.effort,type:row.type,state:row.state,input:0,output:0,calls:0,targets:row.targets??1,
      before:row.usage_context.before??[],after:row.usage_context.after??[]};samples.set(row.job_id,sample);}
    sample.input+=Number(row.input_tokens);sample.output+=Number(row.output_tokens);sample.calls++;
  }
  const forecast=query?predictAnalysis([...samples.values()],query.model,query.effort,query.operation,query.targetCount,limits):null;
  return {provider:settings.llmProvider,defaultModel:settings.model,defaultEffort:settings.reasoningEffort,models,
    account:{windows:limits,observedAt:account?.observed_at??null,error:account?.error_code??null,
      stale:!account?.observed_at||Date.now()-Date.parse(account.observed_at)>120000},forecast,
    appDaily:settings.llmProvider==='codex'?{used:budgets[0]?.calls??0,limit:budget.dailyCalls}:null,
    budget:settings.llmProvider==='codex'?budget:null,
    history:[...samples.values()].slice(0,100),
    quotaNote:'구독 한도는 계정 전체의 사용률입니다. 작업별 예상 증가량은 분석 전후 관측치를 사용하며 다른 앱의 사용량이 함께 반영될 수 있습니다.',
    tokenAllowance:null};
}

export function registerAnalysisUsageRoutes(app:FastifyInstance,db:Database,settings:Settings,config:ConnectorConfig){
  app.patch('/api/v1/usage/llm/budget',async req=>{
    if(req.actor?.role!=='admin')throw new AppError('permission_denied',403);
    if(settings.llmProvider!=='codex')throw new AppError('llm_budget_provider_unsupported',409);
    const budget=budgetSettings.parse(req.body);
    await db.transaction(async tx=>{
      await tx.query('SELECT id FROM organizations WHERE id=$1 FOR NO KEY UPDATE',[ORG]);
      await tx.query(`INSERT INTO llm_budget_settings(organization_id,daily_calls,subscription_percent) VALUES($1,$2,$3)
        ON CONFLICT(organization_id) DO UPDATE SET daily_calls=EXCLUDED.daily_calls,subscription_percent=EXCLUDED.subscription_percent`,
        [ORG,budget.dailyCalls,budget.subscriptionPercent]);
      await audit(tx,req.actor!.id,'llm.budget_updated',ORG,budget);
    });
    return budget;
  });
  const querySchema=analysisSettingsSchema.extend({operation:z.enum(['investigate','investigation-detail']).default('investigate'),targetCount:z.coerce.number().int().min(1).max(200).optional()});
  app.get('/api/v1/analysis/options',async req=>{
    const actor=req.actor!;
    if(roleLevel[actor.role]<1)throw new AppError('permission_denied',403);
    const parsed=querySchema.partial({model:true,effort:true}).parse(req.query);
    let targetCount=parsed.targetCount??1;
    if(parsed.operation==='investigate'&&!parsed.targetCount){
      const tools=new InspectionTools(db,config,await allowedScope(db,config,actor.id));
      await tools.init();
      const linked=new Set(tools.targets.flatMap(target=>(target.metadata.source_repositories??[]).map((source:any)=>source.target_id)));
      targetCount=Math.max(1,tools.targets.filter(target=>target.kind!=='repository'||(target.metadata.repository_kind!=='gitops'&&!linked.has(target.id))).length);
    }
    const result=await analysisUsage(db,settings,actor.id,actor.role==='admin'||actor.role==='reviewer',{
      ...parsed,targetCount,model:parsed.model??settings.model,effort:parsed.effort??settings.reasoningEffort,
    });
    if(settings.llmProvider==='codex'&&result.account.stale)await enqueue(db,'model-account',{},'model-account');
    return {...result,targetCount};
  });
}
