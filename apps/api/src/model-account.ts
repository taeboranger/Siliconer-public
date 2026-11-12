import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {dirname,join} from 'node:path';
import {createInterface} from 'node:readline';
import {z} from 'zod';
import {ORG,type Database} from '../../../packages/storage/src/db.js';
import {AppError} from '../../../packages/core/src/types.js';
import type {Settings} from './config.js';

export const analysisSettingsSchema=z.object({
  model:z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,99}$/),
  effort:z.enum(['low','medium','high','xhigh','max','ultra']),
}).strict();
export type AnalysisSettings=z.infer<typeof analysisSettingsSchema>;
export interface ModelOption {id:string;name:string;efforts:string[];defaultEffort:string}
export interface QuotaWindow {id:string;name:string;minutes:number;usedPercent:number;resetsAt:number;plan:string|null}

export async function codexCommand(){
  const require=createRequire(import.meta.resolve('@openai/codex-sdk'));
  const manifest=require.resolve('@openai/codex/package.json');
  const pkg=JSON.parse(await readFile(manifest,'utf8'));
  return join(dirname(manifest),typeof pkg.bin==='string'?pkg.bin:pkg.bin.codex);
}

export async function readCodexAccount(settings:Settings):Promise<{models:ModelOption[];limits:QuotaWindow[];identity:{email:string;plan:string|null}|null}>{
  const command=await codexCommand();
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[command,'app-server'],{
      windowsHide:true,stdio:['pipe','pipe','pipe'],
      env:{PATH:process.env.PATH??'',HOME:settings.codexHome,CODEX_HOME:settings.codexHome},
    });
    let finished=false,bytes=0;
    let catalog:any,quota:any,identity:any;
    const close=(error?:Error)=>{
      if(finished)return;
      finished=true;clearTimeout(timer);lines.close();child.kill();
      if(error){reject(error);return;}
      try{
        const models:ModelOption[]=(catalog.data??[]).filter((model:any)=>typeof model.model==='string'&&!model.hidden).map((model:any)=>({
          id:model.model,name:String(model.displayName??model.model),
          efforts:(model.supportedReasoningEfforts??[]).map((entry:any)=>entry.reasoningEffort).filter((value:string)=>analysisSettingsSchema.shape.effort.safeParse(value).success),
          defaultEffort:model.defaultReasoningEffort??'low',
        }));
        const buckets=quota.rateLimitsByLimitId??(quota.rateLimits?{default:quota.rateLimits}:{});
        const limits:QuotaWindow[]=[];
        for(const [key,bucket] of Object.entries<any>(buckets)){
          for(const window of [bucket.primary,bucket.secondary]){
            if(!window||!Number.isFinite(window.usedPercent)||!Number.isFinite(window.windowDurationMins)||!Number.isFinite(window.resetsAt))continue;
            limits.push({id:bucket.limitId??key,name:bucket.limitName??bucket.limitId??key,minutes:window.windowDurationMins,
              usedPercent:Math.min(100,Math.max(0,window.usedPercent)),resetsAt:window.resetsAt,plan:bucket.planType??null});
          }
        }
        if(!models.length)throw new Error('empty model catalog');
        const account=identity?.account;
        resolve({models,limits,identity:account?.type==='chatgpt'&&z.email().safeParse(account.email).success?
          {email:account.email,plan:typeof account.planType==='string'?account.planType.slice(0,40):null}:null});
      }catch{reject(new AppError('model_account_unavailable',503));}
    };
    const timer=setTimeout(()=>close(new AppError('model_account_timeout',503)),20000);
    const send=(id:number,method:string,params?:unknown)=>child.stdin.write(JSON.stringify({id,method,...(params?{params}:{})})+'\n');
    child.on('error',()=>close(new AppError('model_account_unavailable',503)));
    child.on('exit',()=>{if(!finished)close(new AppError('model_account_unavailable',503));});
    child.stdin.on('error',()=>close(new AppError('model_account_unavailable',503)));
    child.stderr.resume();
    const lines=createInterface({input:child.stdout});
    lines.on('line',line=>{
      bytes+=Buffer.byteLength(line);
      if(bytes>2*1024*1024){close(new AppError('model_account_invalid',503));return;}
      let message;try{message=JSON.parse(line);}catch{return;}
      if(message.error&&message.id!==3){close(new AppError('model_account_unavailable',503));return;}
      if(message.id===0){
        child.stdin.write(JSON.stringify({method:'initialized'})+'\n');
        send(1,'model/list',{limit:100,includeHidden:false});
        send(2,'account/rateLimits/read');
        send(3,'account/read',{refreshToken:false});
      }
      if(message.id===1)catalog=message.result;
      if(message.id===2)quota=message.result;
      if(message.id===3)identity=message.result??{};
      if(catalog&&quota&&identity)close();
    });
    send(0,'initialize',{clientInfo:{name:'siliconer',version:'0.1.0'}});
  });
}

export async function syncModelAccount(db:Database,settings:Settings){
  if(settings.llmProvider!=='codex')return {models:[{id:settings.model,name:settings.model,efforts:[settings.reasoningEffort],defaultEffort:settings.reasoningEffort}],limits:[] as QuotaWindow[]};
  try{
    const account=await readCodexAccount(settings);
    await saveCodexAccount(db,account);
    return account;
  }catch{
    await db.query(`INSERT INTO model_accounts(organization_id,provider,error_code) VALUES($1,'codex','model_account_unavailable')
      ON CONFLICT(organization_id,provider) DO UPDATE SET error_code='model_account_unavailable'`,[ORG]);
    return null;
  }
}

export async function saveCodexAccount(db:Pick<Database,'query'>,account:Awaited<ReturnType<typeof readCodexAccount>>){
  await db.query(`INSERT INTO model_accounts(organization_id,provider,models,limits,observed_at,account_email,account_plan)
    VALUES($1,'codex',$2,$3,now(),$4,$5) ON CONFLICT(organization_id,provider)
    DO UPDATE SET models=$2,limits=$3,observed_at=now(),error_code=NULL,account_email=$4,account_plan=$5`,
    [ORG,JSON.stringify(account.models),JSON.stringify(account.limits),account.identity?.email??null,account.identity?.plan??null]);
}

export async function selectAnalysisSettings(db:Database,settings:Settings,raw?:unknown):Promise<AnalysisSettings>{
  const selected=analysisSettingsSchema.parse(raw??{model:settings.model,effort:settings.reasoningEffort});
  if(!raw)return selected;
  if(settings.llmProvider==='openai'){
    if(selected.model!==settings.model||selected.effort!==settings.reasoningEffort)throw new AppError('model_not_available',400);
    return selected;
  }
  const [account]=await db.query('SELECT models FROM model_accounts WHERE organization_id=$1 AND provider=$2',[ORG,settings.llmProvider]);
  if(!account?.models?.length&&selected.model===settings.model&&selected.effort===settings.reasoningEffort)return selected;
  const model=(account?.models as ModelOption[]??[]).find(entry=>entry.id===selected.model);
  if(!model||!model.efforts.includes(selected.effort))throw new AppError('model_not_available',400);
  return selected;
}

export function settingsForAnalysis(settings:Settings,selected:Partial<AnalysisSettings>|null|undefined):Settings{
  return {...settings,model:selected?.model??settings.model,reasoningEffort:selected?.effort??settings.reasoningEffort};
}
