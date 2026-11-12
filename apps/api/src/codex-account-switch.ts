import {randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import {mkdir,mkdtemp,readFile,rename,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createInterface} from 'node:readline';
import type {FastifyInstance,FastifyRequest} from 'fastify';
import {z} from 'zod';
import {AppError} from '../../../packages/core/src/types.js';
import {ORG,type Database,type Queryable} from '../../../packages/storage/src/db.js';
import {enqueue} from '../../../packages/storage/src/jobs.js';
import {audit} from './inventory.js';
import {codexCommand,readCodexAccount,saveCodexAccount} from './model-account.js';
import type {Settings} from './config.js';

const activeStates="('queued','starting','waiting')";
const verificationUrl='https://auth.openai.com/codex/device';
const deviceReply=z.object({type:z.literal('chatgptDeviceCode'),loginId:z.uuid(),verificationUrl:z.literal(verificationUrl),
  userCode:z.string().regex(/^[A-Z0-9]{4,8}-[A-Z0-9]{4,8}$/)});

export async function expireCodexSwitches(db:Queryable){
  await db.query(`UPDATE codex_account_switches SET state='failed',user_code=NULL,error_code='expired'
    WHERE organization_id=$1 AND state IN ${activeStates} AND expires_at<=now()`,[ORG]);
}

export function registerCodexAccountSwitch(app:FastifyInstance,db:Database,settings:Settings){
  function admin(req:FastifyRequest){
    if(req.actor?.role!=='admin')throw new AppError('permission_denied',403);
    if(settings.llmProvider!=='codex'||!settings.llm)throw new AppError('codex_account_switch_unavailable',409);
    return req.actor.id;
  }
  app.get('/api/v1/codex/account',async req=>{
    const actor=admin(req);
    const [account]=await db.query("SELECT account_email AS email,account_plan AS plan,error_code AS error FROM model_accounts WHERE organization_id=$1 AND provider='codex'",[ORG]);
    const [attempt]=await db.query(`SELECT id,requested_by,state,user_code,expires_at,error_code FROM codex_account_switches
      WHERE organization_id=$1 AND (requested_by=$2 OR (state IN ${activeStates} AND expires_at>now()))
      ORDER BY (state IN ${activeStates} AND expires_at>now()) DESC,created_at DESC LIMIT 1`,[ORG,actor]);
    if(!attempt)return {account:account??null,attempt:null};
    const own=attempt.requested_by===actor;
    const expired=['queued','starting','waiting'].includes(attempt.state)&&Date.parse(attempt.expires_at)<=Date.now();
    const state=expired?'failed':attempt.state;
    const code=own&&state==='waiting'?attempt.user_code:null;
    return {account:account??null,attempt:{id:own?attempt.id:null,state,expiresAt:attempt.expires_at,
      error:expired?'expired':attempt.error_code,code,verificationUrl:code?verificationUrl:null}};
  });
  app.post('/api/v1/codex/account/switch',async(req,reply)=>{
    const actor=admin(req);
    const id=randomUUID();
    await db.transaction(async tx=>{
      await expireCodexSwitches(tx);
      const started=await tx.query(`INSERT INTO codex_account_switches(id,organization_id,requested_by,state,expires_at)
        VALUES($1,$2,$3,'queued',now()+interval '15 minutes') ON CONFLICT DO NOTHING RETURNING id`,[id,ORG,actor]);
      if(!started.length)throw new AppError('codex_account_switch_in_progress',409);
      await enqueue(tx,'codex-account-switch',{switchId:id},`codex-account-switch:${id}`);
      await audit(tx,actor,'codex.account_switch_requested',id);
    });
    return reply.code(202).send({id});
  });
  app.delete('/api/v1/codex/account/switch/:id',async req=>{
    const actor=admin(req),{id}=z.object({id:z.uuid()}).parse(req.params);
    const cancelled=await db.query(`UPDATE codex_account_switches SET state='cancelled',user_code=NULL
      WHERE id=$1 AND organization_id=$2 AND requested_by=$3 AND state IN ${activeStates} RETURNING id`,[id,ORG,actor]);
    if(!cancelled.length)throw new AppError('codex_account_switch_not_active',409);
    return {ok:true};
  });
}

function loginWithDeviceCode(command:string,directory:string,signal:AbortSignal,publish:(code:string)=>Promise<void>){
  return new Promise<void>((resolve,reject)=>{
    const child=spawn(process.execPath,[command,'-c','cli_auth_credentials_store="file"','app-server'],{
      windowsHide:true,stdio:['pipe','pipe','pipe'],
      env:{PATH:process.env.PATH??'',HOME:directory,CODEX_HOME:directory,NO_COLOR:'1'},
    });
    const lines=createInterface({input:child.stdout});
    let done=false,loginId:string|undefined;
    const finish=(error?:Error)=>{
      if(done)return;
      done=true;
      signal.removeEventListener('abort',abort);
      lines.close();
      child.kill();
      if(error)reject(error);else resolve();
    };
    const failed=()=>finish(new Error('device_login_failed'));
    const abort=()=>finish(new Error('device_login_cancelled'));
    child.on('error',failed);
    child.on('exit',failed);
    child.stdin.on('error',failed);
    child.stderr.resume();
    signal.addEventListener('abort',abort,{once:true});
    if(signal.aborted){abort();return;}
    const send=(message:unknown)=>child.stdin.write(JSON.stringify(message)+'\n');
    lines.on('line',line=>{
      if(done)return;
      if(line.length>65536){failed();return;}
      let message;
      try{message=JSON.parse(line);}catch{return;}
      if((message.id===0||message.id===1)&&message.error){failed();return;}
      if(message.id===0){
        send({method:'initialized'});
        send({id:1,method:'account/login/start',params:{type:'chatgptDeviceCode'}});
      }
      if(message.id===1){
        const result=deviceReply.safeParse(message.result);
        if(!result.success){failed();return;}
        loginId=result.data.loginId;
        void publish(result.data.userCode).catch(failed);
      }
      if(message.method==='account/login/completed'&&loginId&&message.params?.loginId===loginId){
        if(message.params.success===true)finish();else failed();
      }
    });
    send({id:0,method:'initialize',params:{clientInfo:{name:'siliconer',version:'0.1.0'}}});
  });
}

export async function runCodexAccountSwitch(db:Database,settings:Settings,id:string,shutdown:AbortSignal){
  await expireCodexSwitches(db);
  const [attempt]=await db.query(`UPDATE codex_account_switches SET state='starting'
    WHERE id=$1 AND organization_id=$2 AND state='queued' AND expires_at>now() RETURNING expires_at,requested_by`,[id,ORG]);
  if(!attempt){
    await db.query(`UPDATE codex_account_switches SET state='failed',user_code=NULL,error_code='interrupted'
      WHERE id=$1 AND organization_id=$2 AND state IN ('starting','waiting')`,[id,ORG]);
    return;
  }
  const controller=new AbortController();
  const signal=AbortSignal.any([controller.signal,shutdown,AbortSignal.timeout(Math.max(1,Date.parse(attempt.expires_at)-Date.now()))]);
  let checking=false;
  const timer=setInterval(()=>{
    if(checking)return;
    checking=true;
    void db.query(`SELECT 1 FROM codex_account_switches WHERE id=$1 AND organization_id=$2 AND state IN ${activeStates}`,[id,ORG])
      .then(rows=>{if(!rows.length)controller.abort();},()=>controller.abort()).finally(()=>{checking=false;});
  },2000);
  let directory:string|undefined;
  const staged=join(settings.codexHome,`.account-switch-${id}.json`);
  try{
    directory=await mkdtemp(join(tmpdir(),'siliconer-codex-login-'));
    await loginWithDeviceCode(await codexCommand(),directory,signal,async code=>{
      const updated=await db.query(`UPDATE codex_account_switches SET state='waiting',user_code=$3
        WHERE id=$1 AND organization_id=$2 AND state='starting' AND expires_at>now() RETURNING id`,[id,ORG,code]);
      if(!updated.length)controller.abort();
    });
    const account=await readCodexAccount({...settings,codexHome:directory});
    if(!account.identity||!account.limits.length)throw Error('chatgpt_account_unverified');
    signal.throwIfAborted();
    await mkdir(settings.codexHome,{recursive:true,mode:0o700});
    await writeFile(staged,await readFile(join(directory,'auth.json')),{mode:0o600,flag:'wx'});
    await db.transaction(async tx=>{
      const [current]=await tx.query(`SELECT 1 FROM codex_account_switches s JOIN users u ON u.organization_id=s.organization_id AND u.id=s.requested_by
        WHERE s.id=$1 AND s.organization_id=$2 AND s.state IN ('starting','waiting') AND s.expires_at>now()
          AND u.role='admin' AND u.disabled_at IS NULL FOR UPDATE OF s`,[id,ORG]);
      if(!current)throw Error('switch_no_longer_authorized');
      signal.throwIfAborted();
      await saveCodexAccount(tx,account);
      await audit(tx,attempt.requested_by,'codex.account_switch_completed',id);
      await tx.query("UPDATE codex_account_switches SET state='completed',user_code=NULL WHERE id=$1",[id]);
      await rename(staged,join(settings.codexHome,'auth.json'));
    });
  }catch{
    await db.query(`UPDATE codex_account_switches SET state='failed',user_code=NULL,
      error_code=CASE WHEN expires_at<=now() THEN 'expired' ELSE 'device_login_failed' END
      WHERE id=$1 AND organization_id=$2 AND state IN ${activeStates}`,[id,ORG]);
  }finally{
    clearInterval(timer);
    if(directory)await rm(directory,{recursive:true,force:true});
    await rm(staged,{force:true});
  }
}
