import { Pool } from 'pg';
import { randomBytes, randomUUID, scryptSync } from 'node:crypto';
import assert from 'node:assert/strict';
const databaseUrl=process.env.SILICONER_SMOKE_DATABASE_URL ?? 'postgresql://siliconer:siliconer-dev-only@127.0.0.1:55432/siliconer';
const parsed=new URL(databaseUrl);
if(!['localhost','127.0.0.1'].includes(parsed.hostname) || parsed.port!=='55432') throw new Error('Smoke test is restricted to the local development PostgreSQL port 55432');
const origin='http://localhost:3005';
const pool=new Pool({connectionString:databaseUrl});
const id=randomUUID(),email=`smoke-${id}@siliconer.local`,password=randomBytes(24).toString('base64url'),salt=randomBytes(16).toString('hex');
const passwordHash=`${salt}:${scryptSync(password,salt,64).toString('hex')}`;
try {
  assert.equal((await fetch(`${origin}/healthz`)).status,200);
  await pool.query('INSERT INTO users(id,organization_id,email,password_hash,role) VALUES($1,$2,$3,$4,$5)',[id,'00000000-0000-4000-8000-000000000001',email,passwordHash,'admin']);
  assert.equal((await fetch(`${origin}/api/v1/assets`)).status,401);
  const login=await fetch(`${origin}/api/v1/auth/login`,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify({email,password})});
  assert.equal(login.status,200);const session=await login.json();
  const cookie=login.headers.getSetCookie().map(s=>s.split(';')[0]).join('; ');
  const headers={Cookie:cookie,Origin:origin,'X-CSRF-Token':session.csrf,'Content-Type':'application/json'};
  const summary=await fetch(`${origin}/api/v1/summary`,{headers});assert.equal(summary.status,200);assert.equal(typeof (await summary.json()).assets,'number');
  const sync=await fetch(`${origin}/api/v1/sync`,{method:'POST',headers,body:'{}'});assert.equal(sync.status,200);
  const {jobIds}=await sync.json();assert(jobIds.length>0);
  let completed=false;
  for(let attempt=0;attempt<20;attempt++) {
    const result=await fetch(`${origin}/api/v1/jobs/${jobIds[0]}`,{headers});const job=await result.json();
    if(job.state==='succeeded'){completed=true;break;}
    if(['failed','blocked'].includes(job.state))throw new Error(`Worker job failed: ${job.error_code}`);
    await new Promise(resolve=>setTimeout(resolve,500));
  }
  assert(completed,'Worker did not complete the queued assessment');
  assert.equal((await fetch(`${origin}/api/v1/auth/logout`,{method:'POST',headers,body:'{}'})).status,200);
  assert.equal((await fetch(`${origin}/api/v1/summary`,{headers})).status,401);
  console.log('Container smoke passed: Web/API readiness, proxy, session login/logout, CSRF and separate PostgreSQL worker.');
} finally { await pool.query('DELETE FROM users WHERE id=$1 AND email=$2',[id,email]);await pool.end(); }
