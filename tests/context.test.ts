import test from 'node:test';
import assert from 'node:assert/strict';
import { buildSourceContext, safeSourcePath } from '../apps/api/src/context.js';
import { seedDemo } from '../apps/api/src/seed.js';
import { configSchema } from '../packages/connectors/src/config.js';
import { GithubReader } from '../packages/connectors/src/github.js';
import { testDatabase } from './helpers.js';
test('source context defaults to deny and reads only explicit files from the deployed commit', async () => {
  const db=await testDatabase();await seedDemo(db,true);
  const [app]=await db.query("SELECT id FROM applications WHERE name='portal-prod'");
  const config=configSchema.parse({integrations:[{id:'source',name:'Source',kind:'github',appId:'1',installationId:1,privateKeyFileEnv:'KEY_FILE',repositories:[{name:'demo/portal',kind:'source'}],sourcePolicies:[{repository:'demo/portal',allowCodeEgress:false,allowedPaths:['src/service.ts']}]}]});
  const files:string[]=[];
  class Reader extends GithubReader { override async file(repo:string,sha:string,file:string) { assert.equal(repo,'demo/portal');assert.equal(sha,'1'.repeat(40));files.push(file);return file==='package.json' ? JSON.stringify({dependencies:{lodash:'^4.17.20'},scripts:{build:'private script'}}) : 'import _ from "lodash";\nexport const copy = _.cloneDeep;'; } }
  try{
    const deny=await buildSourceContext(db,app.id,'4.17.21',['src/service.ts'],config,c=>new Reader(c));assert.equal(deny.sources.length,0);assert.equal(files.length,0);
    if(config.integrations[0].kind!=='github') throw new Error('Wrong fixture');config.integrations[0].sourcePolicies[0].allowCodeEgress=true;
    const allowed=await buildSourceContext(db,app.id,'4.17.21',['src/service.ts','secrets.ts'],config,c=>new Reader(c));
    assert.deepEqual(files,['package.json','src/service.ts']);assert.equal(allowed.sources.length,2);assert(allowed.unknowns.some(s=>s.includes('secrets.ts')));assert(!JSON.stringify(allowed).includes('private script'));
    assert.throws(()=>safeSourcePath('../secrets.json'));assert.throws(()=>safeSourcePath('.env'));assert.throws(()=>safeSourcePath('src/secrets.json'));
    class Sensitive extends Reader { override async file(repo:string,sha:string,file:string){ if(file==='src/service.ts')return 'export const cfg={"api_key":"do-not-send-this-value"};';return super.file(repo,sha,file); } }
    const blocked=await buildSourceContext(db,app.id,'4.17.21',['src/service.ts'],config,c=>new Sensitive(c));
    assert(!JSON.stringify(blocked).includes('do-not-send-this-value'));assert(blocked.unknowns.some(s=>s.includes('민감 정보')));
  }finally{await db.close();}
});
