import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {dependencyVersions} from '../packages/core/src/dependency-versions.js';
import {testDatabase} from './helpers.js';
import {ORG} from '../packages/storage/src/db.js';
import {configSchema} from '../packages/connectors/src/config.js';
import {GithubReader} from '../packages/connectors/src/github.js';
import {InspectionTools,allowedScope,inspectionPathAllowed} from '../apps/api/src/inspection-tools.js';
import {createUser} from '../apps/api/src/auth.js';
import {registerIntegrations} from '../apps/api/src/inventory.js';

test('dependency inventories distinguish declared ranges from resolved lockfile versions across package managers',()=>{
  assert.equal(dependencyVersions('apps/web/package.json','{"dependencies":{"next":"^15.2.0"}}')[0].basis,'declared');
  const npm=dependencyVersions('package-lock.json',JSON.stringify({packages:{'':{name:'app'},'node_modules/next':{version:'15.2.4'},'node_modules/@scope/pkg':{version:'1.2.3'}}}));assert.equal(npm[0].version,'15.2.4');assert.equal(npm[1].name,'@scope/pkg');
  const pnpm=dependencyVersions('pnpm-lock.yaml',"lockfileVersion: '9.0'\npackages:\n  next@15.2.4: {}\n  '@scope/pkg@1.2.3(peer@1)': {}\n");assert.equal(pnpm[0].version,'15.2.4');assert.equal(pnpm[1].name,'@scope/pkg');
  assert.equal(dependencyVersions('yarn.lock','"next@^15.2.0":\n  version: "15.2.4"\n')[0].version,'15.2.4');
  assert.equal(dependencyVersions('composer.lock','{"packages":[{"name":"laravel/framework","version":"v12.0.0"}]}')[0].name,'laravel/framework');
  assert.equal(dependencyVersions('go.mod','require github.com/test/package v1.2.3')[0].version,'v1.2.3');
  assert.equal(dependencyVersions('go.sum','github.com/test/package v1.2.3 h1:test')[0].basis,'checksum_record','A checksum entry is not proof of the selected Go module version');
  assert.throws(()=>dependencyVersions('package.json','{"dependencies":["next"]}'));
  assert.throws(()=>dependencyVersions('package-lock.json','{}'));
  assert.equal(dependencyVersions('package.json','{"name":"react-server-dom-webpack","version":"19.1.0"}')[0].name,'react-server-dom-webpack');
});

test('selected services can inspect explicitly bound source versions at the declared image commit without GitOps repo confusion',async()=>{
  const db=await testDatabase(),user=await createUser(db,'source-binding@test.local','test-password-binding'),id=randomUUID(),other=randomUUID(),sha='c'.repeat(40);
  const config=configSchema.parse({integrations:[{id:'github',kind:'github',name:'Source',appId:'1',installationId:1,privateKeyFileEnv:'UNUSED_KEY',repositories:[{name:'test/web',kind:'source'}],sourcePolicies:[{repository:'test/web',allowCodeEgress:true,allowedDependencyFiles:true,applicationBindings:[{integrationId:'github',applicationName:'web',imageRepository:'test/web-image'}]}]}]});
  await registerIntegrations(db,config);
  for(const [app,name] of [[id,'web'],[other,'other']])await db.query("INSERT INTO applications(id,organization_id,integration_id,external_uid,name,application_namespace,project,cluster_id,namespace,desired_images,observed_at) VALUES($1,$2,'github',$3,$3,'argocd','default','home','test',$4,now())",[app,ORG,name,JSON.stringify(['test/web-image:'+sha])]);
  let blockedManifest=false;
  class Reader extends GithubReader{
    override async revision():Promise<string>{throw Error('Image commit should be used instead of current main');}
    override async get<T=any>(_repo:string,suffix:string):Promise<T>{assert(suffix.includes(sha));return {tree:[{type:'blob',mode:'100644',path:'apps/web/package.json'},{type:'blob',mode:'100644',path:'pnpm-lock.yaml'},{type:'blob',mode:'100644',path:'src/private.ts'},{type:'blob',mode:'100644',path:'.env'},{type:'blob',mode:'100644',path:'node_modules/bad/package.json'},...(blockedManifest?[{type:'blob',mode:'100644',path:'secrets/package.json'}]:[])]} as T;}
    override async file(_repo:string,revision:string,path:string){assert.equal(revision,sha);assert(['apps/web/package.json','pnpm-lock.yaml'].includes(path));return path.endsWith('package.json')?'{"dependencies":{"next":"^15.2.0"}}':"packages:\n  next@15.2.4: {}\n";}
  }
  try{
    const scope=await allowedScope(db,config,user,[id]);assert.deepEqual(scope.repositories,['test/web']);
    const tools=new InspectionTools(db,config,scope,c=>new Reader(c));await tools.init();assert.equal(tools.targets.find(t=>t.id===id)!.metadata.source_repositories[0].commit_sha,sha);
    const result=await tools.call('dependency_versions',{target_id:id,query:'next'});assert.equal(result.unavailable.length,0);assert.equal(result.evidence[0].facts.binding_basis,'declared_image_commit_tag');assert.equal(result.evidence[0].facts.runtime_verified,false);assert(result.evidence[0].facts.components.some((v:any)=>v.basis==='resolved'&&v.version==='15.2.4'));assert(await tools.canCite(id,result.evidence[0].id));
    assert.equal(result.evidence[0].facts.coverage.npm.complete,true);assert.equal(result.evidence[0].complete,false,'Complete declaration coverage is not complete runtime/image coverage');
    blockedManifest=true;const incomplete=await tools.call('dependency_versions',{target_id:id,query:'next'});assert.equal(incomplete.evidence[0].facts.coverage.npm.complete,false,'Unreadable project manifest must prevent negative declaration coverage');
    await assert.rejects(tools.call('dependency_versions',{target_id:other,query:'next'}),/inspection_scope_denied/);
    const policy=config.integrations[0];if(policy.kind!=='github')throw Error('Fixture');assert(inspectionPathAllowed('apps/web/package.json',policy.sourcePolicies[0]));assert(!inspectionPathAllowed('src/private.ts',policy.sourcePolicies[0]));assert(!inspectionPathAllowed('secrets/package.json',policy.sourcePolicies[0]));
  }finally{await db.close();}
});
