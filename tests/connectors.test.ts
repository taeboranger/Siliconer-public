import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { GithubReader } from '../packages/connectors/src/github.js';
import { canonical } from '../packages/core/src/util.js';
import { listApplications } from '../packages/connectors/src/argocd.js';
import { jsonRequest, type Transport } from '../packages/connectors/src/http.js';

test('trusted CI signature plus GitHub workflow identity verifies the build binding', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const envelope = { repository:'test/source',digest:`sha256:${'a'.repeat(64)}`,commitSha:'a'.repeat(40),sbomHash:'hash' };
  const signature = sign(null, Buffer.from(canonical(envelope)), privateKey).toString('base64');
  class TestReader extends GithubReader { override async get<T = any>(): Promise<T> { return { head_sha:'a'.repeat(40),conclusion:'success',event:'push',head_branch:'main',path:'.github/workflows/prod.yml',repository:{full_name:'test/source'},head_repository:{full_name:'test/source'} } as T; } }
  const reader = new TestReader({ id:'test',name:'Test',kind:'github',appId:'1',installationId:1,privateKeyFileEnv:'TEST_KEY',repositories:[{name:'test/source',kind:'source',ref:'main'}],sourcePolicies:[] });
  const key = publicKey.export({format:'pem',type:'spki'}).toString();
  assert(await reader.verifyBuild('test/source','1','a'.repeat(40),1,envelope,signature,key,'.github/workflows/prod.yml',['main']));
  assert(!await reader.verifyBuild('test/source','1','a'.repeat(40),1,{...envelope,digest:'tampered'},signature,key,'.github/workflows/prod.yml',['main']));
  assert(!await reader.verifyBuild('test/source','1','a'.repeat(40),1,envelope,signature,key,'.github/workflows/other.yml',['main']));
  assert(!await reader.verifyBuild('test/source','1','a'.repeat(40),1,envelope,undefined,key,'.github/workflows/prod.yml',['main']));
});
test('Argo CD connector only GETs approved projects and strips inline secrets', async () => {
  process.env.TEST_ARGO_TOKEN='test-argocd-reader-token'; const calls:string[]=[];
  const transport = (async (url: any, init: any) => { calls.push(String(url)); assert.equal(init.method,undefined); return Response.json({items:[
    {metadata:{name:'app',namespace:'argocd',uid:'uid-1'},spec:{project:'club',source:{repoURL:'https://github.com/test/config',path:'overlays/prod',helm:{parameters:[{name:'secret',value:'do-not-store'}]}},destination:{namespace:'app-prod'}},status:{sync:{status:'Synced',revision:'a'.repeat(40)},health:{status:'Healthy'}}},
    {metadata:{name:'denied',uid:'uid-2'},spec:{project:'other',destination:{namespace:'other'}}},
  ]}); }) as Transport;
  const apps=await listApplications({id:'argo',name:'Argo',kind:'argocd',url:'https://argocd.example.internal',allowInsecureClusterHttp:false,tokenEnv:'TEST_ARGO_TOKEN',projects:['club'],applications:[],githubIntegrationId:'github',clusterId:'club',environment:'prod'},transport);
  assert.equal(apps.length,1); assert(!JSON.stringify(apps).includes('do-not-store')); assert.equal(apps[0].spec.source?.unsupportedOverrides,true); assert(calls[0].includes('projects=club'));
});
test('upstream responses are bounded; authorization failures do not leak response bodies', async () => {
  await assert.rejects(jsonRequest('https://example.invalid',{},(async()=>new Response('PRIVATE_TOKEN',{status:403})) as Transport),/upstream_403/);
  await assert.rejects(jsonRequest('https://example.invalid',{},(async()=>new Response('a'.repeat(100))) as Transport,10),/upstream_size_limit/);
});
