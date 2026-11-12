import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rmdir, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { updateFinalBase, updateMatchingNodeStages, updateGitopsDigest, openRemediationPr } from '../apps/api/src/remediation.js';
import { parse } from 'yaml';
import { configSchema } from '../packages/connectors/src/config.js';
import type { Database } from '../packages/storage/src/db.js';

const replacement='node:22-alpine@sha256:'+'a'.repeat(64);
test('remediation changes only the matching final Dockerfile base image',()=>{
  const source='FROM node:22-alpine AS build\r\nRUN npm ci\r\nFROM node:22-alpine AS run\r\nCOPY --from=build /app /app\r\n';
  assert.equal(updateFinalBase(source,'node:22-alpine',replacement),source.replace('node:22-alpine AS run',replacement+' AS run'));
  assert.equal(updateFinalBase(source+'FROM scratch\n','node:22-alpine',replacement),undefined);
  const shared='FROM node:22-alpine AS base\nFROM base AS build\nFROM base AS runner\n';
  assert.equal(updateFinalBase(shared,'node:22-alpine',replacement),shared.replace('node:22-alpine',replacement));
  assert.equal(updateMatchingNodeStages(source,'node:22-alpine',replacement),source.replaceAll('node:22-alpine',replacement));
  assert.equal(updateMatchingNodeStages(source+'FROM scratch\n','node:22-alpine',replacement),undefined);
});

test('GitOps update replaces a single verified tag with a digest and preserves other images',()=>{
  const tag='a'.repeat(40);
  const digest='sha256:'+'b'.repeat(64);
  const source=`kind: Kustomization\nimages:\n- name: home/service\n  newTag: ${tag}\n- name: home/sidecar\n  newTag: stable\n`;
  const updated=updateGitopsDigest(source,'home/service',new Set([tag]),digest);
  assert.ok(updated);
  assert.deepEqual(parse(updated).images,[{name:'home/service',digest},{name:'home/sidecar',newTag:'stable'}]);
  assert.equal(updateGitopsDigest(source,'home/service',new Set(['unverified']),digest),undefined);
  assert.equal(updateGitopsDigest(source+'- name: home/service\n  newTag: duplicate\n','home/service',new Set([tag]),digest),undefined);
});

test('remediation requires cited, verified build evidence matching the running digest',async()=>{
  const config=configSchema.parse({remediation:{appId:'1',installationId:1,privateKeyFileEnv:'UNSET_TEST_REMEDIATION_KEY',recipes:[{
    application:'app',argoIntegration:'argo',repository:'test/app',dockerfile:'Dockerfile',from:'node:22-alpine',
    replacement,affectedRange:'>=1.1.0 <1.1.1',verifiedReplacementBrotli:'1.1.1',
  }]}});
  const queryArguments:unknown[][]=[];
  const db={async query(_sql:string,args:unknown[]){
    queryArguments.push(args);
    return queryArguments.length===1?[{
      assessment_status:'affected',status:'open',name:'app',integration_id:'argo',
      containers:[{running:true,kind:'regular',digest:'sha256:'+'b'.repeat(64)}],
      context:{evidence:[{kind:'build_observed',facts:{provenance:'verified',digest:'sha256:'+'c'.repeat(64)}}]},
    }]:[];
  }} as unknown as Database;
  await openRemediationPr(db,config,'test-ticket');
  assert.deepEqual(queryArguments[1][2],[]);
});

test('remediation uses the current running image digest and opens only a draft on its own branch',async()=>{
  const keyEnv='SILICONER_TEST_DRAFT_ONLY_APP_KEY';
  const directory=await mkdtemp(join(tmpdir(),'siliconer-remediation-'));
  const keyPath=join(directory,'app.pem');
  const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  await writeFile(keyPath,privateKey.export({type:'pkcs8',format:'pem'}));
  process.env[keyEnv]=keyPath;
  const applicationId='5833644a-0b95-499d-a879-ed63c92f8c01';
  const config=configSchema.parse({integrations:[{id:'collector',kind:'collector',name:'Collector',tokenEnv:'UNUSED_TOKEN',clusterId:'test',
    namespaces:['app'],applicationIds:[applicationId],imagePlatform:'linux/amd64'}],
    remediation:{appId:'1',installationId:1,privateKeyFileEnv:keyEnv,recipes:[{
    application:'app',argoIntegration:'argo',repository:'test/app',dockerfile:'Dockerfile',from:'node:22-alpine',
    replacement,affectedRange:'>=1.1.0 <1.1.1',verifiedReplacementBrotli:'1.1.0',
    nodeBackport:{cve:'CVE-2026-111497',verifiedReplacementNode:'22.23.4'},
  }]}});
  const digest='sha256:'+'b'.repeat(64);
  const manifest='sha256:'+'e'.repeat(64);
  const image=`docker.io/test/app@${digest}`;
  const observed={id:'image-evidence',kind:'image_catalog',source:'image:node-runtime-versions',
    expires_at:new Date(Date.now()+60000).toISOString(),facts:{
      digest:manifest,platform:'linux/amd64',requested_image:image,running_digest_observed:true,
      node_version:'22.23.3',brotli_version:'1.1.0',
    }};
  const vendor={kind:'vendor_fix',facts:{cve:'CVE-2026-111497',status:'affected',observed_evidence_id:observed.id,
    runtime_version:'22.23.3',version:'1.1.0'}};
  const running={running:true,kind:'regular',digest,imageId:`containerd://${image}`};
  let containers=[running];
  const commit='c'.repeat(40);
  const blob='d'.repeat(40);
  const source='FROM node:22-alpine\n';
  const file={type:'file',encoding:'base64',size:source.length,sha:blob,content:Buffer.from(source).toString('base64')};
  const linked:unknown[][]=[];
  const db={
    async query(sql:string){
      if(sql.includes('FROM tickets'))return [{
        assessment_status:'affected',status:'open',name:'app',integration_id:'argo',application_id:applicationId,cluster_id:'test',
        containers,context:{evidence:[observed,vendor]},
      }];
      return [];
    },
    async transaction(run:(tx:{query:(sql:string,args:unknown[])=>Promise<unknown[]>})=>unknown){
      return run({async query(_sql,args){linked.push(args);return [];}});
    },
  } as unknown as Database;
  let branch='';
  let opened=false;
  let writes=0;
  let tokenRequests=0;
  const transport:typeof fetch=async(input,init)=>{
    const url=new URL(String(input));
    const method=init?.method??'GET';
    const path=url.pathname.replace(/^\/repos\/test\/app/,'');
    const data=init?.body?JSON.parse(String(init.body)):null;
    if(path==='/app/installations/1/access_tokens'){tokenRequests++;return Response.json({token:'test-token'});}
    if(method==='GET'&&path==='')return Response.json({full_name:'test/app',default_branch:'main'});
    if(method==='GET'&&path==='/pulls')return Response.json(opened?[{number:42}]:[]);
    if(method==='GET'&&(path==='/commits/main'||path===`/commits/${encodeURIComponent(branch)}`))return Response.json({sha:commit});
    if(method==='GET'&&path==='/contents/Dockerfile')return Response.json(file);
    if(method==='POST'&&path==='/git/refs'){
      assert.match(data.ref,/^refs\/heads\/siliconer\/brotli-[a-f0-9]+$/);
      assert.equal(data.sha,commit);
      branch=data.ref.slice('refs/heads/'.length);
      writes++;
      return Response.json({}, {status:201});
    }
    if(method==='PUT'&&path==='/contents/Dockerfile'){
      assert.equal(data.branch,branch);
      assert.equal(Buffer.from(data.content,'base64').toString(),`FROM ${replacement}\n`);
      writes++;
      return Response.json({});
    }
    if(method==='POST'&&path==='/pulls'){
      assert.equal(data.base,'main');
      assert.equal(data.head,branch);
      assert.equal(data.draft,true);
      opened=true;
      writes++;
      return Response.json({number:42}, {status:201});
    }
    assert.fail(`Unexpected GitHub request ${method} ${path}`);
  };
  try{
    containers=[{...running,digest:'sha256:'+'f'.repeat(64)}];
    await openRemediationPr(db,config,'test-ticket',transport);
    containers=[running];
    await openRemediationPr(db,{...config,integrations:[]},'test-ticket',transport);
    observed.facts.running_digest_observed=false;
    await openRemediationPr(db,config,'test-ticket',transport);
    observed.facts.running_digest_observed=true;
    assert.equal(tokenRequests,0);
    await openRemediationPr(db,config,'test-ticket',transport);
    await openRemediationPr(db,config,'test-ticket',transport);
    assert.equal(writes,3);
    assert.deepEqual(linked.map(args=>args[3]),[42,42]);
  }finally{
    delete process.env[keyEnv];
    await unlink(keyPath);
    await rmdir(directory);
  }
});
