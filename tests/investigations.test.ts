import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {testDatabase} from './helpers.js';
import {createUser,newSession} from '../apps/api/src/auth.js';
import {readSettings} from '../apps/api/src/config.js';
import {createApp} from '../apps/api/src/app.js';
import {registerIntegrations} from '../apps/api/src/inventory.js';
import {configSchema} from '../packages/connectors/src/config.js';
import {ORG} from '../packages/storage/src/db.js';
import {createInvestigation,runInvestigation} from '../apps/api/src/investigations.js';
import {InspectionTools,allowedScope,genericComponents,inspectionPathAllowed} from '../apps/api/src/inspection-tools.js';
import {GithubReader} from '../packages/connectors/src/github.js';
import type {Transport} from '../packages/connectors/src/http.js';
test('user supplied Java report drives autonomous read-only investigation without npm, CVE or OSV',async()=>{
  const db=await testDatabase();const userId=await createUser(db,'inspect@test.local','inspection-test-password');
  const config=configSchema.parse({integrations:[{id:'github',name:'GitHub',kind:'github',appId:'1',installationId:1,privateKeyFileEnv:'TEST_KEY_FILE',repositories:[{name:'example/java-service',kind:'source'}],sourcePolicies:[{repository:'example/java-service',allowCodeEgress:true,allowedPathPrefixes:['src/']}]},{id:'facts',name:'Host facts',kind:'facts',tokenEnv:'TEST_FACTS_TOKEN',assetIds:['home-mysql'],allowedFactKeys:['product','version','require_secure_transport']}]});
  await registerIntegrations(db,config);const appId=randomUUID(),digest=`sha256:${'c'.repeat(64)}`;
  await db.query(`INSERT INTO applications(id,organization_id,integration_id,external_uid,name,application_namespace,project,cluster_id,namespace,desired_images,observed_at) VALUES($1,$2,'github','java-uid','orders-java','argocd','club','home','orders',$3,now())`,[appId,ORG,JSON.stringify(['example/java:old'])]);
  const raw={bomFormat:'CycloneDX',specVersion:'1.6',components:[{name:'log4j-core',version:'2.14.1',purl:'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'},{name:'django',version:'4.2.1',purl:'pkg:pypi/django@4.2.1'},{name:'openssl',version:'1.1.1k',purl:'pkg:rpm/redhat/openssl@1.1.1k'}]};
  await db.query(`INSERT INTO sboms(id,organization_id,repository,commit_sha,image,digest,workflow_run_id,run_attempt,format,content_hash,raw_document,components,complete,unsupported,provenance) VALUES($1,$2,'example/java-service',$3,'example/java:old',$4,'1',1,'CycloneDX','test',$5,'[]',false,3,'verified')`,[randomUUID(),ORG,'c'.repeat(40),digest,JSON.stringify(raw)]);
  await db.query(`INSERT INTO snapshots(id,organization_id,application_id,cluster_id,observed_at,expires_at,complete,namespaces,containers,content_hash) VALUES($1,$2,$3,'home',now(),now()+interval '15 minutes',true,'["orders"]',$4,'snapshot')`,[randomUUID(),ORG,appId,JSON.stringify([{podUid:'pod',workloadUid:'orders',namespace:'orders',container:'app',kind:'regular',digest,running:true}])]);
  const settings=readSettings({SILICONER_DATABASE_URL:'pglite:memory',SILICONER_LLM_ENABLED:'true',OPENAI_MODEL:'test-model',OPENAI_INPUT_USD_PER_MILLION:'1',OPENAI_OUTPUT_USD_PER_MILLION:'2',OPENAI_DAILY_BUDGET_USD:'10'});
  process.env.OPENAI_API_KEY='test-not-a-real-api-key';process.env.TEST_FACTS_TOKEN='test-host-facts-token';
  const app=await createApp(db,config,settings);const session=await newSession(db,userId);const headers={cookie:`siliconer_session=${session.token}; siliconer_csrf=${session.csrf}`,origin:'http://localhost:3000','x-csrf-token':session.csrf};
  const report={title:'Java 서비스에 대한 보안 레포트 검사',reportText:'Apache Log4j 2.14.1이 배포되어 있다면 보안 레포트의 취약 버전 조건에 해당합니다. 우리 Java 서비스의 실제 실행 버전을 확인해 주세요.'};
  const plan={threat:{severity:'unknown',basis:'unknown',headline:'테스트 레포트',impact:'영향 내용 확인',severity_reason:'테스트 레포트에는 심각도 미기재',cvss_score:null},summary:'Java 라이브러리와 실제 배포 버전 검사',products:[{name:'Apache Log4j',kind:'library',ecosystem:'Maven',affected_versions:['2.14.1'],conditions:['해당 버전이 배포 이미지에 포함됨'],fixed_versions:['2.17.1']}],checks:[{id:'version',kind:'version',question:'영향 버전이 이미지에 존재하는가?',required_evidence:'이미지 SBOM'},{id:'runtime',kind:'condition',question:'그 이미지가 현재 실행 중인가?',required_evidence:'실행 digest'}]};
  function response(output:any[]){return Response.json({status:'completed',usage:{input_tokens:100,output_tokens:100},output});}
  let turn=0;
  const transport=(async(_url:any,init:any)=>{
    const payload=JSON.parse(init.body);assert.equal(payload.store,false);assert(!payload.input.some((m:any)=>m.role==='system'&&String(m.content).includes('only npm')));
    if(turn++===0)return response([{content:[{type:'output_text',text:JSON.stringify(plan)}]}]);
    if(turn===2)return response([{type:'function_call',name:'asset_evidence',arguments:JSON.stringify({target_id:appId}),call_id:'a'}]);
    if(turn===3)return response([{type:'function_call',name:'sbom_components',arguments:JSON.stringify({target_id:appId,query:'log4j'}),call_id:'b'}]);
    const evidence=payload.input.filter((m:any)=>m.type==='function_call_output').flatMap((m:any)=>JSON.parse(m.output).evidence??[]);
    const sbom=evidence.find((e:any)=>e.kind==='build_observed'),live=evidence.find((e:any)=>e.kind==='deployment_observed');
    assert(sbom.facts.components[0].purl.startsWith('pkg:maven/'));
    return response([{content:[{type:'output_text',text:JSON.stringify({summary:'레포트 대상 Java 배포본의 버전이 일치합니다.',targets:[{target_id:appId,response_summary:'버전 근거에 따른 판단',version_comparison:[],status:'affected',confidence:'high',explanation:'SBOM 버전과 실행 digest를 연결했습니다.',checks:[{check_id:'version',result:'met',evidence_ids:[sbom.id],explanation:'Maven Log4j 2.14.1 존재'},{check_id:'runtime',result:'met',evidence_ids:[live.id],explanation:'실행 이미지 일치'}],recommended_actions:['해당 레포트의 수정 버전과 추가 환경 조건을 검토하세요.']}],limitations:['실제 익스플로잇을 실행하지 않았습니다.']})}]}]);
  })as Transport;
  try{
    assert.equal((await db.query('SELECT count(*)::integer AS n FROM advisories'))[0].n,0);
    const submitted=await app.inject({method:'POST',url:'/api/v1/investigations',headers,payload:report});assert.equal(submitted.statusCode,202,submitted.body);const id=submitted.json().id;
    const result=await runInvestigation(db,id,settings,config,undefined,transport);assert.equal(result.targets[0].status,'affected');assert.equal(result.tool_calls,2);
    assert.equal(result.ticket_ids.length,1);
    const saved=await app.inject({url:`/api/v1/investigations/${id}`,headers});assert.equal(saved.json().state,'completed');assert.equal(saved.json().plan.products[0].ecosystem,'Maven');assert.equal(saved.json().result.basis,'llm_evidence_analysis');
    const cached=await createInvestigation(db,config,settings,userId,report);assert.equal(cached.cached,true);assert.equal(cached.id,id);
    const noEvidence=await createInvestigation(db,config,settings,userId,{...report,force:true});let noEvidenceTurn=0;
    const unsupported=(async()=>response([{content:[{type:'output_text',text:JSON.stringify(noEvidenceTurn++===0?plan:{summary:'안전하다는 근거 없는 응답',targets:[{target_id:appId,response_summary:'버전 근거에 따른 판단',version_comparison:[],status:'not_affected',confidence:'high',explanation:'증거 없는 모델 결론',checks:plan.checks.map(c=>({check_id:c.id,result:'not_met',evidence_ids:[],explanation:'확인하지 않음'})),recommended_actions:[]}],limitations:[]})}]}]))as Transport;
    const guarded=await runInvestigation(db,noEvidence.id,settings,config,undefined,unsupported);assert.equal(guarded.targets[0].status,'under_investigation');assert.equal(guarded.targets[0].confidence,'low');
    const invalidEvidence=await createInvestigation(db,config,settings,userId,{...report,force:true});let invalidTurn=0;
    const invented=(async()=>response([{content:[{type:'output_text',text:JSON.stringify(invalidTurn++===0?plan:{summary:'잘못된 근거',targets:[{target_id:appId,response_summary:'버전 근거에 따른 판단',version_comparison:[],status:'affected',confidence:'high',explanation:'잘못된 인용',checks:plan.checks.map(c=>({check_id:c.id,result:'met',evidence_ids:['ev:invented'],explanation:'없는 근거'})),recommended_actions:[]}],limitations:[]})}]}]))as Transport;
    await assert.rejects(runInvestigation(db,invalidEvidence.id,settings,config,undefined,invented),/llm_invalid_evidence/);
    assert.equal((await db.query('SELECT state FROM investigations WHERE id=$1',[invalidEvidence.id]))[0].state,'blocked');
    const inventory=genericComponents(raw);assert(inventory.some(c=>c.purl?.startsWith('pkg:pypi/')));assert(inventory.some(c=>c.purl?.startsWith('pkg:rpm/')));
    const scope=await allowedScope(db,config,userId);const tools=new InspectionTools(db,config,scope);await tools.init();
    await assert.rejects(tools.call('run_shell',{command:'rm -rf /'}),/inspection_tool_denied/);await assert.rejects(tools.call('asset_evidence',{target_id:randomUUID()}),/inspection_scope_denied/);
    const producer={assetId:'home-mysql',kind:'database',name:'Home MySQL',observedAt:new Date().toISOString(),facts:{product:'MySQL',version:'8.0.36'}};
    assert.equal((await app.inject({method:'POST',url:'/api/v1/ingest/facts',headers:{authorization:'Bearer test-host-facts-token'},payload:producer})).statusCode,202);
    assert.equal((await app.inject({method:'POST',url:'/api/v1/ingest/facts',headers:{authorization:'Bearer test-host-facts-token'},payload:{...producer,facts:{password:'must-not-be-accepted'}}})).statusCode,403);
    await tools.init();const facts=await tools.call('asset_evidence',{target_id:'facts:home-mysql'});assert.equal(facts.evidence[0].facts.version,'8.0.36');
    const owner=await createUser(db,'inspection-owner@test.local','owner-test-password','developer');await assert.rejects(createInvestigation(db,config,settings,owner,{...report,applicationIds:[appId]}),/inspection_scope_denied/);
    class Reader extends GithubReader{override async revision(){return 'c'.repeat(40);}override async file(_r:string,_s:string,p:string){return p.endsWith('.py')?'from django import http\n': 'public class App { }';}}
    const fileTools=new InspectionTools(db,config,scope,c=>new Reader(c));await fileTools.init();
    for(const path of ['src/App.java','src/views.py','src/main.go']){const out=await fileTools.call('read_repository_file',{target_id:'repo:github:example/java-service',commit_sha:'c'.repeat(40),path,start_line:1,line_count:30});assert.equal(out.evidence.kind,'repository_declared');}
    await assert.rejects(fileTools.call('read_repository_file',{target_id:'repo:github:example/java-service',commit_sha:null,path:'.env',start_line:1,line_count:30}),/source_path_denied/);
    const policy=config.integrations[0];if(policy.kind!=='github')throw new Error('fixture');assert(!inspectionPathAllowed('src/keys.pem',policy.sourcePolicies[0]));
  }finally{delete process.env.OPENAI_API_KEY;await app.close();await db.close();}
});
