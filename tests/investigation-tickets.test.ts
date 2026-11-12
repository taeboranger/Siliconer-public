import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {testDatabase} from './helpers.js';
import {ORG,type Database} from '../packages/storage/src/db.js';
import {createUser,newSession} from '../apps/api/src/auth.js';
import {readSettings} from '../apps/api/src/config.js';
import {createApp} from '../apps/api/src/app.js';
import {registerIntegrations} from '../apps/api/src/inventory.js';
import {configSchema} from '../packages/connectors/src/config.js';
import {createInvestigation,runInvestigation} from '../apps/api/src/investigations.js';
import type {Transport} from '../packages/connectors/src/http.js';

test('version-only MySQL inspections create scoped, durable tickets and reuse them across reruns',async()=>{
  const db=await testDatabase();
  const admin=await createUser(db,'ticket-admin@test.local','test-ticket-password');
  const developer=await createUser(db,'ticket-owner@test.local','test-ticket-password','developer');
  const teammate=await createUser(db,'ticket-teammate@test.local','test-ticket-password','developer');
  const stranger=await createUser(db,'ticket-other@test.local','test-ticket-password','developer');
  const viewer=await createUser(db,'ticket-viewer@test.local','test-ticket-password','viewer');
  const config=configSchema.parse({integrations:[{id:'gitops',kind:'github',name:'GitOps',appId:'1',installationId:1,privateKeyFileEnv:'TEST_UNUSED_KEY',repositories:[{name:'club/config',kind:'gitops'}]},
    {id:'facts',kind:'facts',name:'Registered DB',tokenEnv:'TEST_UNUSED_FACT_TOKEN',assetIds:['missing-db'],allowedFactKeys:['version']} ]});
  await registerIntegrations(db,config);
  const affected=randomUUID(),clean=randomUUID();
  for(const [id,name,image] of [[affected,'mysql-old','mysql:8.0.36'],[clean,'mysql-new','mysql:8.0.37']]){
    await db.query(`INSERT INTO applications(id,organization_id,integration_id,external_uid,name,application_namespace,project,cluster_id,namespace,desired_images,observed_at)
      VALUES($1::uuid,$2,'gitops',$1::text,$3,'argocd','club','home','database',$4,now())`,[id,ORG,name,JSON.stringify([image])]);
    await db.query('INSERT INTO service_owners(organization_id,user_id,application_id) VALUES($1,$2,$3)',[ORG,developer,id]);
  }
  await db.query('INSERT INTO service_owners(organization_id,user_id,application_id) VALUES($1,$2,$3)',[ORG,teammate,affected]);
  const settings=readSettings({SILICONER_DATABASE_URL:'pglite:memory',SILICONER_LLM_ENABLED:'true',OPENAI_MODEL:'test-model',OPENAI_INPUT_USD_PER_MILLION:'1',OPENAI_OUTPUT_USD_PER_MILLION:'2',OPENAI_DAILY_BUDGET_USD:'10'});
  process.env.OPENAI_API_KEY='test-not-a-real-api-key';
  const app=await createApp(db,config,settings);
  async function headers(user:string){const s=await newSession(db,user);return {cookie:`siliconer_session=${s.token}; siliconer_csrf=${s.csrf}`,origin:'http://localhost:3000','x-csrf-token':s.csrf};}
  const ownerHeaders=await headers(developer),peerHeaders=await headers(teammate),otherHeaders=await headers(stranger),adminHeaders=await headers(admin),viewerHeaders=await headers(viewer);
  const report={title:'MySQL 가상 취약점 (테스트 전용)',reportText:'테스트 전용 가상 보안 레포트입니다. MySQL 8.0.36 이하는 영향 버전이고 8.0.37은 제외합니다. 연결된 GitOps의 버전만 점검하고 추가 설정은 후속 확인으로 남깁니다.'};
  const plan={threat:{severity:'unknown',basis:'unknown',headline:'테스트 레포트',impact:'영향 내용 확인',severity_reason:'테스트 레포트에는 심각도 미기재',cvss_score:null},summary:'버전 범위 확인',products:[{name:'MySQL',kind:'database',ecosystem:null,affected_versions:['<=8.0.36'],fixed_versions:['8.0.37'],conditions:['추가 설정 확인 (선택)']}],
    checks:[{id:'version',kind:'version',question:'취약 버전 범위인가?',required_evidence:'GitOps 이미지 태그'}, {id:'config',kind:'condition',question:'추가 설정은?',required_evidence:'설정 확인'}]};
  function transport(ids:string[],fixed=false):Transport{
    let turn=0;
    const respond=(output:any[])=>Response.json({status:'completed',usage:{input_tokens:100,output_tokens:100},output});
    return (async(_url,init)=>{
      const input=JSON.parse(String(init?.body));
      if(turn++===0)return respond([{content:[{type:'output_text',text:JSON.stringify(plan)}]}]);
      if(turn===2)return respond(ids.map((id,i)=>({type:'function_call',name:'asset_evidence',arguments:JSON.stringify({target_id:id}),call_id:`e${i}`})));
      const evidence=input.input.filter((r:any)=>r.type==='function_call_output').flatMap((r:any)=>JSON.parse(r.output).evidence??[]);
      return respond([{content:[{type:'output_text',text:JSON.stringify({summary:'선언된 버전 기준 검사',targets:ids.map(id=>{
        const unknown=id.startsWith('facts:');const safe=id===clean||fixed;const ev=evidence.filter((e:any)=>e.target_id===id);
        return {target_id:id,response_summary:'버전 비교 결과에 따른 대응 판단',version_comparison:[],status:unknown?'under_investigation':safe?'not_affected':'affected',confidence:unknown?'low':'high',explanation:unknown?'등록 버전 없음':safe?'선언 버전이 영향 범위 밖':'GitOps에 취약 버전 선언됨. 실제 실행 확인 아님.',
          checks:[{check_id:'version',result:unknown?'unknown':safe?'not_met':'met',evidence_ids:ev.map((e:any)=>e.id),explanation:unknown?'정확한 버전 확인 필요':safe?'범위 밖 버전 확인':'8.0.36 선언 확인'},
            {check_id:'config',result:'unknown',evidence_ids:[],explanation:'추가 설정은 후속 확인'}],recommended_actions:unknown?['정확한 버전 태그 등록']:['추가 설정 확인','영향 버전을 수정 버전으로 교체']};
      }),limitations:['선언된 버전 기준이며 DB에 직접 접속하지 않았음']})}]}]);
    })as Transport;
  }
  async function run(user:string,ids:string[],fixed=false,database:Database=db){
    const request=await createInvestigation(db,config,settings,user,{...report,applicationIds:[affected,clean],force:true});
    const result=await runInvestigation(database,request.id,settings,config,undefined,transport(ids,fixed));
    return {id:request.id,result};
  }
  try{
    assert.equal((await db.query('SELECT count(*)::int AS n FROM snapshots'))[0].n,0);
    const first=await run(developer,[affected,clean]);
    assert.equal(first.result.targets[0].status,'affected');assert.equal(first.result.targets[1].status,'not_affected');
    assert.equal(first.result.ticket_ids.length,1);const ticketId=first.result.ticket_ids[0];
    const detail=(await app.inject({url:`/api/v1/investigations/${first.id}`,headers:ownerHeaders})).json();
    assert.equal(detail.tickets[0].context.products[0].fixed_versions[0],'8.0.37');
    assert.equal(detail.tickets[0].context.evidence[0].kind,'deployment_desired');
    assert.deepEqual(detail.tickets[0].remediationPrs,[]);
    const pr={repository:'club/mysql',number:12,title:'Fix affected MySQL image',path:'kustomization.yaml'};
    await db.query('INSERT INTO remediation_prs(organization_id,ticket_id,repository,number,title,path) VALUES($1,$2,$3,$4,$5,$6)',
      [ORG,ticketId,pr.repository,pr.number,pr.title,pr.path]);
    const withPr=await app.inject({url:`/api/v1/investigations/${first.id}`,headers:ownerHeaders});
    assert.equal(withPr.statusCode,200,withPr.body);
    assert.deepEqual(withPr.json().tickets.map((ticket:any)=>[ticket.target_id,ticket.remediationPrs]),[[affected,[pr]]]);
    const list=await app.inject({url:'/api/v1/tickets',headers:ownerHeaders});assert.equal(list.statusCode,200,list.body);
    assert.equal(list.json().items[0].investigation_id,first.id);
    const ticketView=await app.inject({url:`/api/v1/tickets/${ticketId}`,headers:ownerHeaders});assert.equal(ticketView.statusCode,200,ticketView.body);assert.equal(ticketView.json().context.threat.headline,'테스트 레포트');assert.equal(ticketView.json().investigations[0].id,first.id);
    const peerList=await app.inject({url:'/api/v1/tickets',headers:peerHeaders});
    assert.equal(peerList.json().items[0].id,ticketId);
    assert.equal(peerList.json().items[0].investigation_id,null);
    assert.equal((await app.inject({url:`/api/v1/tickets/${ticketId}?detail=true`,headers:otherHeaders})).statusCode,403);
    assert.equal((await app.inject({url:`/api/v1/tickets/${ticketId.toUpperCase()}`,headers:otherHeaders})).statusCode,403);
    assert.equal((await app.inject({url:`/api/v1/tickets/${encodeURIComponent(ticketId).replace(/[a-f]/,c=>'%'+c.charCodeAt(0).toString(16))}`,headers:otherHeaders})).statusCode,403);
    assert.equal((await app.inject({url:'/api/v1/summary',headers:ownerHeaders})).json().openTickets,1);
    const edit={status:'in_progress',notes:'업그레이드 예정'};
    const [stateEdit,noteEdit]=await Promise.all([
      app.inject({method:'PATCH',url:`/api/v1/tickets/${ticketId}`,headers:peerHeaders,payload:{status:edit.status}}),
      app.inject({method:'PATCH',url:`/api/v1/tickets/${ticketId}`,headers:viewerHeaders,payload:{notes:edit.notes}}),
    ]);
    assert.equal(stateEdit.statusCode,200,stateEdit.body);
    assert.equal(noteEdit.statusCode,200,noteEdit.body);
    assert.equal((await app.inject({method:'PATCH',url:`/api/v1/tickets/${ticketId}`,headers:otherHeaders,payload:edit})).statusCode,403);
    assert.equal((await app.inject({method:'PATCH',url:`/api/v1/tickets/${ticketId}?detail=true`,headers:otherHeaders,payload:edit})).statusCode,403);
    assert.equal((await app.inject({method:'PATCH',url:`/api/v1/tickets/${ticketId}`,payload:edit})).statusCode,401);
    assert.equal((await app.inject({url:'/api/v1/tickets',headers:otherHeaders})).json().items.length,0);
    const second=await run(developer,[affected,clean]);assert.deepEqual(second.result.ticket_ids,[ticketId]);
    const [retained]=await db.query('SELECT * FROM tickets WHERE id=$1',[ticketId]);assert.equal(retained.status,edit.status);assert.equal(retained.assignee,'');assert.equal(retained.notes,edit.notes);
    assert.equal((await app.inject({url:`/api/v1/investigations/${first.id}`,headers:ownerHeaders})).json().tickets[0].id,ticketId);
    const latest=(await app.inject({url:'/api/v1/tickets',headers:ownerHeaders})).json().items[0];assert.equal(latest.investigation_id,second.id);
    // Parallel forced runs share the unique report/target key, including across creators.
    await Promise.all([run(developer,[affected]),run(admin,[affected])]);
    assert.equal((await db.query('SELECT count(*)::int AS n FROM tickets'))[0].n,1);
    const unknown=await run(admin,['facts:missing-db']);assert.equal(unknown.result.ticket_ids.length,0);
    assert.equal(unknown.result.targets[0].status,'under_investigation');
    assert.equal((await app.inject({url:'/api/v1/tickets',headers:ownerHeaders})).json().items.length,1);
    assert.equal((await app.inject({url:'/api/v1/tickets',headers:adminHeaders})).json().items.length,1);
    // A clean reassessment updates the same ticket without silently resolving human work.
    await db.query('UPDATE applications SET desired_images=$2 WHERE id=$1',[affected,'["mysql:8.0.37"]']);
    const cleanRun=await run(developer,[affected],true);assert.deepEqual(cleanRun.result.ticket_ids,[ticketId]);
    const [cleanTicket]=await db.query('SELECT * FROM tickets WHERE id=$1',[ticketId]);assert.equal(cleanTicket.assessment_status,'not_affected');assert.equal(cleanTicket.status,'in_progress');
    assert.equal((await app.inject({url:'/api/v1/tickets',headers:ownerHeaders})).json().items.length,0);
    assert.equal((await app.inject({url:'/api/v1/tickets?includeNonActionable=true',headers:ownerHeaders})).json().items[0].id,ticketId);
    assert.equal((await app.inject({url:'/api/v1/summary',headers:ownerHeaders})).json().openTickets,0);
    // A failed persistence transaction cannot leave a completed result or orphan ticket.
    const faulty:Database={...db,transaction:fn=>db.transaction(tx=>fn({...tx,query:async(sql,params)=>{if(sql.startsWith('UPDATE investigations SET state=\'completed\''))throw new Error('injected-save-failure');return tx.query(sql,params);}}))};
    const failed=await createInvestigation(db,config,settings,admin,{...report,reportText:report.reportText+' 별도 트랜잭션 롤백 검사',applicationIds:[affected,clean],force:true});
    await assert.rejects(runInvestigation(faulty,failed.id,settings,config,undefined,transport([affected])),/injected-save-failure/);
    assert.equal((await db.query('SELECT state FROM investigations WHERE id=$1',[failed.id]))[0].state,'blocked');
    assert.equal((await db.query('SELECT count(*)::int AS n FROM tickets'))[0].n,1);
    assert.equal((await db.query('SELECT count(*)::int AS n FROM investigation_tickets WHERE investigation_id=$1',[failed.id]))[0].n,0);
    await db.query('DELETE FROM service_owners WHERE organization_id=$1 AND user_id=$2 AND application_id=$3',[ORG,developer,affected]);
    assert.equal((await app.inject({url:'/api/v1/tickets?includeNonActionable=true',headers:ownerHeaders})).json().items.length,0);
    assert.equal((await app.inject({method:'PATCH',url:`/api/v1/tickets/${ticketId}`,headers:ownerHeaders,payload:edit})).statusCode,403);
  }finally{delete process.env.OPENAI_API_KEY;await app.close();await db.close();}
});
