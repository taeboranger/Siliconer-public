import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {assetProfile,resourceScope,applicationPackageReportExcluded,hostSystemReportExcluded} from '../packages/core/src/asset-applicability.js';
import {renderGitops} from '../packages/connectors/src/gitops.js';
import {comparisonPresentation,responseSummary} from '../packages/core/src/presentation.js';
import {testDatabase} from './helpers.js';
import {createUser} from '../apps/api/src/auth.js';
import {configSchema} from '../packages/connectors/src/config.js';
import {registerIntegrations} from '../apps/api/src/inventory.js';
import {ORG} from '../packages/storage/src/db.js';
import {hash} from '../packages/core/src/util.js';
import {readSettings} from '../apps/api/src/config.js';
import {createInvestigation,runInvestigation} from '../apps/api/src/investigations.js';
import {allowedScope,inspectionStamp} from '../apps/api/src/inspection-tools.js';
import type {Transport} from '../packages/connectors/src/http.js';

const issuer={apiVersion:'cert-manager.io/v1',kind:'ClusterIssuer'};
const deployment=(images=['registry:3'],command?:string[])=>({apiVersion:'apps/v1',kind:'Deployment',spec:{template:{spec:{containers:images.map(image=>({image,...(command?{command}:{})}))}}}});
const asset=(docs:any[],images:string[],resolved=true)=>({render_state:resolved?'resolved':'render_incomplete',desired_images:images,source_refs:[{state:'resolved',resource_scope:resourceScope(docs,resolved)}]});
const products=[{name:'Next.js',kind:'library',ecosystem:'npm',affected_versions:['test-only'],fixed_versions:[],conditions:[]}];
const checks=[{id:'version',kind:'version',question:'Affected version?',required_evidence:'Version or applicability evidence'}];
const plan={threat:{severity:'unknown',basis:'unknown',headline:'Test report',impact:'Test only',severity_reason:'Test',cvss_score:null},summary:'Test package report',products,checks};

test('applicability uses verified resource types and official component identity, never asset names or image absence alone',async()=>{
  const config=asset([issuer],[]),registry=asset([deployment()],['registry:3']);
  assert.equal(assetProfile(config).kind,'configuration_only');assert.equal(assetProfile(registry).kind,'oci_registry');
  assert(applicationPackageReportExcluded(plan,assetProfile(config)));assert(applicationPackageReportExcluded(plan,assetProfile(registry)));
  for(const candidate of [asset([deployment(['my-team/registry:3'])],['my-team/registry:3']),asset([deployment(['registry:3','node:24'])],['registry:3','node:24']),asset([deployment(['registry:3'],['sh'])],['registry:3']),asset([issuer],[],false),asset([{apiVersion:'custom.test/v1',kind:'Application'}],[]),{name:'siliconer-registry',desired_images:[],render_state:'resolved',source_refs:[]}])assert.equal(assetProfile(candidate).kind,'unknown');
  for(const product of [{name:'Linux',kind:'os',ecosystem:'deb'},{name:'Distribution',kind:'other',ecosystem:'go'},{name:'Go',kind:'runtime',ecosystem:'Go'},{name:'MySQL',kind:'database',ecosystem:null}])assert(!applicationPackageReportExcluded({...plan,products:[product]},assetProfile(registry)));
  assert(!applicationPackageReportExcluded({...plan,products:[...products,{name:'OpenSSL',kind:'library',ecosystem:'apk'}]},assetProfile(registry)));
  assert(hostSystemReportExcluded(plan,'host_system'));
  assert(!hostSystemReportExcluded(plan,undefined));
  const kernel={name:'Linux kernel',kind:'os',ecosystem:'deb'};
  assert(!hostSystemReportExcluded({...plan,products:[kernel]},'host_system'));
  assert(!hostSystemReportExcluded({...plan,products:[...products,kernel]},'host_system'));
  const rendered=await renderGitops('.',async path=>path==='kustomization.yaml'?'kind: Kustomization\nresources: [issuer.yaml]':'apiVersion: cert-manager.io/v1\nkind: ClusterIssuer\nmetadata:\n  name: media\n');assert.equal(rendered.resourceScope.complete,true);assert.equal(rendered.resourceScope.workload_count,0);
  assert.equal(responseSummary('not_affected',undefined,'not_applicable').label,'해당 없음 · 적용 대상 아님');
  assert(!comparisonPresentation({result:'unknown',observed_version:null},{status:'not_affected',applicability:'not_applicable'}).label.includes('정보 부족'));
  assert.equal(comparisonPresentation({result:'unknown',observed_version:null},{status:'under_investigation'}).observed,'정확한 버전 미확인');
});

test('non-applicable assets skip version reasoning, retain proof, update existing tickets and ignore timestamp-only refreshes',async()=>{
  const db=await testDatabase(),user=await createUser(db,'applicability@test.local','applicability-test-password'),config=configSchema.parse({integrations:[{id:'argo',kind:'argocd',name:'Test',url:'https://argo.test',tokenEnv:'UNUSED_ARGO_TOKEN',projects:['default'],clusterId:'home'},{id:'unrelated',kind:'github',name:'Unrelated',appId:'1',installationId:1,privateKeyFileEnv:'UNUSED_TEST_KEY',repositories:[{name:'other/service',kind:'source'}]},{id:'host-facts',kind:'facts',name:'System inventory',tokenEnv:'TEST_HOST_TOKEN',assetIds:['host:test'],allowedFactKeys:['kernel_release'],assetScope:'host_system'}]});
  await registerIntegrations(db,config);const ids=[randomUUID(),randomUUID()];
  for(const [i,details] of [asset([issuer],[]),asset([deployment()],['registry:3'])].entries())await db.query("INSERT INTO applications(id,organization_id,integration_id,external_uid,name,application_namespace,project,cluster_id,namespace,desired_images,source_refs,render_state,observed_at) VALUES($1,$2,'argo',$3,$3,'argocd','default','home','test',$4,$5,'resolved',now()-interval '10 seconds')",[ids[i],ORG,'asset-'+i,JSON.stringify(details.desired_images),JSON.stringify(details.source_refs)]);
  const report={title:'Applicability test',reportText:'Test report: inspect the declared Next.js package versions on both selected assets.',applicationIds:ids,force:true};
  const ticketId=randomUUID(),sourceKey=hash({report:hash(report.reportText.trim()),target:ids[1]});
  await db.query("INSERT INTO tickets(id,organization_id,source_key,title,target_id,target_name,assessment_status,context,status,assignee,notes) VALUES($1,$2,$3,'Old unknown',$4,'Registry','under_investigation','{}','in_progress','human owner','retain note')",[ticketId,ORG,sourceKey,ids[1]]);
  const settings=readSettings({SILICONER_DATABASE_URL:'pglite:memory',SILICONER_LLM_ENABLED:'true',OPENAI_MODEL:'test',OPENAI_INPUT_USD_PER_MILLION:'1',OPENAI_OUTPUT_USD_PER_MILLION:'2',OPENAI_DAILY_BUDGET_USD:'10'});
  let calls=0;const transport:Transport=async()=>{if(++calls>1)throw Error('Non-React assets must not require version reasoning');return Response.json({status:'completed',usage:{input_tokens:10,output_tokens:10},output:[{content:[{type:'output_text',text:JSON.stringify(plan)}]}]});};
  process.env.OPENAI_API_KEY='applicability-test-only-key';
  try{
    const scope=await allowedScope(db,config,user,ids),before=await inspectionStamp(db,scope,config);await db.query('UPDATE applications SET observed_at=now()');assert.equal(await inspectionStamp(db,scope,config),before,'Refreshing identical declarations must not invalidate an inspection');
    await db.query("INSERT INTO repositories(id,organization_id,integration_id,full_name,revision,kind,observed_at) VALUES($1,$2,'unrelated','other/service',$3,'source',now())",[randomUUID(),ORG,'a'.repeat(40)]);assert.equal(await inspectionStamp(db,scope,config),before,'An unrelated repository must not invalidate the selected assets');
    const created=await createInvestigation(db,config,settings,user,report),result=await runInvestigation(db,created.id,settings,config,undefined,transport);
    assert.equal(calls,1);assert.equal(result.targets.length,3);assert(result.targets.every(t=>t.status==='not_affected'&&t.applicability==='not_applicable'&&t.version_comparison.length===0));assert.equal(result.tool_calls,0);
    const host=result.targets.find(target=>target.target_id==='facts:host:test')!;
    assert.match(host.response_summary,/호스트 OS·실행 커널·OS 패키지/);
    const [saved]=await db.query('SELECT evidence FROM investigations WHERE id=$1',[created.id]);
    assert.equal(saved.evidence.find((e:any)=>e.target_id===host.target_id).facts.basis,'configured_inspection_scope');
    assert.deepEqual(result.ticket_ids,[ticketId]);const [ticket]=await db.query('SELECT * FROM tickets WHERE id=$1',[ticketId]);assert.equal(ticket.context.applicability,'not_applicable');assert.equal(ticket.context.evidence[0].kind,'asset_profile');assert.equal(ticket.status,'in_progress');assert.equal(ticket.assignee,'human owner');assert.equal(ticket.notes,'retain note');
    await db.query('UPDATE applications SET desired_images=$2 WHERE id=$1',[ids[1],'["registry:3","node:24"]']);assert.notEqual(await inspectionStamp(db,scope,config),before,'Changing actual software must invalidate the result');
  }finally{delete process.env.OPENAI_API_KEY;await db.close();}
});
