import semver from 'semver';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import { ORG, type Database } from '../../../packages/storage/src/db.js';
import { hash, normalizeImageId } from '../../../packages/core/src/util.js';
import { AppError, digestSchema, shaSchema } from '../../../packages/core/src/types.js';
import type { ConnectorConfig } from '../../../packages/connectors/src/config.js';
import { githubHeaders, installationToken } from '../../../packages/connectors/src/github.js';
import { jsonRequest } from '../../../packages/connectors/src/http.js';
import { audit } from './inventory.js';
import {nodeBrotliFix} from '../../../packages/core/src/brotli-advisory.js';
import {sourceBindings} from './source-bindings.js';

export function updateFinalBase(contents:string, from:string, replacement:string) {
  const stages=[...contents.matchAll(/^([ \t]*FROM[ \t]+(?:--platform=[^ \t]+[ \t]+)?)([^\s]+)([^\r\n]*)/gim)];
  let index=stages.length-1;
  while(index>=0&&stages[index][2]!==from){
    const alias=stages[index][2].toLowerCase();
    const parent=stages.findLastIndex((stage,i)=>i<index&&/^\s+AS\s+(\S+)\s*$/i.exec(stage[3])?.[1].toLowerCase()===alias);
    if(parent<0)return;
    index=parent;
  }
  const stage=stages[index];
  if(!stage || stage[2]!==from) return undefined;
  return contents.slice(0,stage.index)+stage[1]+replacement+stage[3]+contents.slice(stage.index+stage[0].length);
}

export function updateMatchingNodeStages(contents:string,from:string,replacement:string){
  if(updateFinalBase(contents,from,replacement)===undefined)return;
  return contents.replace(/^([ \t]*FROM[ \t]+(?:--platform=[^ \t]+[ \t]+)?)([^\s]+)([^\r\n]*)/gim,
    (line,prefix,image,suffix)=>image===from?prefix+replacement+suffix:line);
}

export function updateGitopsDigest(contents:string,image:string,previous:Set<string>,replacement:string){
  const doc=parseDocument(contents,{uniqueKeys:true});
  if(doc.errors.length)return;
  const data=doc.toJS({maxAliasCount:0});
  if(data?.kind!=='Kustomization'||!Array.isArray(data.images))return;
  const matches=data.images.flatMap((entry:any,index:number)=>(entry?.newName??entry?.name)===image?[index]:[]);
  if(matches.length!==1)return;
  const [index]=matches;
  const entry=data.images[index];
  const current=entry.digest??entry.newTag;
  if((entry.digest&&entry.newTag)||!previous.has(current)||current===replacement)return;
  if(entry.newTag)doc.deleteIn(['images',index,'newTag']);
  doc.setIn(['images',index,'digest'],replacement);
  return doc.toString();
}

export async function openGitopsRemediationPr(db:Database,config:ConnectorConfig,ticketId:string,digest:string,transport:typeof fetch=fetch){
  const remediation=config.remediation;
  if(!remediation)return;
  z.string().regex(/^sha256:[a-f0-9]{64}$/).parse(digest);
  const [ticket]=await db.query(`SELECT t.status,t.context,a.name,a.integration_id,a.source_refs,s.containers
    FROM tickets t JOIN applications a ON a.organization_id=t.organization_id AND a.id::text=t.target_id
    JOIN LATERAL (SELECT containers,expires_at FROM snapshots WHERE organization_id=a.organization_id AND application_id=a.id
      ORDER BY observed_at DESC LIMIT 1) s ON s.expires_at>now()
    WHERE t.id=$1 AND t.organization_id=$2`,[ticketId,ORG]);
  if(!ticket||ticket.status==='resolved')return;
  const recipe=remediation.recipes.find(r=>r.application===ticket.name&&r.argoIntegration===ticket.integration_id);
  const gitops=recipe?.gitops;
  if(!recipe||!gitops||gitops.repository===recipe.repository||!semver.validRange(recipe.affectedRange)||
    !ticket.source_refs?.some((ref:any)=>ref.repository===gitops.repository))return;
  const [sourcePr]=await db.query('SELECT number FROM remediation_prs WHERE organization_id=$1 AND ticket_id=$2 AND repository=$3 AND path=$4 ORDER BY created_at DESC LIMIT 1',
    [ORG,ticketId,recipe.repository,recipe.dockerfile]);
  if(!sourcePr)return;
  const sourceRequest=await githubRequest(remediation,recipe.repository,transport,false);
  const pr=await sourceRequest('/pulls/'+z.number().int().positive().parse(sourcePr.number));
  if(!pr.merged||pr.base?.repo?.full_name!==recipe.repository||!shaSchema.safeParse(pr.merge_commit_sha).success)return;
  const [build]=await db.query(`SELECT raw_document FROM sboms WHERE organization_id=$1 AND repository=$2 AND provenance='verified'
    AND digest=$3 AND commit_sha=$4 AND (image=$5 OR starts_with(image,$5||':') OR image=$5||'@'||$3)
    ORDER BY collected_at DESC LIMIT 1`,[ORG,recipe.repository,digest,pr.merge_commit_sha,gitops.imageRepository]);
  const versions=bundledBrotliVersions(build?.raw_document);
  if(versions.length!==1||versions[0]!==recipe.verifiedReplacementBrotli||semver.satisfies(versions[0],recipe.affectedRange))return;
  const cited=ticket.context?.evidence?.filter((e:any)=>e.kind==='build_observed'&&e.facts?.provenance==='verified').map((e:any)=>e.facts.digest)??[];
  const running=new Set<string>(ticket.containers.filter((c:any)=>c.running&&c.kind==='regular').map((c:any)=>c.digest));
  const old=await db.query(`SELECT digest,raw_document,commit_sha,image FROM sboms WHERE organization_id=$1 AND repository=$2 AND provenance='verified'
    AND digest=ANY($3::text[]) AND (image=$4 OR starts_with(image,$4||':') OR image=$4||'@'||digest)`,[ORG,recipe.repository,cited,gitops.imageRepository]);
  const previous=new Set<string>();
  for(const row of old){
    if(!running.has(row.digest)||!bundledBrotliVersions(row.raw_document).some(version=>semver.satisfies(version,recipe.affectedRange)))continue;
    previous.add(row.digest);
    if(row.image===`${gitops.imageRepository}:${row.commit_sha}`)previous.add(row.commit_sha);
  }
  if(!previous.size)return;
  const request=await githubRequest(remediation,gitops.repository,transport);
  await openPatchPr(db,ticketId,request,{
    repository:gitops.repository,path:gitops.path,title:'fix(security): deploy verified Brotli image',
    branch:`siliconer/brotli-deploy-${hash({gitops,digest}).slice(0,20)}`,
    body:`Deploys ${gitops.imageRepository}@${digest} from ${recipe.repository}#${sourcePr.number}. Signed build evidence reports bundled Brotli ${versions[0]}.`,
    update:contents=>updateGitopsDigest(contents,gitops.imageRepository,previous,digest),
  });
}

function bundledBrotliVersions(document:any):string[]{
  if(document?.bomFormat!=='CycloneDX'||!Array.isArray(document.components))return [];
  return [...new Set<string>(document.components.flatMap((component:any)=>typeof component?.version==='string'&&
    semver.valid(component.version)&&component.purl===`pkg:generic/node-bundled-brotli@${component.version}`?[component.version]:[]))];
}

export async function openRemediationPr(db:Database,config:ConnectorConfig,ticketId:string,transport:typeof fetch=fetch){
  if(!config.remediation)return;
  const [ticket]=await db.query(`SELECT t.assessment_status,t.status,t.context,a.id AS application_id,a.cluster_id,a.name,a.integration_id,a.desired_images,s.containers
    FROM tickets t JOIN applications a ON a.organization_id=t.organization_id AND a.id::text=t.target_id
    LEFT JOIN LATERAL (SELECT containers,expires_at FROM snapshots WHERE organization_id=a.organization_id AND application_id=a.id
      ORDER BY observed_at DESC,id DESC LIMIT 1) s ON s.expires_at>now()
    WHERE t.id=$1 AND t.organization_id=$2`,[ticketId,ORG]);
  if(ticket?.assessment_status!=='affected'||ticket.status==='resolved')return;
  const recipe=config.remediation.recipes.find(r=>r.application===ticket.name&&r.argoIntegration===ticket.integration_id);
  if(!recipe||!semver.validRange(recipe.affectedRange)||!semver.valid(recipe.verifiedReplacementBrotli))return;
  const replacementNode=recipe.nodeBackport?.verifiedReplacementNode;
  if(replacementNode){
    if(!/^(?:(?:docker\.io\/)?library\/)?node(?::[^@]+)?@sha256:[a-f0-9]{64}$/.test(recipe.replacement)||
       nodeBrotliFix(replacementNode)?.result!=='fixed')return;
  }else if(semver.satisfies(recipe.verifiedReplacementBrotli,recipe.affectedRange))return;
  const running=(ticket.containers??[]).filter((c:any)=>c.running&&c.kind==='regular');
  const digests=running.map((c:any)=>c.digest);
  const cited=ticket.context?.evidence?.filter((e:any)=>e.kind==='build_observed'&&e.facts?.provenance==='verified').map((e:any)=>e.facts.digest)??[];
  const builds=await db.query(`SELECT digest,raw_document FROM sboms
    WHERE organization_id=$1 AND repository=$2 AND provenance='verified' AND digest=ANY($3::text[])`,[ORG,recipe.repository,digests.filter((digest:string)=>cited.includes(digest))]);
  const evidence=ticket.context?.evidence??[];
  const affectedImages=replacementNode?evidence.filter((image:any)=>{
    const facts=image.facts;
    if(image.kind!=='image_catalog'||image.source!=='image:node-runtime-versions'||
      !(Date.parse(image.expires_at)>Date.now())||!digestSchema.safeParse(facts?.digest).success||
      !semver.valid(facts?.node_version)||!semver.valid(facts?.brotli_version)||
      semver.major(facts.node_version)!==semver.major(replacementNode)||nodeBrotliFix(facts.node_version)?.result!=='affected')return false;
    return evidence.some((fix:any)=>fix.kind==='vendor_fix'&&fix.facts?.cve===recipe.nodeBackport?.cve&&
      fix.facts.status==='affected'&&fix.facts.observed_evidence_id===image.id&&
      fix.facts.runtime_version===facts.node_version&&fix.facts.version===facts.brotli_version);
  }):[];
  const matchedRunningImage=affectedImages.find(({facts}:any)=>{
    if(facts.running_digest_observed!==true||facts.platform!=='linux/amd64'||typeof facts.requested_image!=='string')return false;
    const observedDigest=normalizeImageId(facts.requested_image);
    if(!observedDigest||!running.some((c:any)=>c.digest===observedDigest&&
      c.imageId?.replace(/^[a-z-]+:\/\//,'')===facts.requested_image))return false;
    // For an OCI index, the scanner verifies the manifest belongs to it. The collector
    // binding identifies the platform on which this application's Pods run.
    return observedDigest===facts.digest||config.integrations.some(integration=>
      integration.kind==='collector'&&integration.clusterId===ticket.cluster_id&&
      integration.applicationIds.includes(ticket.application_id)&&integration.imagePlatform===facts.platform);
  });
  const declared=recipe.nodeBackport?.declaredImage;
  const declaredBinding=declared&&sourceBindings(ticket,config).find(binding=>binding.repository===recipe.repository&&
    binding.commit_sha&&declared.reference.endsWith(`:${binding.commit_sha}`));
  const matchedDeclaration=!running.length&&declared&&declaredBinding&&ticket.desired_images.includes(declared.reference)
    ?affectedImages.find(({facts}:any)=>facts.requested_image===declared.reference&&facts.digest===declared.digest):undefined;
  const matchedImage=matchedRunningImage??matchedDeclaration;
  const vulnerable=Boolean(matchedImage)||(!replacementNode&&builds.some(build=>bundledBrotliVersions(build.raw_document).some(version=>semver.satisfies(version,recipe.affectedRange))));
  if(!vulnerable)return;
  if(matchedImage)await audit(db,'worker','remediation.image_verified',ticketId,{
    image:matchedImage.facts.requested_image,manifestDigest:matchedImage.facts.digest,
    platform:matchedImage.facts.platform,source:matchedRunningImage?'running_image':'declared_image',
  });

  const request=await githubRequest(config.remediation,recipe.repository,transport);
  await openPatchPr(db,ticketId,request,{
    repository:recipe.repository,path:recipe.dockerfile,
    title:'fix(security): update Node base image for Brotli',
    branch:`siliconer/brotli-${hash(recipe).slice(0,20)}`,
    body:replacementNode
      ?`Pins a verified official Node.js ${replacementNode} image for ${recipe.nodeBackport?.cve}. The vendor fix is backported and the Brotli version can remain ${recipe.verifiedReplacementBrotli}. Build and verify the final image before merging.`
      :`Pins the base image inherited by the final Dockerfile stage. Verify the rebuilt image reports Brotli ${recipe.verifiedReplacementBrotli} with process.versions.brotli before merging.`,
    update:contents=>(recipe.nodeBackport?.updateAllMatchingStages?updateMatchingNodeStages:updateFinalBase)(contents,recipe.from,recipe.replacement),
  });
}

type RemediationConfig=NonNullable<ConnectorConfig['remediation']>;
async function githubRequest(config:RemediationConfig,repository:string,transport:typeof fetch,write=true){
  const {token}=await installationToken(config,[repository],write?{contents:'write',pull_requests:'write'}:{contents:'read',pull_requests:'read'},transport);
  return <T=any>(path:string,method='GET',body?:unknown)=>jsonRequest<T>(`https://api.github.com/repos/${repository}${path}`,{
    method,headers:githubHeaders(token),body:body===undefined?undefined:JSON.stringify(body),
  },transport);
}

async function openPatchPr(db:Database,ticketId:string,request:Awaited<ReturnType<typeof githubRequest>>,patch:{
  repository:string;path:string;title:string;branch:string;body:string;update:(contents:string)=>string|undefined;
}){
  const {repository,title,branch}=patch;
  const repo=await request('');
  if(repo.full_name!==repository)throw new AppError('remediation_repository_mismatch',409);
  const base=z.string().min(1).parse(repo.default_branch);
  if(!/^siliconer\/[a-z0-9-]+$/.test(branch)||base===branch||base.startsWith('siliconer/'))
    throw new AppError('remediation_invalid_base_branch',409);
  const head=`${repository.split('/')[0]}:${branch}`;
  const findPr=async()=>(await request(`/pulls?state=all&head=${encodeURIComponent(head)}&base=${encodeURIComponent(base)}`))[0];
  let pr=await findPr();
  if(!pr){
    const commit=shaSchema.parse((await request(`/commits/${encodeURIComponent(base)}`)).sha);
    const path='/contents/'+patch.path.split('/').map(encodeURIComponent).join('/');
    const file=await request(`${path}?ref=${commit}`);
    if(file.type!=='file'||file.encoding!=='base64'||file.size>65536)throw new AppError('remediation_invalid_dockerfile',409);
    const updated=patch.update(Buffer.from(file.content,'base64').toString('utf8'));
    if(!updated)return;
    try{await request('/git/refs','POST',{ref:`refs/heads/${branch}`,sha:commit});}
    catch(error){if(!(error instanceof AppError)||error.code!=='upstream_422')throw error;}
    const branchFile=await request(`${path}?ref=${encodeURIComponent(branch)}`);
    const content=Buffer.from(updated).toString('base64');
    if(branchFile.encoding!=='base64'||typeof branchFile.content!=='string')throw new AppError('remediation_branch_changed',409);
    if(branchFile.content.replace(/\s/g,'')!==content){
      if(branchFile.sha!==file.sha||shaSchema.parse((await request(`/commits/${encodeURIComponent(branch)}`)).sha)!==commit)
        throw new AppError('remediation_branch_changed',409);
      await request(path,'PUT',{message:title,content,sha:shaSchema.parse(file.sha),branch});
    }
    const body=`${patch.body}\n\nA maintainer reviews the changes and CI results before marking this draft ready and merging it.`;
    try{pr=await request('/pulls','POST',{title,head:branch,base,draft:true,body});}
    catch(error){pr=await findPr();if(!pr)throw error;}
  }
  const number=z.number().int().positive().parse(pr.number);
  await db.transaction(async tx=>{
    const rows=await tx.query(`INSERT INTO remediation_prs(organization_id,ticket_id,repository,number,title,path)
      VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING number`,[ORG,ticketId,repository,number,title,patch.path]);
    if(rows.length)await audit(tx,'worker','remediation.pr_linked',ticketId,{repository,number});
  });
}
