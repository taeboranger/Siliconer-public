import {z} from 'zod';
import {parseAllDocuments} from 'yaml';
import {ORG,type Database} from '../../../packages/storage/src/db.js';
import {AppError,type Role} from '../../../packages/core/src/types.js';
import {hash,cleanText,normalizeImageId} from '../../../packages/core/src/util.js';
import {GithubReader} from '../../../packages/connectors/src/github.js';
import type {ConnectorConfig,GithubConfig} from '../../../packages/connectors/src/config.js';
import {sourceBindings} from './source-bindings.js';
import {dependencyBasenames,dependencyVersions} from '../../../packages/core/src/dependency-versions.js';
import {assetProfile,hostSystemScopeDescription} from '../../../packages/core/src/asset-applicability.js';
import {hostSummary,selectHostPackages} from '../../../packages/core/src/host-inventory.js';
import {brotliCve,distroBrotliFix,nodeBrotliFix} from '../../../packages/core/src/brotli-advisory.js';
export interface InspectionScope{applicationIds:string[];repositories:string[];factAssetIds:string[];userId:string}
export interface InspectionEvidence{id:string;target_id:string;kind:string;source:string;observed_at:string;expires_at:string|null;complete:boolean;facts:any;content_hash:string}
export interface Target{id:string;kind:'application'|'repository'|'runtime_asset';name:string;metadata:any}
export function targetEvidenceIds(target:{observed_evidence_ids?:string[];checks?:{evidence_ids:string[]}[];version_comparison?:{evidence_ids:string[]}[]}){
  const comparisons=[...(target.checks??[]),...(target.version_comparison??[])];
  return [...(target.observed_evidence_ids??[]),...comparisons.flatMap(check=>check.evidence_ids)];
}
function scrub(value:any,depth=0):any{
  if(depth>20)return '[depth limit]';if(typeof value==='string')return cleanText(value,10000);
  if(Array.isArray(value))return value.slice(0,100).map(v=>scrub(v,depth+1));
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).slice(0,50).filter(([k])=>!/^(password|secret|token|authorization|cookie|private_key|env|args|command)$/i.test(k)).map(([k,v])=>[k,scrub(v,depth+1)]));
  return value;
}
export async function allowedScope(db:Database,config:ConnectorConfig,userId:string,selectedIds?:string[],selectedFacts?:string[]):Promise<InspectionScope>{
  const [user]=await db.query('SELECT role FROM users WHERE id=$1 AND organization_id=$2',[userId,ORG]);if(!user)throw new AppError('inspection_scope_denied',403);
  const role=user.role as Role;if(role==='viewer')throw new AppError('permission_denied',403);
  const apps=await db.query(`SELECT a.* FROM applications a WHERE a.organization_id=$1 AND ($2::boolean OR EXISTS(SELECT 1 FROM service_owners o WHERE o.user_id=$3 AND o.application_id=a.id))`,[ORG,role!=='developer',userId]);
  if(selectedIds?.some(id=>!apps.some(a=>a.id===id)))throw new AppError('inspection_scope_denied',403);
  const explicit=selectedIds!==undefined||selectedFacts!==undefined;
  const selected=explicit?apps.filter(a=>selectedIds?.includes(a.id)):apps;
  const repos=new Set<string>();
  if(role!=='developer' && !explicit){for(const i of config.integrations)if(i.kind==='github')i.repositories.forEach(r=>repos.add(r.name));}
  for(const app of selected){
    for(const binding of sourceBindings(app,config))repos.add(binding.repository);
    for(const source of app.source_refs??[])if(typeof source.repository==='string' && /^[\w.-]+\/[\w.-]+$/.test(source.repository))repos.add(source.repository);
    const snapshots=await db.query('SELECT containers FROM snapshots WHERE application_id=$1 AND organization_id=$2 ORDER BY observed_at DESC LIMIT 1',[app.id,ORG]);
    const digests=(snapshots[0]?.containers??[]).map((c:any)=>c.digest??normalizeImageId(c.imageId)).filter(Boolean);
    for(const s of await db.query("SELECT repository,image,digest FROM sboms WHERE organization_id=$1 AND provenance='verified'",[ORG]))if(digests.includes(s.digest)||app.desired_images.includes(s.image)||app.desired_images.some((r:string)=>r.endsWith(`@${s.digest}`)))repos.add(s.repository);
  }
  const allowedFacts=role==='developer'?[]:config.integrations.flatMap(i=>i.kind==='facts'?i.assetIds:[]);
  if(selectedFacts?.some(id=>!allowedFacts.includes(id)))throw new AppError('inspection_scope_denied',403);
  // Keep existing API callers' facts scope unless they explicitly select it.
  const factAssetIds=selectedFacts===undefined?allowedFacts:allowedFacts.filter(id=>selectedFacts.includes(id));
  return {applicationIds:selected.map(a=>a.id),repositories:[...repos].sort(),factAssetIds:[...new Set(factAssetIds)],userId};
}
export async function inspectionStamp(db:Database,scope:InspectionScope,config:ConnectorConfig){
  const [apps,sboms,repos,snapshots,facts,runtimeVersions]=await Promise.all([
    db.query('SELECT id,source_refs,desired_images FROM applications WHERE organization_id=$1 AND id=ANY($2::uuid[]) ORDER BY id',[ORG,scope.applicationIds]),
    db.query(`SELECT id,repository,digest,content_hash,provenance FROM sboms s WHERE s.organization_id=$1
      AND (repository=ANY($3::text[]) OR EXISTS(
        SELECT 1 FROM applications a CROSS JOIN LATERAL jsonb_array_elements_text(a.desired_images) image
        WHERE a.organization_id=$1 AND a.id=ANY($2::uuid[]) AND (image=s.image OR right(image,72)='@'||s.digest)
      ) OR EXISTS(
        SELECT 1 FROM (
          SELECT DISTINCT ON(application_id) containers FROM snapshots WHERE organization_id=$1 AND application_id=ANY($2::uuid[])
          ORDER BY application_id,observed_at DESC,id DESC
        ) snapshot CROSS JOIN LATERAL jsonb_array_elements(snapshot.containers) c WHERE c->>'digest'=s.digest
      )) ORDER BY id`,[ORG,scope.applicationIds,scope.repositories]),
    db.query('SELECT integration_id,full_name,revision FROM repositories WHERE organization_id=$1 AND full_name=ANY($2::text[]) ORDER BY full_name',[ORG,scope.repositories]),
    db.query('SELECT DISTINCT ON(application_id) application_id,containers,complete,(expires_at>now()) AS fresh FROM snapshots WHERE organization_id=$1 AND application_id=ANY($2::uuid[]) ORDER BY application_id,observed_at DESC,id DESC',[ORG,scope.applicationIds]),
    db.query('SELECT DISTINCT ON(asset_id) asset_id,producer_id,content_hash,(expires_at>now()) AS fresh FROM runtime_facts WHERE organization_id=$1 AND asset_id=ANY($2::text[]) ORDER BY asset_id,observed_at DESC,id DESC',[ORG,scope.factAssetIds]),
    db.query('SELECT application_id,digest,container_name,node_version,brotli_version FROM image_runtime_versions WHERE organization_id=$1 AND application_id=ANY($2::uuid[]) ORDER BY application_id,digest,container_name',[ORG,scope.applicationIds]),
  ]);
  const snapshotImages=snapshots.map(({containers,...snapshot})=>({...snapshot,
    images:[...new Set(containers.map((c:any)=>JSON.stringify([c.container,c.kind,c.desiredImage,c.digest??normalizeImageId(c.imageId)??null,c.running,
      c.nodeRuntime?.node??null,c.nodeRuntime?.brotli??null,(c.runtimeVersions??[]).map((item:any)=>`${item.product}:${item.version}`).sort()])))].sort(),
  }));
  return hash({scope,apps,sboms,repos,snapshots:snapshotImages,facts,runtimeVersions,policy:config});
}
const targetArg=z.string().min(1).max(500);
const nullableSha=z.string().regex(/^[a-f0-9]{40}$/).nullable();
const definitions={
  find_assets:{description:'Find allowed applications, repositories and runtime assets by product/service name. Empty query lists candidates.',schema:z.object({query:z.string().max(200)}).strict()},
  asset_evidence:{description:'Read a known application or runtime asset: deployment declarations, observed containers, or collector facts. Never raw secrets.',schema:z.object({target_id:targetArg}).strict()},
  host_packages:{description:'Search observed host dpkg installed binary and source package versions. Query substrings separated by |. Includes Ubuntu/Debian epoch, release revision and architecture. Complete inventory absence only excludes this dpkg scope, never containers or manual installs. Use distribution fixed package revisions; upstream semver alone cannot establish vendor-backported vulnerability status.',schema:z.object({target_id:targetArg,query:z.string().max(200)}).strict()},
  sbom_components:{description:'Search all ecosystems in available image SBOMs (Java/Maven, Python, Go, OS, npm and others). Absence in a partial list is not proof of safety.',schema:z.object({target_id:targetArg,query:z.string().max(200)}).strict()},
  image_components:{description:'Search packages and binaries in the allowed application container images, using your own product names, package names, or package URL fragments separated by |. Use an exact image reference returned in asset evidence to select one image, or null to search all. Returns component versions, available evidence paths, and digest scope. No command execution.',schema:z.object({target_id:targetArg,query:z.string().min(1).max(200),image:z.string().min(1).max(300).nullable()}).strict()},
  image_file_evidence:{description:'Check a file path in an allowed application image and read a version value from it. Choose the exact image reference from asset evidence, an absolute image path, and the version field path. Use one field for key=value or key: value metadata, nested keys for JSON, or [] for a file consisting of a version string. Returns only the version, file size and image digest. No file contents or live volume access.',schema:z.object({target_id:targetArg,image:z.string().min(1).max(300),path:z.string().min(1).max(300),fields:z.array(z.string().regex(/^[A-Za-z0-9_.-]{1,70}$/)).max(6)}).strict()},
  dependency_versions:{description:'Read package manifests and lockfiles from an explicitly linked source repository at the declared image commit, or clearly labelled configured branch fallback. Finds exact resolved npm/pnpm/yarn/composer/Go versions and declared package.json versions, including monorepos. Use for dependency version reports before declaring versions unavailable. Does not execute code or prove runtime state. Query with a package name such as next or react-server-dom; empty query lists versions.',schema:z.object({target_id:targetArg,query:z.string().max(200)}).strict()},
  repository_files:{description:'List allowed repository paths at a pinned commit. Choose a commit from available references or null to resolve the configured declared branch.',schema:z.object({target_id:targetArg,commit_sha:nullableSha,query:z.string().max(200)}).strict()},
  read_repository_file:{description:'Read a bounded part of an allowed source/config/dependency file. Language independent. No execution. Secret files and unauthorized paths are denied.',schema:z.object({target_id:targetArg,commit_sha:nullableSha,path:z.string().max(500),start_line:z.number().int().min(1).max(100000),line_count:z.number().int().min(1).max(120)}).strict()},
};
export const inspectionToolDefinitions=Object.entries(definitions).map(([name,d])=>{const parameters=z.toJSONSchema(d.schema);delete parameters.$schema;return {type:'function',name,description:d.description,strict:true,parameters};});

export function genericComponents(raw:any):{name:string;version:string;purl:string|null}[]{
  const items:any[]=[];let visited=0;
  function collect(list:any,depth=0){if(!Array.isArray(list)||depth>20)return;for(const c of list){if(++visited>50000)throw new AppError('sbom_component_limit');if(c&&typeof c==='object'){items.push(c);collect(c.components,depth+1);}}}
  if(raw?.bomFormat==='CycloneDX')collect(raw.components);else if(typeof raw?.spdxVersion==='string')collect(raw.packages);
  return items.map(c=>({name:String(c.name??''),version:String(c.version??c.versionInfo??''),purl:typeof c.purl==='string'?c.purl:((c.externalRefs??[]).find((r:any)=>r.referenceType==='purl')?.referenceLocator??null)}));
}
export function inspectionPathAllowed(file:string,policy:GithubConfig['sourcePolicies'][number]){
  if(!policy.allowCodeEgress || file.startsWith('/') || file.includes('\\') || file.split('/').some(p=>p==='..'||p==='') || /(?:^|\/)(?:\.env|\.git|node_modules|secrets?|credentials)(?:\.|\/|$)/i.test(file) || /\.(?:pem|key|p12|pfx|jks|keystore)$/i.test(file))return false;
  return policy.allowedPaths.includes(file)||policy.allowedPathPrefixes.some(prefix=>file.startsWith(prefix))||(policy.allowedDependencyFiles&&dependencyBasenames.has(file.split('/').at(-1)!));
}
export class InspectionTools{
  evidence:InspectionEvidence[]=[];targets:Target[]=[];
  private apps:any[]=[];private pinned=new Map<string,string>();
  private imageCatalogs=new Map<string,any>();
  constructor(private db:Database,private config:ConnectorConfig,readonly scope:InspectionScope,private factory=(c:GithubConfig)=>new GithubReader(c)){}
  private async imageSources(targetId:string){
    const target=this.target(targetId);
    const app=this.apps.find(item=>item.id===targetId);
    if(target.kind!=='application'||!app||process.env.SILICONER_IMAGE_CATALOG!=='true')return null;
    const [snapshot]=await this.db.query('SELECT containers,expires_at FROM snapshots WHERE organization_id=$1 AND application_id=$2 AND expires_at>now() ORDER BY observed_at DESC LIMIT 1',[ORG,targetId]);
    const running=(snapshot?.containers??[]).filter((container:any)=>container.running&&container.imageId?.includes('@sha256:'));
    const images=new Map<string,{running:boolean;expires:Date}>();
    for(const container of running){
      const image=container.imageId.replace(/^[a-z-]+:\/\//,'');
      images.set(image,{running:true,expires:new Date(snapshot.expires_at)});
    }
    for(const image of app.desired_images as string[]){
      if(!running.some((container:any)=>container.desiredImage===image)&&!images.has(image))
        images.set(image,{running:false,expires:new Date(Date.now()+(image.includes('@sha256:')?3600000:300000))});
    }
    const unknownRunningImages=(snapshot?.containers??[]).filter((container:any)=>container.running&&
      !container.imageId?.includes('@sha256:')).length;
    return {target,images,unknownRunningImages};
  }
  async collectImageComponents(targetId:string,query:string,onlyImage?:string|null){
    const sources=await this.imageSources(targetId);
    if(!sources||!query.trim())return null;
    const {target,images,unknownRunningImages}=sources;
    const imageReference=onlyImage?.replace(/^[a-z-]+:\/\//,'');
    if(imageReference&&!images.has(imageReference))throw new AppError('inspection_image_out_of_scope',403);
    const evidence=[],unavailable=[];
    const selected=[...images].filter(([image])=>!imageReference||imageReference===image).slice(0,8);
    for(const [image,basis] of selected){
      const key=JSON.stringify([image,query]);
      try{
        let catalog=this.imageCatalogs.get(key);
        if(!catalog){
          const url=new URL('http://127.0.0.1:4192/catalog');
          url.search=new URLSearchParams({image,q:query,bundled:'1'}).toString();
          const response=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(150000)});
          if(!response.ok){await response.body?.cancel();throw Error('image_catalog_unavailable');}
          catalog=await response.json();
          this.imageCatalogs.set(key,catalog);
        }
        evidence.push(this.add(target,'image_catalog',`syft:${catalog.image}`,{
          ...catalog,requested_image:image,running_digest_observed:basis.running,
          scope:'static image catalog, detected OS packages and application dependencies; cannot rule out unrecognized bundled or dynamically installed components',
        },false,new Date(),basis.expires));
        if(catalog.bundledNodeBrotli){
          evidence.push(this.add(target,'image_catalog','image:node-runtime-versions',{
            digest:catalog.digest,platform:catalog.platform,requested_image:image,running_digest_observed:basis.running,
            node_version:catalog.bundledNodeBrotli.node,brotli_version:catalog.bundledNodeBrotli.brotli,
            product:'Node.js bundled Google Brotli',basis:'Version symbols read from the Node executable in the image',
          },true,new Date(),basis.expires));
        }
      }catch{unavailable.push(image);}
    }
    return {evidence,unavailable,unscanned:imageReference?0:Math.max(0,images.size-selected.length)+unknownRunningImages};
  }
  private async collectImageFile(targetId:string,image:string,path:string,fields:string[]){
    const sources=await this.imageSources(targetId);
    if(!sources)throw new AppError('image_catalog_unavailable',409);
    const requestedImage=image.replace(/^[a-z-]+:\/\//,'');
    const basis=sources.images.get(requestedImage);
    if(!basis)throw new AppError('inspection_image_out_of_scope',403);
    const url=new URL('http://127.0.0.1:4192/file-evidence');
    url.search=new URLSearchParams({image:requestedImage,path}).toString();
    for(const field of fields)url.searchParams.append('field',field);
    const response=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(115000)});
    if(!response.ok){
      await response.body?.cancel();
      throw new AppError(response.status===400?'inspection_image_path_denied':'image_file_evidence_unavailable',409);
    }
    const metadata=z.object({digest:z.string().regex(/^sha256:[a-f0-9]{64}$/),platform:z.literal('linux/amd64'),
      path:z.literal(path),size:z.number().int().min(0).max(65536),
      version:z.string().regex(/^v?\d{1,8}\.\d{1,8}[0-9A-Za-z.+_~-]{0,42}$/).nullable()}).parse(await response.json());
    return {evidence:[this.add(sources.target,'image_file','image:file-metadata',{
      ...metadata,requested_image:requestedImage,running_digest_observed:basis.running,fields,
      scope:'File inside this image artifact; runtime mounts and overrides are outside this evidence',
    },true,new Date(),basis.expires)]};
  }
  brotliVendorEvidence(targetId:string){
    const target=this.target(targetId);
    const observations=this.evidence.filter(e=>e.target_id===targetId&&(!e.expires_at||Date.parse(e.expires_at)>Date.now()));
    const result:InspectionEvidence[]=[];
    const emit=(basis:InspectionEvidence,component:string,version:string,fix:{fixedVersion:string;result:string;reference:string},runtime?:string)=>{
      result.push(this.add(target,'vendor_fix',fix.reference,{
        cve:brotliCve,component,version,runtime_version:runtime,fix_version:fix.fixedVersion,status:fix.result,
        observed_evidence_id:basis.id,source_scope:'Vendor fix for this implementation and release only',
      },true,new Date(basis.observed_at),basis.expires_at?new Date(basis.expires_at):null));
    };
    for(const item of observations){
      if(['collector:node-runtime-versions','operator:node-runtime-versions','image:node-runtime-versions'].includes(item.source)){
        const fix=nodeBrotliFix(item.facts.node_version);
        if(fix)emit(item,'Node.js 내장 Brotli',item.facts.brotli_version,fix,item.facts.node_version);
      }
      if(item.kind==='collector_observed'&&item.facts.os_id==='ubuntu'){
        for(const component of item.facts.packages??[]){
          if(component.source_name!=='brotli')continue;
          const fix=distroBrotliFix('ubuntu',item.facts.os_version,component.source_version);
          if(fix)emit(item,`Ubuntu ${component.name}`,component.source_version,fix);
        }
      }
      if(item.kind==='image_catalog'){
        for(const component of item.facts.matches??[]){
          if(component.type!=='deb'||!/^pkg:deb\/debian\//.test(component.purl))continue;
          const params=new URLSearchParams(component.purl.split('?')[1]);
          const release=params.get('distro')?.match(/^debian-(\d+(?:\.\d+)*)$/)?.[1];
          if(!release||params.get('upstream')!=='brotli')continue;
          const fix=distroBrotliFix('debian',release,component.version);
          if(fix)emit(item,`Debian ${component.name}`,component.version,fix);
        }
      }
    }
    return {evidence:result};
  }
  async init(){
    this.apps=await this.db.query('SELECT * FROM applications WHERE organization_id=$1 AND id=ANY($2::uuid[])',[ORG,this.scope.applicationIds]);
    this.targets=this.apps.map(a=>({id:a.id,kind:'application',name:a.name,metadata:{namespace:a.namespace,environment:a.environment,source_repositories:sourceBindings(a,this.config),asset_profile:assetProfile(a)}}));
    for(const i of this.config.integrations)if(i.kind==='github')for(const r of i.repositories)if(this.scope.repositories.includes(r.name))this.targets.push({id:`repo:${i.id}:${r.name}`,kind:'repository',name:r.name,metadata:{integration:i.id,ref:r.ref,repository_kind:r.kind,scope:'repository_declared'}});
    const runtime=await this.db.query('SELECT DISTINCT ON(asset_id) asset_id,asset_kind,display_name FROM runtime_facts WHERE organization_id=$1 AND asset_id=ANY($2::text[]) ORDER BY asset_id,observed_at DESC,id DESC',[ORG,this.scope.factAssetIds]);
    for(const id of this.scope.factAssetIds){
      const observed=runtime.find(row=>row.asset_id===id);
      const producers=this.config.integrations.filter(integration=>integration.kind==='facts'&&integration.assetIds.includes(id));
      const hostScope=producers.length>0&&producers.every(integration=>integration.kind==='facts'&&integration.assetScope==='host_system')&&(!observed||observed.asset_kind==='host');
      this.targets.push({id:`facts:${id}`,kind:'runtime_asset',name:observed?.display_name??id,metadata:{
        kind:observed?.asset_kind??(hostScope?'host':'unknown'),...(!observed?{state:'facts_missing'}:{}),
        ...(hostScope?{inspection_scope:'host_system',scope_producers:producers.map(producer=>producer.id)}:{}),
      }});
    }
  }
  private add(target:Target,kind:string,source:string,facts:any,complete=false,observed=new Date(),expires:Date|null=null){
    const sanitized=scrub(facts);if(JSON.stringify(sanitized)!==JSON.stringify(facts))complete=false;
    const e:InspectionEvidence={id:`ev:${hash({target:target.id,kind,source,sanitized,observed}).slice(0,24)}`,target_id:target.id,kind,source,observed_at:observed.toISOString(),expires_at:expires?.toISOString()??null,complete,facts:sanitized,content_hash:hash(sanitized)};
    if(!this.evidence.some(v=>v.id===e.id))this.evidence.push(e);return e;
  }
  private target(id:string){const t=this.targets.find(t=>t.id===id);if(!t)throw new AppError('inspection_scope_denied',403);return t;}
  applicabilityEvidence(id:string){
    const target=this.target(id),app=this.apps.find(a=>a.id===id),profile=target.metadata.asset_profile;
    if(target.kind==='runtime_asset'&&target.metadata.inspection_scope==='host_system'){
      return this.add(target,'asset_profile',target.metadata.scope_producers.join(', '),{
        kind:'host_system',basis:'configured_inspection_scope',coverage:['host_os','running_kernel','os_packages'],description:hostSystemScopeDescription,
      },true);
    }
    if(target.kind!=='application'||!profile?.complete||!app)throw new AppError('asset_profile_unverified',409);
    return this.add(target,'asset_profile',`${app.integration_id}/${app.name}`,profile,true,new Date(app.observed_at),new Date(new Date(app.observed_at).getTime()+this.config.evidenceTtlSeconds*1000));
  }
  async canCite(targetId:string,evidenceId:string){
    const e=this.evidence.find(e=>e.id===evidenceId);if(!e)return false;if(e.target_id===targetId)return true;
    const target=this.target(targetId),source=this.target(e.target_id);if(target.kind!=='application'||source.kind!=='repository')return false;
    const app=this.apps.find(a=>a.id===target.id);
    return sourceBindings(app,this.config).some(r=>r.repository===source.name)||(app.source_refs??[]).some((r:any)=>r.repository===source.name)||(await this.sboms(target)).some(s=>s.repository===source.name);
  }
  private async sboms(target:Target){
    const rows=await this.db.query('SELECT * FROM sboms WHERE organization_id=$1',[ORG]);
    if(target.kind==='repository')return rows.filter(r=>r.repository===target.name);
    if(target.kind!=='application')return [];
    const app=this.apps.find(a=>a.id===target.id);const [snapshot]=await this.db.query('SELECT containers FROM snapshots WHERE organization_id=$1 AND application_id=$2 ORDER BY observed_at DESC LIMIT 1',[ORG,target.id]);
    const digests=(snapshot?.containers??[]).map((c:any)=>c.digest??normalizeImageId(c.imageId));
    return rows.filter(r=>digests.includes(r.digest)||app.desired_images.includes(r.image)||app.desired_images.some((ref:string)=>ref.endsWith(`@${r.digest}`)));
  }
  private async repository(target:Target,sha:string|null){
    if(target.kind!=='repository')throw new AppError('repository_target_required');
    const c=this.config.integrations.find(i=>i.kind==='github' && i.id===target.metadata.integration);if(c?.kind!=='github')throw new AppError('inspection_scope_denied',403);
    const policy=c.sourcePolicies.find(p=>p.repository===target.name);if(!policy?.allowCodeEgress)throw new AppError('source_egress_denied',403);
    const reader=this.factory(c);let pinned=this.pinned.get(target.id);
    const builds=await this.db.query("SELECT DISTINCT commit_sha FROM sboms WHERE organization_id=$1 AND repository=$2 AND provenance='verified'",[ORG,target.name]);
    const sourceRefs=this.apps.flatMap(a=>[...(a.source_refs??[]).map((s:any)=>({repository:s.repository,revision:s.resolvedRevision})),...sourceBindings(a,this.config).map(s=>({repository:s.repository,revision:s.commit_sha}))]).filter(s=>s.repository===target.name).map(s=>s.revision);
    if(sha && !builds.some(b=>b.commit_sha===sha) && !sourceRefs.includes(sha) && sha!==pinned)throw new AppError('commit_not_in_scope',403);
    if(!sha){if(!pinned){pinned=await reader.revision(target.name,target.metadata.ref);this.pinned.set(target.id,pinned);}sha=pinned;}
    return {reader,policy,sha,available_commits:[...new Set([...builds.map(b=>b.commit_sha),...sourceRefs].filter(s=>/^[a-f0-9]{40}$/.test(s??'')))]};
  }
  async call(name:string,raw:unknown):Promise<any>{
    if(!(name in definitions))throw new AppError('inspection_tool_denied',403);
    const args:any=definitions[name as keyof typeof definitions].schema.parse(raw);
    if(name==='find_assets'){const q=args.query.toLowerCase();return {targets:this.targets.filter(t=>JSON.stringify(t).toLowerCase().includes(q)).slice(0,100),total:this.targets.length,partial:this.targets.length>100};}
    const target=this.target(args.target_id);
    if(name==='image_components')return await this.collectImageComponents(target.id,args.query,args.image)??{error:'image_catalog_unavailable'};
    if(name==='image_file_evidence')return this.collectImageFile(target.id,args.image,args.path,args.fields);
    if(name==='host_packages'){
      if(target.kind!=='runtime_asset')throw new AppError('host_target_required');
      const [row]=await this.db.query('SELECT * FROM runtime_facts WHERE organization_id=$1 AND asset_id=$2 ORDER BY observed_at DESC,id DESC LIMIT 1',[ORG,target.id.slice(6)]);
      if(!row?.facts.host_inventory)return {target,evidence:[],missing:'No host package inventory collected'};
      const selected=selectHostPackages(row.facts.host_inventory,args.query);
      const facts={...hostSummary(row.facts),...selected};
      return {target,evidence:[this.add(target,'collector_observed',row.producer_id,facts,selected.inventory_complete&&!selected.partial,new Date(row.observed_at),new Date(row.expires_at))]};
    }
    if(name==='dependency_versions'){
      const links=target.kind==='repository'?[{target_id:target.id,commit_sha:null,basis:'configured_repository_branch'}]:target.kind==='application'?sourceBindings(this.apps.find(a=>a.id===target.id),this.config):[];
      const evidence=[],unavailable=[];let files=0;
      for(const link of links){
        try{
          const source=this.target(link.target_id),repo=await this.repository(source,link.commit_sha);
          const tree=await repo.reader.get(source.name,`/git/trees/${repo.sha}?recursive=1`);
          if(!Array.isArray(tree.tree))throw new AppError('repository_tree_invalid',502);
          const projectFiles=tree.tree.filter((e:any)=>e.type==='blob'&&typeof e.path==='string'&&!/(?:^|\/)(?:node_modules|vendor|dist|build|\.next)\//.test(e.path));
          const npmNames=new Set(['package.json','package-lock.json','pnpm-lock.yaml','yarn.lock']);
          const npmFiles=projectFiles.filter((e:any)=>npmNames.has(e.path.split('/').at(-1)));
          const candidates=projectFiles.filter((e:any)=>['100644','100755'].includes(e.mode)&&dependencyBasenames.has(e.path.split('/').at(-1))&&inspectionPathAllowed(e.path,repo.policy));
          const versions=[],directDependencies=[],parsedNpm=new Set<string>();
          for(const f of candidates.slice(0,30)){
            if(++files>40)break;
            try{const text=await repo.reader.file(source.name,repo.sha,f.path);if(/(?:PRIVATE KEY-----|https?:\/\/[^\s/]+@|(?:password|secret|api[_-]?key|access[_-]?token)['"]?\s*[:=]\s*['"]?[^\s,'"}]{8})/i.test(text))throw new AppError('sensitive_source_excluded',403);
              const queries=args.query.toLowerCase().split('|'),parsed=dependencyVersions(f.path,text);
              if(npmNames.has(f.path.split('/').at(-1))){parsedNpm.add(f.path);if(f.path.endsWith('package.json'))directDependencies.push(...parsed);}
              versions.push(...queries.flatMap((q:string)=>{const exact=parsed.filter(v=>v.name.toLowerCase()===q);return exact.length?exact:parsed.filter(v=>v.name.toLowerCase().includes(q));}));
            }catch(error){unavailable.push({repository:source.name,path:f.path,error:error instanceof AppError?error.code:'dependency_file_unreadable'});}
          }
          const npmComplete=!tree.truncated&&versions.length<=100&&directDependencies.length<=100&&npmFiles.every((f:any)=>parsedNpm.has(f.path));
          evidence.push(this.add(source,'repository_declared',`https://github.com/${source.name}/tree/${repo.sha}`,{repository:source.name,commit_sha:repo.sha,binding_basis:link.basis,runtime_verified:false,query:args.query,components:versions.slice(0,100),coverage:{npm:{complete:npmComplete,scope:'tracked project npm manifests and lockfiles; excludes generated/vendor trees and runtime',manifest_count:npmFiles.length,parsed_manifest_count:parsedNpm.size,direct_dependencies:directDependencies.slice(0,100),direct_dependencies_partial:directDependencies.length>100}},partial:Boolean(tree.truncated)||candidates.length>30||files>40||versions.length>100,files_considered:candidates.slice(0,30).map((f:any)=>f.path),note:'Only repository-declared inventory. A complete ecosystem coverage can exclude undeclared packages within that scope; it never proves absence in an image or running environment. Unknown or unsupported ecosystems need separate evidence.'},false));
        }catch(error){unavailable.push({target_id:link.target_id,error:error instanceof AppError?error.code:'dependency_collection_failed'});}
      }
      return {target,evidence,unavailable,...(!links.length?{missing:'No explicitly configured source repository binding for this application'}:{})};
    }
    if(name==='asset_evidence'){
      if(target.kind==='runtime_asset'){
        const rows=await this.db.query('SELECT * FROM runtime_facts WHERE organization_id=$1 AND asset_id=$2 ORDER BY observed_at DESC,id DESC LIMIT 1',[ORG,target.id.slice(6)]);
        return {evidence:rows.map(r=>this.add(target,'collector_observed',r.producer_id,hostSummary(r.facts),true,new Date(r.observed_at),new Date(r.expires_at)))};
      }
      if(target.kind!=='application')return {target,scope:'repository_declared'};
      const app=this.apps.find(a=>a.id===target.id);
      const [snapshot]=await this.db.query('SELECT * FROM snapshots WHERE application_id=$1 AND organization_id=$2 ORDER BY observed_at DESC LIMIT 1',[target.id,ORG]);
      const evidence=[this.add(target,'deployment_desired',`${app.integration_id}/${app.name}`,{images:app.desired_images,sources:app.source_refs,sync:app.sync_state,health:app.health_state,render_state:app.render_state},false,new Date(app.observed_at),new Date(new Date(app.observed_at).getTime()+this.config.evidenceTtlSeconds*1000))];
      if(snapshot)evidence.push(this.add(target,'deployment_observed',snapshot.cluster_id,{containers:snapshot.containers},snapshot.complete,new Date(snapshot.observed_at),new Date(snapshot.expires_at)));
      if(snapshot&&Date.parse(snapshot.expires_at)>Date.now()){
        const running=snapshot.containers.filter((c:any)=>c.running&&c.kind==='regular'&&c.digest);
        const probed=new Set<string>();
        for(const container of running){
          const identity={digest:container.digest,container:container.container};
          const addVersion=(source:string,facts:object)=>{
            const key=JSON.stringify([source,identity,facts]);
            if(probed.has(key))return;
            probed.add(key);
            evidence.push(this.add(target,'deployment_observed',source,{...identity,...facts},
              true,new Date(snapshot.observed_at),new Date(snapshot.expires_at)));
          };
          if(container.nodeRuntime)addVersion('collector:node-runtime-versions',{
            node_version:container.nodeRuntime.node,brotli_version:container.nodeRuntime.brotli,
            product:'Node.js bundled Google Brotli',basis:'process.versions verified in the running container',
          });
          for(const {product,version} of container.runtimeVersions??[])addVersion('collector:runtime-binary-version',{
            product,version,basis:'Product binary version queried inside this running container; not proof of a running service process',
          });
        }
        const versions=await this.db.query(`SELECT digest,container_name,node_version,brotli_version,observed_at FROM image_runtime_versions
          WHERE organization_id=$1 AND application_id=$2 AND digest=ANY($3::text[])`,[ORG,target.id,running.map((c:any)=>c.digest)]);
        for(const row of versions.filter(v=>running.some((c:any)=>c.digest===v.digest&&c.container===v.container_name)&&
          !running.some((c:any)=>c.digest===v.digest&&c.container===v.container_name&&c.nodeRuntime))){
          evidence.push(this.add(target,'deployment_observed','operator:node-runtime-versions',
            {digest:row.digest,container:row.container_name,node_version:row.node_version,brotli_version:row.brotli_version,
              product:'Node.js bundled Google Brotli',basis:'process.versions from the same image digest'},
            true,new Date(row.observed_at),new Date(snapshot.expires_at)));
        }
      }
      return {target,evidence};
    }
    if(name==='sbom_components'){
      const q=args.query.toLowerCase();const evidence=[];
      for(const s of (await this.sboms(target)).slice(0,10)){
        const all=genericComponents(s.raw_document),matched=all.filter(c=>JSON.stringify(c).toLowerCase().includes(q));
        evidence.push(this.add(target,'build_observed',`sbom:${s.id}`,{repository:s.repository,commit_sha:s.commit_sha,image:s.image,digest:s.digest,provenance:s.provenance,components:matched.slice(0,100),matched:matched.length,total:all.length,partial:matched.length>100},s.complete&&s.provenance==='verified'&&matched.length<=100,new Date(s.collected_at)));
      }
      return {target,evidence,note:'SBOM describes an image build; use observed digest to establish execution. Unmatched/partial inventory is not proof of absence.'};
    }
    const repo=await this.repository(target,args.commit_sha);
    if(name==='repository_files'){
      const tree=await repo.reader.get(target.name,`/git/trees/${repo.sha}?recursive=1`);
      if(!Array.isArray(tree.tree))throw new AppError('repository_tree_invalid',502);
      const paths=tree.tree.filter((e:any)=>e.type==='blob' && ['100644','100755'].includes(e.mode) && typeof e.path==='string' && inspectionPathAllowed(e.path,repo.policy) && e.path.toLowerCase().includes(args.query.toLowerCase())).map((e:any)=>e.path);
      return {target_id:target.id,commit_sha:repo.sha,scope:'repository_declared',available_commits:repo.available_commits,paths:paths.slice(0,200),partial:Boolean(tree.truncated)||paths.length>200};
    }
    if(!inspectionPathAllowed(args.path,repo.policy))throw new AppError('source_path_denied',403);
    const rawText=await repo.reader.file(target.name,repo.sha,args.path);
    if(rawText.includes('\0')||(rawText.match(/\uFFFD/g)?.length??0)>5)throw new AppError('binary_source_excluded',403);
    if(/(?:PRIVATE KEY-----|(?:password|secret|api[_-]?key|(?:access[_-]?)?token)['"]?\s*[:=]\s*['"]?[^\s,'"}]{8}|https?:\/\/[^\s/]+@)/i.test(rawText))throw new AppError('sensitive_source_excluded',403);
    if(/\.ya?ml$/.test(args.path)){
      const docs=parseAllDocuments(rawText);for(const doc of docs){if(doc.errors.length)throw new AppError('invalid_source_yaml');const v=doc.toJS({maxAliasCount:0});if(v?.kind==='Secret')throw new AppError('sensitive_source_excluded',403);}
    }
    const lines=rawText.split('\n');const text=lines.slice(args.start_line-1,args.start_line-1+args.line_count).map((line,i)=>`${args.start_line+i}: ${line}`).join('\n');
    return {evidence:this.add(target,'repository_declared',`https://github.com/${target.name}/blob/${repo.sha}/${args.path}`,{commit_sha:repo.sha,path:args.path,start_line:args.start_line,text:cleanText(text,10000),partial:args.start_line!==1||lines.length>args.line_count||text.length>10000},false),note:'Repository evidence is not proof of the currently running deployment.'};
  }
}
