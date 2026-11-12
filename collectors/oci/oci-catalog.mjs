import {createServer} from 'node:http';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {readElfBrotli} from './elf-brotli.mjs';
import {allowedImageFile,imageVersionField} from './image-file-evidence.mjs';

const run=promisify(execFile);
const registries=new Set(['docker.io','ghcr.io','quay.io','registry.k8s.io','gcr.io','public.ecr.aws','mcr.microsoft.com']);
const cache=new Map();
const bundledCache=new Map();
let active=false;

export function normalizeReference(value){
  if(!/^[a-zA-Z0-9][a-zA-Z0-9._/@:-]{0,299}$/.test(value)||value.includes('..')||value.includes('//'))return;
  const first=value.split('/')[0];
  const explicit=value.includes('/')&&(first.includes('.')||first.includes(':')||first==='localhost');
  if(explicit&&!registries.has(first))return;
  if(explicit&&first!=='docker.io')return value;
  const path=explicit?value.slice(first.length+1):value;
  return 'docker.io/'+(path.includes('/')?'':'library/')+path;
}

async function imageFile(image,digest,path,maxBuffer){
  const reference=image.replace(/@[^@]+$|:[^/:]+$/,'')+'@'+digest;
  const {stdout}=await run('/tools/regctl',['image','get-file','--platform','linux/amd64',reference,path],{
    encoding:'buffer',timeout:30000,maxBuffer,env:{PATH:'/usr/bin:/bin',HOME:'/scratch',
      ...(process.env.DOCKER_CONFIG?{DOCKER_CONFIG:process.env.DOCKER_CONFIG}:{})},
  });
  return stdout;
}

async function catalog(image){
  const cached=cache.get(image);
  if(cached&&cached.expires>Date.now())return cached.data;
  if(active)throw Error('scanner_busy');
  active=true;
  let directory;
  try{
    directory=await mkdtemp('/scratch/image-');
    const {stdout}=await run('/tools/syft',['scan','--from','registry','--platform','linux/amd64',image,'-o','syft-json'],{
      cwd:directory,env:{PATH:'/usr/bin:/bin',HOME:directory,TMPDIR:directory,
        SYFT_CHECK_FOR_APP_UPDATE:'false',SYFT_LOG_QUIET:'true',SYFT_PACKAGE_SEARCH_UNINDEXED_ARCHIVES:'false',
        ...(process.env.DOCKER_CONFIG?{DOCKER_CONFIG:process.env.DOCKER_CONFIG}:{})},
      timeout:80000,maxBuffer:24*1024*1024,
    });
    const parsed=JSON.parse(stdout),metadata=parsed.source?.metadata;
    const digest=metadata?.manifestDigest;
    if(!/^sha256:[a-f0-9]{64}$/.test(digest)||!Array.isArray(parsed.artifacts))throw Error('scanner_metadata_missing');
    const requestedDigest=image.split('@')[1];
    const repoDigests=Array.isArray(metadata.repoDigests)?metadata.repoDigests:[];
    if(requestedDigest&&requestedDigest!==digest&&!repoDigests.some(ref=>typeof ref==='string'&&ref.endsWith('@'+requestedDigest)))
      throw Error('scanner_digest_mismatch');
    const components=parsed.artifacts.filter(a=>typeof a.name==='string'&&typeof a.version==='string').slice(0,30000).map(a=>({
      name:a.name.slice(0,240),version:a.version.slice(0,120),type:String(a.type??'').slice(0,80),
      purl:String(a.purl??'').slice(0,320),cataloger:String(a.foundBy??'').slice(0,100),
      paths:Array.isArray(a.locations)?[...new Set(a.locations.map(location=>location.path??location.accessPath).filter(allowedImageFile))].slice(0,3):[],
    }));
    const data={digest,platform:'linux/amd64',distro:String(parsed.distro?.name??'').slice(0,80),
      components,artifactCount:parsed.artifacts.length,ecosystems:[...new Set(components.map(a=>a.type))].slice(0,25),
      binaries:components.filter(a=>a.cataloger==='binary-classifier'||
        /(^|\/)(distribution(?:\/distribution)?\/v3|node|java|nginx)$/.test(a.name)).slice(0,10)};
    if(cache.size>=12)cache.delete(cache.keys().next().value);
    cache.set(image,{data,expires:Date.now()+(requestedDigest?24*3600000:5*60000)});
    return data;
  }finally{
    try{if(directory)await rm(directory,{recursive:true,force:true});}finally{active=false;}
  }
}

const server=createServer(async(req,res)=>{
  try{
    const url=new URL(req.url,'http://127.0.0.1');
    if(req.method!=='GET'||!['/catalog','/file-evidence'].includes(url.pathname)){res.writeHead(404).end();return;}
    const image=normalizeReference(url.searchParams.get('image')??'');
    if(url.pathname==='/file-evidence'){
      const path=url.searchParams.get('path'),fields=url.searchParams.getAll('field');
      if(!image||!allowedImageFile(path)||fields.length>6){res.writeHead(400).end();return;}
      const {digest,platform}=await catalog(image);
      const bytes=await imageFile(image,digest,path,64*1024);
      res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({
        digest,platform,path,version:imageVersionField(bytes,fields),size:bytes.length,
      }));
      return;
    }
    const query=(url.searchParams.get('q')??'').toLowerCase().slice(0,300).split('|').map(s=>s.trim()).filter(Boolean);
    if(!image||!query.length){res.writeHead(400).end();return;}
    const {components,...metadata}=await catalog(image);
    const matches=components.filter(a=>query.some(q=>a.name.toLowerCase().includes(q)||a.purl.toLowerCase().includes(q)));
    let bundledNodeBrotli=null;
    const node=metadata.binaries.find(component=>component.name==='node'&&/^\d+\.\d+\.\d+$/.test(component.version));
    if(node&&url.searchParams.get('bundled')==='1'&&query.includes('brotli')){
      const reference=image.replace(/@[^@]+$|:[^/:]+$/,'')+'@'+metadata.digest;
      if(!bundledCache.has(reference)){
        for(const path of ['/usr/local/bin/node','/usr/bin/node']){
          try{
            const version=readElfBrotli(await imageFile(image,metadata.digest,path,160*1024*1024));
            if(version){
              if(bundledCache.size>=30)bundledCache.delete(bundledCache.keys().next().value);
              bundledCache.set(reference,{node:node.version,brotli:version,path});
              break;
            }
          }catch{ /* Other standard binary paths can still be present. */ }
        }
      }
      bundledNodeBrotli=bundledCache.get(reference)??null;
    }
    res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({
      ...metadata,image,matches:matches.slice(0,20),matchCount:matches.length,bundledNodeBrotli,
    }));
  }catch{
    res.writeHead(502,{'content-type':'application/json'}).end('{"error":"image_catalog_unavailable"}');
  }
});
server.listen(4192,'127.0.0.1');
