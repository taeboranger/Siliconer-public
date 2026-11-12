// Read exactly three read-only host mounts. No shell, SSH, Kubernetes API or /host root.
import {readFile,realpath} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';

export function collectHostFacts(osRelease,kernelRelease,dpkgStatus,architecture){
  const os={};
  for(const line of osRelease.split('\n')){
    const m=/^(ID|VERSION_ID|PRETTY_NAME)=(.*)$/.exec(line);
    if(m)os[m[1]]=m[2].replace(/^"(.*)"$/,'$1');
  }
  if(!os.ID||!os.VERSION_ID||!os.PRETTY_NAME||!/^[a-zA-Z0-9.+_-]{1,200}$/.test(kernelRelease.trim()))throw Error('host_identity_incomplete');
  const packages=[],seen=new Set();let paragraphs=0;
  for(const paragraph of dpkgStatus.split(/\r?\n\r?\n/)){
    if(!paragraph.trim())continue;paragraphs++;
    const fields={};for(const line of paragraph.split('\n')){const m=/^([A-Za-z-]+): (.*)$/.exec(line);if(m)fields[m[1]]=m[2];}
    if(!fields.Package||!fields.Status)throw Error('dpkg_status_invalid');
    if(!/^\S+ \S+ installed$/.test(fields.Status))continue;
    const source=/^([a-z0-9+.-]+)(?: \(([^)]+)\))?$/.exec(fields.Source??fields.Package);
    const p={name:fields.Package,version:fields.Version,architecture:fields.Architecture,source_name:source?.[1],source_version:source?.[2]??fields.Version};
    if(!source||!p.version||!p.architecture||!/^\S+$/.test(p.version)||seen.has(p.name+':'+p.architecture))throw Error('dpkg_package_invalid');
    seen.add(p.name+':'+p.architecture);packages.push(p);
  }
  if(!paragraphs||!packages.length||packages.length>10000)throw Error('dpkg_inventory_incomplete');
  packages.sort((a,b)=>(a.name+':'+a.architecture).localeCompare(b.name+':'+b.architecture,'en'));
  return {os_id:os.ID,os_version:os.VERSION_ID,os_name:os.PRETTY_NAME,kernel_release:kernelRelease.trim(),architecture,
    host_inventory:{format:'dpkg',scope:'host_installed_packages',complete:true,packages}};
}

async function main(){
  const {SILICONER_FACTS_URL:url,SILICONER_HOST_ASSET_ID:assetId,SILICONER_HOST_NAME:name}=process.env;
  if(!url||!assetId||!name||!/^https?:$/.test(new URL(url).protocol))throw Error('collector_configuration_missing');
  const [os,kernel,status,token]=await Promise.all(['/host-data/os-release','/host-data/kernel-release','/host-data/dpkg-status','/collector-secret/token'].map(p=>readFile(p,'utf8')));
  if(token.trim().length<32)throw Error('collector_credential_missing');
  const facts=collectHostFacts(os,kernel,status,process.arch==='x64'?'amd64':process.arch);
  const response=await fetch(url,{method:'POST',redirect:'error',signal:AbortSignal.timeout(20000),headers:{Authorization:'Bearer '+token.trim(),'Content-Type':'application/json'},
    body:JSON.stringify({assetId,kind:'host',name,observedAt:new Date().toISOString(),facts})});
  if(response.status!==202)throw Error('facts_ingest_http_'+response.status);
  console.log(JSON.stringify({event:'host_inventory_submitted',assetId,os:facts.os_name,kernel:facts.kernel_release,installed_packages:facts.host_inventory.packages.length}));
}
// Kubernetes projected ConfigMap files are symlinks; Node resolves import.meta.url.
if(process.argv[1]&&import.meta.url===pathToFileURL(await realpath(process.argv[1])).href)main().catch(()=>{console.error('Host inventory collection or submission failed; no fresh evidence was submitted.');process.exitCode=1;});
