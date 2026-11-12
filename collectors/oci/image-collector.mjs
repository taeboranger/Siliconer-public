import { readFile } from 'node:fs/promises';
import { request } from 'node:https';

const { IMAGE_TARGETS, CLUSTER_ID, SNAPSHOT_URL } = process.env;
const targets=JSON.parse(IMAGE_TARGETS??'[]');
if(!targets.length||!CLUSTER_ID||!SNAPSHOT_URL)throw Error('collector_configuration_missing');
const serviceAccount='/var/run/secrets/kubernetes.io/serviceaccount';
const [token,ca,ingestToken]=await Promise.all([
  readFile(serviceAccount+'/token','utf8'),readFile(serviceAccount+'/ca.crt'),readFile('/collector-secret/token','utf8'),
]);
function repository(image){
  return image.replace(/^(?:index\.)?docker\.io\/(?:library\/)?/,'').replace(/@sha256:[a-f0-9]{64}$/,'').replace(/:[^/:]+$/,'');
}

let failures=0;
for(const target of targets){
  try{await collect(target);}
  catch{failures++;console.error(JSON.stringify({event:'image_digest_collection_failed',namespace:target.namespace}));}
}
if(failures)process.exitCode=1;

async function collect({applicationId,namespace,repositories}){
  const observedAt=new Date().toISOString();
  const query=new URLSearchParams({limit:'250',fieldSelector:'status.phase=Running'});
  const path=`/api/v1/namespaces/${encodeURIComponent(namespace)}/pods?${query}`;
  const list=await new Promise((resolve,reject)=>{
    const req=request({hostname:'kubernetes.default.svc',path,ca,headers:{Authorization:'Bearer '+token.trim()},signal:AbortSignal.timeout(15000)},async response=>{
      try{
        if(response.statusCode!==200)throw Error('pod_list_failed');
        const chunks=[];let size=0;
        for await(const chunk of response){size+=chunk.length;if(size>4*1024*1024)throw Error('pod_list_too_large');chunks.push(chunk);}
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      }catch(error){reject(error);}
    });
    req.on('error',reject);req.end();
  });
  if(!Array.isArray(list.items)||list.metadata?.continue)throw Error('pod_list_incomplete');
  const containers=[];
  for(const pod of list.items){
    for(const [kind,field,statusField] of [['regular','containers','containerStatuses'],['init','initContainers','initContainerStatuses'],['ephemeral','ephemeralContainers','ephemeralContainerStatuses']]){
      for(const container of pod.spec[field]??[]){
        if(!repositories.includes(repository(container.image)))continue;
        const status=pod.status?.[statusField]?.find(item=>item.name===container.name);
        const imageId=status?.imageID;
        const digest=typeof imageId==='string'?/(?:@|\/\/)(sha256:[a-f0-9]{64})$/.exec(imageId)?.[1]:undefined;
        const owner=pod.metadata.ownerReferences?.find(item=>item.controller);
        const observation={podUid:pod.metadata.uid,workloadUid:owner?.uid??pod.metadata.uid,
          workloadName:owner?.name??pod.metadata.name,namespace,container:container.name,kind,
          desiredImage:container.image,imageId,digest,running:Boolean(status?.state?.running)};
        containers.push(observation);
      }
    }
  }
  containers.sort((a,b)=>(a.podUid+'/'+a.kind+'/'+a.container).localeCompare(b.podUid+'/'+b.kind+'/'+b.container));
  const response=await fetch(SNAPSHOT_URL,{method:'POST',redirect:'error',signal:AbortSignal.timeout(15000),
    headers:{Authorization:'Bearer '+ingestToken.trim(),'Content-Type':'application/json'},
    body:JSON.stringify({applicationId,clusterId:CLUSTER_ID,observedAt,
      complete:false,namespaces:[namespace],containers}),
  });
  if(response.status!==202)throw Error('snapshot_ingest_http_'+response.status);
  await response.body?.cancel();
  console.log(JSON.stringify({event:'image_digests_submitted',namespace,containers:containers.length}));
}
