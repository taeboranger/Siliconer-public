type Row=Record<string,any>;
export interface ResourceScope{complete:boolean;kinds:string[];workload_count:number;entrypoint_overrides:number;unknown_kinds:string[]}
const workloads=new Set(['v1/Pod','apps/v1/Deployment','apps/v1/StatefulSet','apps/v1/DaemonSet','apps/v1/ReplicaSet','batch/v1/Job','batch/v1/CronJob']);
const configuration=new Set([
  ...['Namespace','ConfigMap','Secret','Service','Endpoints','ServiceAccount','PersistentVolume','PersistentVolumeClaim','ResourceQuota','LimitRange'].map(k=>'v1/'+k),
  ...['Ingress','IngressClass','NetworkPolicy'].map(k=>'networking.k8s.io/v1/'+k),
  'discovery.k8s.io/v1/EndpointSlice',
  ...['Role','RoleBinding','ClusterRole','ClusterRoleBinding'].map(k=>'rbac.authorization.k8s.io/v1/'+k),
  'policy/v1/PodDisruptionBudget','autoscaling/v2/HorizontalPodAutoscaler','storage.k8s.io/v1/StorageClass',
  ...['Certificate','Issuer','ClusterIssuer'].map(k=>'cert-manager.io/v1/'+k),
  ...['VaultAuth','VaultStaticSecret','VaultConnection'].map(k=>'secrets.hashicorp.com/v1beta1/'+k),
]);
export function resourceScope(documents:Row[],resolved:boolean):ResourceScope{
  const kinds=new Set<string>(),unknown=new Set<string>();let count=0,overrides=0;
  for(const d of documents.filter(Boolean)){
    const key=typeof d.apiVersion==='string'&&typeof d.kind==='string'?d.apiVersion+'/'+d.kind:'unrecognized-resource';kinds.add(key);
    if(workloads.has(key)){
      count++;const spec=d.kind==='Pod'?d.spec:d.kind==='CronJob'?d.spec?.jobTemplate?.spec?.template?.spec:d.spec?.template?.spec;
      const containers=[...(spec?.containers??[]),...(spec?.initContainers??[]),...(spec?.ephemeralContainers??[])];
      if(!containers.length||containers.some(c=>typeof c.image!=='string'||!c.image.trim()))unknown.add(key+'/missing-container-image');
      overrides+=containers.filter(c=>c.command?.length||c.args?.length).length;
    }else if(!configuration.has(key))unknown.add(key);
  }
  return {complete:resolved&&kinds.size>0&&!unknown.size,kinds:[...kinds].sort(),workload_count:count,entrypoint_overrides:overrides,unknown_kinds:[...unknown].sort()};
}
export interface AssetProfile{kind:'configuration_only'|'oci_registry'|'unknown';complete:boolean;technologies:string[];description:string;resource_kinds:string[];images:string[];reference?:string}
function officialRegistry(image:string){const repository=image.split('@')[0].replace(/:[^/:]+$/,'').toLowerCase();return ['registry','docker.io/registry','docker.io/library/registry','index.docker.io/library/registry'].includes(repository);}
export function assetProfile(asset:Row):AssetProfile{
  const refs:Row[]=asset.source_refs??[],images:string[]=asset.desired_images??[],scopes:ResourceScope[]=refs.map(r=>r.resource_scope);
  const kinds=[...new Set(scopes.flatMap(s=>s?.kinds??[]))];
  const unknown:AssetProfile={kind:'unknown',complete:false,technologies:[],description:'자산 종류를 확정할 구성 근거가 부족합니다.',resource_kinds:kinds,images};
  if(asset.render_state!=='resolved'||!refs.length||refs.some(r=>r.state!=='resolved')||scopes.some(s=>!s?.complete))return unknown;
  if(scopes.every(s=>s.workload_count===0)&&!images.length)return {kind:'configuration_only',complete:true,technologies:['kubernetes-configuration'],description:`${kinds.map(k=>k.split('/').at(-1)).join(', ')} 설정만 선언된 자산이며 실행 애플리케이션 워크로드가 없습니다.`,resource_kinds:kinds,images};
  if(images.length&&images.every(officialRegistry)&&scopes.some(s=>s.workload_count>0)&&scopes.every(s=>s.entrypoint_overrides===0))return {kind:'oci_registry',complete:true,technologies:['oci-distribution','go'],description:'공식 registry 이미지의 OCI Distribution 레지스트리 서비스이며 JavaScript/React 애플리케이션이 아닙니다.',resource_kinds:kinds,images,reference:'https://distribution.github.io/distribution/'};
  return unknown;
}
function applicationPackageVersionReport(plan:Row){
  if(!plan.products?.length||!plan.checks?.length||plan.checks.some((c:Row)=>c.kind!=='version'))return false;
  // Only language/application package reports. Never skip registry/Go/native/OS,
  // Kubernetes configuration, or mixed reports on the basis of this profile.
  const applicationEcosystems=new Set(['npm','javascript','node.js','maven','java','jvm','pypi','python','composer','nuget','rubygems']);
  return plan.products.every((p:Row)=>p.kind==='library'&&applicationEcosystems.has(String(p.ecosystem??'').trim().toLowerCase()));
}
export function applicationPackageReportExcluded(plan:Row,profile:AssetProfile|undefined){
  return Boolean(profile?.complete&&['configuration_only','oci_registry'].includes(profile.kind)&&applicationPackageVersionReport(plan));
}

export function hostSystemReportExcluded(plan:Row,scope:string|undefined){
  return scope==='host_system'&&applicationPackageVersionReport(plan);
}

export const hostSystemScopeDescription='이 자산의 검사 범위는 호스트 OS·실행 커널·OS 패키지입니다. 애플리케이션 패키지는 각 배포 자산에서 확인합니다.';
