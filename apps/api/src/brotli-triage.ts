import type {InspectionEvidence} from './inspection-tools.js';
import type {EvaluatedTarget} from './investigations.js';

export function observedBrotliComparisons(evidence:InspectionEvidence[]):EvaluatedTarget['version_comparison']{
  const comparisons=new Map<string,EvaluatedTarget['version_comparison'][number]>();
  for(const item of evidence){
    if(item.kind!=='vendor_fix')continue;
    const {component,version,runtime_version,fix_version,status,observed_evidence_id}=item.facts;
    const key=JSON.stringify([component,version,runtime_version,fix_version,status]);
    const comparison=comparisons.get(key)??{
      product:component,
      observed_version:runtime_version?`Brotli ${version} · Node.js ${runtime_version}`:version,
      affected_range:`공급자 공지의 수정 릴리스 이전 (${fix_version})`,
      fixed_version:fix_version,
      result:status==='fixed'?'outside_range':'affected',
      evidence_ids:[],
    };
    if(comparison.evidence_ids.length<=13){
      comparison.evidence_ids=[...new Set([...comparison.evidence_ids,item.id,observed_evidence_id])];
    }
    comparisons.set(key,comparison);
  }
  return [...comparisons.values()].slice(0,20);
}

// Coverage is limited to the enumerated images and the implementations recognized by the inventory.
export function scopedBrotliVerdict(catalog:{evidence:InspectionEvidence[];unavailable:string[];unscanned:number}|null,
  vendor:InspectionEvidence[],observations:InspectionEvidence[]){
  const images=catalog?.evidence.filter(item=>item.source.startsWith('syft:'))??[];
  const comparisons=observedBrotliComparisons(vendor);
  const affected=comparisons.find(item=>item.result==='affected');
  if(affected)return {status:'affected' as const,summary:`${affected.observed_version}은 공급자 수정 릴리스 ${affected.fixed_version} 이전입니다.`,
    comparisons,evidenceIds:affected.evidence_ids};
  if(!catalog||catalog.unavailable.length||catalog.unscanned||!images.length)return null;
  if(observations.some(item=>item.kind==='build_observed'&&item.facts.matched>0))return null;
  const observedIds=new Set(vendor.map(item=>item.facts.observed_evidence_id));
  for(const image of images){
    const {requested_image,digest,binaries,matchCount,matches,artifactCount}=image.facts;
    if(!Array.isArray(matches)||matchCount!==matches.length||!Array.isArray(binaries)||artifactCount>30000)return null;
    if((binaries.some(binary=>binary.name==='node')||binaries.length>=10)&&!observations.some(item=>observedIds.has(item.id)&&
      (item.source==='image:node-runtime-versions'?item.facts.requested_image===requested_image:
        ['collector:node-runtime-versions','operator:node-runtime-versions'].includes(item.source)&&
        (requested_image.endsWith(`@${item.facts.digest}`)||digest===item.facts.digest))))return null;
    if(matches.some(match=>!vendor.some(item=>item.facts.observed_evidence_id===image.id&&
      item.facts.component===`Debian ${match.name}`&&item.facts.version===match.version)))return null;
  }
  return {status:'not_affected' as const,summary:comparisons.length
    ?`${comparisons.map(item=>item.observed_version).join(', ')}에 공급자 수정이 적용됐습니다.`
    :'검사한 이미지의 패키지·바이너리 목록에서 대상 Brotli·Siemens 제품이 검출되지 않았습니다.',
    comparisons,evidenceIds:images.map(item=>item.id)};
}
