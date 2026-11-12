type Row=Record<string,any>;
export function inspectionFailureMessage(code:string){
  return ({evidence_changed:'검사 중 배포나 수집 근거가 변경되어 이 검사에는 최종 판정이 저장되지 않았습니다. 같은 레포트로 다시 검사하세요.',codex_request_uncertain:'Codex 요청이 완료됐는지 확인할 수 없습니다. 사용량이 중복될 수 있어 자동 재시도하지 않았습니다.',codex_request_timeout:'모델 응답 대기 시간이 초과되어 검사를 중단했습니다. 검사 대상을 줄이거나 잠시 후 다시 검사하세요. 로그인 오류로 확인된 것은 아닙니다.',codex_login_required:'Worker의 ChatGPT 로그인이 필요합니다. 운영자가 로그인 상태를 확인해야 합니다.',codex_usage_limit:'ChatGPT/Codex 사용 한도에 도달했습니다. 한도가 회복된 뒤 다시 검사하세요.',llm_call_limit:'Siliconer에 설정된 일일 모델 호출 한도에 도달했습니다. 다음 날 다시 검사하거나 운영자가 한도를 조정해야 합니다.',llm_subscription_budget_reached:'관리자가 설정한 Codex 구독 사용률 기준에 도달했습니다. 한도가 초기화되거나 설정이 바뀌면 다시 검사하세요.',codex_connection_failed:'Codex 응답 연결이 끊어졌습니다. 잠시 후 다시 검사하세요.',llm_invalid_output:'모델 응답이 검사 결과 형식에 맞지 않아 저장하지 못했습니다. 다시 검사해 주세요.'} as Row)[code]??`검사를 완료하지 못했습니다. 오류 코드 ${code}`;
}
export const severityLabels:Record<string,string>={critical:'치명적',high:'높음',medium:'보통',low:'낮음',unknown:'정보 없음'};
export const checkLabels:Record<string,string>={met:'해당됨',not_met:'해당 안 됨',unknown:'확인 못 함'};
export function threatSummary(plan:Row={},fallback?:string){
  const raw=plan.threat??{};
  return {severity:raw.severity??fallback??'unknown',basis:raw.basis??(fallback?'stated':'unknown'),headline:raw.headline??plan.products?.[0]?.conditions?.[0]??'레포트의 취약점 내용',impact:raw.impact??'이전 검사에는 피해 영향 요약이 저장되지 않았습니다. 아래 해당 조건과 레포트 원문을 확인하세요.',severity_reason:raw.severity_reason??'이 검사에는 레포트 심각도 정보가 없습니다. 취약 버전 해당 여부와 심각도는 구분해서 판단합니다.',cvss_score:raw.cvss_score??null};
}
export function responseSummary(status:string,workflow?:string,applicability?:string){
  if(workflow==='resolved')return {label:'처리 완료',tone:'resolved',description:'완료 처리된 티켓입니다. 아래 내용은 검사 당시의 판단과 근거입니다.'};
  if(applicability==='not_applicable')return {label:'해당 없음 · 적용 대상 아님',tone:'not_affected',description:'이 레포트의 기술을 사용하는 자산이 아니므로 버전을 비교할 필요가 없습니다.'};
  if(status==='affected')return {label:'대응 필요',tone:'affected',description:'레포트의 영향 조건에 해당하는 근거가 확인됐습니다. 아래 수정·확인 조치를 진행하세요.'};
  if(status==='not_affected'||status==='fixed')return {label:'이 레포트에 대한 조치 불필요',tone:'not_affected',description:'확인한 범위에서는 이 레포트의 영향 조건에 해당하지 않습니다.'};
  return {label:'확인 후 대응 판단',tone:'under_investigation',description:'핵심 정보가 부족합니다. 확인할 항목을 해결한 뒤 대응 필요 여부를 판단해야 합니다.'};
}
export function evidenceLabel(e:Row){
  if(e.kind==='deployment_desired')return (e.facts?.sources??[]).some((s:Row)=>s.state==='argo_summary')?'Argo CD 이미지 목록':'GitOps 배포 선언';
  return ({asset_profile:'자산 종류·기술 구성',deployment_observed:'실행 컨테이너 관측',build_observed:'이미지 구성요소 / SBOM',image_catalog:'컨테이너 이미지 정적 분석',image_file:'컨테이너 이미지 파일 버전',vendor_fix:'공급자 보안 수정 릴리스',collector_observed:'등록된 서버 정보',repository_declared:'저장소 파일'} as Row)[e.kind]??'수집한 근거';
}
export function comparisonPresentation(comparison:Row,target:Row={}){
  if(target.applicability==='not_applicable')return {observed:'해당 없음',label:'기술 적용 대상이 아니므로 버전 비교 불필요'};
  if(target.status==='not_affected'&&!comparison.observed_version)return {observed:'버전 비교 불필요',label:'해당 조건 비해당 · 판정 근거 참조'};
  return {observed:comparison.observed_version||'정확한 버전 미확인',label:({affected:'영향 범위에 포함',outside_range:'영향 범위에서 제외',unknown:'비교에 필요한 정보 부족'} as Row)[comparison.result]??'판정 근거 확인'};
}
export function observedVersions(evidence:Row[]=[]):string[]{
  return [...new Set(evidence.flatMap(e=>{
    const f=e.facts??{};
    return [...(f.images??[]),...(f.components??[]).filter((c:Row)=>c.version).map((c:Row)=>`${c.name} ${c.version}`),...(f.packages??[]).filter((c:Row)=>c.version).map((c:Row)=>`${c.name} ${c.version}`),...(f.kernel_release?[`실행 커널 ${f.kernel_release}`]:[]),...(f.version?[`${f.product??''} ${f.version}`.trim()]:[])];
  }))].slice(0,12) as string[];
}
export function targetName(target:Row,evidence:Row[]=[],tickets:Row[]=[]){
  const saved=target.target_name??tickets.find(t=>t.target_id===target.target_id)?.target_name;
  if(saved)return saved;
  const source=evidence.find(e=>e.target_id===target.target_id&&e.kind==='deployment_desired')?.source;
  return source?.split('/').at(-1)??target.target_id?.replace(/^repo:[^:]+:/,'')??'검사 대상';
}
export function collectionSummary(asset:Row){
  const hasImages=asset.desired_images?.length>0;
  const refs:Row[]=asset.source_refs??[];
  if(asset.render_state==='resolved')return {label:'GitOps 설정·이미지 확인',description:'저장소의 배포 설정을 재구성해 이미지 선언을 확인했습니다.',level:'complete'};
  if(hasImages&&(asset.render_state==='summary_only'||refs.some(r=>r.state==='argo_summary')))return {label:'Argo CD 이미지 목록 확인',description:'이미지 태그로 버전 비교가 가능합니다. GitOps 저장소의 설정 전체와 실행 버전은 별도로 확인해야 합니다.',level:'summary'};
  if(hasImages)return {label:'이미지 확인 · 설정 일부 미확인',description:'확인한 이미지 정보는 버전 비교에 사용할 수 있습니다. 일부 저장소 설정은 수집하거나 재구성하지 못했습니다.',level:'partial'};
  return {label:'이미지 정보 확인 필요',description:'비교할 이미지 버전 정보가 아직 없습니다. Argo CD 이미지 목록이나 GitOps 저장소 연결을 확인하세요.',level:'missing'};
}
