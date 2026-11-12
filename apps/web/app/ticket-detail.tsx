import TicketForm from './ticket-form';
import RemediationPrList from './remediation-pr-list';
import {AssessmentView,ThreatOverview} from './assessment-view';
import {responseSummary} from '../../../packages/core/src/presentation';
type Row=Record<string,any>;
const remediationErrors:Record<string,string>={
  remediation_branch_rules_unavailable:'GitHub 요금제에서 이 비공개 저장소의 브랜치 보호 규칙을 사용할 수 없어 PR 생성을 중단했습니다.',
  remediation_branch_rules_required:'기본 브랜치에 필수 리뷰와 CI 규칙을 설정한 뒤 PR을 생성할 수 있습니다.',
  remediation_branch_changed:'수정 브랜치가 변경되어 자동으로 덮어쓸 수 없습니다.',
};
export default function TicketDetail({ticket,busy,save,openInvestigation}:{ticket:Row;busy:boolean;save:(body:Row)=>Promise<any>;openInvestigation:(id:string)=>void}){
  const context=ticket.context??{};
  const target={applicability:context.applicability,applicability_reason:context.applicability_reason,status:ticket.assessment_status??ticket.finding_status,explanation:context.explanation??ticket.finding_summary,response_summary:context.response_summary,checks:context.checks??[],version_comparison:context.version_comparison??[],recommended_actions:context.recommended_actions??[]};
  const plan={threat:context.threat,products:context.products??[],checks:context.check_definitions??[],limitations:context.limitations??[]};
  const evidence=context.evidence??ticket.finding_evidence??[];
  const stale=evidence.some((e:Row)=>e.expires_at&&Date.parse(e.expires_at)<=Date.now());
  const verdict=responseSummary(target.status,undefined,target.applicability);
  const latest=ticket.investigations?.[0];
  return <article className="ticket-detail"><header><span className="eyebrow">{ticket.target_name??ticket.application??'검사 대상'}</span><h2>{ticket.title??ticket.canonical_id}</h2>{context.reference_url?<a href={context.reference_url} target="_blank" rel="noreferrer">보안 레포트 원문 열기 ↗</a>:null}</header>
    <p><span className={`badge badge-${verdict.tone}`}>{verdict.label}</span> {target.response_summary||verdict.description}{stale?<small className="block muted">검사 당시 기록</small>:null}</p>
    {latest?<button className="text-button" onClick={()=>openInvestigation(latest.id)}>연결된 검사 결과 열기</button>:null}
    <details className="technical-details"><summary>저장된 판정 근거</summary>
      <ThreatOverview plan={plan} fallback={ticket.advisory_severity}/>
      <AssessmentView target={target} plan={plan} evidence={evidence} showVerdict={false}/>
    </details>
    <section className="ticket-management"><h3>티켓 처리</h3><TicketForm key={ticket.id} ticket={ticket} busy={busy} save={save}/></section>
    {ticket.remediationPrs?.length||ticket.remediationJobs?.length ? <section><h3>자동 수정 PR</h3>
      {ticket.remediationJobs?.filter((job:Row)=>job.error_code||job.state==='queued'||job.state==='running').map((job:Row)=>
        <p key={job.type}>{job.error_code?(remediationErrors[job.error_code]??`PR 작업이 중단됐습니다. 오류 코드 ${job.error_code}`):
          job.state==='queued'?'PR 준비 대기 중':'PR을 준비하는 중입니다.'}</p>)}
      <RemediationPrList items={ticket.remediationPrs??[]}/>
    </section> : null}
    {ticket.investigations?.length?<details className="technical-details"><summary>연결된 검사와 재검사 이력 ({ticket.investigations.length})</summary>{ticket.investigations.map((i:Row)=><p key={i.id}><button className="text-button" onClick={()=>openInvestigation(i.id)}>{new Date(i.created_at).toLocaleString('ko-KR')} · 검사 결과 열기</button></p>)}</details>:null}
    <small className="muted">티켓 ID: {ticket.id}</small>
  </article>;
}
