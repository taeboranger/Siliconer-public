'use client';
import {useEffect,useState,type FormEvent} from 'react';
import Link from 'next/link';
import TicketForm from './ticket-form';
import RemediationPrList,{type RemediationPr} from './remediation-pr-list';
import AnalysisSetup,{type AnalysisChoice} from './analysis-setup';
import {comparisonPresentation,inspectionFailureMessage,targetName} from '../../../packages/core/src/presentation';

type Row=Record<string,any>;
type Submit=(path:string,body:unknown,method?:string)=>Promise<any>;
const states:Record<string,string>={queued:'대기',planning:'레포트 해석 중',collecting:'근거 조사 중',completed:'완료',blocked:'중단',failed:'실패'};
const verdicts:Record<string,string>={affected:'작업 필요',not_affected:'작업 불필요',under_investigation:'확인 필요'};
const time=(value?:string)=>value?new Date(value).toLocaleString('ko-KR'):'—';

function overallVerdict(targets:Row[],total=targets.length){
  if(targets.some(target=>target.status==='affected'))return 'affected';
  if(!targets.length||targets.length<total||targets.some(target=>target.status==='under_investigation'))return 'under_investigation';
  return 'not_affected';
}

export default function InspectionPanel({initialId='',data,request,submit,canSubmit,canDelete,llmEnabled,busy,allowRuntime=false}:{
  initialId?:string;data:Row;request:(path:string)=>Promise<any>;submit:Submit;
  canSubmit:boolean;canDelete:boolean;llmEnabled:boolean;busy:boolean;allowRuntime?:boolean;
}){
  if(initialId)return <InspectionDetail id={initialId} request={request} submit={submit} canSubmit={canSubmit} llmEnabled={llmEnabled} busy={busy} revision={data}/>;
  return <InspectionList data={data} request={request} submit={submit} canSubmit={canSubmit} canDelete={canDelete} llmEnabled={llmEnabled} busy={busy} allowRuntime={allowRuntime}/>;
}

function InspectionList({data,request,submit,canSubmit,canDelete,llmEnabled,busy,allowRuntime}:{
  data:Row;request:(path:string)=>Promise<any>;submit:Submit;canSubmit:boolean;canDelete:boolean;llmEnabled:boolean;busy:boolean;allowRuntime:boolean;
}){
  const [title,setTitle]=useState('');
  const [text,setText]=useState('');
  const [url,setUrl]=useState('');
  const [runtime,setRuntime]=useState<Row[]>([]);
  const [reports,setReports]=useState<Row[]>([]);
  const [reportId,setReportId]=useState('');
  const [scope,setScope]=useState('all');
  const [choice,setChoice]=useState<AnalysisChoice|null>(null);
  const [message,setMessage]=useState('');
  const [formOpen,setFormOpen]=useState(false);
  useEffect(()=>{
    let active=true;
    if(canSubmit)request('security-reports?limit=100').then(result=>{if(active)setReports(result.items);}).catch(error=>{if(active)setMessage(error.message);});
    if(allowRuntime)request('runtime-assets').then(result=>{if(active)setRuntime(result.items);}).catch(error=>{if(active)setMessage(error.message);});
    const source=new URLSearchParams(window.location.search).get('report');
    if(source){setReportId(source);setFormOpen(true);}
    return ()=>{active=false;};
  },[request,canSubmit,allowRuntime]);
  useEffect(()=>{
    if(!reportId)return;
    let active=true;
    request(`security-reports/${reportId}`).then(report=>{
      if(active){
        setTitle(report.title);setText(report.body);setUrl(report.reference_url??'');
        if(report.id!==reportId)setReportId(report.id);
      }
    }).catch(error=>{if(active)setMessage(error.message);});
    return ()=>{active=false;};
  },[reportId,request]);

  async function create(event:FormEvent){
    event.preventDefault();setMessage('');
    try{
      const result=await submit('investigations',{
        title,...(reportId?{reportId}:{reportText:text,...(url.trim()?{referenceUrl:url.trim()}:{})}),
        ...(scope!=='all'?{applicationIds:[],factAssetIds:[scope]}:{}),
        ...(choice?{analysisSettings:choice}:{}),
      });
      window.location.assign(`/investigations/${result.id}`);
    }catch{}
  }
  async function remove(row:Row){
    if(!window.confirm(`“${row.title}” 검사 결과를 목록에서 삭제할까요? 보안 레포트와 연결된 티켓은 보관됩니다.`))return;
    try{await submit(`investigations/${row.id}`,{},'DELETE');setMessage('검사 결과를 목록에서 삭제했습니다.');}catch{}
  }

  return <section>
    <div className="section-toolbar"><p className="muted">레포트별 대응 여부와 분석 이력</p>{canSubmit?<button className="primary" onClick={()=>setFormOpen(value=>!value)}>{formOpen?'입력 닫기':'새 검사'}</button>:null}</div>
    {canSubmit&&formOpen?<form className="inspection-form" onSubmit={create}>
      <div className="analysis-options"><label>보안 레포트<select value={reportId} onChange={event=>{
        setReportId(event.target.value);if(!event.target.value){setTitle('');setText('');setUrl('');}
      }}><option value="">새 레포트 입력</option>{reportId&&!reports.some(report=>report.id===reportId)?<option value={reportId}>{title||'저장된 레포트'}</option>:null}{reports.map(report=><option key={report.id} value={report.id}>{report.title}</option>)}</select></label>
        {allowRuntime&&runtime.length?<label>검사 대상<select value={scope} onChange={event=>setScope(event.target.value)}><option value="all">연결된 전체 자산</option>{runtime.map(asset=><option key={asset.id} value={asset.id}>{asset.name}</option>)}</select></label>:null}
      </div>
      <label>검사 제목<input required maxLength={200} value={title} onChange={event=>setTitle(event.target.value)} placeholder="예: Spring 취약점 영향 검사"/></label>
      <label>레포트 내용<textarea required rows={6} minLength={30} maxLength={100000} value={text} readOnly={Boolean(reportId)} onChange={event=>setText(event.target.value)} placeholder="영향 버전과 취약 조건을 포함한 레포트를 입력하세요."/></label>
      {!reportId?<div className="analysis-options"><label>텍스트 파일<input type="file" accept=".txt,.md,.json" onChange={event=>{
        const file=event.target.files?.[0];if(!file)return;
        if(file.size>100000){setMessage('100KB 이하의 파일을 선택하세요.');return;}
        void file.text().then(setText).catch(()=>setMessage('파일을 읽지 못했습니다.'));
      }}/></label><label>원문 URL<input type="url" value={url} onChange={event=>setUrl(event.target.value)} placeholder="https://…"/></label></div>:null}
      <AnalysisSetup request={request} value={choice} onChange={setChoice} targetCount={scope==='all'?undefined:1}/>
      <div className="section-toolbar"><small className="muted">레포트 원문과 분석 결과가 자동 저장됩니다.</small><button className="primary" disabled={busy||!llmEnabled||!choice}>검사 시작</button></div>
    </form>:null}
    {message?<p className="notice" role="status">{message}</p>:null}
    <div className="table-wrap"><table><thead><tr><th>레포트</th><th>결과</th><th>진행 상태</th><th>시작 / 종료</th>{canDelete?<th>관리</th>:null}</tr></thead>
      <tbody>{(data.items??[]).map((row:Row)=>{
        const verdict=row.affected_count?'affected':row.unknown_count||!row.assessed_count||row.assessed_count<row.target_count?'under_investigation':'not_affected';
        return <tr key={row.id}><td><Link className="result-link" prefetch={false} href={`/investigations/${row.id}`}>{row.title}</Link><small className="block muted">{row.analysis_settings?.model??'기존 분석'}</small></td>
          <td>{row.state==='completed'?<span className={`badge badge-${verdict}`}>{verdicts[verdict]}</span>:'—'}</td>
          <td>{states[row.state]??row.state}{row.state==='collecting'?<small className="block muted">{row.stage}</small>:null}</td>
          <td><small className="block">{time(row.started_at)}</small><small className="block muted">{time(row.finished_at)}</small></td>
          {canDelete?<td>{['completed','blocked','failed'].includes(row.state)?<button disabled={busy} onClick={()=>void remove(row)}>삭제</button>:null}</td>:null}
        </tr>;
      })}</tbody>
    </table></div>{!data.items?.length?<p className="empty">새 레포트로 첫 검사를 시작하세요.</p>:null}
  </section>;
}

function InspectionDetail({id,request,submit,canSubmit,llmEnabled,busy,revision}:{
  id:string;request:(path:string)=>Promise<any>;submit:Submit;canSubmit:boolean;llmEnabled:boolean;busy:boolean;revision:Row;
}){
  const [detail,setDetail]=useState<Row|null>(null);
  const [error,setError]=useState('');
  const [expanded,setExpanded]=useState<string[]>([]);
  const [filter,setFilter]=useState('all');
  const [choices,setChoices]=useState<Record<string,AnalysisChoice>>({});
  useEffect(()=>{
    let active=true;
    request(`investigations/${id}`).then(result=>{if(active){setDetail(result);setError('');}}).catch(reason=>{if(active)setError(reason.message);});
    return ()=>{active=false;};
  },[id,request,revision]);
  if(error)return <p className="error" role="alert">{error}</p>;
  if(!detail)return <p role="status">검사 결과를 불러오는 중입니다.</p>;
  const targets:Row[]=detail.result?.targets??[];
  const verdict=overallVerdict(targets,detail.result?.target_count??targets.length);
  const visible=targets.filter(target=>filter==='all'||target.status===filter);

  return <article className="inspection-detail-page">
    <Link prefetch={false} href="/">검사 목록</Link>
    <header className={`analysis-overview verdict-${verdict}`}>
      <h1>{detail.state==='completed'?verdicts[verdict]:states[detail.state]??detail.state}</h1>
      <p className="report-title">{detail.title}</p>
      {detail.state==='completed'?<div className="result-counts">{Object.entries(verdicts).map(([status,label])=><span key={status}>{label} <strong>{targets.filter(target=>target.status===status).length}</strong></span>)}</div>:<p role="status">{detail.stage}</p>}
    </header>
    <div className="analysis-metadata"><span>시작 {time(detail.started_at)}</span><span>종료 {time(detail.finished_at)}</span><span>{detail.analysis_settings?.model??'기존 모델'} · {detail.analysis_settings?.effort??'기본 추론'}</span></div>
    {detail.error_code?<p className="warning">{inspectionFailureMessage(detail.error_code)}</p>:null}
    {detail.result?.evidence_changed?<p className="notice">{Array.isArray(detail.result.changed_target_ids)
      ? `검사 당시 결과를 보관했습니다. 근거가 유지된 대상은 티켓에 반영했습니다.`
      : '검사 도중 배포·수집 근거가 변경됐습니다. 검사 당시 결과를 보관했습니다.'}</p>:
      detail.stale?<p className="notice">검사 당시의 결과입니다. 현재 상태는 새 검사로 확인하세요.</p>:null}
    {detail.result?<>
      <div className="section-toolbar"><label>대상 필터<select value={filter} onChange={event=>setFilter(event.target.value)}><option value="all">전체 자산</option>{Object.entries(verdicts).map(([status,label])=><option value={status} key={status}>{label}</option>)}</select></label><div className="actions"><button onClick={()=>setExpanded(visible.map(target=>target.target_id))}>모두 펼치기</button><button onClick={()=>setExpanded([])}>모두 접기</button></div></div>
      {visible.map(target=>{
        const targetId=target.target_id as string;
        const open=expanded.includes(targetId);
        const choice=choices[targetId]??(detail.analysis_settings?.model?detail.analysis_settings:null);
        const history=detail.detail_history?.find((entry:Row)=>entry.target_id===targetId&&entry.model===choice?.model&&entry.effort===choice?.effort);
        const latest=detail.result.details?.[targetId];
        const generated=history?.body??(!choice||!latest?.analysis_settings||(latest.analysis_settings.model===choice.model&&latest.analysis_settings.effort===choice.effort)?latest:null);
        const job=detail.detail_jobs?.find((entry:Row)=>entry.target_id===targetId);
        const pending=job?.state==='queued'||job?.state==='running';
        const ticket=detail.tickets?.find((entry:Row)=>entry.target_id===targetId);
        const remediationPrs:RemediationPr[]=ticket?.remediationPrs??[];
        return <div className="target-assessment" key={targetId}><details open={open} onToggle={event=>{
          const next=event.currentTarget.open;
          setExpanded(current=>next===current.includes(targetId)?current:next?[...current,targetId]:current.filter(value=>value!==targetId));
        }}>
          <summary><strong>{targetName(target,detail.evidence,detail.tickets)}</strong><span className={`badge badge-${target.status}`}>{verdicts[target.status]??'확인 필요'}</span></summary>
          {open?<>
            <p>{target.response_summary}</p>
            {target.status==='affected'&&target.recommended_actions?.length?<div className="recommended-action"><strong>권고 조치</strong><ul>{target.recommended_actions.map((action:string,index:number)=><li key={index}>{action}</li>)}</ul></div>:null}
            {generated?<section className="generated-analysis"><h3>상세 분석과 조치 권고</h3><p>{generated.explanation}</p>{generated.recommended_actions?.length?<ol>{generated.recommended_actions.map((action:string,index:number)=><li key={index}>{action}</li>)}</ol>:null}
              {generated.limitations?.length?<details><summary>추가 확인 사항</summary><ul>{generated.limitations.map((item:string,index:number)=><li key={index}>{item}</li>)}</ul></details>:null}
              <small className="muted">{generated.analysis_settings?.model??'기존 모델'} · 생성 {time(generated.generated_at)}</small>
            </section>:null}
            {canSubmit&&llmEnabled?<details className="technical-details" open={!generated}><summary>{generated?'다른 모델로 상세 분석':'상세 분석 설정'}</summary>
              <AnalysisSetup operation="investigation-detail" targetCount={1} request={request} value={choice} onChange={next=>setChoices(current=>({...current,[targetId]:next}))}/>
              {pending?<p role="status">{job.state==='queued'?'상세 분석 대기 중':'상세 분석 생성 중'}</p>:generated?<p className="muted">이 모델의 저장된 분석을 표시하고 있습니다.</p>:<button className="primary" disabled={busy||!choice} onClick={()=>{void submit(`investigations/${id}/details`,{targetId,analysisSettings:choice}).catch(()=>{});}}>상세 분석·조치 권고 생성</button>}
              {job?.error_code?<p className="warning">{inspectionFailureMessage(job.error_code)}</p>:null}
            </details>:null}
            {target.version_comparison?.length?<details className="technical-details"><summary>버전 비교 근거</summary><div className="table-wrap"><table><thead><tr><th>제품</th><th>확인 버전</th><th>영향 범위</th><th>수정 버전</th></tr></thead><tbody>{target.version_comparison.map((version:Row,index:number)=><tr key={index}><td>{version.product}</td><td>{comparisonPresentation(version,target).observed}</td><td>{version.affected_range}</td><td>{version.fixed_version??'미기재'}</td></tr>)}</tbody></table></div></details>:null}
            {ticket?<details className="ticket-management"><summary>연결된 대응 티켓</summary><TicketForm key={ticket.id} ticket={ticket} busy={busy} save={body=>submit(`tickets/${ticket.id}`,body,'PATCH')}/></details>:null}
          </>:null}
        </details>
          {remediationPrs.length?<section className="inspection-remediation-prs">
            <h3>보안 패치 PR 생성됨</h3>
            <RemediationPrList items={remediationPrs}/>
          </section>:null}
        </div>;
      })}
    </>:null}
    <details className="technical-details"><summary>검사에 사용한 보안 레포트</summary>{detail.reference_url?<a href={detail.reference_url} target="_blank" rel="noreferrer">원문 URL 열기</a>:null}<pre>{detail.report_text}</pre></details>
    {detail.usage?.length?<details className="technical-details"><summary>이 검사에서 사용한 토큰</summary>{detail.usage.map((item:Row,index:number)=><p key={index}>{item.model} / {item.effort} · 입력 {Number(item.input_tokens).toLocaleString()} · 출력 {Number(item.output_tokens).toLocaleString()} · {item.calls}회 호출</p>)}</details>:null}
  </article>;
}
