'use client';
import {useEffect,useState} from 'react';
import Link from 'next/link';
type Row=Record<string,any>;

export default function ReportLibrary({data,request,canInspect}:{data:Row;request:(path:string)=>Promise<any>;canInspect:boolean}){
  const [selected,setSelected]=useState('');
  const [report,setReport]=useState<Row|null>(null);
  const [error,setError]=useState('');
  useEffect(()=>{
    if(!selected)return;
    let active=true;setError('');setReport(null);
    request(`security-reports/${selected}`).then(value=>{if(active)setReport(value);}).catch(reason=>{if(active)setError(reason.message);});
    return ()=>{active=false;};
  },[selected,request]);
  return <section>
    <p className="muted">검사에 사용한 레포트 원문과 연결된 분석 이력</p>
    <div className="table-wrap"><table><thead><tr><th>보안 레포트</th><th>분석</th><th>저장 시각</th><th>검사</th></tr></thead>
      <tbody>{(data.items??[]).map((item:Row)=><tr key={item.id}><td><button className="text-button result-link" onClick={()=>setSelected(item.id)}>{item.title}</button></td>
        <td>{item.analysis_count}건</td><td>{new Date(item.created_at).toLocaleString('ko-KR')}</td><td>{canInspect?<a href={`/?report=${item.id}`}>새 검사</a>:null}</td></tr>)}</tbody>
    </table></div>
    {!data.items?.length?<p className="empty">검사를 시작하면 보안 레포트가 자동으로 저장됩니다.</p>:null}
    {error?<p role="alert" className="error">{error}</p>:null}
    {selected&&!report&&!error?<p role="status">레포트를 불러오는 중입니다.</p>:null}
    {report?<article className="help"><div className="section-toolbar"><h2>{report.title}</h2><button onClick={()=>{setSelected('');setReport(null);}}>닫기</button></div>
      {report.reference_url?<a href={report.reference_url} target="_blank" rel="noreferrer">원문 URL 열기</a>:null}
      <details className="technical-details"><summary>저장된 레포트 원문</summary><pre>{report.body}</pre></details>
      <h3>분석 이력</h3>{report.analyses.map((analysis:Row)=><p key={analysis.id}><Link prefetch={false} href={`/investigations/${analysis.id}`}>{analysis.title}</Link><small className="block muted">{new Date(analysis.created_at).toLocaleString('ko-KR')} · {analysis.analysis_settings?.model??'기존 모델'}</small></p>)}
    </article>:null}
  </section>;
}
