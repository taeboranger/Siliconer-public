'use client';
import {useEffect,useState} from 'react';

type Row=Record<string,any>;
export interface AnalysisChoice {model:string;effort:string}
interface Budget {dailyCalls:number;subscriptionPercent:number}
const effortLabels:Record<string,string>={low:'낮음 · 빠르게',medium:'보통',high:'높음',xhigh:'매우 높음',max:'최대',ultra:'Ultra'};
const number=(value:number)=>Math.round(value).toLocaleString('ko-KR');
const windowName=(minutes:number)=>minutes===300?'5시간 한도':minutes===10080?'주간 한도':`${minutes}분 한도`;

export function QuotaSummary({data}:{data:Row}){
  const windows:Row[]=data.forecast?.windows??data.account?.windows??[];
  return <div className="quota-summary">
    {windows.map(window=><div className="quota-window" key={`${window.id}-${window.minutes}`}>
      <div><strong>{windowName(window.minutes)}</strong><span>사용 {window.usedPercent}% · 남음 {Math.max(0,100-window.usedPercent)}%</span></div>
      <progress value={window.usedPercent} max={100} aria-label={`${windowName(window.minutes)} 사용률`}/>
      <small>초기화 {new Date(window.resetsAt*1000).toLocaleString('ko-KR')}{windows.some(item=>item.id!==window.id)?` · ${window.name}`:''}</small>
      {window.predictedIncrease?<p className="usage-forecast">이번 분석 예상 +{window.predictedIncrease.low}–{window.predictedIncrease.high}%p</p>:data.forecast?<small className="block muted">이번 분석의 예상 한도 소모 · 산출 이력 부족</small>:null}
    </div>)}
    {!windows.length?<p className="muted">{data.account?.error?'계정 사용량을 조회하지 못했습니다. 로그인 상태를 확인하거나 다시 조회하세요.':'계정 사용량을 조회하는 중입니다. 잠시 후 새로고침해 주세요.'}</p>:null}
    {data.account?.stale&&data.account?.observedAt?<small className="muted">마지막 조회 {new Date(data.account.observedAt).toLocaleString('ko-KR')} · 갱신 대기</small>:null}
    {data.appDaily?<small className="muted">앱의 하루 모델 호출 {data.appDaily.used} / {data.appDaily.limit}회</small>:null}
    {data.budget?.subscriptionPercent<100?<small className="muted">앱의 구독 사용률 중단 기준 {data.budget.subscriptionPercent}%</small>:null}
  </div>;
}

export default function AnalysisSetup({value,onChange,request,operation='investigate',targetCount}:{
  value:AnalysisChoice|null;onChange:(choice:AnalysisChoice)=>void;request:(path:string)=>Promise<any>;
  operation?:'investigate'|'investigation-detail';targetCount?:number;
}){
  const [data,setData]=useState<Row|null>(null);
  const [error,setError]=useState('');
  const [revision,setRevision]=useState(0);
  const model=value?.model,effort=value?.effort;
  useEffect(()=>{
    if(!data?.account?.stale||data.account.error)return;
    const timer=setTimeout(()=>setRevision(value=>value+1),5000);
    return ()=>clearTimeout(timer);
  },[data]);
  useEffect(()=>{
    let active=true;
    const params=new URLSearchParams({operation});
    if(model)params.set('model',model);
    if(effort)params.set('effort',effort);
    if(targetCount)params.set('targetCount',String(targetCount));
    setError('');
    request(`analysis/options?${params}`).then(result=>{
      if(!active)return;
      setData(result);
      if(!model)onChange({model:result.defaultModel,effort:result.defaultEffort});
    }).catch(reason=>{if(active)setError(reason.message);});
    return ()=>{active=false;};
  },[request,model,effort,operation,targetCount,revision]);

  const selected=data?.models?.find((item:Row)=>item.id===model);
  const forecast=data?.forecast;
  return <section className="analysis-setup" aria-label="모델과 예상 사용량">
    <div className="analysis-setup-heading"><h3>분석 설정</h3><button type="button" className="text-button" onClick={()=>setRevision(value=>value+1)}>사용량 새로고침</button></div>
    <div className="analysis-options">
      <label>모델<select value={model??''} disabled={!data} onChange={event=>{
        const option=data?.models.find((item:Row)=>item.id===event.target.value);
        onChange({model:event.target.value,effort:option?.efforts.includes(effort)?effort!:option?.defaultEffort??'low'});
      }}>{!data?<option>모델 조회 중</option>:data.models.map((option:Row)=><option value={option.id} key={option.id}>{option.name}</option>)}</select></label>
      <label>추론 수준<select value={effort??''} disabled={!data} onChange={event=>onChange({model:model!,effort:event.target.value})}>
        {(selected?.efforts??[effort??'low']).map((item:string)=><option value={item} key={item}>{effortLabels[item]??item}</option>)}
      </select></label>
    </div>
    {error?<p className="error" role="alert">{error}</p>:null}
    {data?<>
      <div className="token-estimate"><strong>{forecast?.tokens?`예상 ${number(forecast.tokens.low)}–${number(forecast.tokens.high)} 토큰`:'예상 토큰 산출 이력 부족'}</strong>
        <small>{forecast?.sampleCount?`같은 모델·추론 수준의 과거 분석 ${forecast.sampleCount}건 기준`:'분석 이력이 쌓이면 모델별 예상치를 표시합니다.'}{operation==='investigate'&&data.targetCount?` · 대상 ${data.targetCount}개`:''}</small>
      </div>
      <QuotaSummary data={data}/>
      <small className="muted">계정 전체의 구독 사용률입니다. 작업별 예상치는 공유 계정 사용과 작업 크기에 따라 달라집니다. 토큰 총량은 계정 조회값에 제공되지 않습니다.</small>
    </>:null}
  </section>;
}

function BudgetEditor({budget,used,busy,save}:{budget:Budget;used:number;busy:boolean;save:(budget:Budget)=>Promise<void>}){
  const [dailyCalls,setDailyCalls]=useState(budget.dailyCalls);
  const [subscriptionPercent,setSubscriptionPercent]=useState(budget.subscriptionPercent);
  const unchanged=dailyCalls===budget.dailyCalls&&subscriptionPercent===budget.subscriptionPercent;
  return <form className="help" onSubmit={event=>{
    event.preventDefault();
    if(!busy&&!unchanged)void save({dailyCalls,subscriptionPercent}).catch(()=>{});
  }}>
    <h2>모델 사용 한도 설정</h2>
    <label>Siliconer 일일 호출 한도 · {dailyCalls}회
      <input type="range" min={1} max={1000} step={1} value={dailyCalls} disabled={busy}
        onChange={event=>setDailyCalls(event.target.valueAsNumber)}/>
    </label>
    <small>오늘 {used}회 사용 · 이 설정에서 {Math.max(0,dailyCalls-used)}회 남음</small>
    <label>Codex 구독 사용률 중단 기준 · {subscriptionPercent}%
      <input type="range" min={1} max={100} step={1} value={subscriptionPercent} disabled={busy}
        onChange={event=>setSubscriptionPercent(event.target.valueAsNumber)}/>
    </label>
    <small>마지막으로 조회한 5시간·주간 사용률 중 하나가 설정값에 도달하면 새 모델 호출을 멈춥니다. 100%는 Codex 자체 한도를 따릅니다.</small>
    <div className="actions"><button className="primary" type="submit" disabled={busy||unchanged}>한도 저장</button></div>
  </form>;
}

export function UsageOverview({data,busy,saveBudget}:{data:Row;busy:boolean;saveBudget:(budget:Budget)=>Promise<void>}){
  const history:Row[]=data.history??[];
  const budget=data.budget as Budget|undefined;
  return <section><QuotaSummary data={data}/>
    {budget?<BudgetEditor key={`${budget.dailyCalls}-${budget.subscriptionPercent}`} budget={budget} used={data.appDaily?.used??0} busy={busy} save={saveBudget}/>:null}
    <h2>분석별 실제 토큰 사용</h2>
    <div className="table-wrap"><table><thead><tr><th>작업</th><th>모델</th><th>추론</th><th>입력</th><th>출력</th><th>모델 호출</th></tr></thead>
      <tbody>{history.map((item,index)=><tr key={index}><td>{item.type==='investigation-detail'?'상세 분석':'1차 검사'}</td><td>{item.model}</td><td>{effortLabels[item.effort]??item.effort}</td><td>{number(item.input)}</td><td>{number(item.output)}</td><td>{item.calls}회</td></tr>)}</tbody>
    </table></div>{!history.length?<p>아직 완료된 분석 사용량이 없습니다.</p>:null}
  </section>;
}
