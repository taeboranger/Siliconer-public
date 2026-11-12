import {useEffect,useState} from 'react';

interface AccountState {
  account:{email:string|null;plan:string|null;error:string|null}|null;
  attempt:{id:string|null;state:'queued'|'starting'|'waiting'|'completed'|'cancelled'|'failed';
    expiresAt:string;error:string|null;code:string|null;verificationUrl:string|null}|null;
}
const activeStates=['queued','starting','waiting'];

export default function CodexAccountSettings({request,submit,refresh,busy}:{
  request:(path:string,options?:RequestInit)=>Promise<AccountState>;
  submit:(path:string,body?:unknown,method?:string)=>Promise<unknown>;
  refresh:()=>void;
  busy:boolean;
}){
  const [state,setState]=useState<AccountState|null>(null);
  const [revision,setRevision]=useState(0);
  const [error,setError]=useState('');
  const attempt=state?.attempt;
  const active=attempt&&activeStates.includes(attempt.state);
  useEffect(()=>{
    const controller=new AbortController();
    let timer:ReturnType<typeof setTimeout>;
    async function load(){
      try{
        const result=await request('codex/account',{signal:controller.signal});
        if(controller.signal.aborted)return;
        setState(result);
        setError('');
        if(result.attempt&&activeStates.includes(result.attempt.state))timer=setTimeout(load,2500);
      }catch(reason){
        if(!controller.signal.aborted)setError((reason as Error).message);
      }
    }
    void load();
    return ()=>{controller.abort();clearTimeout(timer);};
  },[request,revision]);
  const changedId=attempt?.state==='completed'?attempt.id:null;
  useEffect(()=>{if(changedId)refresh();},[changedId,refresh]);
  function run(path:string,method='POST'){
    void submit(path,{},method).then(()=>setRevision(value=>value+1)).catch(()=>{});
  }
  return <section className="help" aria-label="Codex 연동 계정">
    <h2>Codex 연동 계정</h2>
    <p>{state?.account?.email?<><strong>{state.account.email}</strong>{state.account.plan?<> · {state.account.plan}</>:null}</>:
      state?'연동 계정 정보를 확인하지 못했습니다.':'연동 계정을 조회하는 중입니다.'}</p>
    {error?<p role="alert">{error} <button type="button" onClick={()=>setRevision(value=>value+1)}>다시 조회</button></p>:null}
    {attempt?.state==='queued'?<p role="status">현재 작업이 끝나면 로그인 코드를 요청합니다.</p>:null}
    {attempt?.state==='starting'?<p role="status">로그인 코드를 요청하는 중입니다.</p>:null}
    {attempt?.state==='waiting'&&attempt.code&&attempt.verificationUrl?<div>
      <p>연결할 ChatGPT 계정으로 로그인해 아래 코드를 입력하세요.</p>
      <p><code>{attempt.code}</code> · {new Date(attempt.expiresAt).toLocaleTimeString('ko-KR')}까지</p>
      <a href={attempt.verificationUrl} target="_blank" rel="noreferrer">OpenAI 기기 인증 페이지 열기 ↗</a>
    </div>:attempt?.state==='waiting'?<p role="status">다른 관리자가 계정을 변경하는 중입니다.</p>:null}
    {attempt?.state==='completed'?<p role="status">새 Codex 계정으로 연결됐습니다.</p>:null}
    {attempt?.state==='cancelled'?<p role="status">계정 변경을 취소했습니다.</p>:null}
    {attempt?.state==='failed'?<p role="alert">{attempt.error==='expired'?'로그인 요청이 만료됐습니다.':'로그인을 완료하지 못했습니다. ChatGPT의 기기 코드 로그인 설정을 확인해 주세요.'} 기존 계정을 계속 사용합니다.</p>:null}
    <div className="actions">
      {active&&attempt.id?<button type="button" disabled={busy} onClick={()=>run('codex/account/switch/'+attempt.id,'DELETE')}>계정 변경 취소</button>:
        <button type="button" disabled={busy||!state||Boolean(active)} onClick={()=>run('codex/account/switch')}>계정 변경</button>}
    </div>
  </section>;
}
