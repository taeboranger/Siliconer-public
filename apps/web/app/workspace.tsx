'use client';
import { useCallback, useDeferredValue, useEffect, useRef, useState, type FormEvent } from 'react';
import InspectionPanel from './inspection-panel';
import TicketDetail from './ticket-detail';
import PermissionsSummary from './permissions-summary';
import RuntimeAssets from './runtime-assets';
import ReportLibrary from './report-library';
import UserManagement from './user-management';
import {UsageOverview} from './analysis-setup';
import CodexAccountSettings from './codex-account-settings';
import {collectionSummary,responseSummary} from '../../../packages/core/src/presentation';

type Row = Record<string, any>;
type Tab = 'investigations' | 'security-reports' | 'assets' | 'runtime-assets' | 'tickets' | 'jobs' | 'integrations' | 'usage/llm' | 'users';
interface Session { user: { id: string; email: string; role: string }; csrf: string; demo: boolean; llmEnabled?: boolean }
const labels: Record<string, string> = { affected: '영향 확인', not_affected: '영향 없음', under_investigation: '확인 필요', fixed: '수정 확인',
  open: '미처리', in_progress: '처리 중', blocked: '보류', resolved: '종결', queued: '대기', running: '실행 중', succeeded: '완료', failed: '실패',
  connected: '연결됨', pending: '미연결', error: '오류', demo: '데모', high: '높음', medium: '보통', low: '낮음', critical: '긴급', unknown: '미확인' };
const errors: Record<string, string> = { invalid_credentials: '이메일 또는 비밀번호를 확인하세요.', permission_denied: '이 작업을 수행할 권한이 없습니다.', service_scope_denied: '배정된 서비스에만 접근할 수 있습니다.',
  csrf_rejected: '세션을 새로고침한 뒤 다시 시도하세요.', authentication_required: '로그인이 필요합니다.', llm_disabled: 'LLM 분석이 비활성화되어 있습니다.', llm_budget_exceeded: '분석 예산을 초과했습니다.',
  invalid_request: '입력값을 확인하세요.', internal_error: '서버에서 처리하지 못했습니다. 작업 상태와 서버 설정을 확인하세요.', rate_limited: '요청이 많습니다. 잠시 후 다시 시도하세요.',
  evidence_stale: '근거가 만료되었습니다. 먼저 동기화와 재검사를 실행하세요.', inspection_in_progress:'진행 중인 검사는 삭제할 수 없습니다. 작업이 종료된 뒤 다시 시도하세요.', investigation_not_found:'삭제됐거나 존재하지 않는 검사 결과입니다.', network_error: '서버에 연결할 수 없습니다. API 실행 상태를 확인하세요.' };
errors.model_not_available='선택한 모델 또는 추론 수준을 현재 계정에서 사용할 수 없습니다. 모델 목록을 새로고침하세요.';
errors.email_already_registered='이미 등록된 이메일입니다.';
errors.own_account_change_denied='본인 계정의 역할이나 상태는 변경할 수 없습니다.';
errors.user_not_found='사용자 계정을 찾을 수 없습니다.';
errors.security_report_not_found='보안 레포트를 찾을 수 없거나 접근 권한이 없습니다.';
async function api(path: string, options: RequestInit = {}, csrf?: string) {
  let response: Response;
  try { response = await fetch(`/api/v1/${path}`, { ...options, cache: 'no-store', headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...options.headers } }); }
  catch (e) { if ((e as Error).name === 'AbortError') throw e; throw new Error(errors.network_error); }
  let body: any; try { body = await response.json(); } catch { throw new Error(errors.network_error); }
  if (!response.ok) { const code = body.error?.code ?? 'internal_error'; const error = new Error(errors[code] ?? `요청을 처리하지 못했습니다 (${code}).`); (error as any).status = response.status; throw error; }
  return body;
}
errors.codex_account_switch_in_progress='이미 진행 중인 계정 변경이 있습니다.';
errors.codex_account_switch_not_active='변경 요청이 이미 종료됐습니다. 새로고침해 확인하세요.';
errors.codex_account_switch_unavailable='Codex 연동 계정 변경을 사용할 수 없는 환경입니다.';
const date = (value: unknown) => value ? new Date(String(value)).toLocaleString('ko-KR', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '미수집';
function Badge({ value }: { value: string }) { return <span className={`badge badge-${value}`}>{labels[value] ?? value}</span>; }
function Empty({ children }: { children: React.ReactNode }) { return <div className="empty">{children}</div>; }

const jobKinds: Record<string,string> = {
  investigate:'레포트 1차 검사', 'investigation-detail':'자산 상세 분석', sync:'연동 동기화',
  'model-account':'모델·구독 사용량 갱신',
  'codex-account-switch':'Codex 연동 계정 변경',
  remediate:'보안 수정 PR 준비',
  'remediate-gitops':'GitOps 배포 PR 준비',
  notify:'티켓 알림', report:'패치 영향 분석',
};
const jobStates: Record<string,string> = {queued:'대기 중',running:'진행 중',succeeded:'완료',blocked:'중단됨',failed:'실패'};
const jobErrors: Record<string,string> = {
  codex_request_timeout:'모델 응답 시간이 초과됐습니다.', codex_login_required:'Worker의 ChatGPT 로그인 확인이 필요합니다.',
  codex_usage_limit:'ChatGPT/Codex 사용 한도에 도달했습니다.', llm_call_limit:'Siliconer의 일일 모델 호출 한도에 도달했습니다.',
  llm_subscription_budget_reached:'관리자가 설정한 Codex 구독 사용률 기준에 도달했습니다.',
  codex_connection_failed:'모델 응답 연결이 끊어졌습니다.', codex_request_uncertain:'모델 요청의 완료 여부를 확인하지 못했습니다.',
  llm_request_uncertain:'모델 요청의 완료 여부를 확인하지 못했습니다.', llm_invalid_output:'모델 응답 형식이 올바르지 않습니다.',
  evidence_changed:'검사 도중 수집 근거가 바뀌었습니다.', inspection_scope_denied:'검사 대상에 대한 접근 권한이 바뀌었습니다.',
};

function JobTable({items,loading,filtered,openInvestigation}:{items:Row[];loading:boolean;filtered:boolean;openInvestigation:(id:string)=>void}){
  return <div className="table-wrap" aria-busy={loading}><table>
    <thead><tr><th>작업</th><th>대상</th><th>상태</th><th>요청 시각</th><th>최근 갱신</th></tr></thead>
    <tbody>{items.map(row=>{
      const message=row.error_code&&(jobErrors[row.error_code]??'작업을 처리하는 중 오류가 발생했습니다.');
      return <tr key={row.id}>
        <td>{jobKinds[row.type]??row.type}</td>
        <td className="cell-summary">{row.investigation_id?<button className="text-button ticket-title" onClick={()=>openInvestigation(row.investigation_id)}>{row.title}</button>:row.title??'—'}{row.target_name?<small className="block muted">{row.target_name}</small>:null}</td>
        <td><span className={`badge badge-${row.state}`}>{jobStates[row.state]??row.state}</span>
          {row.stage?<small className="block muted">{row.stage}</small>:null}
          {row.attempt>1?<small className="block muted">{row.attempt}번째 시도</small>:null}
          {message?<details><summary>{message}</summary><code>{row.error_code}</code></details>:null}
        </td>
        <td>{date(row.created_at)}</td><td>{date(row.updated_at)}</td>
      </tr>;
    })}</tbody>
  </table>{!loading&&!items.length?<Empty>{filtered?'이 상태의 작업이 없습니다.':'등록된 작업이 없습니다.'}</Empty>:null}</div>;
}

export default function Workspace({ demo,initialInvestigationId='' }: { demo: boolean;initialInvestigationId?:string }) {
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  const [requestedTab, setTab] = useState<Tab>('investigations');
  const tab = requestedTab === 'users' && session?.user.role !== 'admin' ? 'investigations' : requestedTab;
  const inspectionId=initialInvestigationId;
  const [integrationErrors,setIntegrationErrors]=useState(0);
  useEffect(()=>{
    const params=new URLSearchParams(window.location.search),id=params.get('investigation');
    if(id&&/^[a-f0-9-]{36}$/.test(id)){window.location.replace(`/investigations/${id}`);return;}
    const view=params.get('view');
    if(view&&['investigations','security-reports','assets','runtime-assets','tickets','jobs','integrations','usage/llm','users'].includes(view))setTab(view as Tab);
  },[]);
  const [data, setData] = useState<Row>({ items: [] });
  const [search, setSearch] = useState(''); const query = useDeferredValue(search);
  const [status, setStatus] = useState(''); const [jobType,setJobType]=useState('');
  const [includeNonActionable,setIncludeNonActionable]=useState(false);
  const [cursor, setCursor] = useState(''); const [previousCursors, setPreviousCursors] = useState<string[]>([]);
  const [loading, setLoading] = useState(false); const [error, setError] = useState(''); const [notice, setNotice] = useState('');
  const [revision, setRevision] = useState(0); const [selected, setSelected] = useState<{ type: 'assets' | 'tickets'; id: string } | null>(null);
  const [detail, setDetail] = useState<Row | null>(null); const [detailError, setDetailError] = useState(''); const [busy, setBusy] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const refresh = useCallback(() => setRevision(n => n + 1), []);
  useEffect(() => { let active = true; api('auth/session').then(s => { if (active) setSession(s); }).catch(() => { if (active) setSession(null); }); return () => { active = false; }; }, []);
  useEffect(() => { const timer = setInterval(() => { if (!document.hidden && session) refresh(); }, 15000); return () => clearInterval(timer); }, [session, refresh]);
  useEffect(()=>{
    if(!session)return;
    const controller=new AbortController();
    void api('summary',{signal:controller.signal}).then(stats=>setIntegrationErrors(stats.integrationErrors??0)).catch(()=>{});
    return ()=>controller.abort();
  },[session,revision]);
  useEffect(() => {
    if (!session) { setSelected(null); setData({ items: [] }); return; }
    if(initialInvestigationId){setData({revision});return;}
    const controller = new AbortController(); setLoading(true); setError('');
    const params = new URLSearchParams({ limit: '50', q: query }); if (status) params.set('status', status); if (cursor) params.set('cursor', cursor);
    if(tab==='jobs'&&jobType)params.set('type',jobType);
    if(tab==='tickets'&&includeNonActionable)params.set('includeNonActionable','true');
    api(`${tab}?${params}`, { signal: controller.signal })
      .then(setData)
      .catch(e => { if (e.name !== 'AbortError') { setError(e.message); if (e.status === 401) setSession(null); } })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [session, tab, query, status, jobType, includeNonActionable, cursor, revision,initialInvestigationId]);
  useEffect(() => {
    if (!selected) { setDetail(null); dialog.current?.close(); return; }
    if (!dialog.current?.open) dialog.current?.showModal();
    const controller = new AbortController(); setDetailError('');
    api(`${selected.type}/${selected.id}`, { signal: controller.signal }).then(setDetail).catch(e => { if (e.name !== 'AbortError') setDetailError(e.message); });
    return () => controller.abort();
  }, [selected, revision]);
  async function mutate(path: string, body: unknown = {}, method = 'POST') {
    setBusy(true); setNotice(''); setError('');
    try { const result = await api(path, { method, body: JSON.stringify(body) }, session?.csrf); refresh(); return result; }
    catch (e) { const message = (e as Error).message; setError(message); if (selected) setDetailError(message); throw e; }
    finally { setBusy(false); }
  }
  function changeTab(next: Tab) { if(initialInvestigationId){window.location.assign(next==='investigations'?'/':`/?view=${encodeURIComponent(next)}`);return;}if(tab===next)return;setTab(next); setSearch(''); setStatus(''); setJobType(''); setCursor(''); setPreviousCursors([]); setData({ items: [] }); setNotice(''); }
  function open(type: 'assets' | 'tickets', id: string) { setDetail(null); setSelected({ type, id }); }
  function openInvestigation(id:string) { window.location.assign(`/investigations/${id}`); }
  async function sync() { try { const r = await mutate('sync'); setNotice(`${r.jobIds.length}개 동기화 작업을 등록했습니다.`); } catch {} }

  if (session === undefined) return <main className="boot" aria-live="polite">Siliconer를 불러오는 중입니다.</main>;
  if (!session) return <Login demo={demo} onLogin={setSession} />;
  const admin = session.user.role === 'admin'; const reviewer = admin || session.user.role === 'reviewer';
  const tabs: { id: Tab; name: string }[] = [{ id: 'investigations', name: '레포트 검사' }, { id:'security-reports',name:'보안 레포트'}, { id: 'tickets', name: '대응 티켓' }, { id: 'assets', name: '배포 자산' }, ...(reviewer ? [{ id: 'jobs' as Tab, name: '작업 상태' }] : []), ...(admin ? [{ id: 'integrations' as Tab, name: '연동 설정' }, { id: 'usage/llm' as Tab, name: '분석 사용량' }, { id: 'users' as Tab, name: '사용자 관리' }] : [])];
  if(reviewer)tabs.splice(4,0,{id:'runtime-assets',name:'서버 자산'});
  const items: Row[] = data.items ?? [];
  return <div className="shell">
    <a className="skip" href="#main">본문으로 이동</a>
    <header className="header"><div className="brand">Siliconer <span>실리코너</span></div><div className="account"><span>{session.user.email} <small>({session.user.role})</small></span><button onClick={() => { void mutate('auth/logout').then(() => setSession(null)).catch(() => {}); }}>로그아웃</button></div></header>
    {(demo || session.demo) ? <div className="demo-banner">로컬 데모 · 가상 보안 레포트와 배포 데이터입니다. 실제 인프라에 연결되어 있지 않습니다.</div> : null}
    <div className="body"><nav className="sidebar" aria-label="주요 메뉴">{tabs.map(t => <button key={t.id} aria-current={tab === t.id ? 'page' : undefined} onClick={() => changeTab(t.id)}>{t.name}</button>)}<p>읽기 전용 인프라 분석<br />운영 변경 기능 없음</p></nav>
      <main id="main" className="main">
        {!inspectionId?<div className="page-title"><div><h1>{tabs.find(t => t.id === tab)?.name}</h1><p>{tab === 'investigations' ? '보안 레포트를 제출하고 관련 자산과 취약 조건을 검사합니다.' : tab === 'assets' ? '배포 선언과 실제 실행 상태를 구분해 확인합니다.' : tab === 'integrations' ? '연동 범위와 마지막 수집 상태를 확인합니다.' : tab === 'usage/llm' ? '분석 예산과 토큰 사용량을 확인합니다.' : tab === 'users' ? '계정을 만들고 역할과 로그인 상태를 관리합니다.' : '수집한 정보와 처리 상태를 확인합니다.'}</p></div><div className="actions"><button disabled={loading} onClick={refresh}>새로고침</button>{admin && tab !== 'users' ? <button className="primary" disabled={busy} onClick={() => void sync()}>연동 동기화</button> : null}</div></div>:null}

        {integrationErrors>0?<p className="warning">수집 오류가 있는 연동이 {integrationErrors}개 있습니다.</p>:null}
        {error ? <p className="error" role="alert">{error}</p> : null}{notice ? <p className="notice" role="status">{notice}</p> : null}
        {['security-reports','assets','tickets','jobs','users'].includes(tab) ? <div className="filters">
          {tab==='jobs'?<label>작업 종류<select value={jobType} onChange={e=>{setJobType(e.target.value);setCursor('');setPreviousCursors([]);}}><option value="">전체 작업</option>{Object.entries(jobKinds).map(([type,label])=><option key={type} value={type}>{label}</option>)}</select></label>:null}
          {tab!=='jobs'?<label className="search">검색<input value={search} placeholder={tab==='users'?'이메일':tab==='tickets'?'레포트·대상':'서비스명 또는 Namespace'} onChange={e=>{setSearch(e.target.value);setCursor('');setPreviousCursors([]);}}/></label>:null}
          {tab==='tickets'||tab==='jobs'?<label>상태<select value={status} onChange={e=>{setStatus(e.target.value);setCursor('');setPreviousCursors([]);}}><option value="">전체 상태</option>{(tab==='jobs'?['queued','running','succeeded','blocked','failed']:['open','in_progress','blocked','resolved']).map(s=><option key={s} value={s}>{tab==='jobs'?jobStates[s]:labels[s]}</option>)}</select></label>:null}
          {tab==='tickets'?<label className="ticket-history-filter"><input type="checkbox" checked={includeNonActionable} onChange={e=>{
            setIncludeNonActionable(e.target.checked);setCursor('');setPreviousCursors([]);
          }}/>대응 불필요 이력 포함</label>:null}
          <span className="result-count" aria-live="polite">{loading?'조회 중…':`${items.length}개 표시`}</span>
        </div>:null}
        {tab === 'users' ? <UserManagement users={data.items ?? []} currentUserId={session.user.id} busy={busy || loading} loading={loading}
          create={async body => { await mutate('users', body); setSearch(''); setCursor(''); setPreviousCursors([]); setNotice('계정을 생성했습니다.'); }}
          update={async (id, body) => { await mutate(`users/${id}`, body, 'PATCH'); setNotice('계정 설정을 저장했습니다.'); }}
        /> : tab === 'investigations' ? <InspectionPanel initialId={inspectionId} data={data} request={api} submit={mutate} canSubmit={session.user.role !== 'viewer'} canDelete={admin} llmEnabled={Boolean(session.llmEnabled)} busy={busy} allowRuntime={reviewer} /> : tab === 'runtime-assets' ? <RuntimeAssets data={data}/> : tab==='security-reports'?<ReportLibrary data={data} request={api} canInspect={session.user.role!=='viewer'}/> : tab === 'usage/llm' ? <>{admin&&session.llmEnabled&&data.provider==='codex'?<CodexAccountSettings request={api} submit={mutate} refresh={refresh} busy={busy}/>:null}<UsageOverview data={data} busy={busy} saveBudget={async budget=>{await mutate('usage/llm/budget',budget,'PATCH');setNotice('모델 사용 한도를 저장했습니다.');}} /></> : tab==='jobs' ? <JobTable items={items} loading={loading} filtered={Boolean(status||jobType)} openInvestigation={openInvestigation}/> : <div className="table-wrap" tabIndex={0} aria-label={`${tabs.find(t => t.id === tab)?.name} 표`} aria-busy={loading}>
          <table><thead><tr>{(tab === 'assets' ? ['서비스','Namespace','배포 상태','확인한 정보','실행 관측','수집 시각'] : tab === 'tickets' ? ['레포트','대상','대응 판단','처리 상태'] : ['연동','범위','상태','마지막 성공','관리']).map(h => <th key={h}>{h}</th>)}</tr></thead>
          <tbody>{items.map(row => <tr key={row.id}>{tab === 'assets' ? <><td><button className="text-button" onClick={() => open('assets', row.id)}>{row.name}</button><small className="muted block">{row.environment}</small></td><td>{row.namespace}</td><td>{row.sync_state}<small className="muted block">{row.health_state}</small></td><td><span title={collectionSummary(row).description}>{collectionSummary(row).label}</span></td><td>{row.runtime_observed_at && new Date(row.runtime_expires_at) > new Date() ? row.runtime_complete ? '실행 상태 수집됨' : '부분 수집' : '실행 버전 별도 확인'}</td><td>{date(row.observed_at)}</td></> : tab === 'tickets' ? <>
            <td><button className="text-button ticket-title" onClick={()=>open('tickets',row.id)}>{row.canonical_id}</button></td>
            <td>{row.application}</td>
            <td><span className={'badge badge-'+responseSummary(row.finding_status,undefined,row.context?.applicability).tone}>{responseSummary(row.finding_status,undefined,row.context?.applicability).label}</span></td>
            <td><Badge value={row.status}/></td>
          </> : <><td>{row.name}<small className="muted block">{row.kind}</small></td><td className="cell-summary">{row.scope}</td><td><Badge value={row.state} />{row.last_error ? <code className="block">{row.last_error}</code> : null}</td><td>{date(row.last_success_at)}</td><td>{['github','argocd'].includes(row.kind) && row.state !== 'demo' ? <button disabled={busy} onClick={() => { void mutate(`integrations/${row.id}/test`).then(() => setNotice('연결 확인 작업을 등록했습니다.')).catch(() => {}); }}>연결 확인</button> : '인입 전용 / 데모'}</td></>}</tr>)}</tbody></table>
          {!loading && !items.length ? <Empty>{search || status ? '조건에 맞는 항목이 없습니다.' : tab === 'integrations' ? <>아직 연동이 없습니다. 서버의 integrations.json에 대상과 Secret 참조를 설정한 뒤 재시작하세요. 비밀값은 이 화면에 입력하지 않습니다.</> : tab==='tickets'?'표시할 대응 티켓이 없습니다. 검사에서 대응이 필요한 것으로 확인되면 티켓을 만듭니다.':'아직 수집한 배포 자산이 없습니다.'}</Empty> : null}
        </div>}
        {data.nextCursor || previousCursors.length ? <div className="pagination"><button disabled={!previousCursors.length} onClick={() => { setCursor(previousCursors.at(-1) ?? ''); setPreviousCursors(previousCursors.slice(0,-1)); }}>이전</button><span>{previousCursors.length + 1} 페이지</span><button disabled={!data.nextCursor} onClick={() => { setPreviousCursors([...previousCursors,cursor]); setCursor(data.nextCursor); }}>다음</button></div> : null}
        {tab === 'integrations' ? <PermissionsSummary data={data}/> : null}
        {tab !== 'users' ? <footer>자동 판정은 수집된 범위와 관측 시점에 한정됩니다. 증거 부족·만료·수집 실패는 확인 필요로 표시합니다.</footer> : null}
      </main></div>
    <dialog ref={dialog} onClose={() => setSelected(null)} onClick={e => { if (e.target === e.currentTarget) setSelected(null); }} aria-labelledby="detail-title"><div className="detail"><div className="detail-heading"><h2 id="detail-title">{selected?.type === 'assets' ? '배포 자산 상세' : '대응 티켓'}</h2><button autoFocus onClick={() => setSelected(null)} aria-label="상세 닫기">닫기</button></div>{detailError ? <p className="error" role="alert">{detailError}</p> : null}{!selected ? null : !detail ? <p aria-live="polite">불러오는 중…</p> : selected?.type === 'tickets' ? <TicketDetail ticket={detail} busy={busy} save={body=>mutate('tickets/'+detail.id,body,'PATCH')} openInvestigation={openInvestigation}/> : <AssetDetail detail={detail} />}</div></dialog>
  </div>;
}

function Login({ demo, onLogin }: { demo: boolean; onLogin: (s: Session) => void }) {
  const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  async function submit(e: FormEvent) { e.preventDefault(); setBusy(true); setError(''); try { onLogin(await api('auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })); } catch(e) { setError((e as Error).message); } finally { setBusy(false); } }
  return <main className="login"><div className="login-box"><div className="brand">Siliconer <span>실리코너</span></div><h1>배포 보안 검토</h1><p>보안 레포트 검사 결과와 판단 근거를 확인하세요.</p>{demo ? <p className="demo-banner">로컬 데모입니다. 실제 인프라와 연결되지 않습니다.</p> : null}<form onSubmit={submit}><label>이메일<input name="email" type="email" autoComplete="username" required value={email} onChange={e => setEmail(e.target.value)} /></label><label>비밀번호<input name="password" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} /></label>{error ? <p role="alert" className="error">{error}</p> : null}<button className="primary" type="submit" disabled={busy}>{busy ? '로그인 중…' : '로그인'}</button>{demo ? <button type="button" onClick={() => { setEmail('admin@siliconer.local'); setPassword('siliconer-demo-2026'); }}>데모 계정 채우기</button> : null}</form><small>관리자가 생성한 계정으로 로그인합니다.</small></div></main>;
}

function AssetDetail({ detail: d }: { detail: Row }) { return <><h3>{d.name}</h3><dl><dt>클러스터</dt><dd>{d.cluster_id}</dd><dt>Namespace</dt><dd>{d.namespace}</dd><dt>Argo CD 프로젝트</dt><dd>{d.project}</dd><dt>상태</dt><dd>{d.sync_state} / {d.health_state}</dd></dl><section className="collection-explanation"><h3>Siliconer가 확인한 정보</h3><p><strong>{collectionSummary(d).label}</strong></p><p>{collectionSummary(d).description}</p><p className="muted">위 Synced / Healthy는 Argo CD의 배포 상태입니다. 이미지 버전 수집 범위와는 별개입니다.</p></section><h3>확인한 이미지 목록</h3><ul>{d.desired_images.map((s: string) => <li className="break" key={s}><code>{s}</code></li>)}</ul><details><summary>GitOps 출처</summary><pre>{JSON.stringify(d.source_refs,null,2)}</pre></details><h3>실행 관측</h3>{!d.snapshots.length ? <p className="notice">현재는 실제 실행 컨테이너를 별도로 수집하지 않습니다. 정확한 이미지 태그가 있으면 버전 범위 비교가 가능하며, 실행 버전 확인은 필요할 때 추가합니다.</p> : d.snapshots.slice(0,3).map((s: Row) => <div key={s.id} className="record"><p>{date(s.observed_at)} / {s.complete ? '전체 수집' : '부분 수집'}</p>{s.containers.map((c: Row) => <div className="container" key={`${c.podUid}/${c.container}`}><strong>{c.workloadName} / {c.container}</strong><span>{c.kind} / {c.running ? '실행 중' : '비실행'}</span><code className="break">{c.digest ?? c.imageId ?? 'digest 미확인'}</code></div>)}</div>)}</>; }
