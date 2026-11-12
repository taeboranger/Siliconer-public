type Row=Record<string,any>;
export default function RuntimeAssets({data}:{data:Row}){
  const date=(value:string)=>value?new Date(value).toLocaleString('ko-KR'):'미수집';
  return <section><h2>서버 관측 정보</h2><p>호스트 OS·실행 커널과 dpkg 설치 패키지를 확인합니다. 설치 여부는 서비스 실행·외부 노출 여부와 다릅니다. 레포트 검사에서 서버를 선택하면 이 정보를 근거로 판정하고 내부 티켓을 연결합니다.</p>
    {(data.items??[]).map((r:Row)=><article className="help" key={r.id}><h3>{r.name}</h3><p>{r.stale?'수집 정보 갱신 필요':'최신 관측 정보'} · 수집 {date(r.observed_at)} · 만료 {date(r.expires_at)}</p>
      <dl><dt>운영체제</dt><dd>{r.facts.os_name??'미확인'} ({r.facts.architecture??'미확인'})</dd><dt>현재 실행 커널</dt><dd>{r.facts.kernel_release??'미확인'}</dd><dt>설치 패키지</dt><dd>{r.facts.package_inventory?`${r.facts.package_inventory.count}개 · ${r.facts.package_inventory.format} · ${r.facts.package_inventory.complete?'목록 수집 완료':'부분 수집'}`:'미수집'}</dd></dl>
      <p className="muted">조회 범위: 호스트의 dpkg 설치 목록. 컨테이너 내부, 수동 설치 바이너리, 애플리케이션 라이브러리와 서버 설정은 별도 근거가 필요합니다.</p></article>)}
    {!data.items?.length?<p>등록된 서버 수집기가 없습니다.</p>:null}
  </section>;
}
