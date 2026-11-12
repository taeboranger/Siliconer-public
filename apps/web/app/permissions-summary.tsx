type Row=Record<string,any>;
export default function PermissionsSummary({data}:{data:Row}){
  const access=data.access??{};
  return <section className="help"><h2>현재 권한과 데이터 범위</h2>
    <div className="table-wrap"><table className="comparison-table"><thead><tr><th>대상</th><th>사용하는 권한</th></tr></thead><tbody>
      <tr><td>GitHub App</td><td>설정된 저장소 {access.repositories?.length??0}개의 Contents·Actions·Metadata 읽기. 허용한 의존성·설정 파일을 검사 근거로 사용합니다.</td></tr>
      <tr><td>Argo CD</td><td>{access.argoProjects?.length?`${access.argoProjects.join(', ')} 프로젝트의 허용 애플리케이션·배포 선언 조회`:'미연결'}</td></tr>
      <tr><td>홈서버 수집기</td><td>OS 정보·실행 커널·dpkg 설치 목록 파일 3개 읽기. 전용 토큰으로 지정 자산의 관측 정보만 제출합니다.</td></tr>
      <tr><td>모델 실행</td><td>{access.llmProvider==='codex'?`Worker의 ChatGPT 구독 로그인. 기본 ${access.llmModel}, 분석마다 모델·추론 수준 선택. 앱의 하루 호출 한도 ${access.llmDailyCalls}회.`:'Worker의 OpenAI API 자격증명과 설정된 모델 사용.'}</td></tr>
      <tr><td>구독 사용량</td><td>Worker 로그인 계정의 모델 목록, 5시간·주간 한도 사용률과 초기화 시각 조회. API·Web는 저장된 조회값과 분석별 토큰 기록을 표시합니다.</td></tr>
      <tr><td>Siliconer DB</td><td>보안 레포트 원문, 분석 설정·결과·근거·사용량과 내부 티켓 저장·조회·수정. 스키마 변경은 별도 Migrator가 담당합니다.</td></tr>
      <tr><td>Secret 공급</td><td>Vault Secrets Operator가 전용 8개 경로를 읽어 필요한 컨테이너에 공급합니다. GitHub App 키와 ChatGPT 로그인은 Worker에 보관합니다.</td></tr>
    </tbody></table></div>
    <h3>사용자 역할</h3>
    <div className="table-wrap"><table><thead><tr><th>기능</th><th>관리자</th><th>보안 검토자</th><th>개발자</th><th>조회 전용</th></tr></thead><tbody>
      <tr><td>검사·상세 분석·모델 선택</td><td>전체 대상</td><td>전체 대상</td><td>담당 서비스</td><td>저장된 결과 조회</td></tr>
      <tr><td>보안 레포트 보관함</td><td>조직 전체</td><td>조직 전체</td><td>본인이 등록하거나 검사에 사용한 레포트</td><td>조직 전체 조회</td></tr>
      <tr><td>종료된 검사 삭제</td><td>가능</td><td>—</td><td>—</td><td>—</td></tr>
      <tr><td>서버 자산·작업 상태</td><td>조회</td><td>조회</td><td>—</td><td>—</td></tr>
      <tr><td>티켓 처리</td><td>조직 전체</td><td>조직 전체</td><td>접근 가능한 티켓</td><td>조회</td></tr>
      <tr><td>분석 시작 전 사용량 확인</td><td>조직 분석 이력</td><td>조직 분석 이력</td><td>본인 분석 이력</td><td>—</td></tr>
      <tr><td>사용자 조회·생성·역할 변경·활성화 관리</td><td>가능</td><td>—</td><td>—</td><td>—</td></tr>
      <tr><td>연동·전체 사용량 관리</td><td>가능</td><td>—</td><td>—</td><td>—</td></tr>
    </tbody></table></div>
    <details className="technical-details"><summary>GitHub 저장소와 파일 전송 범위</summary>
      <ul>{access.repositories?.map((repository:string)=><li key={repository}>{repository}{access.codeEgressRepositories?.includes(repository)?' · 허용된 의존성·설정 파일을 모델에 전달':''}</li>)}</ul>
    </details>
    <p className="muted">검사 삭제는 목록에서 이력을 숨깁니다. 원문 레포트, 연결된 티켓과 감사 기록은 보관합니다. 인프라 접근은 읽기 전용으로 제한됩니다.</p>
  </section>;
}
