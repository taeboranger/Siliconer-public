# Siliconer (실리코너)

새 보안 레포트를 받으면 가장 먼저 궁금한 건 **우리 서비스도 영향을 받는지, 어디부터 고쳐야 하는지**다. Siliconer에 레포트를 넣으면 연결된 서비스와 서버를 조사해 대응이 필요한 대상과 판단 근거를 정리한다.

## 어떻게 쓰나요?

1. **보안 레포트를 등록하고 검사한다.** Siliconer가 레포트에서 영향 제품, 버전 범위, 설정 조건을 읽는다.
2. **서비스별 결과를 확인한다.** GitHub의 소스와 의존성, Argo CD의 배포 선언, Kubernetes에서 수집한 실행 이미지나 서버 패키지 정보를 대조한다. 결과에서 대응이 필요한지 먼저 보고, 필요하면 어떤 버전이나 설정이 해당했는지 상세 근거를 펼쳐 본다.
3. **팀에서 조치한다.** 대응이 필요한 것으로 확인된 대상에는 내부 티켓이 생긴다. 티켓을 볼 수 있는 팀원은 담당자 지정 없이 상태와 메모를 수정할 수 있다. 자동 수정이 설정된 경우 Siliconer가 새 브랜치에 초안 PR을 열고, 팀원이 검토한 뒤 병합한다.

예를 들어 MySQL 취약점 레포트를 넣으면 GitOps에 선언된 MySQL 이미지 버전과 레포트의 영향 범위를 비교할 수 있다. 실행 이미지 정보도 수집돼 있다면 선언된 버전과 실제 관측 정보를 구분해서 보여준다. MySQL에 직접 접속하지 않고 버전 영향을 확인할 수 있다.

## 어떤 도움이 되나요?

- **서비스마다 수동으로 뒤지는 시간을 줄인다.** 저장소, 배포 설정, 실행 이미지에서 관련 근거를 모아 한 화면에서 비교한다. Node.js 의존성뿐 아니라 Java, Python, 데이터베이스, OS 패키지 등도 연결된 근거로 검사할 수 있다.
- **조치할 곳을 먼저 찾는다.** 영향이 확인된 대상만 새 티켓을 만든다. 근거가 부족한 대상은 검사 결과에 표시하며, 확인된 영향과 구분한다.
- **팀이 같은 기록을 보고 이어서 일한다.** 보안 레포트와 검사 결과를 보관하고, 같은 레포트와 서비스를 다시 검사하면 기존 티켓에 최신 판정을 연결한다. 메모와 처리 상태는 보존한다.

검사 범위는 연결된 저장소와 수집된 배포·실행 정보에 따라 달라진다. CVE 번호나 SBOM이 없어도 레포트와 확인 가능한 근거로 검사할 수 있다. [검사 방식과 지원 범위](docs/Report_Driven_Inspection_v1.2.md)

## 빠르게 실행

Node.js 24와 pnpm 11.25.0을 사용한다.

```powershell
pnpm install
pnpm demo
```

[로컬 화면](http://localhost:3000)에 접속한 뒤 **데모 계정 채우기 → 로그인**을 누른다. 데모 계정은 `admin@siliconer.local` / `siliconer-demo-2026`이고 실제 인프라에 연결하지 않는다. 가상 데이터로 취약 배포, 수정 배포, 선언만 있는 경우를 확인할 수 있다. 데이터는 `.data/demo`에 저장한다. 데모는 운영 모드에서 실행할 수 없다.

데모는 LLM을 끄므로 새 레포트 검사는 보류된다. **배포 자산**과 **대응 티켓** 화면에서 가상 데이터를 볼 수 있다. 실제 검사는 PostgreSQL 환경에서 Worker의 LLM 모델·인증·예산과 읽기 연동을 설정한 뒤 실행한다.

실제 PostgreSQL로 전체 컨테이너를 실행할 수도 있다. 아래 Compose는 **로컬 개발 전용**이며 빈 연동 설정으로 시작한다.

```powershell
docker compose --profile app up -d --build
```

웹은 [localhost:3005](http://localhost:3005), PostgreSQL은 `127.0.0.1:55432`다. 관리자 생성과 실제 연동 설정은 [실행·운영 가이드](docs/Runbook.md)를 따른다. 

## 코드 구조와 검증

```text
apps/api/src/          API, Worker, 인증, 수집·판정·리포트, CLI
apps/web/app/          Next.js 조회/검토 화면
packages/core/src/     SBOM·버전 매칭·판정 집계·입력 스키마
packages/storage/src/  PostgreSQL, 체크섬 migration, 작업 lease
packages/connectors/   GitHub App, Argo CD, 제한된 GitOps 렌더러
config/               빈 설정 및 연동 예시 (비밀값 없음)
deploy/               Dockerfile, Kustomize/VSO, 초기 관리자 예시
scripts/              개발 실행, CI SBOM 서명·업로드, 이미지 digest 갱신
tests/                도메인·인증·권한·연동·큐·LLM 비용/근거 검증
```

```powershell
pnpm check
# 위 단위/통합 검사를 실제 PostgreSQL에서도 실행
$env:SILICONER_TEST_DATABASE_URL='postgresql://siliconer:siliconer-dev-only@127.0.0.1:55432/siliconer'
pnpm test
# Compose 전체 기동 후 컨테이너 간 통신/인증/Worker 검사
pnpm test:containers
```

테스트는 기본적으로 메모리 PGlite를 쓰며 PostgreSQL URL을 지정하면 매번 고유한 임시 스키마를 생성·정리한다. 외부 GitHub/Argo CD/OpenAI 자격증명 없이 실행할 수 있다. 실제 외부 연동 성공을 대신 보증하지는 않는다.

## 연결과 배포

실제 검사를 켜려면 Worker에 모델 인증을 설정하고 검사에 필요한 저장소와 자산을 연결한다. `config/integrations.example.json`에 GitHub App, Argo CD, SBOM 제출 예제가 있다. 운영 환경의 주소, 인증 값과 배포 설정은 별도로 준비한다.

- [검사 방식과 지원 범위](docs/Report_Driven_Inspection_v1.2.md)
- [로컬 실행과 연동 설정](docs/Runbook.md)
- [구현 기록](docs/Implementation_Status.md)
