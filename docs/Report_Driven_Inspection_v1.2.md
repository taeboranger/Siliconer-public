# 사용자 레포트 기반 검사 v1.2

사용자 요청을 재확인하여 제품의 주 흐름을 수정한다. 이전 문서·v0.1 구현에서 npm/OSV 매칭을 제품 전체 범위처럼 다룬 것은 잘못된 해석이었다.

## 핵심 사용 흐름

1. 사용자가 보안 레포트 내용을 붙여 넣거나 텍스트 파일을 불러와 검사를 요청한다.
2. LLM이 제품·영향 버전·전제 조건·설정/코드 조건과 확인할 질문을 추출한다.
3. LLM이 읽기 전용 조회 도구를 선택하여 관련 자산을 찾고 필요한 근거를 수집한다.
4. 서비스/저장소/런타임 자산별로 영향 판단, 조건별 확인 결과, 증거 인용, 추가 검사·대응 사항을 보고한다.
5. `affected` 대상별로 내부 대응 티켓을 자동 생성·연결한다. 확인이 필요한 대상은 검사 결과에서 확인한다. 티켓 접근 권한이 있는 사용자는 메모와 처리 상태를 수정할 수 있다.

언어와 제품은 제한하지 않는다. Java/Maven, Python, Go, C/C++, Node.js, OS, DB, 웹 서버, Kubernetes에 대한 레포트를 같은 조사 흐름에 넣을 수 있다. **CVE 번호·OSV 등록·npm 패키지·SBOM은 검사 시작의 필수조건이 아니다.** OSV/npm deterministic matcher는 선택적인 보조 기능이다. 크롤러가 새로운 레포트를 자동으로 찾을 필요도 없다.

## 구현한 검사 도구

| 도구 | 역할 |
|---|---|
| `find_assets` | 권한 범위의 애플리케이션·저장소·등록된 런타임 자산을 이름/제품으로 찾음 |
| `asset_evidence` | GitOps/Argo 선언, 실행 snapshot 또는 collector가 제출한 버전·설정 사실 조회 |
| `sbom_components` | SBOM 원문의 모든 생태계 구성요소 검색. 기존 npm matcher의 필터와 독립 |
| `repository_files` | 허용된 저장소에서 commit을 고정하여 관련 파일 경로 탐색 |
| `read_repository_file` | 허용된 Java/Python/Go 코드, 의존성 manifest, Dockerfile, 설정 등의 필요한 줄 범위 읽기 |

코드 파일은 저장소별 사전 허용 범위 안에서 LLM이 직접 찾는다. 매 검사마다 사용자가 관련 파일을 일일이 지정하지 않아도 된다. GitHub 설정의 `sourcePolicies`에 `allowedPaths` 또는 `allowedPathPrefixes`를 지정하고, 조직의 외부 전송 정책에 따라 `allowCodeEgress`를 활성화한다. 기본은 차단이다.

## API와 실행

- `POST /api/v1/investigations`: `title`, `reportText`, 선택적 `referenceUrl`, `applicationIds`, `force`.
- `GET /api/v1/investigations`: 요청 및 진행 상태 목록.
- `GET /api/v1/investigations/{id}`: 추출한 검사 계획, 조회한 증거, 조건별 결과, 최종 분석, 연결된 `tickets`. 완료 결과의 `ticket_ids`도 제공한다.
- `GET /api/v1/tickets`, `PATCH /api/v1/tickets/{id}`로 티켓을 조회하고 처리 상태나 메모를 수정한다. 목록에 대응 불필요 이력을 포함하려면 `includeNonActionable=true`를 지정한다.
- `POST /api/v1/ingest/facts`: 허용된 외부 collector가 DB/OS/서비스 버전·설정 사실을 제출.

원문 URL은 출처로 저장하고 자동 방문하지 않는다. 현재 업로드 입력은 텍스트(.txt/.md/.json)다. PDF는 텍스트로 변환하거나 본문을 붙여 넣는다.

Worker에서 LLM을 활성화하고 제공자를 선택한다. `openai`는 Responses API 키와 모델·가격·예산을 사용하고, `codex`는 공식 SDK의 ChatGPT 구독 로그인과 모델·일일 호출 제한을 사용한다. API 키 또는 Codex 인증 캐시는 Worker에만 제공한다. DB migration v3(검사)·v4(티켓 연결)·v5(제공자·구독 호출 제한)가 필요하며 운영 배포에서는 migrator Job을 먼저 실행한다.

## 자동 티켓 연결

- 영향 버전 사용이 확인되면 `affected` 티켓, 버전 등 핵심 근거가 부족하면 `under_investigation` 티켓을 만든다. `not_affected`에는 새 티켓을 만들지 않는다.
- 같은 레포트 본문(양끝 공백 제외)과 같은 대상은 재검사·동시 요청에서도 같은 티켓을 사용한다. 본문을 수정한 레포트는 별도 레포트로 취급한다. 캐시 재사용은 재생성 없이 기존 티켓을 반환한다.
- 재검사는 판정·설명·영향/수정 버전·출처·인용 근거·추가 확인 사항을 갱신한다. 담당자·메모·처리 상태는 보존한다. 영향 없음으로 바뀌어도 기존 티켓의 최신 판정만 갱신하고, 자동 종결·재개하지 않는다. 이전 검사와 티켓의 연결 및 당시 판단도 유지한다.
- 검사 완료 저장·티켓 생성/갱신·연결·알림 큐 등록을 하나의 DB 트랜잭션으로 처리한다. 중간 실패 시 일부 티켓만 남기지 않는다.
- 선택적 HTTPS 알림 수신처가 설정되어 있으면 티켓 ID·판정·검사 화면 링크를 기존 알림 큐로 전송한다. GitHub Issues/Jira 등 외부 티켓 생성은 포함하지 않는다.
- 내부 티켓 생성은 기존 Siliconer DB의 DML 권한을 사용한다. 개발자의 조회 범위는 본인 검사와 서비스 권한을 따른다. 로그인한 사용자는 조회할 수 있는 티켓을 처리할 수 있다.

예를 들어 MySQL 레포트라면 GitOps의 정확한 이미지 태그·SBOM·등록된 버전으로 영향 범위를 비교할 수 있다. DB 직접 접속이나 실행 snapshot은 필수가 아니다. 버전 조건을 확인했다면 추가 설정 조건이 미확인이어도 버전 위험 티켓을 만들고 후속 확인으로 남긴다. 선언된 버전 확인과 실제 실행·악용 가능성 확인은 구분한다. `latest`, 불명확한 태그, 근거 만료 등으로 정확한 버전을 모르면 버전 확인 티켓을 만든다.

## 범위·권한·판정

- 관리자가 연결한 GitHub/Argo CD/관측 정보만 사용한다. 미연결 Linux 서버나 DB에 LLM이 임의로 SSH/SQL을 실행하지 않는다.
- 런타임 사실 인입은 `kind: facts`, `assetIds`, `allowedFactKeys`, `tokenEnv`로 허용한다. 예: MySQL의 product/version/require_secure_transport, Linux OS/version, Nginx version. 키별 허용 목록과 TTL을 검증하고 Secret·토큰·환경변수 원문은 수용하지 않는다.
- **직접 OS/DB에 접속하는 자동 collector 프로그램은 아직 포함하지 않는다.** 연결·사실 정보가 없으면 필요한 connector/확인 항목을 제시한다. 어떤 제품이든 보고서를 해석할 수 있다는 말이 모든 서버를 이미 관측할 수 있다는 뜻은 아니다.
- 저장소 선언, 이미지 빌드, 실제 실행 증거를 구분한다. source branch를 읽은 사실을 현재 운영 배포의 증거로 승격하지 않는다.
- 모델의 target ID, check ID, 인용한 evidence ID 및 소유 범위를 서버에서 검사한다. 핵심 근거 누락·만료·필수 검사 누락은 `under_investigation`으로 격하하고 임의 인용은 거부한다. 검사 계획은 버전 비교(`version`)와 추가 조건(`condition`)을 구분한다. 근거 있는 버전 판정은 실행 관측이 없다는 이유만으로 격하하지 않으며, 부가 조건 미확인은 후속 확인으로 남긴다. 부분 SBOM에서 패키지를 찾지 못한 것만으로 안전 판정하지 않도록 모델에 지시한다.
- 결과는 `llm_evidence_analysis`로 표시한다. 근거를 해석한 분석이며 익스플로잇 실행이나 완전한 안전 보증이 아니다.
- 조회는 최대 16회·모델 반복 8회로 제한한다. 입력/출력 상한과 DB의 원자적 비용 예약을 사용한다. Worker 중단·응답 불명은 자동 재과금 요청 없이 보류한다.
- 기존 인증/RBAC/감사·큐·비용·캐시·Docker/GitOps 기반을 재사용한다. API 키/관리자 권한을 LLM에 주지 않는다. 패치/PR/운영 변경 기능은 없다.

## 검증 범위

새 통합 테스트는 사용자 Java 레포트 제출 → LLM 검사 계획 → 도구로 실행 snapshot/Maven SBOM 조회 → 근거 인용 결과까지 검증한다. CVE/OSV 데이터는 준비하지 않는다. Python/RPM 구성요소 조회, Java/Python/Go 파일 조회, DB 사실 인입, 경로·권한·임의 명령 차단, 근거 없는 안전 판정 격하와 조작된 인용 거부도 검사한다.

자동 티켓 통합 테스트는 MySQL GitOps 버전으로 영향을 판단하고, 영향이 확인된 대상의 티켓을 검증한다. 강제 재검사·동시 요청의 중복 방지, 메모와 처리 상태 보존, 이전 검사 연결, 권한 회수, 실패 트랜잭션 롤백도 검사한다. 테스트의 MySQL 영향 범위는 가상 데이터다.

LLM 응답은 테스트 transport로 검증한다. 실제 운영 토큰으로 GitHub/Argo/OpenAI에 연결해 확인한 결과와 구분한다. 프론트엔드는 기존 화면에 제출 폼과 결과 표시만 추가하며 디자인·반응형 작업은 범위에서 제외한다.
