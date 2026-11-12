# Siliconer v0.1 실행·운영 가이드

> 현재 주 기능은 [사용자 레포트 기반 검사 v1.2](Report_Driven_Inspection_v1.2.md)다. 아래 OSV/npm 분석은 보조 기능이다. 주 검사를 사용하려면 Worker의 LLM 설정과 읽기 연동을 구성한다.

## 1. 로컬 실행

빠른 기능 확인은 `pnpm demo`를 사용한다. 데모 데이터는 실제 보안 공지가 아니며 외부 API를 호출하지 않는다. 서버를 종료하려면 실행 터미널에서 Ctrl+C를 누른다.

실제 PostgreSQL 기반 개발은 다음 순서다.

1. `docker compose up -d db`로 이 프로젝트 전용 DB를 시작한다. 기본 개발 비밀번호는 `siliconer-dev-only`, 포트는 55432이며 loopback에만 공개한다.
2. `.env.example`을 `.env`로 복사한다. `SILICONER_DATABASE_URL`의 비밀번호를 실제 로컬 DB 값으로 바꾼다. 기존 볼륨이 있으면 Compose의 비밀번호 환경변수 변경만으로 DB 비밀번호가 바뀌지 않는다.
3. `config/empty.json`을 `config/integrations.json`로 복사한다. 초기에는 빈 연동으로 실행하고 연동별 설정·자격증명을 준비한 뒤 바꾼다. 이 파일에도 토큰 원문을 넣지 않는다.
4. `.env`에 초기 `SILICONER_ADMIN_EMAIL`, `SILICONER_ADMIN_PASSWORD`를 지정한다. 비밀번호는 14자 이상이다. 운영에서는 Secret Manager의 bootstrap 경로를 사용한다.
5. `pnpm db:migrate`, `pnpm admin:create`, `pnpm dev` 순으로 실행한다. 개발 서버가 API와 Worker를 한 프로세스에서 실행한다.

별도 Worker를 띄울 때는 PostgreSQL을 사용하고 API의 `SILICONER_EMBEDDED_WORKER`를 끈다. PGlite 디렉터리는 여러 프로세스가 공유할 수 없다.

## 2. 전체 Compose 실행

```powershell
docker compose --profile app up -d --build
$env:SILICONER_ADMIN_EMAIL = Read-Host '관리자 이메일'
$env:SILICONER_ADMIN_PASSWORD = Read-Host '관리자 비밀번호 (14자 이상)' -MaskInput
docker compose --profile app run --rm -e SILICONER_ADMIN_EMAIL -e SILICONER_ADMIN_PASSWORD migrate node dist/cli.js admin
Remove-Item Env:\SILICONER_ADMIN_PASSWORD
```

[localhost:3005](http://localhost:3005)에서 로그인한다. Compose는 `config/empty.json`을 마운트하므로 실제 연동을 켜려면 API/Worker의 파일 마운트와 필요한 Secret 주입을 명시적으로 설정한다. 전체 `.env`를 모든 컨테이너에 공유하지 않는다. 이 Compose는 LLM을 끈 로컬 개발 구성이고 HTTPS 운영 배포를 대체하지 않는다.

`pnpm test:containers`는 이 로컬 DB에 임시 사용자 한 명을 만들어 로그인·프록시·작업 큐를 검사하고 삭제한다. 외부 DB에는 실행되지 않도록 host/port를 제한했다. 개발 DB 비밀번호를 바꿨다면 `SILICONER_SMOKE_DATABASE_URL`을 지정한다.

종료는 `docker compose --profile app stop`이다. 데이터 볼륨은 보존된다. `down -v` 같은 데이터 삭제 명령을 일반 종료에 사용하지 않는다.

## 3. GitHub·Argo CD 연동

`config/integrations.example.json`은 기존 개인 저장소/config 방식에 맞춘 **설명용 예시**다. 실제 App ID/installation, 앱 이름, URL, 허용 저장소로 수정한다. 홈서버/동아리는 별도 설정과 자격증명을 사용한다.

- GitHub App: 선택된 source/config repo에 `Contents:read`, `Actions:read`, Metadata만 준다. GitHub 발급 PKCS#1 PEM도 서버에서 PKCS#8로 정규화해 JWT에 사용한다. installation token은 메모리에서 갱신한다.
- `privateKeyFileEnv`에는 PEM 값이 아니라 **파일 경로가 들어 있는 환경변수 이름**을 지정한다. 예: `GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/github.pem`.
- Argo CD: 실제 AppProject의 `applications,get`만 허용한다. `projects`, `applications`는 수집 allowlist다. 전역 default role의 실효 권한은 별도로 검증한다.
- 사설 CA는 읽기 전용 CA 파일과 `NODE_EXTRA_CA_CERTS`로 주입한다. TLS 검증을 끄지 않는다.
- 연동 파일 변경 후 API/Worker를 재시작한다. 기본 폴링 주기는 5분이며 관리자 화면의 동기화·재검사로 즉시 작업을 등록할 수 있다.
- webhook은 선택 사항이다. 주소는 `/api/v1/webhooks/github/<integration-id>`, 서명 Secret은 설정의 `webhookSecretEnv`로 참조한다. 서명된 raw body와 delivery ID를 검증한다.

Kustomize는 현재 **로컬 resources/bases + images + namespace/라벨/annotation**의 이미지 추적 범위를 지원한다. patches, generators, components, Helm, multi-source 합성 등은 `render_incomplete`로 표시한다. remote base, 경로 탈출, plugin 실행은 허용하지 않는다. 이 제한은 일반 Kustomize 전체 호환을 뜻하지 않는다.

## 4. SBOM 공급 및 출처 검증

지원 입력은 CycloneDX 또는 SPDX 2.x JSON, 첫 매칭 생태계는 npm이다. OS 패키지·다른 생태계는 미지원 수집 범위로 기록하고 단순 버전 비교로 확정하지 않는다.

`POST /api/v1/ingest/sbom`에는 repo 범위 인입 토큰을 사용한다. 업로드 본문은 `repository`, 40자 `commitSha`, `image`, `sha256:...` digest, `workflowRunId`, `runAttempt`, `sbom`, `complete`, 선택적 `signature`다. 최대 10MiB다. `complete`는 npm 구성요소 범위가 완전할 때만 true로 선언한다.

토큰 인증만 통과한 자료는 **unverified**다. 검증된 빌드로 인정하려면 다음 두 조건을 모두 만족해야 한다.

1. 신뢰하는 CI의 Ed25519 키로 digest·commit·SBOM hash·workflow run/attempt·complete 선언을 서명한다. 개인 서명키는 승인된 production CI에만 보관하고 공개키만 Siliconer에 마운트한다.
2. Siliconer가 GitHub API에서 그 build run의 성공 여부, repo/head repo, SHA, branch, workflow path를 확인한다. 외부 PR/fork run은 인정하지 않는다.

`node scripts/ci-envelope.mjs sbom.json envelope.json`으로 서명한다. 필요한 환경변수는 `GITHUB_REPOSITORY`, `GITHUB_SHA`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `SILICONER_IMAGE`, `SILICONER_IMAGE_DIGEST`, `SILICONER_CI_SIGNING_KEY_FILE`, `SILICONER_SBOM_COMPLETE`다. 서명기는 CI에서 생성한 최종 이미지 SBOM을 사용해야 한다. 소스 lockfile SBOM으로 이미지 SBOM을 대체하지 않는다.

**참조한 build workflow가 성공으로 종료된 이후**에 `node scripts/upload-envelope.mjs envelope.json`을 호출한다. HTTPS endpoint와 인입 토큰은 `SILICONER_INGEST_URL`, `SILICONER_INGEST_TOKEN`으로 주입한다. 같은 build run이 아직 실행 중이면 출처 검증은 통과하지 않는다. 별도 `workflow_run: completed` 수신 작업이나 완료 후 업로드 단계를 사용한다. 서명키를 저장소 artifact에 담지 않는다.

CI가 사설 서버에 접근할 수 없다면 서명된 envelope를 CI artifact로 보존한 뒤 신뢰하는 내부 작업이 완료된 run에서 내려받아 업로드한다. **중앙의 Actions artifact 자동 다운로드는 아직 구현하지 않았다.** artifact 만료 전에 DB로 수용하고 백업한다. 현재 원본 SBOM은 PostgreSQL JSONB에 보존한다.

## 5. 실행 관측 인입

MVP는 `desired_only`로 동작할 수 있다. 실제 `fixed`에는 실행 digest가 필요하다. 선택적 collector가 보내는 주소는 `/api/v1/ingest/observations`다. Kubernetes API에 접근하는 collector 실행 프로그램의 자동 설치는 포함하지 않았다.

연동 설정에 `kind:collector`, `id/name/tokenEnv`, `clusterId`, `namespaces`, `applicationIds`를 추가한다. 자산 ID는 `/api/v1/assets`에서 조회한다. 전용 토큰은 이 클러스터·namespace·앱으로 제한된다.

```json
{
  "applicationId": "실제 앱 UUID",
  "clusterId": "home",
  "observedAt": "현재 ISO-8601 UTC 시각",
  "complete": true,
  "namespaces": ["허용 namespace"],
  "containers": [{
    "podUid": "pod-uid", "workloadUid": "workload-uid", "workloadName": "service",
    "namespace": "허용 namespace", "container": "app", "kind": "regular",
    "desiredImage": "registry/repository:tag", "imageId": "registry/repository@sha256:64자리해시",
    "digest": "sha256:64자리해시", "running": true
  }]
}
```

위 문자열은 형식 설명용이며 실제 요청에서는 유효한 UUID·시각·digest로 치환한다. 토큰은 중앙 인입용이고 K8s API projected token과 다르다. `complete`는 해당 앱의 모든 Pod/컨테이너를 성공적으로 수집했을 때만 true다. 원본 env/args/annotations/Secret은 보내지 않는다. OCI index와 child manifest digest의 자동 동등성 검증은 아직 지원하지 않으므로 일치하는 platform digest/SBOM이 없으면 확인 필요를 유지한다.

## 6. 보고서·비용·코드 정책

LLM은 기본 비활성화다. Worker에만 `OPENAI_API_KEY`를 넣고 설정에 모델 ID·입력/출력 100만 토큰당 USD 가격·일간 예산·출력 토큰 상한을 지정한다. 모델 ID는 가능하면 고정 snapshot을 사용한다. API는 키 없이 보고서 작업을 등록할 수 있다.

요청 전 PostgreSQL에서 예상 상한 비용을 원자적으로 예약하고 응답 usage로 정산한다. 캐시 입력 가격 할인은 적용하지 않는 보수적 추정이다. timeout/청구 불명 요청은 `uncertain`으로 예약을 유지하고 자동 재시도하지 않는다. 사용량 화면을 확인한 뒤 운영자가 실제 청구를 확인해 정산해야 한다. Worker는 기본 1개 작업을 순차 실행한다.

Responses는 `store:false`, 도구 미제공, JSON Schema 출력, evidence ID 검증을 사용한다. `store:false`가 전체 데이터 미보관을 보장하지는 않는다. [OpenAI 데이터 제어](https://developers.openai.com/api/docs/guides/your-data)를 확인한다.

기본 컨텍스트는 정제한 공지·버전·배포 근거다. 코드 분석을 허용하려면 GitHub 설정의 저장소별 `sourcePolicies`에서 `allowCodeEgress:true`, `allowedPaths`를 **조직 정책 승인 후** 지정한다. 요청은 그중 최대 5개 파일을 선택한다. 최신 브랜치가 아니라 검증된 실행 digest에 연결된 commit을 조회한다. 단일 커밋을 식별할 수 없으면 소스 조회를 건너뛴다.

`packageManifestPath`에서는 dependencies/peerDependencies/engines 등 허용된 제약만 추출한다. 코드 조각은 최대 첫 100줄/파일당 약 6천 자이며 비밀 가능성이 있는 파일은 제외한다. 공식 release notes를 추가하려면 `releaseRepository`와 `releaseTagPrefix`를 명시한다. 조회 대상은 고정된 GitHub API이며 LLM이 임의 URL을 방문하지 않는다. 코드 전체 검색·벡터 인덱싱은 수행하지 않는다.

## 7. K8s·VSO·기존 GitOps 배포

`deploy/kustomize`의 내용을 별도 Siliconer-config 저장소 루트로 옮기면 기존 `base/overlays/prod` 구조가 된다. placeholder 도메인·이미지·Argo CD 저장소 URL·Vault role을 실제 값으로 바꾼 뒤 검토한다. 예제의 값은 운영 환경에 맞게 설정한다.

- 기본 API/Web/Worker/migrator SA는 token 자동 마운트가 꺼져 있고 K8s RBAC 권한이 없다. 비특권 UID 10001, 읽기 전용 root filesystem을 사용한다.
- PostgreSQL은 전용 앱 DB/schema를 준비한다. migration 계정은 schema DDL, API/Worker는 필요한 테이블 DML과 schema_migrations SELECT만 준다. API/Worker에 DB owner나 관리자 kubeconfig를 주지 않는다.
- VSO는 기존 VaultConnection을 참조한다. `siliconer-prod-vso` 역할은 `siliconer-prod`의 `siliconer-vault-auth` SA에만 바인딩하고 아래 KV v2 path만 read 허용한다: `kv/data/siliconer-prod-api`, `kv/data/siliconer-prod-worker`, `kv/data/siliconer-prod-migrator`.
- API/Worker의 `database-url`은 DML 계정, migrator의 값은 별도 DDL 계정이다. Worker Secret에는 선택적 `openai-api-key`, `notification-url`이 있다. Web에는 외부 연동 Secret을 주입하지 않는다.
- connector를 실제로 켤 때는 API에 ingest/webhook 토큰과 검증용 GitHub PEM/CI 공개키, Worker에 GitHub PEM/Argo CD token을 명시적 `secretKeyRef`/읽기 전용 파일로 추가한다. JSON의 env 이름과 주입한 이름이 같아야 한다. 기본 템플릿은 빈 연동이므로 이 credential을 요구하지 않는다.
- namespace → 인증/설정 → VSO Secret → 동일 Sync phase migration hook → 앱 순서다. Job은 필수 Secret 참조로 준비를 기다리고 300초 안에 실패를 드러낸다. VSO readiness/health customization은 설치 버전에 맞춰 검증한다.
- `siliconer.example.invalid`와 TLS Secret은 placeholder다. 기존 ingress/TLS issuer·Cloudflare 경로에 맞춰 설정한다. API `/api` 경로와 Web `/` 경로를 같은 origin에 배치한다. DNS/외부 API 주소를 임의로 추정해 생성하지 않는다.
- CNI가 NetworkPolicy를 실제로 지원하는지 검증하고 ingress/DB/DNS/GitHub/OpenAI/Argo CD egress 정책을 환경별로 추가한다. 기본 템플릿은 환경을 알 수 없어 임의의 차단 정책을 포함하지 않는다.

초기 관리자는 `deploy/examples/bootstrap-admin-job.yaml`을 검토하여 일회성으로 생성한다. 계정이 이미 있으면 다시 만들지 않는다. bootstrap Secret은 운영자가 완료 후 폐기한다.

공개 저장소의 CI는 검사와 빌드를 수행한다. 이미지를 게시하고 배포 설정을 갱신하는 작업은 각 운영 환경에서 구성한다.

## 8. 알림·로그·백업

`SILICONER_NOTIFICATION_URL`은 관리자가 고정한 HTTPS JSON 수신 endpoint다. 메시지는 권고문 ID·서비스·판정·우선순위·Siliconer 링크로 제한하고 Idempotency-Key를 보낸다. 네트워크 장애 경계의 exactly-once를 보장하지 않으므로 수신 측도 키로 중복 제거해야 한다. Slack/Discord 전용 메시지 포맷 adapter는 포함하지 않았다.

일반 API/Worker는 원본 요청 body, Authorization/Cookie, upstream 오류 body를 로그에 남기지 않는다. 임의 명령·SSH·sync/배포 기능은 제공하지 않는다. 감사 로그는 내부 작업과 사용자 판단을 별도 기록한다.

DB에는 SBOM 원문·판정 근거·보고서·계정이 함께 있으므로 암호화 백업과 접근 통제를 적용한다. `pg_dump`를 전용 백업 계정으로 수행하고 별도 매체/위치에 보관한다. 복원은 격리된 PostgreSQL에서 migration checksum·원본 SBOM hash·로그인·재검사를 확인한 뒤 절체한다. 단일 노드 볼륨 스냅샷만으로 HA나 외부 백업을 대신하지 않는다. v0.1은 장기 증거 자동 삭제를 수행하지 않으므로 보존량·디스크 quota를 모니터링하고 보존 정책을 운영자가 관리한다.
