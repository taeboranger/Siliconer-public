# v0.1 구현 범위 및 검증 기록

> 이 문서는 이전 v0.1의 기록이다. 현재 주 흐름은 [사용자 레포트 기반 검사 v1.2](Report_Driven_Inspection_v1.2.md)이며, 아래 npm 제한은 보조 deterministic matcher에 해당한다. 새 LLM 조사 흐름의 대상 언어/제품 제한이 아니다.

기준일: 2026-11-10. 이 문서는 설계의 목표와 현재 코드를 구분한다.

## 구현된 흐름

| 영역 | 구현 |
|---|---|
| 실행 기반 | Node 24 / pnpm, Fastify API, 별도 Worker, Next.js Web, PostgreSQL migration/checksum/잠금, 로컬 PGlite 데모 |
| 인증·권한 | scrypt 비밀번호, DB 세션·CSRF·Origin 검사, 역할별 접근, 담당 서비스 범위, 로그인 rate limit, 감사 로그 |
| GitHub | GitHub App JWT/installation token 갱신, 선택 repo/ref/파일 조회, raw-body webhook HMAC·중복 제거, build run identity 확인 |
| Argo CD | 허용 project/application GET, 인스턴스·namespace·UID 구분, source revision 보존, inline 민감 필드 제외 |
| GitOps | 기존 Kustomize base/overlay 및 이미지 치환의 제한된 해석, 미지원 기능·override 명시, 경로/크기/alias 제한 |
| SBOM | SPDX 2.x/CycloneDX JSON, npm purl 정규화, digest/commit/hash 저장, 인입 인증과 서명·CI provenance 분리 |
| 권고문 | OSV querybatch·pagination, tracked advisory 수정/철회 재조회, CVE/GHSA alias 중복 처리와 충돌 표시, 불변 revision |
| 판정 | npm semver·prerelease·구간 비교, desired/live 분리, runtime SBOM 근거, mixed rollout/partial/zero/stale의 보수적 집계, 수동 결정 별도 이력 |
| 실행 관측 | cluster/namespace/app 범위 인입 계약, snapshot 시각·TTL·imageID/digest 충돌 검사 |
| 보고서 | Responses API JSON Schema·store:false, 없는 evidence ID 거부, metadata 우선, 명시적 파일 정책에 따른 배포 commit 소스/제약·공식 GitHub release notes 조회 |
| 비용·캐시 | DB의 원자적 일간 예약/정산, 응답 불명 비용 보류, 환경/근거/정책/모델·프롬프트를 포함하는 캐시, 이전 근거 보고서 stale 표시 |
| 작업·알림 | PostgreSQL lease·SKIP LOCKED·활성 중복 방지·제한된 재시도·만료 회수, LLM lease 만료 자동 재요청 차단, 고정 HTTPS JSON webhook |
| UI | 로그인, 영향/자산/권고문/티켓/작업/연동/사용량, 검색·상태 필터·페이지 이동·근거·수동 판단·보고서·티켓 편집, 작은 화면 표 스크롤 |
| 배포 | 분리 Docker 이미지, local Compose, Kustomize/VSO·동일 Sync phase migration, 선택적 CI image publish와 config digest 갱신 |

## 현재 제한

- 첫 버전 매칭 대상은 **npm**이다. OS 배포판 백포트·다른 언어 생태계는 자동 확정하지 않는다.
- Kustomize 전체 엔진은 아니다. patches/generators/components/Helm/multi-source 및 Argo CD source override는 `render_incomplete`다. 정확한 runtime 증거가 없으면 수정 완료로 표시하지 않는다.
- OCI index↔platform manifest 동등성의 자동 검증은 아직 없다. 직접 일치하는 digest/SBOM이 없으면 unknown을 유지한다.
- K8s/호스트/독립 DB collector 프로그램은 Phase 2다. MVP에는 관측 인입과 권한 예시를 제공하며 자동 설치·임의 실행 기능은 없다.
- 중앙의 Actions artifact 자동 pull, OCI attestation 자동 발견, S3 분리 보관은 아직 없다. CI 서명 envelope 인입 경로를 구현했다. 네트워크가 닫혀 있으면 내부 전달 작업이 필요하다.
- 알림은 일반 HTTPS JSON receiver다. Slack/Discord/SMTP 전용 adapter는 없다.
- 인증은 로컬 계정 방식이다. OIDC/SSO·MFA·다중 조직 공유 설치는 이후 범위다. 설치당 한 조직, 환경별 별도 DB/자격증명을 사용한다.
- 코드 분석은 명시적으로 허용된 파일의 일부만 조회한다. 전체 코드 검색이나 API 미사용 증명, 완전한 호환성 보장은 제공하지 않는다.
- Worker는 기본 1 replica/순차 실행이다. 비용 예약은 DB에서 원자적으로 제한하지만 대규모 동시 실행·처리량은 별도 측정이 필요하다.
- LLM 청구 불명 예약의 자동 과금 대조/관리 UI 정산, 장기 증거 자동 삭제, 외부 백업 작업의 스케줄링은 포함하지 않았다. 사용량·디스크·백업은 운영자가 관리한다.

## 검증

- 실제 PostgreSQL 17 임시 스키마에서 테스트 25개: 인증·CSRF·서비스 범위, webhook HMAC/dedupe, SBOM provenance, stale/mixed rollout, alias 충돌, 버전 경계, source 정책, queue lease/재시도, LLM 예산·cache·evidence 검증.
- PGlite에서도 같은 단위/통합 테스트를 실행했다. 운영 런타임 이미지에는 PGlite를 포함하지 않는다.
- TypeScript 검사와 Next.js 프로덕션 빌드, API/Worker/CLI 번들 빌드.
- API/Web Docker 이미지 빌드와 실제 Compose 기동, Web→API 로그인/로그아웃·CSRF·PostgreSQL→별도 Worker 작업 처리 smoke test.
- Kustomize overlay를 `kubectl kustomize`로 렌더링. 클러스터에 apply하지 않았다.
- Chromium 브라우저에서 로그인, 상세 조회, 티켓 편집/저장, 상세 닫기, 작은 화면(390px) 표 스크롤과 문서 가로 overflow를 확인했다. 실제 모바일 기기 검증은 아니다.

외부 GitHub App·운영 Argo CD·OpenAI 유료 API에 실제 토큰으로 연결하지 않았다. 해당 어댑터의 통신 계약/실패는 테스트 transport로 검증했다. 운영 Vault/CNI/Argo RBAC와 실제 데이터의 완전성은 연동 시 확인해야 한다. 운영 배포, DNS 변경, 외부 저장소 push를 수행하지 않았다.
