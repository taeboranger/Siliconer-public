import { ORG, type Database } from '../../../packages/storage/src/db.js';
import { normalizeImageId, cleanText, hash } from '../../../packages/core/src/util.js';
import { GithubReader } from '../../../packages/connectors/src/github.js';
import { jsonRequest } from '../../../packages/connectors/src/http.js';
import type { ConnectorConfig } from '../../../packages/connectors/src/config.js';
import { AppError } from '../../../packages/core/src/types.js';
export interface SourceEvidence { id: string; kind: string; source: string; contentHash: string; text: string }
export function safeSourcePath(file: string) {
  if (!/^[\w@./-]+$/.test(file) || file.startsWith('/') || file.split('/').includes('..') || /(?:^|\/)(?:\.env|secrets?|credentials|node_modules|\.git)(?:\.|\/|$)/i.test(file) || !/\.(?:[cm]?[jt]sx?|json|md)$/.test(file)) throw new AppError('source_path_denied', 403);
  return file;
}
export async function buildSourceContext(db: Database, applicationId: string, target: string, codePaths: string[], config: ConnectorConfig, readerFactory = (c: any) => new GithubReader(c)) {
  const sources: SourceEvidence[] = []; const unknowns: string[] = [];
  const [snapshot] = await db.query('SELECT containers FROM snapshots WHERE application_id=$1 AND organization_id=$2 AND expires_at>now() ORDER BY observed_at DESC LIMIT 1', [applicationId, ORG]);
  const digests = [...new Set((snapshot?.containers ?? []).map((c: any) => c.digest ?? normalizeImageId(c.imageId)).filter(Boolean))];
  const sboms = digests.length ? await db.query("SELECT DISTINCT repository,commit_sha FROM sboms WHERE organization_id=$1 AND digest=ANY($2::text[]) AND provenance='verified'", [ORG,digests]) : [];
  if (sboms.length !== 1) return { sources, unknowns: ['실행 이미지와 단일 소스 커밋의 연결이 불명확하여 소스 코드를 조회하지 않았습니다.'] };
  const build = sboms[0];
  const githubConfig = config.integrations.find(c => c.kind === 'github' && c.repositories.some(r => r.name === build.repository));
  if (githubConfig?.kind !== 'github') return { sources, unknowns: ['소스 저장소를 읽을 수 있는 연동이 없습니다.'] };
  const policy = githubConfig.sourcePolicies.find(p => p.repository === build.repository);
  if (!policy?.allowCodeEgress) return { sources, unknowns: ['저장소의 코드 외부 전송 정책이 차단 상태입니다. 소스와 의존성 제약은 분석하지 않았습니다.'] };
  const github = readerFactory(githubConfig);
  async function snippet(file: string, kind: string) {
    safeSourcePath(file);
    const text = await github.file(build.repository,build.commit_sha,file);
    // Reject suspicious files entirely rather than relying only on token replacement.
    if (/(?:PRIVATE KEY-----|(?:password|secret|api[_-]?key|(?:access[_-]?)?token)['"]?\s*[:=]\s*['"]?[^\s,'"}]{8})/i.test(text)) { unknowns.push(`${file}: 민감 정보 가능성으로 제외했습니다.`); return; }
    let value: string;
    if (kind === 'dependency_constraints') {
      const manifest = JSON.parse(text);
      value = cleanText(JSON.stringify({ dependencies: manifest.dependencies, devDependencies: manifest.devDependencies, peerDependencies: manifest.peerDependencies, engines: manifest.engines }),6000);
    } else value = cleanText(text.split('\n').slice(0,100).map((line,i)=>`${i+1}: ${line}`).join('\n'),6000);
    sources.push({id:`source:${hash({repository:build.repository,commit:build.commit_sha,file,text:value})}`,kind,source:`https://github.com/${build.repository}/blob/${build.commit_sha}/${file}`,contentHash:hash(value),text:value});
  }
  try { await snippet(policy.packageManifestPath,'dependency_constraints'); } catch { unknowns.push('배포 커밋의 package.json을 읽지 못했습니다.'); }
  for (const file of codePaths.slice(0,5)) {
    if (!policy.allowedPaths.includes(file)) { unknowns.push(`${file}: 허용 파일 목록에 없어 제외했습니다.`); continue; }
    try { await snippet(file,'code_snippet'); } catch { unknowns.push(`${file}: 파일 또는 커밋 접근에 실패했습니다.`); }
  }
  if (!codePaths.length) unknowns.push('코드 사용 위치가 지정되지 않아 실제 API 호출 여부는 확인하지 않았습니다.');
  if (policy.releaseRepository) {
    try {
      const release = await jsonRequest(`https://api.github.com/repos/${policy.releaseRepository}/releases/tags/${encodeURIComponent(`${policy.releaseTagPrefix}${target}`)}`,{headers:{Accept:'application/vnd.github+json','User-Agent':'Siliconer/0.1'}});
      const text=cleanText(String(release.body ?? ''),8000);
      if (text) sources.push({id:`release:${hash(text)}`,kind:'release_notes',source:`https://github.com/${policy.releaseRepository}/releases/tag/${encodeURIComponent(`${policy.releaseTagPrefix}${target}`)}`,contentHash:hash(text),text});
      else unknowns.push('릴리스 노트 본문이 없습니다.');
    } catch { unknowns.push('설정한 공식 저장소의 릴리스 노트를 조회하지 못했습니다.'); }
  } else unknowns.push('공식 릴리스 노트 저장소가 설정되지 않았습니다.');
  return {sources,unknowns};
}
