import semver from 'semver';
import type { Advisory, Component, Status } from './types.js';

export interface VersionMatch { match: 'affected' | 'not_affected' | 'unknown'; fixedVersions: string[]; reason: string }
export function matchVersion(advisory: Advisory, component: Component): VersionMatch {
  const entries = advisory.affected.filter(a => a.package.ecosystem.toLowerCase() === component.ecosystem.toLowerCase() && a.package.name === component.name);
  const fixedVersions: string[] = [];
  if (advisory.withdrawn || entries.length === 0) return { match: 'unknown', fixedVersions, reason: advisory.withdrawn ? '권고문이 철회되어 재검토가 필요합니다.' : '대상 패키지에 대한 검증된 범위가 없습니다.' };
  if (component.ecosystem !== 'npm' || !semver.valid(component.version)) return { match: 'unknown', fixedVersions, reason: '지원하지 않는 생태계 또는 버전 형식입니다.' };
  let unknown = false; let evaluated = false; let affected = false;
  for (const entry of entries) {
    if (entry.versions.some(v => !semver.valid(v))) unknown = true;
    if (entry.versions.includes(component.version)) affected = true;
    if (entry.versions.length) evaluated = true;
    for (const range of entry.ranges) {
      if (range.type !== 'SEMVER' || range.events.length === 0) { unknown = true; continue; }
      let open = false; let introduced: string | undefined;
      for (const event of range.events) {
        if (Object.values(event).filter(v => v !== undefined).length !== 1) { unknown = true; continue; }
        if (event.introduced !== undefined) {
          if (open || (event.introduced !== '0' && !semver.valid(event.introduced))) { unknown = true; continue; }
          introduced = event.introduced; open = true;
        } else {
          const end = event.fixed ?? event.last_affected ?? event.limit;
          if (!open || !end || !semver.valid(end) || (introduced && introduced !== '0' && semver.lt(end,introduced))) { unknown = true; open = false; introduced = undefined; continue; }
          const lower = introduced === '0' || (introduced && semver.gte(component.version, introduced));
          const upper = event.last_affected ? semver.lte(component.version, end) : semver.lt(component.version, end);
          if (lower && upper) affected = true;
          if (event.fixed) fixedVersions.push(event.fixed);
          open = false; evaluated = true;
        }
      }
      if (open) { evaluated = true; if (introduced === '0' || (introduced && semver.gte(component.version, introduced))) affected = true; }
    }
  }
  const fixes = [...new Set(fixedVersions)].sort(semver.compare);
  return { match: affected ? 'affected' : unknown || !evaluated ? 'unknown' : 'not_affected', fixedVersions: fixes,
    reason: affected ? 'SBOM에서 권고문의 영향 버전 범위가 일치합니다. 공격 경로의 도달 가능성은 별도 검토가 필요합니다.' : unknown || !evaluated ? '해석하지 못한 영향 범위가 있어 안전 여부를 확정할 수 없습니다.' : '현재 버전은 확인한 권고문의 영향 범위 밖입니다.' };
}

export interface ContainerAssessment {
  status: Status; reason: string; evidenceIds: string[]; fixedVersions: string[];
}
export function aggregate(containers: ContainerAssessment[], complete: boolean, fresh: boolean): Status {
  if (!fresh) return 'under_investigation';
  if (containers.some(c => c.status === 'affected')) return 'affected';
  if (!complete || containers.length === 0 || containers.some(c => c.status === 'under_investigation')) return 'under_investigation';
  if (containers.every(c => c.status === 'fixed')) return 'fixed';
  if (containers.every(c => c.status === 'not_affected' || c.status === 'fixed')) return 'not_affected';
  return 'under_investigation';
}
