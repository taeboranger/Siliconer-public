import { ORG, type Database } from '../../../packages/storage/src/db.js';
import type { Component } from '../../../packages/core/src/types.js';
import { jsonRequest, type Transport } from '../../../packages/connectors/src/http.js';
import { AppError } from '../../../packages/core/src/types.js';
import { saveAdvisory } from './inventory.js';
export async function syncOsv(db: Database, transport: Transport = fetch) {
  const sboms = await db.query('SELECT components FROM sboms WHERE organization_id=$1', [ORG]);
  const packages = [...new Map(sboms.flatMap(s => s.components as Component[]).filter(c => c.ecosystem === 'npm').map(c => [`${c.name}@${c.version}`, c])).values()];
  const ids = new Set<string>();
  for (let i = 0; i < packages.length; i += 100) {
    const batch = packages.slice(i, i + 100);
    let queries: any[] = batch.map(p => ({ package: { ecosystem: 'npm', name: p.name }, version: p.version }));
    let pages = 0;
    while (queries.length) {
      if (++pages > 20) throw new AppError('osv_pagination_limit', 502);
      const data = await jsonRequest('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries }) }, transport);
      if (!Array.isArray(data.results) || data.results.length !== queries.length) throw new AppError('osv_incomplete_response', 502);
      const next: any[] = [];
      data.results.forEach((result: any, index: number) => {
        for (const vuln of result.vulns ?? []) if (typeof vuln.id === 'string' && /^[\w.-]{1,200}$/.test(vuln.id)) ids.add(vuln.id);
        if (result.next_page_token) next.push({ ...queries[index], page_token: result.next_page_token });
      });
      queries = next;
    }
  }
  // Re-fetch tracked advisories too: withdrawn records can disappear from version queries.
  for (const row of await db.query('SELECT canonical_id FROM advisories WHERE organization_id=$1', [ORG])) if (/^[\w.-]{1,200}$/.test(row.canonical_id) && !row.canonical_id.startsWith('DEMO-')) ids.add(row.canonical_id);
  for (const id of ids) await saveAdvisory(db, await jsonRequest(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {}, transport));
  return ids.size;
}
