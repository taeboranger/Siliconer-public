import { z } from 'zod';
import { AppError, type Component, type Sbom } from './types.js';
import { hash } from './util.js';

export function parsePurl(purl: string): Component | undefined {
  const match = /^pkg:npm\/(.+)@([^?#]+)(?:[?#].*)?$/.exec(purl);
  if (!match) return undefined;
  try {
    const name = decodeURIComponent(match[1]);
    const version = decodeURIComponent(match[2]);
    if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name) || !version || version.length > 200) return undefined;
    return { purl: `pkg:npm/${name.startsWith('@') ? `%40${name.slice(1)}` : name}@${encodeURIComponent(version)}`, ecosystem: 'npm', name, version };
  } catch { return undefined; }
}

const record = z.record(z.string(), z.unknown());
export function parseSbom(input: unknown, declaredComplete = false): Sbom {
  const doc = record.parse(input);
  const components = new Map<string, Component>();
  let unsupported = 0;
  function add(purl: unknown) {
    const component = typeof purl === 'string' ? parsePurl(purl) : undefined;
    if (component) components.set(component.purl, component); else unsupported++;
  }
  let format: Sbom['format'];
  if (doc.bomFormat === 'CycloneDX' && typeof doc.specVersion === 'string') {
    format = 'CycloneDX';
    let visited = 0;
    function visit(items: unknown, depth = 0) {
      if (depth > 20) throw new AppError('sbom_depth_exceeded');
      if (!Array.isArray(items)) return;
      for (const item of items) {
        if (++visited > 50000) throw new AppError('sbom_component_limit');
        const c = record.parse(item);
        add(c.purl);
        visit(c.components, depth + 1);
      }
    }
    visit(doc.components);
  } else if (typeof doc.spdxVersion === 'string' && doc.spdxVersion.startsWith('SPDX-2.')) {
    format = 'SPDX';
    if (!Array.isArray(doc.packages) || doc.packages.length > 50000) throw new AppError('invalid_spdx_packages');
    for (const item of doc.packages) {
      const c = record.parse(item);
      const refs = Array.isArray(c.externalRefs) ? c.externalRefs : [];
      const ref = refs.map(r => record.parse(r)).find(r => r.referenceType === 'purl');
      add(ref?.referenceLocator);
    }
  } else throw new AppError('unsupported_sbom_format');
  return { format, components: [...components.values()], hash: hash(input), unsupported, complete: declaredComplete && unsupported === 0 && components.size > 0 };
}
