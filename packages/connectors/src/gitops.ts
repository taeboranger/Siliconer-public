import path from 'node:path';
import { parseAllDocuments } from 'yaml';
import { AppError } from '../../core/src/types.js';
type ReadFile = (path: string) => Promise<string>;
interface Rendered { images: string[]; state: 'resolved' | 'render_incomplete'; hashes: string[]; unsupported: string[]; resourceScope: ReturnType<typeof resourceScope> }
import { hash } from '../../core/src/util.js';
import {resourceScope} from '../../core/src/asset-applicability.js';

// Deliberately bounded subset: resources/bases, namespace/labels and image transforms.
// Unsupported Kustomize features make the result incomplete rather than silently succeeding.
export async function renderGitops(rootPath: string, read: ReadFile): Promise<Rendered> {
  const visited = new Set<string>(); const hashes: string[] = []; const unsupported = new Set<string>();
  let fileCount = 0; let bytes = 0;
  const allowed = new Set(['apiVersion', 'kind', 'resources', 'bases', 'images', 'namespace', 'commonLabels', 'labels', 'commonAnnotations']);
  function safe(file: string) {
    const normalized = path.posix.normalize(file);
    if (normalized === '..' || normalized.startsWith('../') || normalized.startsWith('/') || /[:\\]/.test(normalized)) throw new AppError('remote_or_unsafe_gitops_path', 422);
    return normalized;
  }
  async function parse(file: string) {
    if (++fileCount > 200) throw new AppError('gitops_graph_limit', 422);
    const text = await read(safe(file)); bytes += Buffer.byteLength(text);
    if (bytes > 8 * 1024 * 1024) throw new AppError('gitops_size_limit', 422);
    hashes.push(hash({ path: file, text }));
    const documents = parseAllDocuments(text, { uniqueKeys: true });
    return documents.map(doc => { if (doc.errors.length) throw new AppError('invalid_gitops_yaml', 422); return doc.toJS({ maxAliasCount: 0 }); });
  }
  async function directory(dir: string, depth: number): Promise<any[]> {
    if (depth > 16 || visited.size > 200) throw new AppError('gitops_graph_limit', 422);
    dir = safe(dir); if (visited.has(dir)) throw new AppError('gitops_cycle', 422); visited.add(dir);
    let manifest: any;
    for (const name of ['kustomization.yaml', 'kustomization.yml', 'Kustomization']) {
      try { [manifest] = await parse(path.posix.join(dir, name)); break; }
      catch (e) { if (!(e instanceof AppError && e.code === 'upstream_404')) throw e; }
    }
    if (!manifest || manifest.kind && manifest.kind !== 'Kustomization') throw new AppError('kustomization_missing', 422);
    for (const key of Object.keys(manifest)) if (!allowed.has(key)) unsupported.add(key);
    const docs: any[] = [];
    for (const resource of [...(manifest.resources ?? []), ...(manifest.bases ?? [])]) {
      if (typeof resource !== 'string') throw new AppError('invalid_gitops_resource');
      const target = safe(path.posix.join(dir, resource));
      if (/\.ya?ml$/i.test(target)) docs.push(...await parse(target));
      else docs.push(...await directory(target, depth + 1));
    }
    for (const image of manifest.images ?? []) {
      if (!image || typeof image.name !== 'string' || !Object.keys(image).every(k => ['name', 'newName', 'newTag', 'digest'].includes(k))) { unsupported.add('image_transform'); continue; }
      for (const doc of docs) for (const c of containers(doc)) {
        const current = String(c.image ?? '');
        const imageName = current.split('@')[0].replace(/:[^/:]+$/, '');
        if (imageName !== image.name) continue;
        const name = image.newName ?? imageName;
        c.image = image.digest ? `${name}@${image.digest}` : image.newTag ? `${name}:${image.newTag}` : `${name}${current.slice(imageName.length)}`;
      }
    }
    visited.delete(dir); return docs;
  }
  const docs = await directory(rootPath || '.', 0);
  const images = [...new Set(docs.flatMap(d => containers(d).map(c => c.image)).filter((s): s is string => typeof s === 'string'))];
  return { images, state: unsupported.size ? 'render_incomplete' : 'resolved', hashes, unsupported: [...unsupported],resourceScope:resourceScope(docs,!unsupported.size) };
}
function containers(doc: any): any[] {
  if (!doc) return [];
  const spec = doc.kind === 'Pod' ? doc.spec : doc.kind === 'CronJob' ? doc.spec?.jobTemplate?.spec?.template?.spec : ['Deployment','StatefulSet','DaemonSet','ReplicaSet','Job'].includes(doc.kind) ? doc.spec?.template?.spec : undefined;
  return [...(spec?.containers ?? []), ...(spec?.initContainers ?? []), ...(spec?.ephemeralContainers ?? [])];
}
