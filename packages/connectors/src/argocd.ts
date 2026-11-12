import { z } from 'zod';
import { AppError } from '../../core/src/types.js';
import { jsonRequest, type Transport } from './http.js';
import { type ArgoConfig, secret } from './config.js';
const source = z.object({ repoURL: z.string(), targetRevision: z.string().optional(), path: z.string().optional(), chart: z.string().optional(), ref: z.string().optional(),
  helm:z.unknown().optional(),kustomize:z.unknown().optional(),plugin:z.unknown().optional(),directory:z.unknown().optional(),
}).transform(({helm,kustomize,plugin,directory,...safe})=>({...safe,unsupportedOverrides:helm!==undefined || kustomize!==undefined || plugin!==undefined || directory!==undefined}));
const appSchema = z.object({
  metadata: z.object({ name: z.string(), namespace: z.string().default('argocd'), uid: z.string() }),
  spec: z.object({ project: z.string().default('default'), source: source.optional(), sources: z.array(source).optional(), destination: z.object({ namespace: z.string().default('default'), server: z.string().optional(), name: z.string().optional() }) }),
  status: z.object({ sync: z.object({ status: z.string().optional(), revision: z.string().optional(), revisions: z.array(z.string()).optional() }).optional(), health: z.object({ status: z.string().optional() }).optional(), summary:z.object({images:z.array(z.string().max(2000)).max(1000).default([])}).optional() }).default({}),
}).strip();
export async function listApplications(config: ArgoConfig, transport: Transport = fetch) {
  const apps: z.infer<typeof appSchema>[] = [];
  for (const project of config.projects) {
    const url = new URL(`${config.url.replace(/\/$/, '')}/api/v1/applications`); url.searchParams.append('projects', project);
    const data = await jsonRequest(url.toString(), { headers: { Authorization: `Bearer ${secret(config.tokenEnv)}` } }, transport);
    if (!Array.isArray(data.items)) throw new AppError('invalid_argocd_response', 502);
    for (const raw of data.items) {
      const app = appSchema.parse(raw);
      if (!config.projects.includes(app.spec.project)) continue;
      if (config.applications.length && !config.applications.includes(`${app.metadata.namespace}/${app.metadata.name}`)) continue;
      apps.push(app);
    }
  }
  return [...new Map(apps.map(app => [app.metadata.uid, app])).values()];
}
