import { readFile } from 'node:fs/promises';
import { z } from 'zod';
const envName = z.string().regex(/^[A-Z][A-Z0-9_]*$/);
const repo = z.string().regex(/^[\w.-]+\/[\w.-]+$/);
const base = { id: z.string().regex(/^[a-z0-9-]{1,80}$/), name: z.string().min(1).max(100) };
export const githubConfig = z.object({ ...base, kind: z.literal('github'), appId: z.string(), installationId: z.number().int().positive(),
  privateKeyFileEnv: envName, webhookSecretEnv: envName.optional(),
  repositories: z.array(z.object({ name: repo, kind: z.enum(['source', 'gitops']), ref: z.string().default('main') })).min(1).max(100),
  sourcePolicies: z.array(z.object({ repository: repo, allowCodeEgress: z.boolean().default(false), allowedPaths: z.array(z.string().max(300)).max(20).default([]),
    allowedDependencyFiles:z.boolean().default(false),
    applicationBindings:z.array(z.object({integrationId:z.string(),applicationName:z.string().min(1),imageRepository:z.string().min(1).optional()})).max(100).default([]),
    allowedPathPrefixes: z.array(z.string().regex(/^(?!\/)(?!.*\.\.)(?!.*\\)[\w./-]+\/$/)).max(20).default([]),
    packageManifestPath: z.string().max(300).default('package.json'), releaseRepository: repo.optional(), releaseTagPrefix: z.string().max(50).default('v'),
  })).default([]),
});
export const argoConfig = z.object({ ...base, kind: z.literal('argocd'), url: z.url().refine(s => ['https:','http:'].includes(new URL(s).protocol) && !new URL(s).username && !new URL(s).password),
  allowInsecureClusterHttp:z.boolean().default(false),
  tokenEnv: envName, projects: z.array(z.string().min(1)).min(1), applications: z.array(z.string()).default([]),
  githubIntegrationId: z.string().optional(), clusterId: z.string(), environment: z.string().default('prod'),
}).refine(c=>new URL(c.url).protocol==='https:'||(c.allowInsecureClusterHttp&&/^[a-z0-9-]+\.[a-z0-9-]+\.svc(?:\.cluster\.local)?$/.test(new URL(c.url).hostname)),{message:'HTTP requires explicit opt-in and a cluster-local Kubernetes service hostname'});
export const ingestConfig = z.object({ ...base, kind: z.literal('ingest'), tokenEnv: envName, repositories: z.array(repo).min(1),
  githubIntegrationId: z.string().optional(), workflowPath: z.string().optional(), allowedRefs: z.array(z.string()).default(['main']),
  publicKeyFileEnv: envName.optional(),
});
export const collectorConfig = z.object({ ...base, kind: z.literal('collector'), tokenEnv: envName, clusterId: z.string(), namespaces: z.array(z.string()).min(1), applicationIds: z.array(z.uuid()).min(1),
  bindings:z.array(z.strictObject({applicationId:z.uuid(),namespace:z.string().min(1).max(100)})).max(100).optional(),
  imagePlatform:z.literal('linux/amd64').optional(),
  nodeRuntimeProbe:z.boolean().optional(),
  runtimeVersionProbe:z.boolean().optional(),
});
export const factsConfig=z.object({...base,kind:z.literal('facts'),tokenEnv:envName,assetIds:z.array(z.string().min(1).max(200)).min(1),allowedFactKeys:z.array(z.string().regex(/^[\w.-]{1,100}$/)).min(1).max(100),assetScope:z.literal('host_system').optional()});
export const integrationSchema = z.discriminatedUnion('kind', [githubConfig, argoConfig, ingestConfig, collectorConfig,factsConfig]);
export type Integration = z.infer<typeof integrationSchema>;
export type GithubConfig = z.infer<typeof githubConfig>;
export type ArgoConfig = z.infer<typeof argoConfig>;
export type IngestConfig = z.infer<typeof ingestConfig>;
const pinnedImage = z.string().regex(/^[\w./:-]+@sha256:[a-f0-9]{64}$/);
const dockerRecipe = z.strictObject({
  application: z.string().min(1), argoIntegration: z.string().min(1), repository: repo,
  dockerfile: z.string().regex(/^(?:[\w-]+\/)*Dockerfile(?:\.[\w-]+)?$/),
  from: z.string().regex(/^[\w./:@-]+$/), replacement: pinnedImage,
  affectedRange: z.string().min(1).max(200), verifiedReplacementBrotli: z.string().min(1).max(40),
  nodeBackport: z.strictObject({
    cve:z.literal('CVE-2026-111497'),
    verifiedReplacementNode:z.string().regex(/^\d+\.\d+\.\d+$/),
    declaredImage:z.strictObject({
      reference:z.string().regex(/^[\w./:-]+:[a-f0-9]{40}$/),
      digest:z.string().regex(/^sha256:[a-f0-9]{64}$/),
    }).optional(),
    updateAllMatchingStages:z.boolean().optional(),
  }).optional(),
  gitops: z.strictObject({
    repository: repo,
    path: z.string().regex(/^(?:[\w-]+\/)*kustomization\.ya?ml$/),
    imageRepository: z.string().regex(/^[\w./:-]+$/),
  }).optional(),
});
export const configSchema = z.object({ integrations: z.array(integrationSchema).max(100).default([]), osv: z.boolean().default(false),
  remediation: z.strictObject({appId:z.string().regex(/^\d+$/),installationId:z.number().int().positive(),
    privateKeyFileEnv:envName, recipes:z.array(dockerRecipe).max(20)}).optional(),
  pollSeconds: z.number().int().min(60).max(86400).default(300), evidenceTtlSeconds: z.number().int().min(60).max(86400).default(900),
}).superRefine((value, ctx) => {
  const ids = value.integrations.map(i => i.id);
  if (new Set(ids).size !== ids.length) ctx.addIssue({ code: 'custom', message: 'Duplicate integration id' });
  for (const i of value.integrations) {
    if ((i.kind === 'argocd' || i.kind === 'ingest') && i.githubIntegrationId && !value.integrations.some(g => g.id === i.githubIntegrationId && g.kind === 'github'))
      ctx.addIssue({ code: 'custom', message: 'Unknown GitHub integration reference' });
  }
});
export type ConnectorConfig = z.infer<typeof configSchema>;
export async function loadConnectorConfig(path?: string): Promise<ConnectorConfig> {
  if (!path) return configSchema.parse({});
  return configSchema.parse(JSON.parse(await readFile(path, 'utf8')));
}
export function secret(name: string): string {
  const value = process.env[name];
  if (!value || value.length < 8) throw new Error('credential_missing');
  return value;
}
