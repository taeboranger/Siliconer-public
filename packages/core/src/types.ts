import { z } from 'zod';

export const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
export const shaSchema = z.string().regex(/^[a-f0-9]{40}$/);
export const statusSchema = z.enum(['affected', 'not_affected', 'under_investigation', 'fixed']);
export type Status = z.infer<typeof statusSchema>;
export type Role = 'admin' | 'reviewer' | 'developer' | 'viewer';
export interface Component { purl: string; ecosystem: string; name: string; version: string }
export interface Sbom {
  format: 'CycloneDX' | 'SPDX'; components: Component[]; hash: string;
  unsupported: number; complete: boolean;
}
export const advisorySchema = z.object({
  id: z.string().min(1).max(200),
  aliases: z.array(z.string().max(200)).max(100).default([]),
  modified: z.iso.datetime(), published: z.iso.datetime().optional(),
  summary: z.string().max(5000).default(''), details: z.string().max(100000).default(''),
  withdrawn: z.iso.datetime().optional(),
  affected: z.array(z.object({
    package: z.object({ ecosystem: z.string(), name: z.string(), purl: z.string().optional() }),
    versions: z.array(z.string()).default([]),
    ranges: z.array(z.object({ type: z.string(), events: z.array(z.object({
      introduced: z.string().optional(), fixed: z.string().optional(),
      last_affected: z.string().optional(), limit: z.string().optional(),
    })) })).default([]),
    database_specific: z.record(z.string(), z.unknown()).optional(),
  })).max(1000),
  references: z.array(z.object({ type: z.string(), url: z.url() })).max(100).default([]),
  database_specific: z.record(z.string(), z.unknown()).optional(),
  severity: z.array(z.object({ type: z.string(), score: z.string() })).default([]),
});
export type Advisory = z.infer<typeof advisorySchema>;
const runtimeVersionSchema=z.strictObject({
  product:z.enum(['python','java','postgresql','mysql','mariadb','redis','valkey','mongodb','nginx','apache-httpd','php','ruby','openssl','dotnet','aspnetcore']),
  version:z.string().regex(/^[0-9][0-9A-Za-z._+-]{0,49}$/),
});
export interface Observation {
  podUid: string; workloadUid: string; workloadName: string;
  namespace: string; container: string; kind: 'regular' | 'init' | 'ephemeral';
  desiredImage: string; imageId?: string; digest?: string; running: boolean;
  nodeRuntime?: {node:string;brotli:string};
  runtimeVersions?: z.infer<typeof runtimeVersionSchema>[];
}
export const observationSchema = z.object({
  podUid: z.string().min(1).max(200), workloadUid: z.string().min(1).max(200),
  workloadName: z.string().min(1).max(200), namespace: z.string().min(1).max(100),
  container: z.string().min(1).max(100), kind: z.enum(['regular', 'init', 'ephemeral']),
  desiredImage: z.string().min(1).max(1000), imageId: z.string().max(2000).optional(),
  digest: digestSchema.optional(), running: z.boolean(),
  nodeRuntime:z.strictObject({node:z.string().regex(/^\d+\.\d+\.\d+$/).max(30),brotli:z.string().regex(/^\d+\.\d+\.\d+$/).max(30)}).optional(),
  runtimeVersions:z.array(runtimeVersionSchema).max(32).optional(),
});
export const snapshotSchema = z.object({
  applicationId: z.uuid(), clusterId: z.string().min(1).max(200),
  observedAt: z.iso.datetime(), complete: z.boolean(),
  namespaces: z.array(z.string().max(100)).min(1).max(100),
  containers: z.array(observationSchema).max(10000),
});
export type Snapshot = z.infer<typeof snapshotSchema>;
export const ingestSchema = z.object({
  repository: z.string().regex(/^[\w.-]+\/[\w.-]+$/), commitSha: shaSchema,
  image: z.string().min(1).max(1000), digest: digestSchema,
  workflowRunId: z.string().regex(/^\d+$/), runAttempt: z.number().int().positive().default(1),
  sbom: z.unknown(), complete: z.boolean().default(false),
  signature: z.string().max(1000).optional(),
});

export class AppError extends Error {
  constructor(public code: string, public statusCode = 400, public detail?: string) { super(code); }
}
export const roleLevel: Record<Role, number> = { viewer: 0, developer: 1, reviewer: 2, admin: 3 };
