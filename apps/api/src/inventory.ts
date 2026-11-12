import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { ORG, type Database, type Queryable } from '../../../packages/storage/src/db.js';
import { advisorySchema, AppError, ingestSchema, snapshotSchema, type Advisory } from '../../../packages/core/src/types.js';
import { hash, cleanText } from '../../../packages/core/src/util.js';
import { normalizeImageId } from '../../../packages/core/src/util.js';
import { parseSbom } from '../../../packages/core/src/sbom.js';
import { enqueue } from '../../../packages/storage/src/jobs.js';
import { GithubReader,githubRepository } from '../../../packages/connectors/src/github.js';
import { listApplications } from '../../../packages/connectors/src/argocd.js';
import { renderGitops } from '../../../packages/connectors/src/gitops.js';
import type {Transport} from '../../../packages/connectors/src/http.js';
import { secret, type ConnectorConfig, type Integration, type IngestConfig } from '../../../packages/connectors/src/config.js';

export async function audit(db: Queryable, actor: string, action: string, target: string, details: unknown = {}) {
  await db.query('INSERT INTO audit_events(id,organization_id,actor,action,target,details) VALUES($1,$2,$3,$4,$5,$6)', [randomUUID(), ORG, actor, action, target, JSON.stringify(details)]);
}
export async function registerIntegrations(db: Database, config: ConnectorConfig) {
  for (const c of config.integrations) {
    const scope = c.kind === 'github' ? c.repositories.map(r => r.name).join(', ') : c.kind === 'argocd' ? c.projects.join(', ') : c.kind === 'ingest' ? c.repositories.join(', ') : c.kind==='collector' ? c.namespaces.join(', ') : c.assetIds.join(', ');
    await db.query(`INSERT INTO integrations(id,organization_id,kind,name,scope) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT(id) DO UPDATE SET name=$4,scope=$5,updated_at=now()`, [c.id, ORG, c.kind, c.name, scope]);
  }
}
export async function saveAdvisory(db: Database, input: unknown) {
  const doc = advisorySchema.parse(input); const contentHash = hash(doc);
  return db.transaction(async tx => {
    const aliases = [...new Set([doc.id, ...doc.aliases])];
    const found = await tx.query('SELECT DISTINCT advisory_id FROM advisory_aliases WHERE organization_id=$1 AND alias=ANY($2::text[])', [ORG, aliases]);
    if (found.length > 1) throw new AppError('advisory_alias_conflict', 409);
    const id = found[0]?.advisory_id ?? randomUUID();
    const [previous] = await tx.query('SELECT content_hash,modified_at FROM advisories WHERE id=$1', [id]);
    if (previous && new Date(previous.modified_at).getTime() > Date.parse(doc.modified)) return id;
    if (previous?.content_hash === contentHash) return id;
    const severity = String(doc.database_specific?.severity ?? 'unknown').toLowerCase();
    await tx.query(`INSERT INTO advisories(id,organization_id,canonical_id,summary,severity,document,content_hash,modified_at,withdrawn)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET summary=$4,severity=$5,document=$6,content_hash=$7,modified_at=$8,withdrawn=$9,updated_at=now()`,
    [id, ORG, doc.id, cleanText(doc.summary), ['critical','high','medium','low'].includes(severity) ? severity : 'unknown', JSON.stringify(doc), contentHash, doc.modified, Boolean(doc.withdrawn)]);
    for (const alias of aliases) await tx.query('INSERT INTO advisory_aliases(organization_id,alias,advisory_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [ORG, alias, id]);
    await tx.query('INSERT INTO advisory_revisions(id,advisory_id,content_hash,document) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING', [randomUUID(), id, contentHash, JSON.stringify(doc)]);
    await tx.query('UPDATE findings SET stale=true WHERE organization_id=$1 AND advisory_id=$2', [ORG, id]);
    return id;
  });
}
export async function ingestSbom(db: Database, raw: unknown, config: IngestConfig, connectors: ConnectorConfig, reader?: GithubReader) {
  const input = ingestSchema.parse(raw);
  if (!config.repositories.includes(input.repository)) throw new AppError('repository_not_allowed', 403);
  const sbom = parseSbom(input.sbom, input.complete);
  const envelope = { repository: input.repository, commitSha: input.commitSha, image: input.image, digest: input.digest, workflowRunId: input.workflowRunId, runAttempt: input.runAttempt, sbomHash: sbom.hash, complete: input.complete };
  let verified = false;
  if (config.githubIntegrationId && config.workflowPath && config.publicKeyFileEnv && input.signature) {
    const github = connectors.integrations.find(i => i.kind === 'github' && i.id === config.githubIntegrationId);
    if (github?.kind === 'github') verified = await (reader ?? new GithubReader(github)).verifyBuild(input.repository, input.workflowRunId, input.commitSha, input.runAttempt, envelope, input.signature, await readFile(secret(config.publicKeyFileEnv), 'utf8'), config.workflowPath, config.allowedRefs);
  }
  return db.transaction(async tx => {
    const [row] = await tx.query(`INSERT INTO sboms(id,organization_id,repository,commit_sha,image,digest,workflow_run_id,run_attempt,format,content_hash,raw_document,components,complete,unsupported,provenance)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(organization_id,digest,content_hash,provenance) DO UPDATE SET id=sboms.id RETURNING id`,
    [randomUUID(), ORG, input.repository, input.commitSha, input.image, input.digest, input.workflowRunId, input.runAttempt, sbom.format, sbom.hash, JSON.stringify(input.sbom), JSON.stringify(sbom.components), sbom.complete, sbom.unsupported, verified ? 'verified' : 'unverified']);
    await audit(tx, config.id, 'sbom.ingest', row.id, { provenance: verified ? 'verified' : 'unverified', digest: input.digest });
    await tx.query('UPDATE findings SET stale=true WHERE organization_id=$1', [ORG]);
    if (connectors.osv) await enqueue(tx, 'osv', {}, 'osv');
    if(verified&&connectors.remediation?.recipes.some(recipe=>recipe.repository===input.repository&&recipe.gitops)){
      const tickets=await tx.query(`SELECT DISTINCT ticket_id FROM remediation_prs WHERE organization_id=$1 AND repository=$2`,[ORG,input.repository]);
      for(const ticket of tickets)await enqueue(tx,'remediate-gitops',{ticketId:ticket.ticket_id,digest:input.digest},
        `remediate-gitops:${ticket.ticket_id}:${input.digest}`);
    }
    return { id: row.id, provenance: verified ? 'verified' : 'unverified', components: sbom.components.length, unsupported: sbom.unsupported };
  });
}
export async function ingestSnapshot(db: Database, raw: unknown, config: Extract<Integration, {kind: 'collector'}>, ttl: number) {
  const input = snapshotSchema.parse(raw);
  if(input.containers.some(c=>(c.nodeRuntime||c.runtimeVersions?.length)&&
    ((c.nodeRuntime&&!config.nodeRuntimeProbe)||(c.runtimeVersions?.length&&!config.runtimeVersionProbe)||
      !c.running||c.kind!=='regular'||!c.digest||c.digest!==normalizeImageId(c.imageId))))
    throw new AppError('collector_runtime_probe_scope_denied',403);
  if(input.containers.some(c=>c.digest && normalizeImageId(c.imageId) && c.digest!==normalizeImageId(c.imageId))) throw new AppError('conflicting_image_digest');
  if (input.clusterId !== config.clusterId || !config.applicationIds.includes(input.applicationId) || input.namespaces.some(n => !config.namespaces.includes(n)) || input.containers.some(c => !input.namespaces.includes(c.namespace))) throw new AppError('collector_scope_denied', 403);
  const [app] = await db.query('SELECT cluster_id,namespace FROM applications WHERE id=$1 AND organization_id=$2', [input.applicationId, ORG]);
  const bound=config.bindings
    ?input.namespaces.every(namespace=>config.bindings!.some(binding=>binding.applicationId===input.applicationId&&binding.namespace===namespace))
    :input.namespaces.includes(app?.namespace);
  if (!app || app.cluster_id !== input.clusterId || !bound) throw new AppError('application_scope_denied', 403);
  const age = Date.now() - Date.parse(input.observedAt);
  if (age < -30000 || age > ttl * 1000) throw new AppError('snapshot_expired');
  return db.transaction(async tx => {
    const [row] = await tx.query(`INSERT INTO snapshots(id,organization_id,application_id,cluster_id,observed_at,expires_at,complete,namespaces,containers,content_hash)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(organization_id,application_id,content_hash) DO UPDATE SET id=snapshots.id RETURNING id`,
    [randomUUID(), ORG, input.applicationId, input.clusterId, input.observedAt, new Date(Date.parse(input.observedAt) + ttl * 1000), input.complete, JSON.stringify(input.namespaces), JSON.stringify(input.containers), hash(input)]);
    await tx.query('UPDATE findings SET stale=true WHERE organization_id=$1 AND application_id=$2', [ORG, input.applicationId]);
    return { id: row.id };
  });
}
export async function syncIntegration(db: Database, config: ConnectorConfig, id: string, transport?:Transport) {
  const integration = config.integrations.find(i => i.id === id);
  if (!integration) throw new AppError('integration_not_found', 404);
  try {
    if (integration.kind === 'github') {
      const github = new GithubReader(integration);
      for (const repo of integration.repositories) {
        const revision = await github.revision(repo.name, repo.ref);
        await db.query(`INSERT INTO repositories(id,organization_id,integration_id,full_name,revision,kind,observed_at) VALUES($1,$2,$3,$4,$5,$6,now())
          ON CONFLICT(organization_id,integration_id,full_name) DO UPDATE SET revision=$5,kind=$6,observed_at=now()`, [randomUUID(), ORG, id, repo.name, revision, repo.kind]);
      }
    } else if (integration.kind === 'argocd') {
      const apps = await listApplications(integration,transport);
      const githubConfig = config.integrations.find(i => i.id === integration.githubIntegrationId && i.kind === 'github');
      const github = githubConfig?.kind==='github'?new GithubReader(githubConfig):undefined;
      for (const app of apps) {
        const sources = app.spec.sources ?? (app.spec.source ? [app.spec.source] : []);
        let renderState = sources.length === 1 ? 'resolved' : 'render_incomplete';
        const refs: any[] = []; const images: string[] = [...(app.status.summary?.images??[])];
        for (const [index, source] of sources.entries()) {
          const parsedRepository=githubRepository(source.repoURL);
          const repository=githubConfig?.kind==='github'?githubConfig.repositories.find(r=>r.name.toLowerCase()===parsedRepository?.toLowerCase())?.name??parsedRepository:parsedRepository;
          const revision = app.status.sync?.revisions?.[index] ?? (sources.length === 1 ? app.status.sync?.revision : undefined);
          const ref: any = { repository: repository ?? source.repoURL, path: source.path, requestedRevision: source.targetRevision, resolvedRevision: revision, state: 'unresolved',...(!github?{reason:'github_not_configured'}:{}) };
          if (github && githubConfig?.kind==='github' && !source.chart && !source.unsupportedOverrides && repository && /^[a-f0-9]{40}$/.test(revision ?? '') && githubConfig.repositories.some(r => r.name === repository)) {
            try {
              const rendered = await renderGitops(source.path ?? '.', file => github.file(repository, revision!, file));
              images.push(...rendered.images); ref.state = rendered.state; ref.hashes = rendered.hashes; ref.unsupported = rendered.unsupported;ref.resource_scope=rendered.resourceScope;
              if (rendered.state !== 'resolved') renderState = 'render_incomplete';
            } catch (error) { ref.error = error instanceof AppError ? error.code : 'render_failed'; renderState = 'render_incomplete'; }
          } else renderState = 'render_incomplete';
          refs.push(ref);
        }
        if(images.length&&!github)renderState='summary_only';
        if(images.length&&renderState!=='resolved')refs.push({state:'argo_summary',basis:'Argo CD status.summary.images; not a verified runtime snapshot',images:app.status.summary?.images??[]});
        await db.query(`INSERT INTO applications(id,organization_id,integration_id,external_uid,name,application_namespace,project,cluster_id,namespace,environment,source_refs,desired_images,sync_state,health_state,render_state,observed_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now()) ON CONFLICT(organization_id,integration_id,application_namespace,external_uid)
          DO UPDATE SET name=$5,project=$7,cluster_id=$8,namespace=$9,environment=$10,source_refs=$11,desired_images=$12,sync_state=$13,health_state=$14,render_state=$15,observed_at=now()`,
        [randomUUID(), ORG, id, app.metadata.uid, app.metadata.name, app.metadata.namespace, app.spec.project, integration.clusterId, app.spec.destination.namespace, integration.environment, JSON.stringify(refs), JSON.stringify([...new Set(images)]), app.status.sync?.status ?? 'Unknown', app.status.health?.status ?? 'Unknown', renderState]);
      }
      await db.query('UPDATE findings SET stale=true WHERE organization_id=$1 AND application_id IN(SELECT id FROM applications WHERE integration_id=$2)', [ORG, id]);
    } else throw new AppError('integration_push_only');
    await db.query("UPDATE integrations SET state='connected',last_success_at=now(),last_error=NULL,updated_at=now() WHERE id=$1", [id]);
  } catch (error) {
    await db.query("UPDATE integrations SET state='error',last_error=$2,updated_at=now() WHERE id=$1", [id, error instanceof AppError ? error.code : 'connector_failed']);
    throw error;
  }
}
