import Fastify, { type FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { z, ZodError } from 'zod';
import { randomBytes, randomUUID } from 'node:crypto';
import { AppError, roleLevel, statusSchema, type Role } from '../../../packages/core/src/types.js';
import { hash, secureEqual } from '../../../packages/core/src/util.js';
import { ORG, SCHEMA_VERSION, type Database, type Queryable } from '../../../packages/storage/src/db.js';
import { enqueue } from '../../../packages/storage/src/jobs.js';
import type { ConnectorConfig, Integration } from '../../../packages/connectors/src/config.js';
import { secret } from '../../../packages/connectors/src/config.js';
import { verifyWebhook } from '../../../packages/connectors/src/github.js';
import { audit, ingestSbom, ingestSnapshot, saveAdvisory } from './inventory.js';
import { newSession, passwordMatches, sessionActor, createUser, type Actor } from './auth.js';
import type { Settings } from './config.js';
import {registerInvestigationRoutes} from './investigations.js';
import {ticketAccessSql} from './investigation-tickets.js';
import {analysisUsage,registerAnalysisUsageRoutes} from './analysis-usage.js';
import {registerCodexAccountSwitch} from './codex-account-switch.js';
import {readLlmBudget} from './llm-budget.js';

declare module 'fastify' { interface FastifyRequest { actor: Actor | null; rawBody: Buffer | null } }
const listSchema = z.object({ cursor: z.uuid().optional(), limit: z.coerce.number().int().min(1).max(100).default(50), q: z.string().max(200).default(''), status: z.string().max(40).optional() });
const userRole = z.enum(['admin','reviewer','developer','viewer']);
const idParam = (request: FastifyRequest) => z.object({ id: z.uuid() }).parse(request.params).id;
const effective = "CASE WHEN f.stale OR f.expires_at<now() THEN 'under_investigation' ELSE f.status END";
const ticketAssessment = `CASE WHEN t.finding_id IS NULL THEN t.assessment_status ELSE ${effective} END`;
const jobDisplay = `SELECT j.id,j.type,j.state,j.attempt,j.error_code,j.created_at,j.updated_at,
  CASE WHEN j.type IN ('investigate','investigation-detail','remediate') THEN COALESCE(i.title,'삭제되거나 찾을 수 없는 검사')
       WHEN j.type='sync' THEN COALESCE(integration.name,j.payload->>'integrationId')
       WHEN j.type='notify' THEN COALESCE(t.title,j.payload->>'title')
       WHEN j.type='report' THEN advisory.canonical_id END AS title,
  CASE WHEN j.type='investigation-detail' THEN COALESCE(target.name,j.payload->>'targetId')
       WHEN j.type='notify' THEN COALESCE(t.target_name,j.payload->>'application')
       WHEN j.type='report' THEN application.name END AS target_name,
  CASE WHEN j.type='investigate' AND j.state='running' THEN i.stage END AS stage,
  i.id AS investigation_id
  FROM job_rows j
  LEFT JOIN investigations i ON i.organization_id=j.organization_id AND i.deleted_at IS NULL
    AND i.id::text=j.payload->>'investigationId' AND j.type IN ('investigate','investigation-detail','remediate')
  LEFT JOIN integrations integration ON integration.organization_id=j.organization_id
    AND integration.id=j.payload->>'integrationId' AND j.type='sync'
  LEFT JOIN tickets t ON t.organization_id=j.organization_id AND t.id::text=j.payload->>'ticketId' AND j.type='notify'
  LEFT JOIN findings finding ON finding.organization_id=j.organization_id AND finding.id::text=j.payload->>'findingId' AND j.type='report'
  LEFT JOIN advisories advisory ON advisory.id=finding.advisory_id
  LEFT JOIN applications application ON application.id=finding.application_id
  LEFT JOIN LATERAL (SELECT item->>'target_name' AS name FROM jsonb_array_elements(i.result->'targets') item
    WHERE j.type='investigation-detail' AND item->>'target_id'=j.payload->>'targetId' LIMIT 1) target ON true`;
export async function createApp(db: Database, config: ConnectorConfig, settings: Settings, logger = false) {
  const app = Fastify({ bodyLimit: 10 * 1024 * 1024, logger: logger ? { redact: ['req.headers.authorization','req.headers.cookie','res.headers.set-cookie'], serializers: { req: (r: any) => ({ method: r.method, url: String(r.url).split('?')[0] }) } } : false, trustProxy: false });
  app.decorateRequest('actor', null); app.decorateRequest('rawBody', null);
  await app.register(cookie); await app.register(helmet); await app.register(rateLimit, { max: 120, timeWindow: '1 minute' });
  app.removeContentTypeParser('application/json');
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
    req.rawBody = body as Buffer;
    try { done(null, JSON.parse((body as Buffer).toString('utf8'))); } catch { done(new AppError('invalid_json')); }
  });
  app.addHook('onRequest', async (req, reply) => {
    reply.header('Cache-Control', 'no-store').header('X-Request-Id', req.id);
    if (req.url.startsWith('/api/v1/') && !['/api/v1/auth/login','/api/v1/ingest/','/api/v1/webhooks/'].some(p => req.url.startsWith(p))) {
      req.actor = await sessionActor(db, req.cookies.siliconer_session) ?? null;
      if (!req.actor) throw new AppError('authentication_required', 401);
      if (req.actor.role === 'developer') {
        let resourcePath:string;try{resourcePath=decodeURIComponent(req.url.split('?')[0]);}catch{throw new AppError('invalid_request',400);}
        const resource = /^\/api\/v1\/(assets|findings|tickets|impact-reports)\/([a-f0-9-]{36})(?:\/|$)/i.exec(resourcePath);
        if (resource) {
          const id = z.uuid().parse(resource[2]);
          if(resource[1]==='tickets'){
            if(!(await db.query(`SELECT 1 FROM tickets t WHERE t.id=$1 AND t.organization_id=$2 AND ${ticketAccessSql('$3::uuid')}`,[id,ORG,req.actor.id])).length)throw new AppError('service_scope_denied',403);
          }else{
            const lookup = resource[1] === 'assets' ? 'SELECT id AS application_id FROM applications WHERE id=$1 AND organization_id=$2' : resource[1] === 'findings' ? 'SELECT application_id FROM findings WHERE id=$1 AND organization_id=$2' : 'SELECT f.application_id FROM reports r JOIN findings f ON f.id=r.finding_id WHERE r.id=$1 AND r.organization_id=$2';
            const [target] = await db.query(lookup, [id, ORG]);
            if (!target || !(await db.query('SELECT 1 FROM service_owners WHERE organization_id=$1 AND user_id=$2 AND application_id=$3', [ORG, req.actor.id, target.application_id])).length) throw new AppError('service_scope_denied', 403);
          }
        }
      }
      if (!['GET','HEAD','OPTIONS'].includes(req.method)) {
        const csrf = req.headers['x-csrf-token'];
        if (req.headers.origin !== settings.baseUrl || typeof csrf !== 'string' || !secureEqual(hash(csrf), req.actor.csrf_hash)) throw new AppError('csrf_rejected', 403);
      }
    }
  });
  app.setErrorHandler((error, req, reply) => {
    const status = error instanceof AppError ? error.statusCode : error instanceof ZodError ? 400 : (error as any).statusCode ?? 500;
    const code = error instanceof AppError ? error.code : error instanceof ZodError ? 'invalid_request' : status === 429 ? 'rate_limited' : status === 413 ? 'body_too_large' : status < 500 ? 'request_rejected' : 'internal_error';
    if (status >= 500) req.log.error({ requestId: req.id, code }, 'Request failed');
    reply.code(status).send({ error: { code, requestId: req.id } });
  });
  const requireRole = (req: FastifyRequest, role: Role) => { if (!req.actor || roleLevel[req.actor.role] < roleLevel[role]) throw new AppError('permission_denied', 403); };
  async function manageUsers<T>(req: FastifyRequest, action: (tx: Queryable, actor: Actor) => Promise<T>) {
    requireRole(req, 'admin');
    const actor = req.actor!;
    return db.transaction(async tx => {
      // Serialize account changes and recheck the actor after any concurrent change.
      await tx.query('SELECT id FROM organizations WHERE id=$1 FOR NO KEY UPDATE', [ORG]);
      const [admin] = await tx.query("SELECT id FROM users WHERE organization_id=$1 AND id=$2 AND role='admin' AND disabled_at IS NULL", [ORG, actor.id]);
      if (!admin) throw new AppError('permission_denied', 403);
      return action(tx, actor);
    });
  }
  const cookies = { httpOnly: true, secure: settings.production, sameSite: 'strict' as const, path: '/', maxAge: 43200 };
  app.get('/health/live', async () => ({ status: 'ok' }));
  app.get('/health/ready', async (_req, reply) => { try { if (!(await db.query('SELECT version FROM schema_migrations WHERE version=$1',[SCHEMA_VERSION])).length) throw new Error('schema_not_ready'); return { status: 'ready' }; } catch { return reply.code(503).send({ status: 'not_ready' }); } });
  app.post('/api/v1/auth/login', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req, reply) => {
    if (req.headers.origin !== settings.baseUrl) throw new AppError('origin_rejected', 403);
    const body = z.object({ email: z.email().max(200), password: z.string().min(1).max(256) }).parse(req.body);
    const [user] = await db.query('SELECT id,password_hash FROM users WHERE email=$1 AND organization_id=$2 AND disabled_at IS NULL', [body.email.toLowerCase(), ORG]);
    const valid = await passwordMatches(body.password, user?.password_hash ?? '');
    if (!user || !valid) throw new AppError('invalid_credentials', 401);
    const { current, session } = await db.transaction(async tx => {
      const [current] = await tx.query('SELECT id,email,role FROM users WHERE id=$1 AND organization_id=$2 AND disabled_at IS NULL FOR SHARE', [user.id, ORG]);
      if (!current) throw new AppError('invalid_credentials', 401);
      const session = await newSession(tx, current.id);
      await audit(tx, current.id, 'auth.login', current.id);
      return { current, session };
    });
    reply.setCookie('siliconer_session', session.token, cookies).setCookie('siliconer_csrf', session.csrf, { ...cookies, httpOnly: false });
    return { user: current, csrf: session.csrf, demo: settings.demo, llmEnabled: settings.llm, llmProvider:settings.llmProvider };
  });
  app.get('/api/v1/auth/session', async (req, reply) => {
    let csrf = req.cookies.siliconer_csrf;
    if (!csrf || !secureEqual(hash(csrf), req.actor!.csrf_hash)) {
      csrf = randomBytes(32).toString('base64url');
      await db.query('UPDATE sessions SET csrf_hash=$2 WHERE token_hash=$1', [hash(req.cookies.siliconer_session!), hash(csrf)]);
      reply.setCookie('siliconer_csrf', csrf, { ...cookies, httpOnly: false });
    }
    return { user: { id: req.actor!.id, email: req.actor!.email, role: req.actor!.role }, csrf, demo: settings.demo, llmEnabled: settings.llm, llmProvider:settings.llmProvider };
  });
  app.post('/api/v1/auth/logout', async (req, reply) => {
    await db.query('DELETE FROM sessions WHERE token_hash=$1', [hash(req.cookies.siliconer_session!)]);
    reply.clearCookie('siliconer_session', { path: '/' }).clearCookie('siliconer_csrf', { path: '/' }); return { ok: true };
  });
  app.get('/api/v1/summary', async req => {
    const owner = req.actor!.role === 'developer' ? req.actor!.id : null;
    const [counts, assets, integrations, openTickets, jobs] = await Promise.all([
      db.query(`SELECT ${effective} AS status,count(*)::integer AS count FROM findings f WHERE organization_id=$1 AND ($2::uuid IS NULL OR EXISTS(SELECT 1 FROM service_owners o WHERE o.user_id=$2 AND o.application_id=f.application_id)) GROUP BY 1`, [ORG, owner]),
      db.query('SELECT count(*)::integer AS count FROM applications a WHERE organization_id=$1 AND ($2::uuid IS NULL OR EXISTS(SELECT 1 FROM service_owners o WHERE o.user_id=$2 AND o.application_id=a.id))', [ORG, owner]),
      db.query("SELECT count(*)::integer AS count FROM integrations WHERE organization_id=$1 AND state='error'", [ORG]),
      db.query(`SELECT count(*)::integer AS count FROM tickets t LEFT JOIN findings f ON f.id=t.finding_id
        WHERE t.organization_id=$1 AND t.status<>'resolved' AND (${ticketAssessment})='affected' AND ($2::uuid IS NULL OR ${ticketAccessSql('$2::uuid')})`, [ORG, owner]),
      db.query("SELECT count(*)::integer AS count FROM jobs WHERE organization_id=$1 AND state IN ('queued','running')", [ORG]),
    ]);
    return { counts: Object.fromEntries(counts.map(r => [r.status, r.count])), assets: assets[0].count, integrationErrors: integrations[0].count, openTickets: openTickets[0].count, pendingJobs: jobs[0].count, demo: settings.demo };
  });
  app.get('/api/v1/assets', async req => {
    const q = listSchema.parse(req.query);
    const rows = await db.query(`SELECT a.*,s.observed_at AS runtime_observed_at,s.expires_at AS runtime_expires_at,s.complete AS runtime_complete FROM applications a
      LEFT JOIN LATERAL(SELECT observed_at,expires_at,complete FROM snapshots WHERE application_id=a.id ORDER BY observed_at DESC LIMIT 1)s ON true
      WHERE a.organization_id=$1 AND ($2::uuid IS NULL OR a.id>$2) AND (a.name ILIKE $3 OR a.namespace ILIKE $3)
      AND ($5::uuid IS NULL OR EXISTS(SELECT 1 FROM service_owners o WHERE o.user_id=$5 AND o.application_id=a.id)) ORDER BY a.id LIMIT $4`, [ORG, q.cursor ?? null, `%${q.q}%`, q.limit + 1, req.actor!.role === 'developer' ? req.actor!.id : null]);
    return page(rows, q.limit);
  });
  app.get('/api/v1/assets/:id', async req => {
    const id = idParam(req);
    const [asset] = await db.query('SELECT * FROM applications WHERE id=$1 AND organization_id=$2', [id, ORG]);
    if (!asset) throw new AppError('asset_not_found', 404);
    const snapshots = await db.query('SELECT * FROM snapshots WHERE application_id=$1 AND organization_id=$2 ORDER BY observed_at DESC LIMIT 10', [id, ORG]);
    return { ...asset, snapshots };
  });
  app.get('/api/v1/advisories', async req => {
    const q = listSchema.parse(req.query);
    return page(await db.query(`SELECT id,canonical_id,summary,severity,modified_at,withdrawn FROM advisories WHERE organization_id=$1 AND ($2::uuid IS NULL OR id>$2) AND (canonical_id ILIKE $3 OR summary ILIKE $3) ORDER BY id LIMIT $4`, [ORG, q.cursor ?? null, `%${q.q}%`, q.limit + 1]), q.limit);
  });
  app.get('/api/v1/advisories/:id', async req => {
    const id = idParam(req); const [row] = await db.query('SELECT * FROM advisories WHERE id=$1 AND organization_id=$2', [id, ORG]);
    if (!row) throw new AppError('advisory_not_found', 404);
    return { ...row, revisions: await db.query('SELECT id,content_hash,created_at FROM advisory_revisions WHERE advisory_id=$1 ORDER BY created_at DESC', [id]) };
  });
  app.post('/api/v1/advisories', async req => { requireRole(req, 'admin'); const id = await saveAdvisory(db, req.body); await audit(db, req.actor!.id, 'advisory.import', id); return { id }; });
  app.get('/api/v1/findings', async req => {
    const q = listSchema.parse(req.query);
    const status = q.status ? statusSchema.parse(q.status) : null;
    const rows = await db.query(`SELECT f.id,${effective} AS status,f.status AS automated_status,f.priority,f.stale,f.summary,f.fixed_versions,f.assessed_at,f.expires_at,
      a.canonical_id,a.summary AS advisory_summary,a.severity,p.name AS application,p.namespace,p.environment,p.id AS application_id
      FROM findings f JOIN advisories a ON a.id=f.advisory_id JOIN applications p ON p.id=f.application_id
      WHERE f.organization_id=$1 AND ($2::uuid IS NULL OR f.id>$2) AND (a.canonical_id ILIKE $3 OR p.name ILIKE $3 OR a.summary ILIKE $3)
      AND ($4::text IS NULL OR ${effective}=$4) AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM service_owners o WHERE o.user_id=$6 AND o.application_id=f.application_id)) ORDER BY f.id LIMIT $5`, [ORG, q.cursor ?? null, `%${q.q}%`, status, q.limit + 1, req.actor!.role === 'developer' ? req.actor!.id : null]);
    return page(rows, q.limit);
  });
  app.get('/api/v1/findings/:id', async req => {
    const id = idParam(req);
    const [finding] = await db.query(`SELECT f.*,${effective} AS status,f.status AS automated_status,a.canonical_id,a.document AS advisory,a.severity,p.name AS application,p.namespace,p.environment
      FROM findings f JOIN advisories a ON a.id=f.advisory_id JOIN applications p ON p.id=f.application_id WHERE f.id=$1 AND f.organization_id=$2`, [id, ORG]);
    if (!finding) throw new AppError('finding_not_found', 404);
    const [history, decisions, reports, tickets] = await Promise.all([
      db.query('SELECT id,status,evaluator_version,created_at FROM assessments WHERE finding_id=$1 ORDER BY created_at DESC LIMIT 30', [id]),
      db.query('SELECT id,status,rationale,expires_at,created_at FROM decisions WHERE finding_id=$1 ORDER BY created_at DESC LIMIT 20', [id]),
      db.query('SELECT id,model,created_at,expires_at FROM reports WHERE finding_id=$1 ORDER BY created_at DESC LIMIT 20', [id]),
      db.query('SELECT * FROM tickets WHERE finding_id=$1 AND organization_id=$2', [id, ORG]),
    ]);
    return { ...finding, history, decisions, reports, ticket: tickets[0] ?? null };
  });
  app.post('/api/v1/findings/:id/reassess', async req => {
    requireRole(req, 'reviewer'); const id = idParam(req); await assertFinding(db, id);
    await audit(db, req.actor!.id, 'finding.reassess', id); return { jobId: await enqueue(db, 'assess', {}, 'assess') };
  });
  app.post('/api/v1/findings/:id/decision', async req => {
    requireRole(req, 'reviewer'); const findingId = idParam(req); await assertFinding(db, findingId);
    const body = z.object({ status: statusSchema, rationale: z.string().min(10).max(4000), expiresAt: z.iso.datetime() }).parse(req.body);
    if (Date.parse(body.expiresAt) <= Date.now() || Date.parse(body.expiresAt) > Date.now() + 90 * 86400000) throw new AppError('invalid_decision_expiry');
    const id = randomUUID(); await db.query('INSERT INTO decisions(id,organization_id,finding_id,actor_id,status,rationale,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)', [id, ORG, findingId, req.actor!.id, body.status, body.rationale, body.expiresAt]);
    await audit(db, req.actor!.id, 'finding.decision', findingId, { status: body.status }); return { id };
  });
  app.post('/api/v1/findings/:id/impact-report', async req => {
    requireRole(req, 'reviewer'); const id = idParam(req); await assertFinding(db, id);
    if (!settings.llm) throw new AppError('llm_disabled', 409);
    const body = z.object({ targetVersion: z.string().min(1).max(100),codePaths:z.array(z.string().max(300)).max(5).default([]) }).parse(req.body);
    await audit(db, req.actor!.id, 'report.request', id);
    return { jobId: await enqueue(db, 'report', { findingId: id, targetVersion: body.targetVersion,codePaths:body.codePaths }, `report:${id}:${body.targetVersion}:${hash(body.codePaths)}`) };
  });
  app.get('/api/v1/impact-reports/:id', async req => {
    const [report] = await db.query('SELECT r.*,f.input_hash AS current_input_hash,f.stale AS finding_stale FROM reports r JOIN findings f ON f.id=r.finding_id WHERE r.id=$1 AND r.organization_id=$2', [idParam(req), ORG]);
    if (!report) throw new AppError('report_not_found', 404); return { ...report, stale: new Date(report.expires_at) <= new Date() || report.finding_stale || report.finding_input_hash !== report.current_input_hash };
  });
  app.get('/api/v1/tickets', async req => {
    const q = listSchema.extend({includeNonActionable:z.enum(['true','false']).optional()}).parse(req.query);
    const rows = await db.query(`SELECT t.*,a.severity AS advisory_severity,COALESCE(a.canonical_id,t.title) AS canonical_id,COALESCE(p.name,t.target_name) AS application,
      ${ticketAssessment} AS finding_status,linked.investigation_id FROM tickets t
      LEFT JOIN findings f ON f.id=t.finding_id LEFT JOIN advisories a ON a.id=f.advisory_id LEFT JOIN applications p ON p.id=f.application_id
      LEFT JOIN LATERAL(SELECT it.investigation_id FROM investigation_tickets it JOIN investigations i ON i.id=it.investigation_id AND i.organization_id=it.organization_id
        WHERE it.ticket_id=t.id AND it.organization_id=t.organization_id AND i.deleted_at IS NULL AND ($5::uuid IS NULL OR i.created_by=$5)
        ORDER BY i.created_at DESC,i.id DESC LIMIT 1)linked ON true
      WHERE t.organization_id=$1
      AND ($2::uuid IS NULL OR (t.updated_at,t.id)<(SELECT updated_at,id FROM tickets WHERE organization_id=$1 AND id=$2))
      AND ($3::text IS NULL OR t.status=$3)
      AND ($5::uuid IS NULL OR ${ticketAccessSql('$5::uuid')})
      AND (COALESCE(a.canonical_id,t.title,'') ILIKE $6 OR COALESCE(p.name,t.target_name,'') ILIKE $6)
      AND ($7::boolean OR COALESCE((${ticketAssessment}), 'under_investigation') NOT IN ('not_affected','fixed'))
      ORDER BY t.updated_at DESC,t.id DESC LIMIT $4`, [ORG, q.cursor ?? null, q.status ?? null, q.limit + 1, req.actor!.role === 'developer' ? req.actor!.id : null, `%${q.q}%`, q.includeNonActionable==='true']);
    return page(rows, q.limit);
  });
  app.get('/api/v1/tickets/:id',async req=>{
    const id=idParam(req);
    const [ticket]=await db.query(`SELECT t.*,a.canonical_id,a.severity AS advisory_severity,a.summary AS advisory_summary,p.name AS application,${effective} AS finding_status,f.summary AS finding_summary,f.evidence AS finding_evidence,f.fixed_versions
      FROM tickets t LEFT JOIN findings f ON f.id=t.finding_id LEFT JOIN advisories a ON a.id=f.advisory_id LEFT JOIN applications p ON p.id=f.application_id
      WHERE t.id=$1 AND t.organization_id=$2`,[id,ORG]);
    if(!ticket)throw new AppError('ticket_not_found',404);
    const investigations=await db.query(`SELECT i.id,i.title,i.created_at,i.expires_at,it.assessment FROM investigation_tickets it JOIN investigations i ON i.id=it.investigation_id AND i.organization_id=it.organization_id
      WHERE it.ticket_id=$1 AND it.organization_id=$2 AND i.deleted_at IS NULL AND ($3::uuid IS NULL OR i.created_by=$3) ORDER BY i.created_at DESC`,[id,ORG,req.actor!.role==='developer'?req.actor!.id:null]);
    const remediationPrs=await db.query('SELECT repository,number,title,path,created_at FROM remediation_prs WHERE organization_id=$1 AND ticket_id=$2 ORDER BY created_at DESC',[ORG,id]);
    const remediationJobs=await db.query(`SELECT DISTINCT ON(type) type,state,error_code FROM jobs
      WHERE organization_id=$1 AND payload->>'ticketId'=$2::text AND type IN ('remediate','remediate-gitops')
      ORDER BY type,created_at DESC`,[ORG,id]);
    return {...ticket,investigations,remediationPrs,remediationJobs};
  });
  app.post('/api/v1/tickets', async req => {
    requireRole(req, 'developer'); const body = z.object({ findingId: z.uuid() }).parse(req.body); await assertFinding(db, body.findingId);
    if (req.actor!.role === 'developer' && !(await db.query('SELECT 1 FROM service_owners o JOIN findings f ON f.application_id=o.application_id WHERE o.user_id=$1 AND f.id=$2 AND o.organization_id=$3', [req.actor!.id, body.findingId, ORG])).length) throw new AppError('service_scope_denied', 403);
    const [ticket] = await db.query(`INSERT INTO tickets(id,organization_id,finding_id)
      SELECT $1,$2,id FROM findings WHERE id=$3 AND organization_id=$2 AND status='affected' AND NOT stale AND expires_at>now()
      ON CONFLICT(organization_id,finding_id) DO UPDATE SET id=tickets.id RETURNING id`, [randomUUID(), ORG, body.findingId]);
    if (!ticket) throw new AppError('ticket_not_actionable',409);
    await audit(db, req.actor!.id, 'ticket.create', ticket.id); return ticket;
  });
  app.patch('/api/v1/tickets/:id', async req => {
    const id = idParam(req);
    const body = z.object({status:z.enum(['open','in_progress','blocked','resolved']).optional(),notes:z.string().max(8000).optional()})
      .refine(value=>value.status!==undefined||value.notes!==undefined).parse(req.body);
    return db.transaction(async tx=>{
      const [ticket]=await tx.query(`UPDATE tickets SET status=COALESCE($3,status),notes=COALESCE($4,notes),updated_at=now()
        WHERE id=$1 AND organization_id=$2 RETURNING id,status,notes`, [id, ORG, body.status??null, body.notes??null]);
      if (!ticket) throw new AppError('ticket_not_found',404);
      await audit(tx,req.actor!.id,'ticket.update',id);
      return ticket;
    });
  });
  app.get('/api/v1/integrations', async req => { requireRole(req, 'admin'); return { items: await db.query('SELECT * FROM integrations WHERE organization_id=$1 ORDER BY name', [ORG]), configured: config.integrations.length, osvEnabled: config.osv,
    access:{githubConfigured:config.integrations.some(i=>i.kind==='github'),repositories:config.integrations.flatMap(i=>i.kind==='github'?i.repositories.map(r=>r.name):[]),codeEgressRepositories:config.integrations.flatMap(i=>i.kind==='github'?i.sourcePolicies.filter(p=>p.allowCodeEgress).map(p=>p.repository):[]),argoProjects:[...new Set(config.integrations.flatMap(i=>i.kind==='argocd'?i.projects:[]))],directKubernetesApi:false,llmProvider:settings.llmProvider,llmModel:settings.model,llmDailyCalls:(await readLlmBudget(db,settings.llmDailyCalls)).dailyCalls}
  }; });
  for (const action of ['sync','test']) app.post(`/api/v1/integrations/:id/${action}`, async req => {
    requireRole(req, 'admin'); const { id } = z.object({ id: z.string() }).parse(req.params);
    if (!config.integrations.some(c => c.id === id)) throw new AppError('integration_not_found', 404);
    await audit(db, req.actor!.id, `integration.${action}`, id); return { jobId: await enqueue(db, 'sync', { integrationId: id }, `sync:${id}`) };
  });
  app.post('/api/v1/sync', async req => {
    requireRole(req, 'admin');
    const jobs: string[] = [];
    for (const i of config.integrations) if (i.kind === 'github' || i.kind === 'argocd') jobs.push(await enqueue(db, 'sync', { integrationId: i.id }, `sync:${i.id}`));
    if (config.osv) jobs.push(await enqueue(db, 'osv', {}, 'osv'));
    return { jobIds: jobs };
  });
  app.get('/api/v1/jobs', async req => {
    requireRole(req, 'reviewer');
    const q=listSchema.extend({type:z.string().max(40).optional()}).parse(req.query);
    return page(await db.query(`WITH job_rows AS (
      SELECT * FROM jobs WHERE organization_id=$1 AND ($4::text IS NULL OR state=$4) AND ($5::text IS NULL OR type=$5)
      AND ($2::uuid IS NULL OR (created_at,id)<(SELECT created_at,id FROM jobs WHERE organization_id=$1 AND id=$2))
      ORDER BY created_at DESC,id DESC LIMIT $3
    ) ${jobDisplay} ORDER BY j.created_at DESC,j.id DESC`,[ORG,q.cursor??null,q.limit+1,q.status??null,q.type??null]),q.limit);
  });
  app.get('/api/v1/jobs/:id', async req => {
    requireRole(req, 'reviewer');
    const [job] = await db.query(`WITH job_rows AS (SELECT * FROM jobs WHERE organization_id=$1 AND id=$2) ${jobDisplay}`, [ORG, idParam(req)]);
    if (!job) throw new AppError('job_not_found', 404); return job;
  });
  app.get('/api/v1/usage/llm', async req => { requireRole(req, 'admin'); return analysisUsage(db,settings,req.actor!.id,true); });
  app.get('/api/v1/audit', async req => { requireRole(req, 'admin'); return { items: await db.query('SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100', [ORG]) }; });
  app.get('/api/v1/users', async req => {
    requireRole(req, 'admin');
    const q = listSchema.parse(req.query);
    return page(await db.query(`SELECT id,email,role,created_at,disabled_at FROM users
      WHERE organization_id=$1 AND strpos(lower(email),lower($4))>0
      AND ($2::uuid IS NULL OR email>(SELECT email FROM users WHERE organization_id=$1 AND id=$2))
      ORDER BY email LIMIT $3`, [ORG, q.cursor ?? null, q.limit + 1, q.q]), q.limit);
  });
  app.post('/api/v1/users', async req => manageUsers(req, async (tx, actor) => {
    const body = z.object({ email: z.email().max(200), password: z.string().min(14).max(256), role: userRole }).parse(req.body);
    const id = await createUser(tx, body.email, body.password, body.role);
    await audit(tx, actor.id, 'user.create', id, { role: body.role });
    return { id };
  }));
  app.patch('/api/v1/users/:id', async req => manageUsers(req, async (tx, actor) => {
    const id = idParam(req);
    const body = z.strictObject({ role: userRole.optional(), enabled: z.boolean().optional() })
      .refine(value => value.role !== undefined || value.enabled !== undefined).parse(req.body);
    if (id === actor.id) throw new AppError('own_account_change_denied', 403);
    const [target] = await tx.query<{ role: Role; disabled_at: Date | null }>('SELECT role,disabled_at FROM users WHERE organization_id=$1 AND id=$2', [ORG, id]);
    if (!target) throw new AppError('user_not_found', 404);
    const role = body.role ?? target.role;
    const enabled = body.enabled ?? (target.disabled_at === null);
    if (role !== target.role || enabled !== (target.disabled_at === null)) {
      await tx.query(`UPDATE users SET role=$3,disabled_at=CASE WHEN $4 THEN NULL ELSE COALESCE(disabled_at,now()) END
        WHERE organization_id=$1 AND id=$2`, [ORG, id, role, enabled]);
      await tx.query('DELETE FROM sessions WHERE user_id=$1', [id]);
      await audit(tx, actor.id, 'user.update', id, { previousRole: target.role, role, enabled });
    }
    return { id };
  }));
  app.post('/api/v1/service-owners', async req => { requireRole(req, 'admin'); const body = z.object({ userId: z.uuid(), applicationId: z.uuid() }).parse(req.body); await db.query('INSERT INTO service_owners(organization_id,user_id,application_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [ORG, body.userId, body.applicationId]); await audit(db, req.actor!.id, 'service.assign', body.applicationId, { userId: body.userId }); return { ok: true }; });

  function bearer(req: FastifyRequest, kind: 'ingest' | 'collector'): Integration {
    const authorization = req.headers.authorization;
    if (!authorization?.startsWith('Bearer ')) throw new AppError('ingest_authentication_required', 401);
    const token = authorization.slice(7);
    const match = config.integrations.find(c => c.kind === kind && process.env[c.tokenEnv] && secureEqual(hash(token), hash(process.env[c.tokenEnv]!)));
    if (!match) throw new AppError('ingest_authentication_required', 401); return match;
  }
  app.post('/api/v1/ingest/sbom', async (req, reply) => { const c = bearer(req, 'ingest'); if (c.kind !== 'ingest') throw new AppError('ingest_scope_denied', 403); return reply.code(202).send(await ingestSbom(db, req.body, c, config)); });
  app.post('/api/v1/ingest/observations', async (req, reply) => { const c = bearer(req, 'collector'); if (c.kind !== 'collector') throw new AppError('collector_scope_denied', 403); return reply.code(202).send(await ingestSnapshot(db, req.body, c, config.evidenceTtlSeconds)); });
  app.post('/api/v1/webhooks/github/:id', async (req, reply) => {
    const { id } = z.object({ id: z.string() }).parse(req.params);
    const integration = config.integrations.find(i => i.id === id && i.kind === 'github');
    if (integration?.kind !== 'github' || !integration.webhookSecretEnv) throw new AppError('webhook_not_configured', 404);
    if (!req.rawBody || !verifyWebhook(req.rawBody, typeof req.headers['x-hub-signature-256'] === 'string' ? req.headers['x-hub-signature-256'] : undefined, secret(integration.webhookSecretEnv))) throw new AppError('webhook_signature_rejected', 401);
    const delivery = z.string().min(1).max(100).parse(req.headers['x-github-delivery']);
    const body = z.object({ repository: z.object({ full_name: z.string() }).optional() }).parse(req.body);
    if (body.repository && !integration.repositories.some(r => r.name === body.repository!.full_name)) throw new AppError('repository_not_allowed', 403);
    const duplicate = await db.transaction(async tx => {
      const rows = await tx.query('INSERT INTO webhook_deliveries(integration_id,delivery_id) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING delivery_id', [id, delivery]);
      if (!rows.length) return true;
      await enqueue(tx, 'sync', { integrationId: id }, `sync:${id}`);
      for (const i of config.integrations) if (i.kind === 'argocd' && i.githubIntegrationId === id) await enqueue(tx, 'sync', { integrationId: i.id }, `sync:${i.id}`);
      return false;
    });
    return reply.code(202).send({ accepted: true, duplicate });
  });
  registerInvestigationRoutes(app,db,config,settings);
  registerAnalysisUsageRoutes(app,db,settings,config);
  registerCodexAccountSwitch(app,db,settings);
  return app;
}
function page(rows: any[], limit: number) { return { items: rows.slice(0, limit), nextCursor: rows.length > limit ? rows[limit - 1].id : null }; }
async function assertFinding(db: Database, id: string) { if (!(await db.query('SELECT id FROM findings WHERE id=$1 AND organization_id=$2', [id, ORG])).length) throw new AppError('finding_not_found', 404); }
