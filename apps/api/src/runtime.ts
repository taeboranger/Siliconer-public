import { ORG, type Database } from '../../../packages/storage/src/db.js';
import { claim, enqueue, finish, reap, type Job } from '../../../packages/storage/src/jobs.js';
import { AppError } from '../../../packages/core/src/types.js';
import type { ConnectorConfig } from '../../../packages/connectors/src/config.js';
import { syncIntegration, audit } from './inventory.js';
import { assessAll } from './assessment.js';
import { syncOsv } from './feeds.js';
import { generateReport } from './reports.js';
import type { Settings } from './config.js';
import {runInvestigation,runInvestigationDetail} from './investigations.js';
import {syncModelAccount} from './model-account.js';
import {openRemediationPr,openGitopsRemediationPr} from './remediation.js';
import {expireCodexSwitches,runCodexAccountSwitch} from './codex-account-switch.js';

export class Runtime {
  private busy = false;
  private lastSchedule = 0;
  private timer?: ReturnType<typeof setInterval>;
  private readonly shutdown=new AbortController();
  constructor(readonly db: Database, readonly config: ConnectorConfig, readonly settings: Settings, private log: (event: Record<string, unknown>) => void = () => {}) {}
  async schedule() {
    if (Date.now() - this.lastSchedule < this.config.pollSeconds * 1000) return;
    this.lastSchedule = Date.now();
    for (const i of this.config.integrations) if (i.kind === 'github' || i.kind === 'argocd') await enqueue(this.db, 'sync', { integrationId: i.id }, `sync:${i.id}`);
    if (this.config.osv) await enqueue(this.db, 'osv', {}, 'osv');
    if(this.settings.llm&&this.settings.llmProvider==='codex')await enqueue(this.db,'model-account',{},'model-account');
    await this.db.query('DELETE FROM sessions WHERE expires_at<now()');
    await expireCodexSwitches(this.db);
    await reap(this.db);
  }
  async tick() {
    if (this.busy) return;
    this.busy = true;
    try {
      const job = await claim(this.db); if (!job) return;
      const heartbeat = setInterval(() => { void this.db.query("UPDATE jobs SET lease_until=now()+interval '5 minutes' WHERE id=$1 AND lease_token=$2 AND state='running'", [job.id, job.lease_token]).catch(() => {}); }, 30000);
      const tracksUsage=['investigate','investigation-detail'].includes(job.type)&&this.settings.llmProvider==='codex';
      const before=tracksUsage?await syncModelAccount(this.db,this.settings).catch(()=>null):null;
      try { await this.execute(job); await finish(this.db, job); }
      catch (error) {
        const code = error instanceof AppError ? error.code : 'job_failed';
        const retryable = !['report','investigate','investigation-detail'].includes(job.type) && !(error instanceof AppError && error.statusCode < 500);
        await finish(this.db, job, code, retryable);
        if(job.type==='investigate')await this.db.query("UPDATE investigations SET state='blocked',stage='검사 보류',error_code=$2,finished_at=now(),updated_at=now() WHERE id=$1 AND state<>'completed' AND deleted_at IS NULL",[job.payload.investigationId,code]);
        this.log({ jobId: job.id, type: job.type, code });
        await audit(this.db, 'worker', 'job.failed', job.id, { code });
      } finally {
        clearInterval(heartbeat);
        if(tracksUsage){
          const after=await syncModelAccount(this.db,this.settings).catch(()=>null);
          await this.db.query('UPDATE jobs SET usage_context=$2 WHERE id=$1',[job.id,JSON.stringify({before:before?.limits??[],after:after?.limits??[]})]).catch(()=>this.log({code:'usage_snapshot_failed',jobId:job.id}));
        }
      }
    } finally { this.busy = false; }
  }
  async execute(job: Job) {
    switch (job.type) {
      case 'sync': await syncIntegration(this.db, this.config, job.payload.integrationId); break;
      case 'osv': if (!this.config.osv) throw new AppError('osv_disabled', 409); await syncOsv(this.db); break;
      case 'assess': await assessAll(this.db, this.config.evidenceTtlSeconds); break;
      case 'report': await generateReport(this.db, job.payload.findingId, job.payload.targetVersion, this.settings, job.id, fetch, this.config,job.payload.codePaths ?? []); break;
      case 'investigate': await runInvestigation(this.db,job.payload.investigationId,this.settings,this.config,job.id);break;
      case 'investigation-detail': await runInvestigationDetail(this.db,this.config,this.settings,{
        investigationId:job.payload.investigationId,targetId:job.payload.targetId,requestedBy:job.payload.requestedBy,analysisSettings:job.payload.analysisSettings,
      },job.id);break;
      case 'model-account': await syncModelAccount(this.db,this.settings);break;
      case 'codex-account-switch': await runCodexAccountSwitch(this.db,this.settings,job.payload.switchId,this.shutdown.signal);break;
      case 'notify': await this.notify(job); break;
      case 'remediate': await openRemediationPr(this.db,this.config,job.payload.ticketId); break;
      case 'remediate-gitops': await openGitopsRemediationPr(this.db,this.config,job.payload.ticketId,job.payload.digest); break;
      default: throw new AppError('unknown_job_type');
    }
  }
  private async notify(job: Job) {
    if (!this.settings.notificationUrl) return;
    const payload = job.payload;
    if ((await this.db.query('SELECT 1 FROM notification_deliveries WHERE organization_id=$1 AND event_hash=$2', [ORG, payload.eventHash])).length) return;
    const response = await fetch(this.settings.notificationUrl, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000), headers: { 'Content-Type': 'application/json', 'Idempotency-Key': payload.eventHash },
      body: JSON.stringify({ advisory: payload.advisory, title:payload.title,ticketId:payload.ticketId, application: payload.application, status: payload.status, priority: payload.priority, url: payload.investigationId?`${this.settings.baseUrl}/investigations/${encodeURIComponent(payload.investigationId)}`:`${this.settings.baseUrl}/?finding=${encodeURIComponent(payload.findingId)}` }) });
    if (!response.ok) { await response.body?.cancel(); throw new AppError('notification_failed', 502); }
    await response.body?.cancel();
    await this.db.query('INSERT INTO notification_deliveries(organization_id,event_hash) VALUES($1,$2) ON CONFLICT DO NOTHING', [ORG, payload.eventHash]);
  }
  start() {
    if (this.timer) return;
    this.timer = setInterval(() => { void this.schedule().then(() => this.tick()).catch(() => this.log({ code: 'worker_tick_failed' })); }, 1000);
  }
  async stop() {
    if (this.timer) clearInterval(this.timer);
    this.shutdown.abort();
    while (this.busy) await new Promise(resolve => setTimeout(resolve, 100));
  }
}
