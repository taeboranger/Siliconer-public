import { randomUUID } from 'node:crypto';
import { ORG, type Database, type Queryable } from './db.js';
export interface Job { id: string; type: string; payload: Record<string, any>; attempt: number; lease_token: string }
export async function enqueue(db: Queryable, type: string, payload: unknown, dedupeKey: string, runAfter = new Date()) {
  const id = randomUUID();
  const rows = await db.query('INSERT INTO jobs(id,organization_id,type,payload,dedupe_key,run_after) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING id',
    [id, ORG, type, JSON.stringify(payload), dedupeKey, runAfter]);
  return rows[0]?.id ?? (await db.query("SELECT id FROM jobs WHERE organization_id=$1 AND dedupe_key=$2 AND state IN ('queued','running')", [ORG, dedupeKey]))[0]?.id;
}
export async function claim(db: Database): Promise<Job | undefined> {
  return db.transaction(async tx => {
    const [job] = await tx.query<Job>(`SELECT id,type,payload,attempt,lease_token FROM jobs WHERE organization_id=$1 AND
      ((state='queued' AND run_after<=now()) OR (state='running' AND lease_until<now() AND type NOT IN ('report','investigate','investigation-detail'))) AND attempt<3
      ORDER BY run_after FOR UPDATE SKIP LOCKED LIMIT 1`, [ORG]);
    if (!job) return undefined;
    const leaseToken = randomUUID();
    await tx.query("UPDATE jobs SET state='running',attempt=attempt+1,lease_until=now()+interval '5 minutes',lease_token=$2,updated_at=now() WHERE id=$1", [job.id, leaseToken]);
    return { ...job, attempt: job.attempt + 1, lease_token: leaseToken };
  });
}
export async function finish(db: Queryable, job: Job, error?: string, retryable = true) {
  const retry = Boolean(error && retryable && job.attempt < 3);
  await db.query(`UPDATE jobs SET state=$3,error_code=$4,lease_until=NULL,run_after=now()+($5::integer * interval '1 second'),updated_at=now()
    WHERE id=$1 AND lease_token=$2 AND state='running'`, [job.id, job.lease_token, error ? retry ? 'queued' : retryable ? 'failed' : 'blocked' : 'succeeded', error ?? null, 15 * 2 ** job.attempt]);
}
export async function reap(db: Queryable) {
  await db.query("UPDATE llm_usage SET state='uncertain' WHERE state='reserved' AND job_id IN(SELECT id FROM jobs WHERE state='running' AND type IN ('report','investigate','investigation-detail') AND lease_until<now())");
  await db.query("UPDATE jobs SET state='blocked',error_code='llm_request_uncertain',updated_at=now() WHERE state='running' AND type IN ('report','investigate','investigation-detail') AND lease_until<now()");
  await db.query("UPDATE investigations SET state='blocked',stage='검사 보류',error_code='llm_request_uncertain',finished_at=now(),updated_at=now() WHERE deleted_at IS NULL AND state IN ('queued','planning','collecting') AND id IN(SELECT (payload->>'investigationId')::uuid FROM jobs WHERE type='investigate' AND state='blocked' AND error_code='llm_request_uncertain')");
  await db.query("UPDATE jobs SET state='failed',error_code='lease_expired',updated_at=now() WHERE state='running' AND lease_until<now() AND attempt>=3");
}
