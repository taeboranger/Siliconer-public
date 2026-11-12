import test from 'node:test';
import assert from 'node:assert/strict';
import { enqueue, claim, finish, reap } from '../packages/storage/src/jobs.js';
import { testDatabase } from './helpers.js';
test('durable queue deduplicates active jobs, claims atomically and rejects stale acknowledgements', async () => {
  const db = await testDatabase();
  try {
    const [a,b] = await Promise.all([enqueue(db,'assess',{},'same'),enqueue(db,'assess',{},'same')]); assert.equal(a,b);
    const [one,two] = await Promise.all([claim(db),claim(db)]); const first = one ?? two; assert(first); assert(!one || !two);
    await db.query("UPDATE jobs SET lease_until=now()-interval '1 second' WHERE id=$1", [first.id]);
    const second = await claim(db); assert(second); assert.notEqual(second.lease_token, first.lease_token);
    await finish(db,first); assert.equal((await db.query('SELECT state FROM jobs WHERE id=$1',[first.id]))[0].state,'running');
    await finish(db,second,'upstream_429'); assert.equal((await db.query('SELECT state FROM jobs WHERE id=$1',[first.id]))[0].state,'queued');
    await db.query("UPDATE jobs SET run_after=now()-interval '1 second' WHERE id=$1",[first.id]);
    const third = await claim(db); assert(third); await finish(db,third,'upstream_429');
    assert.equal((await db.query('SELECT state FROM jobs WHERE id=$1',[first.id]))[0].state,'failed');
    assert.notEqual(await enqueue(db,'assess',{},'same'), first.id);
    const next = await claim(db); assert(next);
    await db.query("UPDATE jobs SET attempt=3,lease_until=now()-interval '1 second' WHERE id=$1",[next.id]); await reap(db);
    assert.equal((await db.query('SELECT error_code FROM jobs WHERE id=$1',[next.id]))[0].error_code,'lease_expired');
    const reportId=await enqueue(db,'report',{},'report');const report=await claim(db);assert.equal(report?.id,reportId);
    await db.query("UPDATE jobs SET lease_until=now()-interval '1 second' WHERE id=$1",[reportId]);
    assert.equal(await claim(db),undefined);await reap(db);
    assert.equal((await db.query('SELECT state FROM jobs WHERE id=$1',[reportId]))[0].state,'blocked');
    const investigationId=await enqueue(db,'investigate',{},'investigation');const investigation=await claim(db);assert.equal(investigation?.id,investigationId);
    await db.query("UPDATE jobs SET lease_until=now()-interval '1 second' WHERE id=$1",[investigationId]);assert.equal(await claim(db),undefined);await reap(db);
    assert.equal((await db.query('SELECT state FROM jobs WHERE id=$1',[investigationId]))[0].state,'blocked');
  } finally { await db.close(); }
});
