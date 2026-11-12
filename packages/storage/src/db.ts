import { Pool, type PoolClient } from 'pg';
import { migrations } from './schema.js';
import { hash } from '../../core/src/util.js';
import { mkdir } from 'node:fs/promises';

export const ORG = '00000000-0000-4000-8000-000000000001';
export const SCHEMA_VERSION=migrations.at(-1)!.version;
export interface Queryable {
  query<T = Record<string, any>>(sql: string, params?: unknown[]): Promise<T[]>;
  exec(sql: string): Promise<void>;
}
export interface Database extends Queryable {
  transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}
function pgQueries(client: Pool | PoolClient): Queryable {
  return { async query<T>(sql: string, params: unknown[] = []) { return (await client.query(sql, params)).rows as T[]; },
    async exec(sql) { await client.query(sql); } };
}
export async function openDatabase(url: string, production = false): Promise<Database> {
  if (url.startsWith('pglite:')) {
    if (production) throw new Error('Production requires a PostgreSQL connection URL');
    const { PGlite } = await import('@electric-sql/pglite');
    const directory = url === 'pglite:memory' ? undefined : url.slice(7);
    if (directory) await mkdir(directory, { recursive: true });
    const pg = new PGlite(directory);
    await pg.waitReady;
    return { async query<T>(sql: string, params: unknown[] = []) { return (await pg.query<T>(sql, params)).rows; },
      async exec(sql) { await pg.exec(sql); },
      transaction: fn => pg.transaction(tx => fn({ async query<T>(sql: string, params: unknown[] = []) { return (await tx.query<T>(sql, params)).rows; }, async exec(sql) { await tx.exec(sql); } })),
      close: () => pg.close() };
  }
  if (!/^postgres(?:ql)?:\/\//.test(url)) throw new Error('Invalid database URL');
  const pool = new Pool({ connectionString: url, max: 8, connectionTimeoutMillis: 5000, statement_timeout: 30000 });
  return { ...pgQueries(pool), async transaction(fn) {
    const client = await pool.connect();
    try { await client.query('BEGIN'); const result = await fn(pgQueries(client)); await client.query('COMMIT'); return result; }
    catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }, close: () => pool.end() };
}
export async function migrate(db: Database): Promise<void> {
  await db.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())');
  await db.transaction(async tx => {
    await tx.exec('LOCK TABLE schema_migrations IN EXCLUSIVE MODE');
    for (const migration of migrations) {
      const [existing] = await tx.query('SELECT checksum FROM schema_migrations WHERE version=$1', [migration.version]);
      const checksum = hash(migration.sql);
      if (existing) { if (existing.checksum !== checksum) throw new Error('Migration checksum mismatch'); continue; }
      await tx.exec(migration.sql);
      await tx.query('INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)', [migration.version, checksum]);
    }
    await tx.query('INSERT INTO organizations(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING', [ORG, 'Siliconer']);
  });
}
