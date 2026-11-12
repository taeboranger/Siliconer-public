import { randomUUID } from 'node:crypto';
import { openDatabase, migrate, type Database } from '../packages/storage/src/db.js';
export async function testDatabase(): Promise<Database> {
  const url = process.env.SILICONER_TEST_DATABASE_URL;
  if (!url) { const db = await openDatabase('pglite:memory'); await migrate(db); return db; }
  const schema = `siliconer_test_${randomUUID().replaceAll('-','')}`;
  const admin = await openDatabase(url);
  await admin.exec(`CREATE SCHEMA "${schema}"`);
  const isolated = new URL(url); isolated.searchParams.set('options', `-c search_path=${schema}`);
  const db = await openDatabase(isolated.toString());
  await migrate(db);
  return { ...db, async close() {
    await db.close();
    if (!/^siliconer_test_[a-f0-9]{32}$/.test(schema)) throw new Error('Unsafe test cleanup target');
    await admin.exec(`DROP SCHEMA "${schema}" CASCADE`); await admin.close();
  } };
}
