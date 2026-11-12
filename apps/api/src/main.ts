import { openDatabase, migrate } from '../../../packages/storage/src/db.js';
import { loadConnectorConfig, configSchema } from '../../../packages/connectors/src/config.js';
import { readSettings } from './config.js';
import { registerIntegrations } from './inventory.js';
import { createApp } from './app.js';
import { Runtime } from './runtime.js';
import { seedDemo } from './seed.js';

const settings = readSettings();
const config = settings.demo ? configSchema.parse({ evidenceTtlSeconds: 86400 }) : await loadConnectorConfig(settings.configFile);
const db = await openDatabase(settings.databaseUrl, settings.production);
if (!settings.production) await migrate(db);
await registerIntegrations(db, config);
if (settings.demo) await seedDemo(db, true);
const app = await createApp(db, config, settings, true);
const runtime = new Runtime(db, config, settings, event => app.log.error(event));
if (process.env.SILICONER_EMBEDDED_WORKER === 'true') {
  if (settings.production) throw new Error('Use the separate worker process in production');
  runtime.start();
}
await app.listen({ host: settings.host, port: settings.port });
let stopping = false;
async function stop() {
  if (stopping) return; stopping = true;
  await app.close(); await runtime.stop(); await db.close();
}
process.on('SIGINT', () => void stop()); process.on('SIGTERM', () => void stop());
