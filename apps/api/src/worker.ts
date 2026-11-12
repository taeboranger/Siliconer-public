import { openDatabase } from '../../../packages/storage/src/db.js';
import { loadConnectorConfig } from '../../../packages/connectors/src/config.js';
import { readSettings } from './config.js';
import { registerIntegrations } from './inventory.js';
import { Runtime } from './runtime.js';
const settings = readSettings(process.env, true);
if (settings.databaseUrl.startsWith('pglite:')) throw new Error('Separate worker requires PostgreSQL; use embedded worker for PGlite');
const config = await loadConnectorConfig(settings.configFile);
const db = await openDatabase(settings.databaseUrl, settings.production);
await registerIntegrations(db, config);
const runtime = new Runtime(db, config, settings, event => process.stderr.write(`${JSON.stringify(event)}\n`));
runtime.start();
let stopping = false;
async function stop() { if (stopping) return; stopping = true; await runtime.stop(); await db.close(); }
process.on('SIGINT', () => void stop()); process.on('SIGTERM', () => void stop());
