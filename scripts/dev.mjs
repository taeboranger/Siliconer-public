import 'dotenv/config';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
const root = path.resolve(import.meta.dirname, '..');
const require = createRequire(import.meta.url);
const webRequire = createRequire(path.join(root, 'apps/web/package.json'));
const demo = process.argv.includes('--demo');
const env = { ...process.env, NODE_ENV: 'development', NEXT_TELEMETRY_DISABLED: '1', SILICONER_EMBEDDED_WORKER: 'true' };
if (demo) { env.SILICONER_DEMO = 'true'; env.SILICONER_DATABASE_URL = 'pglite:./.data/demo'; delete env.SILICONER_CONFIG_FILE; env.SILICONER_LLM_ENABLED = 'false'; }
if (!env.SILICONER_DATABASE_URL) { console.error('Set SILICONER_DATABASE_URL in .env, or run pnpm demo.'); process.exit(1); }
const children = [
  spawn(process.execPath, [require.resolve('tsx/cli'), 'apps/api/src/main.ts'], { cwd: root, env, stdio: 'inherit', windowsHide: true }),
  spawn(process.execPath, [webRequire.resolve('next/dist/bin/next'), 'dev', '--hostname', '127.0.0.1'], { cwd: path.join(root, 'apps/web'), env, stdio: 'inherit', windowsHide: true }),
];
console.log(`\nSiliconer: http://localhost:3000${demo ? '\nDemo login: admin@siliconer.local / siliconer-demo-2026 (development only)' : ''}\n`);
let stopping = false;
function stop(code = 0) { if (stopping) return; stopping = true; for (const child of children) child.kill('SIGTERM'); process.exitCode = code; }
for (const child of children) child.on('exit', code => stop(code ?? 0));
process.on('SIGINT', () => stop()); process.on('SIGTERM', () => stop());
