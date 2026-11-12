import { build } from 'esbuild';
await build({ entryPoints: ['apps/api/src/main.ts','apps/api/src/worker.ts','apps/api/src/cli.ts'], outdir: 'dist', bundle: true, platform: 'node', target: 'node24', format: 'esm', packages: 'external', sourcemap: true });
