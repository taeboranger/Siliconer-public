import 'dotenv/config';
import { z } from 'zod';
export function readSettings(env: NodeJS.ProcessEnv = process.env, requireLlmKey = false) {
  const production = env.NODE_ENV === 'production';
  const demo = env.SILICONER_DEMO === 'true';
  const llmProvider=z.enum(['openai','codex']).parse(env.SILICONER_LLM_PROVIDER??'openai');
  if (production && demo) throw new Error('Demo mode is forbidden in production');
  const settings = {
    production, demo, databaseUrl: env.SILICONER_DATABASE_URL || (demo ? 'pglite:./.data/demo' : ''),
    host: env.SILICONER_HOST ?? '127.0.0.1', port: Number(env.SILICONER_PORT ?? 4100),
    baseUrl: env.SILICONER_BASE_URL ?? 'http://localhost:3000',
    configFile: env.SILICONER_CONFIG_FILE,
    llm: env.SILICONER_LLM_ENABLED === 'true', llmProvider, model: env.SILICONER_LLM_MODEL??env.OPENAI_MODEL??(llmProvider==='codex'?'gpt-6.1-sol':''),
    codexHome:env.SILICONER_CODEX_HOME??'/var/lib/siliconer-codex',llmDailyCalls:Number(env.SILICONER_LLM_DAILY_CALLS??50),
    codexTimeoutSeconds:Number(env.SILICONER_CODEX_TIMEOUT_SECONDS??300),
    reasoningEffort:z.enum(['low','medium','high','xhigh','max','ultra']).parse(env.SILICONER_REASONING_EFFORT??'low'),
    llmInputPrice: Number(env.OPENAI_INPUT_USD_PER_MILLION ?? 0), llmOutputPrice: Number(env.OPENAI_OUTPUT_USD_PER_MILLION ?? 0),
    llmDailyBudget: Number(env.OPENAI_DAILY_BUDGET_USD ?? 1), llmMaxOutput: Number(env.OPENAI_MAX_OUTPUT_TOKENS ?? 2000),
    notificationUrl: env.SILICONER_NOTIFICATION_URL,
  };
  if (!settings.databaseUrl) throw new Error('Set SILICONER_DATABASE_URL or use pnpm demo');
  const url = new URL(settings.baseUrl);
  if (url.origin !== settings.baseUrl || (production && url.protocol !== 'https:')) throw new Error('SILICONER_BASE_URL must be an origin; production requires HTTPS');
  z.number().int().min(1).max(65535).parse(settings.port);
  z.number().int().min(100).max(16000).parse(settings.llmMaxOutput);
  z.number().int().min(1).max(1000).parse(settings.llmDailyCalls);
  z.number().int().min(30).max(600).parse(settings.codexTimeoutSeconds);
  z.number().positive().finite().parse(settings.llmDailyBudget);
  if (settings.llm && (!settings.model || (llmProvider==='openai'&&((requireLlmKey && !env.OPENAI_API_KEY)||settings.llmInputPrice <= 0 || settings.llmOutputPrice <= 0)))) throw new Error('LLM requires a model and provider credentials; OpenAI API also requires explicit token prices');
  if (production && settings.databaseUrl.startsWith('pglite:')) throw new Error('PGlite is development-only');
  if (settings.notificationUrl && new URL(settings.notificationUrl).protocol !== 'https:') throw new Error('Notification URL requires HTTPS');
  return settings;
}
export type Settings = ReturnType<typeof readSettings>;
