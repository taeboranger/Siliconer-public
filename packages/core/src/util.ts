import { createHash, timingSafeEqual } from 'node:crypto';

export function canonical(value: unknown): string {
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}
export const hash = (value: unknown) => createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex');
export function secureEqual(a: string, b: string): boolean {
  const aa = Buffer.from(a); const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
export const iso = (date: string | Date) => new Date(date).toISOString();
export function cleanText(text: string, max = 4000): string {
  return text.replace(/(?:sk-[\w-]{12,}|gh[pousr]_[\w]{16,}|github_pat_[\w]{16,}|Bearer\s+[^\s"']+)/gi, '[REDACTED]')
    .replace(/-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----/g, '[REDACTED]')
    .replace(/(password|secret|token|api[_-]?key)["']?\s*[:=]\s*["']?[^\s,"'}]+/gi, '$1=[REDACTED]')
    .replace(/https?:\/\/[^\s/@]+:[^\s/@]+@/gi, 'https://[REDACTED]@').slice(0, max);
}
export function normalizeImageId(raw?: string): string | undefined {
  return raw?.match(/(?:^|[@/])?(sha256:[a-f0-9]{64})$/)?.[1];
}
