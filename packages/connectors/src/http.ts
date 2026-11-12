import { AppError } from '../../core/src/types.js';
export type Transport = typeof fetch;
export async function jsonRequest<T = any>(url: string, init: RequestInit = {}, transport: Transport = fetch, maxBytes = 8 * 1024 * 1024): Promise<T> {
  const response = await transport(url, { ...init, redirect: 'error', signal: init.signal ?? AbortSignal.timeout(20000) });
  if (!response.ok) throw new AppError(`upstream_${response.status}`, 502);
  if (Number(response.headers.get('content-length') ?? 0) > maxBytes) throw new AppError('upstream_size_limit', 502);
  const reader = response.body?.getReader();
  if (!reader) throw new AppError('upstream_empty', 502);
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    for (;;) {
      const next = await reader.read(); if (next.done) break;
      length += next.value.length;
      if (length > maxBytes) throw new AppError('upstream_size_limit', 502);
      chunks.push(next.value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) as T; }
  catch { throw new AppError('upstream_invalid_json', 502); }
}
