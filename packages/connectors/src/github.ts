import { readFile } from 'node:fs/promises';
import { importPKCS8, SignJWT } from 'jose';
import { createHmac, createPrivateKey, verify } from 'node:crypto';
import { AppError, shaSchema } from '../../core/src/types.js';
import { secureEqual, canonical } from '../../core/src/util.js';
import { jsonRequest, type Transport } from './http.js';
import { type GithubConfig, secret } from './config.js';

export function githubRepository(url:string):string|undefined{
  return /^(?:https:\/\/github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([\w.-]+\/[\w.-]+?)(?:\.git)?\/?$/.exec(url)?.[1];
}

export class GithubReader {
  private cached?: { token: string; expires: number };
  constructor(readonly config: GithubConfig, private transport: Transport = fetch) {}
  private assertRepo(repository: string) {
    if (!this.config.repositories.some(r => r.name === repository)) throw new AppError('repository_not_allowed', 403);
  }
  async token() {
    if (this.cached && this.cached.expires > Date.now() + 60000) return this.cached.token;
    const result = await installationToken(this.config, this.config.repositories.map(r => r.name), { contents: 'read', actions: 'read', metadata: 'read' }, this.transport);
    if (!result.token || !Number.isFinite(Date.parse(result.expires_at))) throw new AppError('invalid_installation_token', 502);
    this.cached = { token: result.token, expires: Date.parse(result.expires_at) }; return result.token;
  }
  async get<T = any>(repository: string, suffix: string): Promise<T> {
    this.assertRepo(repository);
    if (!suffix.startsWith('/') || suffix.includes('..') || /^\/\//.test(suffix)) throw new AppError('invalid_github_path');
    return jsonRequest(`https://api.github.com/repos/${repository}${suffix}`, { headers: githubHeaders(await this.token()) }, this.transport);
  }
  async revision(repository: string, ref: string) {
    const commit = await this.get(repository, `/commits/${encodeURIComponent(ref)}`);
    return shaSchema.parse(commit.sha);
  }
  async file(repository: string, revision: string, path: string): Promise<string> {
    shaSchema.parse(revision);
    if (path.startsWith('/') || path.split('/').some(s => s === '..') || path.includes('\\')) throw new AppError('invalid_repository_path');
    const file = await this.get(repository, `/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${revision}`);
    if (file.type !== 'file' || file.encoding !== 'base64' || file.size > 1024 * 1024 || typeof file.content !== 'string') throw new AppError('repository_file_unavailable', 422);
    return Buffer.from(file.content, 'base64').toString('utf8');
  }
  async verifyBuild(repository: string, runId: string, commit: string, attempt: number, envelope: unknown, signature: string | undefined, publicKey: string | undefined, workflowPath: string, allowedRefs: string[]) {
    if (!signature || !publicKey) return false;
    try { if (!verify(null, Buffer.from(canonical(envelope)), publicKey, Buffer.from(signature, 'base64'))) return false; } catch { return false; }
    if (!/^\d+$/.test(runId)) return false;
    const run = await this.get(repository, `/actions/runs/${runId}/attempts/${attempt}`);
    if (run.head_sha !== commit || run.conclusion !== 'success' || run.event === 'pull_request' || run.event === 'pull_request_target' || !allowedRefs.includes(run.head_branch) || run.path?.split('@')[0] !== workflowPath || run.repository?.full_name !== repository || run.head_repository?.full_name !== repository) return false;
    return true;
  }
}
export function githubHeaders(token:string) {
  return { Authorization:`Bearer ${token}`, Accept:'application/vnd.github+json', 'X-GitHub-Api-Version':'2026-03-10', 'Content-Type':'application/json', 'User-Agent':'Siliconer/0.1' };
}
export async function installationToken(config:Pick<GithubConfig,'appId'|'installationId'|'privateKeyFileEnv'>, repositories:string[], permissions:Record<string,'read'|'write'>, transport:Transport=fetch) {
  const pem = createPrivateKey(await readFile(secret(config.privateKeyFileEnv), 'utf8')).export({ format: 'pem', type: 'pkcs8' }).toString();
  const key = await importPKCS8(pem, 'RS256');
  const jwt = await new SignJWT({}).setProtectedHeader({ alg: 'RS256' }).setIssuer(config.appId)
    .setIssuedAt(Math.floor(Date.now() / 1000) - 30).setExpirationTime('8m').sign(key);
  return jsonRequest<{token:string;expires_at:string}>(`https://api.github.com/app/installations/${config.installationId}/access_tokens`,{
    method:'POST',headers:githubHeaders(jwt),body:JSON.stringify({repositories:repositories.map(repo=>repo.split('/')[1]),permissions}),
  },transport);
}
export function verifyWebhook(raw: Buffer, signature: string | undefined, key: string) {
  if (!signature || !/^sha256=[a-f0-9]{64}$/.test(signature)) return false;
  return secureEqual(signature, `sha256=${createHmac('sha256', key).update(raw).digest('hex')}`);
}
