import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import type { Database, Queryable } from '../../../packages/storage/src/db.js';
import { ORG } from '../../../packages/storage/src/db.js';
import { AppError, type Role } from '../../../packages/core/src/types.js';
import { hash } from '../../../packages/core/src/util.js';
const scrypt = promisify(scryptCallback);
export async function passwordHash(password: string) {
  const salt = randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64) as Buffer;
  return `${salt}:${derived.toString('hex')}`;
}
export async function passwordMatches(password: string, stored: string) {
  const [salt, digest] = stored.split(':');
  const derived = await scrypt(password, salt ?? 'siliconer-dummy-salt', 64) as Buffer;
  const expected = Buffer.from(digest ?? '00'.repeat(64), 'hex');
  return expected.length === derived.length && timingSafeEqual(derived, expected);
}
export async function createUser(db: Queryable, email: string, password: string, role: Role = 'admin') {
  if (password.length < 14 || password.length > 256) throw new Error('Password must contain 14 to 256 characters');
  const id = randomUUID();
  const [created] = await db.query('INSERT INTO users(id,organization_id,email,password_hash,role) VALUES($1,$2,$3,$4,$5) ON CONFLICT(email) DO NOTHING RETURNING id', [id, ORG, email.toLowerCase(), await passwordHash(password), role]);
  if (!created) throw new AppError('email_already_registered', 409);
  return id;
}
export async function newSession(db: Queryable, userId: string) {
  const token = randomBytes(32).toString('base64url'); const csrf = randomBytes(32).toString('base64url');
  await db.query('INSERT INTO sessions(token_hash,user_id,csrf_hash,expires_at) VALUES($1,$2,$3,now()+interval \'12 hours\')', [hash(token), userId, hash(csrf)]);
  return { token, csrf };
}
export interface Actor { id: string; email: string; role: Role; organization_id: string; csrf_hash: string }
export async function sessionActor(db: Database, token: string | undefined): Promise<Actor | undefined> {
  if (!token || token.length > 100) return undefined;
  return (await db.query<Actor>(`SELECT u.id,u.email,u.role,u.organization_id,s.csrf_hash FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=$1 AND s.expires_at>now() AND u.organization_id=$2 AND u.disabled_at IS NULL`, [hash(token), ORG]))[0];
}
