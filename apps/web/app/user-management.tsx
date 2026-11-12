import { useState, type FormEvent } from 'react';

const roleLabels = { viewer: '조회 전용', developer: '서비스 담당자', reviewer: '보안 검토자', admin: '관리자' };
type UserRole = keyof typeof roleLabels;
export interface UserRow {
  id: string;
  email: string;
  role: UserRole;
  created_at: string;
  disabled_at: string | null;
}

export default function UserManagement({ users, currentUserId, busy, loading, create, update }: {
  users: UserRow[];
  currentUserId: string;
  busy: boolean;
  loading: boolean;
  create: (body: Record<string, unknown>) => Promise<void>;
  update: (id: string, body: { role?: UserRole; enabled?: boolean }) => Promise<void>;
}) {
  const [editing, setEditing] = useState<{ id: string; role: UserRole } | null>(null);

  async function addUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      await create(Object.fromEntries(new FormData(form)));
      form.reset();
    } catch {}
  }

  async function saveRole(event: FormEvent<HTMLFormElement>, user: UserRow, role: UserRole) {
    event.preventDefault();
    try {
      await update(user.id, { role });
      setEditing(null);
    } catch {}
  }

  async function toggleAccount(user: UserRow) {
    const enabled = Boolean(user.disabled_at);
    if (!enabled && !window.confirm(`${user.email} 계정을 비활성화할까요? 로그인 중인 세션이 종료됩니다.`)) return;
    try {
      await update(user.id, { enabled });
    } catch {}
  }

  return <>
    <details className="technical-details">
      <summary>사용자 계정 추가</summary>
      <form onSubmit={addUser}>
        <div className="form-grid">
          <label>이메일<input name="email" type="email" maxLength={200} required /></label>
          <label>초기 비밀번호<input name="password" type="password" minLength={14} maxLength={256} autoComplete="new-password" required /></label>
          <label>역할<select name="role">{Object.entries(roleLabels).map(([role, label]) => <option key={role} value={role}>{label}</option>)}</select></label>
        </div>
        <button className="primary" type="submit" disabled={busy}>계정 생성</button>
      </form>
    </details>
    <div className="table-wrap" aria-busy={loading}>
      <table aria-label="사용자 계정 목록">
        <thead><tr><th>이메일</th><th>역할</th><th>상태</th><th>생성일</th><th>관리</th></tr></thead>
        <tbody>{users.map(user => <tr key={user.id}>
          <td>{user.email}{user.id === currentUserId ? <small className="muted block">내 계정</small> : null}</td>
          <td>{roleLabels[user.role]}</td>
          <td><span className={`badge badge-${user.disabled_at ? 'blocked' : 'connected'}`}>{user.disabled_at ? '비활성' : '활성'}</span></td>
          <td>{new Date(user.created_at).toLocaleDateString('ko-KR')}</td>
          <td>{user.id === currentUserId ? '—' : editing?.id === user.id ? (
            <form className="actions" onSubmit={event => void saveRole(event, user, editing.role)}>
              <select aria-label={`${user.email} 새 역할`} value={editing.role} disabled={busy} onChange={event => setEditing({ id: user.id, role: event.target.value as UserRole })}>
                {Object.entries(roleLabels).map(([role, label]) => <option key={role} value={role}>{label}</option>)}
              </select>
              <button type="submit" disabled={busy || editing.role === user.role}>저장</button>
              <button type="button" disabled={busy} onClick={() => setEditing(null)}>취소</button>
            </form>
          ) : (
            <div className="actions">
              <button disabled={busy} onClick={() => setEditing({ id: user.id, role: user.role })}>역할 변경</button>
              <button disabled={busy} onClick={() => void toggleAccount(user)}>{user.disabled_at ? '활성화' : '비활성화'}</button>
            </div>
          )}</td>
        </tr>)}</tbody>
      </table>
      {!loading && !users.length ? <div className="empty">표시할 계정이 없습니다.</div> : null}
    </div>
    <p className="muted">역할을 변경하거나 계정을 비활성화하면 해당 계정의 로그인 세션이 종료됩니다.</p>
  </>;
}
