import { useEffect, useState } from 'react';
import { api, type ApiToken, type Role, type TokenScope, type User } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { Modal } from '../components/Modal.tsx';
import { dateTime } from '../format.ts';

const ROLES: { id: Role; label: string; help: string }[] = [
  { id: 'admin', label: 'Administrator', help: 'Everything, including users, sign-in, tokens, the digest and approving exceptions.' },
  { id: 'analyst', label: 'Analyst', help: 'Scans, tickets, owners and schedules; proposes exceptions for an administrator to approve.' },
  { id: 'viewer', label: 'Viewer', help: 'Reads every dashboard and report; changes nothing.' },
];
const SCOPES: { id: TokenScope; label: string; help: string }[] = [
  { id: 'read', label: 'Read', help: 'Reports, findings, portfolio and evidence.' },
  { id: 'scan', label: 'Scan', help: 'Start scans, for example from CI.' },
  { id: 'tickets', label: 'Tickets', help: 'Create tracker issues from findings.' },
];
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Settings → Users & access: the user table, the add-user form, and API tokens. */
export function UsersPage({ me }: { me?: User }) {
  return (
    <div className="stack">
      <UsersCard me={me} />
      <TokensCard />
    </div>
  );
}

function UsersCard({ me }: { me?: User }) {
  const [users, setUsers] = useState<User[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reset, setReset] = useState<User | null>(null);
  const [remove, setRemove] = useState<User | null>(null);
  const [adding, setAdding] = useState(false);
  const load = () => api.users().then(setUsers).catch((e) => setError(message(e)));
  useEffect(() => { load(); }, []);

  const patch = async (u: User, p: { role?: Role; disabled?: boolean }) => {
    setError(null);
    try {
      const saved = await api.updateUser(u.id, p);
      setUsers((list) => (list ?? []).map((x) => (x.id === u.id ? saved : x)));
    } catch (e) {
      setError(message(e));
    }
  };

  return (
    <section className="card">
      <div className="card-head">
        <div><h2>Users</h2><p className="sub">Who can sign in and what they may do. Single sign-on users appear here after their first sign-in.</p></div>
        <button type="button" className="btn small primary" onClick={() => setAdding(true)}><I.plus /> Add user</button>
      </div>
      {error && <p className="error" role="alert">{error}</p>}
      {!users ? <p className="empty">Loading…</p> : (
        <ul className="user-list" aria-label="Users">
          {users.map((u) => {
            const self = u.id === me?.id;
            return (
              <li key={u.id} className={`user-row ${u.disabled ? 'disabled' : ''}`}>
                <span className="avatar" aria-hidden="true">{u.displayName.split(/\s+/).map((w) => w[0]).slice(0, 2).join('').toUpperCase()}</span>
                <span className="user-id">
                  <span className="pkg">{u.displayName}{self && <span className="tag" style={{ marginLeft: 6 }}>you</span>}{u.disabled && <span className="tag warn" style={{ marginLeft: 6 }}>disabled</span>}</span>
                  <span className="muted small">@{u.username}{u.lastLoginAt ? ` · last sign-in ${dateTime(u.lastLoginAt)}` : ' · never signed in'}</span>
                </span>
                <label className="user-role-sel">
                  <span className="sr-only">Role for {u.username}</span>
                  <select value={u.role} disabled={self} title={self ? 'You cannot change your own role' : ROLES.find((r) => r.id === u.role)?.help} onChange={(e) => patch(u, { role: e.target.value as Role })}>
                    {ROLES.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
                  </select>
                </label>
                <span className="user-actions">
                  <button type="button" className="btn small" disabled={self} title={self ? 'You cannot disable your own account' : u.disabled ? 'Let this person sign in again' : 'Keep the account but block sign-in'} onClick={() => patch(u, { disabled: !u.disabled })}>{u.disabled ? 'Enable' : 'Disable'}</button>
                  <button type="button" className="btn small" onClick={() => setReset(u)}><I.key /> Reset password</button>
                  <button type="button" className="btn small ghost icon" disabled={self} title={self ? 'You cannot delete your own account' : `Delete ${u.username}`} aria-label={`Delete ${u.username}`} onClick={() => setRemove(u)}><I.trash /></button>
                </span>
              </li>
            );
          })}
        </ul>
      )}
      <details className="role-help">
        <summary>What each role can do</summary>
        <dl className="kv">{ROLES.map((r) => <div key={r.id} className="kv-row"><dt>{r.label}</dt><dd>{r.help}</dd></div>)}</dl>
      </details>
      {adding && <AddUserModal onClose={() => setAdding(false)} onAdded={(u) => { setUsers((l) => [...(l ?? []), u]); setAdding(false); }} />}
      {reset && <ResetPasswordModal user={reset} onClose={() => setReset(null)} />}
      {remove && (
        <Modal title={`Delete ${remove.displayName}?`} onClose={() => setRemove(null)}>
          <p>@{remove.username} will no longer be able to sign in. Audit entries and the exceptions they proposed or approved keep their name.</p>
          <div className="actions">
            <button type="button" className="btn danger" onClick={async () => { try { await api.deleteUser(remove.id); setUsers((l) => (l ?? []).filter((x) => x.id !== remove.id)); setRemove(null); } catch (e) { setError(message(e)); setRemove(null); } }}><I.trash /> Delete user</button>
            <button type="button" className="btn ghost" onClick={() => setRemove(null)}>Cancel</button>
          </div>
        </Modal>
      )}
    </section>
  );
}

function AddUserModal({ onClose, onAdded }: { onClose: () => void; onAdded: (u: User) => void }) {
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const ready = username.trim() && password.length >= 8 && !busy;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      onAdded(await api.createUser({ username: username.trim(), password, displayName: displayName.trim() || username.trim(), role }));
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="Add a user" onClose={onClose}>
      <form className="auth-form" onSubmit={submit} noValidate>
        <label className="field"><span>Username</span><input type="text" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" autoFocus /></label>
        <label className="field"><span>Display name <span className="muted">(optional)</span></span><input type="text" value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="off" /></label>
        <label className="field"><span>Temporary password</span><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={8} /><span className="hint">At least 8 characters. Share it with the person; they can change it after signing in.</span></label>
        <fieldset className="choice-set">
          <legend>Role</legend>
          {ROLES.map((r) => (
            <label key={r.id} className={`choice ${role === r.id ? 'on' : ''}`}><input type="radio" name="role" value={r.id} checked={role === r.id} onChange={() => setRole(r.id)} /><span><strong>{r.label}</strong><span className="muted small">{r.help}</span></span></label>
          ))}
        </fieldset>
        {error && <p className="error" role="alert">{error}</p>}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={!ready}>{busy ? 'Adding…' : 'Add user'}</button>
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Modal>
  );
}

function ResetPasswordModal({ user, onClose }: { user: User; onClose: () => void }) {
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password.length < 8 || busy) return;
    setBusy(true);
    setStatus(null);
    try {
      await api.setPassword(user.id, { password });
      setStatus({ ok: true, text: `Password set for @${user.username}.` });
      setPassword('');
    } catch (err) {
      setStatus({ ok: false, text: message(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={`Reset password for ${user.displayName}`} onClose={onClose}>
      <form className="auth-form" onSubmit={submit} noValidate>
        <label className="field"><span>New password</span><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={8} autoFocus /><span className="hint">At least 8 characters. Their current sessions stay signed in.</span></label>
        <div className="actions">
          <button type="submit" className="btn primary" disabled={password.length < 8 || busy}>{busy ? 'Saving…' : 'Set password'}</button>
          <button type="button" className="btn ghost" onClick={onClose}>{status?.ok ? 'Done' : 'Cancel'}</button>
          {status && <span className={status.ok ? 'hint' : 'error'} role="status">{status.text}</span>}
        </div>
      </form>
    </Modal>
  );
}

function TokensCard() {
  const [tokens, setTokens] = useState<ApiToken[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<TokenScope[]>(['read']);
  const [busy, setBusy] = useState(false);
  const [reveal, setReveal] = useState<{ name: string; token: string } | null>(null);
  const [revoke, setRevoke] = useState<ApiToken | null>(null);
  useEffect(() => { api.tokens().then(setTokens).catch((e) => setError(message(e))); }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !scopes.length || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.createToken({ name: name.trim(), scopes });
      setReveal({ name: name.trim(), token: r.token });
      setTokens(await api.tokens());
      setName('');
      setScopes(['read']);
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card">
      <div className="card-head"><div><h2>API tokens</h2><p className="sub">For CI pipelines and scripts. Send one as <code>Authorization: Bearer …</code>. A token is shown once, when it is created.</p></div></div>
      {error && <p className="error" role="alert">{error}</p>}
      <form className="token-form" onSubmit={create}>
        <label className="field grow"><span>Name</span><input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="CI pipeline" autoComplete="off" /></label>
        <fieldset className="scopes">
          <legend>Scopes</legend>
          {SCOPES.map((s) => (
            <label key={s.id} className="check" title={s.help}><input type="checkbox" checked={scopes.includes(s.id)} onChange={(e) => setScopes((cur) => (e.target.checked ? [...cur, s.id] : cur.filter((x) => x !== s.id)))} /> {s.label}</label>
          ))}
        </fieldset>
        <button type="submit" className="btn primary" disabled={!name.trim() || !scopes.length || busy}><I.plus /> {busy ? 'Creating…' : 'Create token'}</button>
      </form>
      {!tokens ? <p className="empty">Loading…</p> : tokens.length === 0 ? <p className="empty">No tokens yet.</p> : (
        <div className="table-wrap">
          <table className="tbl">
            <thead><tr><th>Name</th><th>Scopes</th><th>Created</th><th>Last used</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id}>
                  <td className="pkg">{t.name}<div className="muted small">by {t.createdBy}</div></td>
                  <td>{t.scopes.map((s) => <span key={s} className="tag" style={{ marginRight: 4 }}>{SCOPES.find((x) => x.id === s)?.label ?? s}</span>)}</td>
                  <td className="muted">{dateTime(t.createdAt)}</td>
                  <td className="muted">{t.lastUsedAt ? dateTime(t.lastUsedAt) : 'never'}</td>
                  <td className="num"><button type="button" className="btn small ghost" onClick={() => setRevoke(t)}>Revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {reveal && <RevealModal name={reveal.name} token={reveal.token} onClose={() => setReveal(null)} />}
      {revoke && (
        <Modal title={`Revoke “${revoke.name}”?`} onClose={() => setRevoke(null)}>
          <p>Anything still using this token will get 401 from the next request on. This cannot be undone; create a new token if it is still needed.</p>
          <div className="actions">
            <button type="button" className="btn danger" onClick={async () => { try { await api.revokeToken(revoke.id); setTokens((l) => (l ?? []).filter((x) => x.id !== revoke.id)); } catch (e) { setError(message(e)); } setRevoke(null); }}>Revoke token</button>
            <button type="button" className="btn ghost" onClick={() => setRevoke(null)}>Cancel</button>
          </div>
        </Modal>
      )}
    </section>
  );
}

function RevealModal({ name, token, onClose }: { name: string; token: string; onClose: () => void }) {
  const [copied, setCopied] = useState<'ok' | 'failed' | null>(null);
  const copy = async () => {
    try { await navigator.clipboard.writeText(token); setCopied('ok'); } catch { setCopied('failed'); }
  };
  return (
    <Modal title={`Token “${name}”`} onClose={onClose}>
      <p>Copy it now. For safety the server keeps only a hash, so it cannot be shown again.</p>
      <div className="reveal">
        <code className="reveal-token" aria-label="Token">{token}</code>
        <button type="button" className="btn primary" onClick={copy}>{copied === 'ok' ? <><I.check /> Copied</> : <><I.copy /> Copy</>}</button>
      </div>
      {copied === 'failed' && <p className="error">Clipboard blocked by the browser; select the token and copy it by hand.</p>}
      <div className="actions"><button type="button" className="btn" onClick={onClose}>Done</button></div>
    </Modal>
  );
}
