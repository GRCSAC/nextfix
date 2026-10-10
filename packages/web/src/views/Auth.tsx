import { useEffect, useState } from 'react';
import { api, ApiError, type Session } from '../api.ts';
import { I, Wordmark } from '../components/Icons.tsx';

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** First run: creates the administrator account and signs them in. */
export function SetupPage({ onDone }: { onDone: (s: Session) => void }) {
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mismatch = confirm.length > 0 && confirm !== password;
  const ready = username.trim().length > 0 && password.length >= 8 && confirm === password && !busy;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      onDone(await api.setup({ username: username.trim(), password, displayName: displayName.trim() || username.trim() }));
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthFrame title="Set up NextFix" lead="Create the first administrator. This account manages users, sign-in and the weekly digest; you can add analysts and viewers afterwards.">
      <form className="auth-form" onSubmit={submit} noValidate>
        <label className="field"><span>Username</span><input type="text" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required /></label>
        <label className="field"><span>Display name <span className="muted">(optional)</span></span><input type="text" value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" /></label>
        <label className="field"><span>Password</span><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required minLength={8} aria-describedby="pw-hint" /><span className="hint" id="pw-hint">At least 8 characters.</span></label>
        <label className="field"><span>Confirm password</span><input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required aria-invalid={mismatch || undefined} />{mismatch && <span className="error" role="alert">The passwords do not match.</span>}</label>
        {error && <p className="error" role="alert">{error}</p>}
        <button type="submit" className="btn primary" disabled={!ready}>{busy ? 'Creating…' : 'Create administrator'}</button>
      </form>
    </AuthFrame>
  );
}

/** Local sign-in, plus one button per single sign-on provider the server offers. */
export function LoginPage({ session, onDone, notice }: { session: Session; onDone: (s: Session) => void; notice?: string | null }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [lockedUntil, setLockedUntil] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [tick, setTick] = useState(0);
  const providers = session.oidc?.providers ?? [];
  const locked = lockedUntil !== null && lockedUntil > Date.now();
  useEffect(() => {
    if (!locked) return;
    const t = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [locked]);
  void tick;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy || locked) return;
    setBusy(true);
    setError(null);
    try {
      onDone(await api.login({ username: username.trim(), password }));
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        const secs = err.retryAfter ?? 60;
        setLockedUntil(Date.now() + secs * 1000);
        setError(`Too many attempts. Try again in ${fmtSecs(secs)}.`);
      } else if (err instanceof ApiError && err.status === 401) {
        setError('Wrong username or password.');
      } else setError(message(err));
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  const remaining = locked ? Math.ceil((lockedUntil! - Date.now()) / 1000) : 0;

  return (
    <AuthFrame title="Sign in" lead="From findings to fixes. Sign in to see what to fix next, and why.">
      {notice && <p className="banner" role="status">{notice}</p>}
      {providers.length > 0 && (
        <div className="sso-buttons">
          {providers.map((p) => <a key={p.id} className="btn" href={api.oidcStartUrl(p.id)}><I.login /> Sign in with {p.name}</a>)}
        </div>
      )}
      {providers.length > 0 && session.authMode !== 'oidc' ? <div className="auth-or" role="separator">or with a local account</div> : providers.length > 0 ? <div className="auth-or" role="separator">or</div> : null}
      <form className="auth-form" onSubmit={submit} noValidate>
        <label className="field"><span>Username</span><input type="text" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required /></label>
        <label className="field"><span>Password</span><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
        {error && <p className="error" role="alert">{locked ? `Too many attempts. Try again in ${fmtSecs(remaining)}.` : error}</p>}
        <button type="submit" className="btn primary" disabled={busy || locked || !username.trim() || !password}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
      <p className="hint">Forgot your password? An administrator can reset it under Settings → Users &amp; access.</p>
    </AuthFrame>
  );
}

function fmtSecs(s: number): string {
  if (s >= 120) return `${Math.ceil(s / 60)} minutes`;
  if (s >= 60) return '1 minute';
  return `${Math.max(1, s)} second${s === 1 ? '' : 's'}`;
}

function AuthFrame({ title, lead, children }: { title: string; lead: string; children: React.ReactNode }) {
  return (
    <main className="auth" id="main">
      <div className="auth-card card">
        <div className="auth-brand"><Wordmark size={40} /><span className="wordmark">Next<b>Fix</b></span></div>
        <div className="tagline">Find › Prioritize › Fix › Prove</div>
        <h1>{title}</h1>
        <p className="lead">{lead}</p>
        {children}
      </div>
    </main>
  );
}
