import { useEffect, useRef, useState } from 'react';
import { api, type User } from '../api.ts';
import { I } from './Icons.tsx';
import { Modal } from './Modal.tsx';

const ROLE_LABEL = { admin: 'Administrator', analyst: 'Analyst', viewer: 'Viewer' } as const;
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Name and role in the top bar; opens a small menu with change password and sign out. */
export function UserMenu({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const [open, setOpen] = useState(false);
  const [changing, setChanging] = useState(false);
  const [stopped, setStopped] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey); };
  }, [open]);
  const initials = user.displayName.split(/\s+/).map((w) => w[0]).filter(Boolean).slice(0, 2).join('').toUpperCase() || user.username[0]!.toUpperCase();
  return (
    <div className="user-menu" ref={ref}>
      <button type="button" className="user-btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span className="avatar" aria-hidden="true">{initials}</span>
        <span className="user-text"><span className="user-name">{user.displayName}</span><span className="user-role">{ROLE_LABEL[user.role]}</span></span>
        <I.chevronDown className="muted" />
      </button>
      {open && (
        <div className="menu" role="menu" aria-label="Account">
          <div className="menu-head"><strong>{user.displayName}</strong><span className="muted small">@{user.username} · {ROLE_LABEL[user.role]}</span></div>
          <button type="button" role="menuitem" onClick={() => { setOpen(false); setChanging(true); }}><I.key /> Change password</button>
          <button type="button" role="menuitem" onClick={() => { setOpen(false); onSignOut(); }}><I.logout /> Sign out</button>
          {user.role === 'admin' && <button type="button" role="menuitem" onClick={() => { setOpen(false); void stopServer(); }}><I.close /> Stop the dashboards</button>}
        </div>
      )}
      {changing && <ChangePasswordModal user={user} onClose={() => setChanging(false)} />}
      {stopped && (
        <div className="stopped-notice" role="alert">
          <strong>The dashboards have stopped.</strong>
          <p>{stopped}</p>
          <p className="small muted">Start them again from the Start Menu ("NextFix dashboards") or with <code>nextfix serve</code>.</p>
        </div>
      )}
    </div>
  );

  async function stopServer() {
    if (!window.confirm('Stop the dashboards? The server process exits and this page stops working until it is started again.')) return;
    try {
      const r = await api.shutdown();
      setStopped(r.message);
    } catch (e) {
      window.alert(e instanceof Error ? e.message : String(e));
    }
  }
}

export function ChangePasswordModal({ user, onClose }: { user: User; onClose: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const mismatch = confirm.length > 0 && confirm !== next;
  const ready = current.length > 0 && next.length >= 8 && confirm === next && !busy;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setStatus(null);
    try {
      await api.setPassword(user.id, { currentPassword: current, password: next });
      setStatus({ ok: true, text: 'Password changed.' });
      setCurrent(''); setNext(''); setConfirm('');
    } catch (err) {
      setStatus({ ok: false, text: message(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="Change password" onClose={onClose}>
      <form className="auth-form" onSubmit={submit} noValidate>
        <label className="field"><span>Current password</span><input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" autoFocus /></label>
        <label className="field"><span>New password</span><input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" minLength={8} /><span className="hint">At least 8 characters.</span></label>
        <label className="field"><span>Confirm new password</span><input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" aria-invalid={mismatch || undefined} />{mismatch && <span className="error" role="alert">The passwords do not match.</span>}</label>
        <div className="actions">
          <button type="submit" className="btn primary" disabled={!ready}>{busy ? 'Saving…' : 'Change password'}</button>
          <button type="button" className="btn ghost" onClick={onClose}>{status?.ok ? 'Done' : 'Cancel'}</button>
          {status && <span className={status.ok ? 'hint' : 'error'} role="status">{status.text}</span>}
        </div>
      </form>
    </Modal>
  );
}
