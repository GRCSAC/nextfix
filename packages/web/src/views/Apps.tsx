import { useState } from 'react';
import { api, type Role, type Schedule, type Target } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { Modal } from '../components/Modal.tsx';
import { dateTime } from '../format.ts';

interface Props {
  targets: Target[];
  currentId: number | null;
  busy: boolean;
  role: Role;
  onSelect: (id: number) => void;
  onAdd: (dir: string) => void;
  onRemove: (id: number) => void;
  onUpdated: (t: Target) => void;
}

const SCHEDULES: { hours: number | null; label: string }[] = [
  { hours: null, label: 'Manual only' },
  { hours: 6, label: 'Every 6 hours' },
  { hours: 12, label: 'Every 12 hours' },
  { hours: 24, label: 'Daily' },
  { hours: 168, label: 'Weekly' },
];
const scheduleLabel = (s?: Schedule | null) => (s ? SCHEDULES.find((x) => x.hours === s.everyHours)?.label ?? `Every ${s.everyHours} h` : 'Manual only');
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function Apps({ targets, currentId, busy, role, onSelect, onAdd, onRemove, onUpdated }: Props) {
  const [dir, setDir] = useState('');
  const [confirm, setConfirm] = useState<number | null>(null);
  const [editing, setEditing] = useState<Target | null>(null);
  const canEdit = role !== 'viewer';
  const canRemove = role === 'admin';
  return (
    <div className="stack">
      {canEdit ? (
        <section className="card">
          <h2>Add an application</h2>
          <p className="sub">A Node.js project (npm, yarn or pnpm lockfile), a Python project with pinned requirements or a lockfile, a Go module, or a folder with a container image or SBOM in its config. The first scan runs right away.</p>
          <form className="inline-form" onSubmit={(e) => { e.preventDefault(); if (dir.trim()) { onAdd(dir.trim()); setDir(''); } }}>
            <input type="text" value={dir} onChange={(e) => setDir(e.target.value)} placeholder="C:\path\to\your\app" aria-label="Project folder" />
            <button type="submit" className="btn primary" disabled={busy || !dir.trim()}><I.plus /> Scan</button>
          </form>
        </section>
      ) : (
        <p className="hint"><I.info /> Viewers can open every application but not add, scan or change one. Ask an analyst or administrator.</p>
      )}
      <section className="card">
        <h2>Applications</h2>
        <ul className="app-list">
          {targets.map((t) => (
            <li key={t.id} className={t.id === currentId ? 'current' : ''}>
              <button type="button" className="app-row" onClick={() => onSelect(t.id)}>
                <span className="icon-box"><I.cube size={20} /></span>
                <span className="grow">
                  <span className="pkg">{t.name ?? t.dir}</span>
                  <div className="small muted mono">{t.dir}</div>
                  <div className="small muted app-meta"><span><I.user size={13} /> {t.owner || 'unassigned'}</span><span><I.clock size={13} /> {scheduleLabel(t.schedule)}</span><span><I.list size={13} /> {t.accessLogs?.length ? `${t.accessLogs.length} access log${t.accessLogs.length === 1 ? '' : 's'}` : 'no access logs'}</span></div>
                </span>
                <span className="muted small app-last">{t.lastScan ? `${t.lastScan.summary.findings} findings · ${t.lastScan.summary.byDecision.Act} fix now · ${dateTime(t.lastScan.createdAt)}` : 'never scanned'}</span>
              </button>
              {confirm === t.id ? (
                <span className="actions">
                  <button type="button" className="btn small danger" onClick={() => { onRemove(t.id); setConfirm(null); }}>Remove and delete history</button>
                  <button type="button" className="btn small ghost" onClick={() => setConfirm(null)}>Cancel</button>
                </span>
              ) : (
                <span className="app-actions">
                  <button type="button" className="btn ghost icon" aria-label={`Edit owner, schedule and access logs for ${t.name ?? t.dir}`} title={canEdit ? 'Owner, scan schedule and access logs' : 'Viewers cannot change the owner, schedule or access logs'} disabled={!canEdit} onClick={() => setEditing(t)}><I.edit /></button>
                  <button type="button" className="btn ghost icon" aria-label={`Remove ${t.name ?? t.dir}`} title={canRemove ? 'Remove the application and its history' : 'Only an administrator can remove an application'} disabled={!canRemove} onClick={() => setConfirm(t.id)}><I.trash /></button>
                </span>
              )}
            </li>
          ))}
          {!targets.length && <li className="empty">No applications yet.</li>}
        </ul>
      </section>
      {editing && <EditTargetModal t={editing} onClose={() => setEditing(null)} onSaved={(t) => { onUpdated(t); setEditing(null); }} />}
    </div>
  );
}

function EditTargetModal({ t, onClose, onSaved }: { t: Target; onClose: () => void; onSaved: (t: Target) => void }) {
  const [owner, setOwner] = useState(t.owner ?? '');
  const [hours, setHours] = useState<number | null>(t.schedule?.everyHours ?? null);
  const [logs, setLogs] = useState((t.accessLogs ?? []).join('\n'));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const accessLogs = logs.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      onSaved(await api.updateTarget(t.id, { owner: owner.trim() || null, schedule: hours ? { everyHours: hours } : null, accessLogs: accessLogs.length ? accessLogs : null }));
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={t.name ?? t.dir} onClose={onClose}>
      <form className="auth-form" onSubmit={submit} noValidate>
        <label className="field"><span>Owner</span><input type="text" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Team or person who fixes it" autoFocus autoComplete="off" /><span className="hint">Shown in the portfolio and the weekly digest.</span></label>
        <label className="field"><span>Scan schedule</span><select value={hours ?? ''} onChange={(e) => setHours(e.target.value ? Number(e.target.value) : null)}>{SCHEDULES.map((s) => <option key={String(s.hours)} value={s.hours ?? ''}>{s.label}</option>)}</select><span className="hint">The server scans on this cadence while it runs; Scan again still works any time.</span></label>
        <label className="field"><span>Access logs</span><textarea value={logs} onChange={(e) => setLogs(e.target.value)} rows={3} placeholder={'/var/log/nginx/access.log\nC:\\logs\\alb'} spellCheck={false} /><span className="hint">One file or folder per line, on the machine NextFix runs on: nginx or Apache combined logs, AWS ALB logs, or JSON lines (Caddy, Cloudflare, Traefik, pino). The next scan counts the last 30 days of requests per route, so exposure is observed rather than inferred.</span></label>
        {error && <p className="error" role="alert">{error}</p>}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Modal>
  );
}
