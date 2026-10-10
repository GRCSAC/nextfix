import { useState } from 'react';
import type { Target } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { dateTime } from '../format.ts';

interface Props {
  targets: Target[];
  currentId: number | null;
  busy: boolean;
  onSelect: (id: number) => void;
  onAdd: (dir: string) => void;
  onRemove: (id: number) => void;
}

export function Apps({ targets, currentId, busy, onSelect, onAdd, onRemove }: Props) {
  const [dir, setDir] = useState('');
  const [confirm, setConfirm] = useState<number | null>(null);
  return (
    <div className="stack">
      <section className="card">
        <h2>Add an application</h2>
        <p className="sub">A Node.js project with a <code>package-lock.json</code>, or a Python project with pinned requirements or a lockfile. The first scan runs right away.</p>
        <form className="inline-form" onSubmit={(e) => { e.preventDefault(); if (dir.trim()) { onAdd(dir.trim()); setDir(''); } }}>
          <input type="text" value={dir} onChange={(e) => setDir(e.target.value)} placeholder="C:\path\to\your\app" aria-label="Project folder" />
          <button type="submit" className="btn primary" disabled={busy || !dir.trim()}><I.plus /> Scan</button>
        </form>
      </section>
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
                </span>
                <span className="muted small">{t.lastScan ? `${t.lastScan.summary.findings} findings · ${t.lastScan.summary.byDecision.Act} fix now · ${dateTime(t.lastScan.createdAt)}` : 'never scanned'}</span>
              </button>
              {confirm === t.id ? (
                <span className="actions">
                  <button type="button" className="btn small danger" onClick={() => { onRemove(t.id); setConfirm(null); }}>Remove and delete history</button>
                  <button type="button" className="btn small ghost" onClick={() => setConfirm(null)}>Cancel</button>
                </span>
              ) : (
                <button type="button" className="btn ghost icon" aria-label={`Remove ${t.name ?? t.dir}`} onClick={() => setConfirm(t.id)}><I.trash /></button>
              )}
            </li>
          ))}
          {!targets.length && <li className="empty">No applications yet.</li>}
        </ul>
      </section>
    </div>
  );
}
