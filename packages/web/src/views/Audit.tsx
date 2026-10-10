import { useEffect, useState } from 'react';
import { api, type AuditRow } from '../api.ts';
import { dateTime } from '../format.ts';

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Settings → Audit log: who did what, newest first, a page at a time. */
export function AuditPage() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [next, setNext] = useState<number | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');

  const load = async (before?: number | null) => {
    setBusy(true);
    setError(null);
    try {
      const page = await api.audit(before ?? undefined);
      setRows((cur) => (before ? [...cur, ...page.rows] : page.rows));
      setNext(page.next ?? null);
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => { load(); }, []);

  const needle = q.trim().toLowerCase();
  const shown = needle ? rows.filter((r) => `${r.username} ${r.action} ${r.target ?? ''} ${r.detail ?? ''} ${r.ip ?? ''}`.toLowerCase().includes(needle)) : rows;

  return (
    <section className="card">
      <div className="card-head">
        <div><h2>Audit log</h2><p className="sub">Sign-ins, scans, exceptions, settings and user changes, with who and from where.</p></div>
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter loaded rows…" aria-label="Filter audit rows" />
      </div>
      {error && <p className="error" role="alert">{error}</p>}
      <ul className="audit-cards" aria-label="Audit entries">
        {shown.map((r) => (
          <li key={r.id}>
            <span className="audit-top"><span className="pkg">{r.username}</span> <code>{r.action}</code></span>
            {r.target && <span>{r.target}</span>}
            <span className="muted small">{dateTime(r.at)}{r.detail ? ` · ${r.detail}` : ''}{r.ip ? ` · ${r.ip}` : ''}</span>
          </li>
        ))}
        {!shown.length && !busy && <li className="empty">{rows.length ? 'Nothing matches the filter.' : 'No entries yet.'}</li>}
      </ul>
      <div className="table-wrap audit-table">
        <table className="tbl audit">
          <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Detail</th><th>From</th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.id}>
                <td className="muted nowrap">{dateTime(r.at)}</td>
                <td className="pkg">{r.username}</td>
                <td><code>{r.action}</code></td>
                <td>{r.target ?? <span className="muted">—</span>}</td>
                <td className="muted">{r.detail ?? ''}</td>
                <td className="mono small muted">{r.ip ?? ''}</td>
              </tr>
            ))}
            {!shown.length && !busy && <tr><td colSpan={6} className="empty">{rows.length ? 'Nothing matches the filter.' : 'No entries yet.'}</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="actions">
        {next ? <button type="button" className="btn" disabled={busy} onClick={() => load(next)}>{busy ? 'Loading…' : 'Load more'}</button> : rows.length > 0 && !busy ? <span className="hint">That is the whole log.</span> : null}
        <span className="muted small">{rows.length} loaded{needle ? `, ${shown.length} shown` : ''}</span>
      </div>
    </section>
  );
}
