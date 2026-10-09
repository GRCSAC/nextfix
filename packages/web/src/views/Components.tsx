import { useMemo, useState } from 'react';
import type { ScanReport } from '../api.ts';
import { STATE_LABEL, STATE_ORDER, componentWorstTier, type ComponentState } from '../format.ts';

export function Components({ report, go }: { report: ScanReport; go: (page: string, id?: string, query?: Record<string, string>) => void }) {
  const [q, setQ] = useState('');
  const [state, setState] = useState<ComponentState | 'all'>('all');
  const [scope, setScope] = useState<'all' | 'direct' | 'dev'>('all');

  const rows = useMemo(() => {
    const list = report.components ?? [];
    const counts = new Map<string, number>();
    for (const f of report.findings) counts.set(f.component.purl, (counts.get(f.component.purl) ?? 0) + 1);
    const needle = q.trim().toLowerCase();
    return list
      .map((c) => ({ c, st: componentWorstTier(report, c.purl), n: counts.get(c.purl) ?? 0 }))
      .filter((r) => (state === 'all' || r.st === state) && (scope === 'all' || (scope === 'direct' ? r.c.direct : r.c.dev)) && (!needle || r.c.name.toLowerCase().includes(needle)))
      .sort((a, b) => STATE_ORDER.indexOf(a.st) - STATE_ORDER.indexOf(b.st) || b.n - a.n || a.c.name.localeCompare(b.c.name));
  }, [report, q, state, scope]);

  if (!report.components) return <div className="card"><p className="empty">This scan predates component listing. Run <strong>Scan again</strong> to see every component.</p></div>;

  return (
    <div className="stack">
      <div className="filters">
        <select aria-label="State" value={state} onChange={(e) => setState(e.target.value as ComponentState | 'all')}>
          <option value="all">Any state</option>
          {STATE_ORDER.map((s) => <option key={s} value={s}>{STATE_LABEL[s]}</option>)}
        </select>
        <select aria-label="Scope" value={scope} onChange={(e) => setScope(e.target.value as 'all' | 'direct' | 'dev')}>
          <option value="all">Direct and transitive</option>
          <option value="direct">Direct only</option>
          <option value="dev">Dev dependencies</option>
        </select>
        <input type="search" placeholder="Search components…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search components" />
        <span className="hint">{rows.length} of {report.components.length}</span>
      </div>
      <div className="card table-wrap">
        <table className="tbl">
          <thead><tr><th>Component</th><th>Version</th><th className="hide-sm">Kind</th><th>State</th><th className="num">Findings</th></tr></thead>
          <tbody>
            {rows.map(({ c, st, n }) => (
              <tr key={c.purl} className={n ? 'row' : ''} onClick={() => n && go('findings', undefined, { q: c.name })} tabIndex={n ? 0 : -1} onKeyDown={(e) => { if (n && e.key === 'Enter') go('findings', undefined, { q: c.name }); }}>
                <td className="pkg">{c.name}</td>
                <td className="mono">{c.version}</td>
                <td className="hide-sm muted">{c.dev ? 'dev' : c.direct ? 'direct' : 'transitive'}</td>
                <td><span className={`state s-${st}`}>{STATE_LABEL[st]}</span></td>
                <td className="num">{n || <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
