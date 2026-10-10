import { useMemo, useState } from 'react';
import type { ScanReport } from '../api.ts';
import { STATE_LABEL, STATE_ORDER, componentWorstTier, type ComponentState } from '../format.ts';

type Scope = 'all' | 'direct' | 'dev' | 'project' | 'image';

/** OS packages are listed by source package; the binary packages behind it are worth showing. */
const isOsPackage = (type?: string) => type === 'deb' || type === 'apk' || type === 'rpm';

export function Components({ report, go }: { report: ScanReport; go: (page: string, id?: string, query?: Record<string, string>) => void }) {
  const [q, setQ] = useState('');
  const [state, setState] = useState<ComponentState | 'all'>('all');
  const [scope, setScope] = useState<Scope>('all');
  const images = (report.images ?? []).filter((i) => !i.error);
  const failed = (report.images ?? []).filter((i) => i.error);
  const hasImages = (report.images ?? []).length > 0;

  const rows = useMemo(() => {
    const list = report.components ?? [];
    const counts = new Map<string, number>();
    for (const f of report.findings) counts.set(f.component.purl, (counts.get(f.component.purl) ?? 0) + 1);
    const needle = q.trim().toLowerCase();
    const inScope = (c: (typeof list)[number]) => {
      switch (scope) {
        case 'direct':
          return c.direct;
        case 'dev':
          return c.dev;
        case 'project':
          return c.origin !== 'image';
        case 'image':
          return !!c.image;
        default:
          return true;
      }
    };
    return list
      .map((c) => ({ c, st: componentWorstTier(report, c.purl), n: counts.get(c.purl) ?? 0 }))
      .filter((r) => (state === 'all' || r.st === state) && inScope(r.c) && (!needle || r.c.name.toLowerCase().includes(needle)))
      .sort((a, b) => STATE_ORDER.indexOf(a.st) - STATE_ORDER.indexOf(b.st) || b.n - a.n || a.c.name.localeCompare(b.c.name));
  }, [report, q, state, scope]);

  if (!report.components) return <div className="card"><p className="empty">This scan predates component listing. Run <strong>Scan again</strong> to see every component.</p></div>;

  return (
    <div className="stack">
      {hasImages && (
        <div className="card images" aria-label="Container images">
          {images.map((i) => (
            <div key={i.ref} className="image-row">
              <span className="mono">{i.ref}</span>
              <span className="muted small">{i.os ? `${i.os} · ` : ''}{i.components} components{i.unqueried ? ` · ${i.unqueried} without advisory data` : ''} · via {i.source}</span>
            </div>
          ))}
          {failed.map((i) => (
            <div key={i.ref} className="image-row image-err">
              <span className="mono">{i.ref}</span>
              <span className="small">{i.error}</span>
            </div>
          ))}
        </div>
      )}
      <div className="filters">
        <select aria-label="State" value={state} onChange={(e) => setState(e.target.value as ComponentState | 'all')}>
          <option value="all">Any state</option>
          {STATE_ORDER.map((s) => <option key={s} value={s}>{STATE_LABEL[s]}</option>)}
        </select>
        <select aria-label="Scope" value={scope} onChange={(e) => setScope(e.target.value as Scope)}>
          <option value="all">Direct and transitive</option>
          <option value="direct">Direct only</option>
          <option value="dev">Dev dependencies</option>
          {hasImages && <option value="project">Project lockfiles only</option>}
          {hasImages && <option value="image">In the image</option>}
        </select>
        <input type="search" placeholder="Search components…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search components" />
        <span className="hint">{rows.length} of {report.components.length}</span>
      </div>
      <div className="card table-wrap">
        <table className="tbl">
          <thead><tr><th>Component</th><th>Version</th><th className="hide-sm">Ecosystem</th><th className="hide-sm">Kind</th>{hasImages && <th className="hide-sm">Where</th>}<th>State</th><th className="num">Findings</th></tr></thead>
          <tbody>
            {rows.map(({ c, st, n }) => (
              <tr key={c.purl} className={n ? 'row' : ''} onClick={() => n && go('findings', undefined, { q: c.name })} tabIndex={n ? 0 : -1} onKeyDown={(e) => { if (n && e.key === 'Enter') go('findings', undefined, { q: c.name }); }}>
                <td className="pkg">{c.name}{isOsPackage(c.packageType) && c.path !== c.name && <span className="muted small"> ({(c.paths ?? [c.path]).join(', ')})</span>}</td>
                <td className="mono">{c.version}</td>
                <td className="hide-sm muted">{c.ecosystem}</td>
                <td className="hide-sm muted">{c.dev ? 'dev' : c.direct ? 'direct' : c.origin === 'image' ? c.packageType ?? 'image' : 'transitive'}</td>
                {hasImages && <td className="hide-sm muted">{c.origin === 'image' ? 'image' : c.image ? 'lockfile · in image' : 'lockfile'}</td>}
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
