import { useEffect, useMemo, useState } from 'react';
import { api, type Portfolio as PortfolioData, type PortfolioTarget, type Posture } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { dateTime } from '../format.ts';

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

const POSTURES: { id: Posture; icon: string; cls: string; help: string }[] = [
  { id: 'Exposed', icon: '▲', cls: 'act', help: 'Something needs fixing now' },
  { id: 'Attention', icon: '●', cls: 'attend', help: 'Fixes due next release cycle' },
  { id: 'Contained', icon: '◐', cls: 'watch', help: 'Only watched findings remain' },
  { id: 'Clean', icon: '✓', cls: 'good', help: 'Nothing open' },
  { id: 'Never scanned', icon: '○', cls: 'muted', help: 'No scan yet' },
];
const RANK = Object.fromEntries(POSTURES.map((p, i) => [p.id, i])) as Record<Posture, number>;

function ago(iso?: string): string {
  if (!iso) return 'never';
  const d = (Date.now() - Date.parse(iso)) / 86_400_000;
  if (d < 1 / 24) return 'just now';
  if (d < 1) return `${Math.round(d * 24)} h ago`;
  if (d < 30) return `${Math.round(d)} day${Math.round(d) === 1 ? '' : 's'} ago`;
  return dateTime(iso);
}

/** Every application on one page: posture tiles, then rows sorted by posture and the oldest SLA breach. */
export function Portfolio({ onOpen }: { onOpen: (id: number) => void }) {
  const [data, setData] = useState<PortfolioData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Posture | null>(null);
  useEffect(() => {
    const ac = new AbortController();
    api.portfolio(ac.signal).then(setData).catch((e) => { if (!ac.signal.aborted) setError(message(e)); });
    return () => ac.abort();
  }, []);

  const rows = useMemo(() => {
    const list = [...(data?.targets ?? [])].sort((a, b) => RANK[a.posture] - RANK[b.posture] || (b.oldestPastSlaDays ?? -1) - (a.oldestPastSlaDays ?? -1) || (b.byDecision.Act + b.byDecision.Attend) - (a.byDecision.Act + a.byDecision.Attend) || a.name.localeCompare(b.name));
    return filter ? list.filter((t) => t.posture === filter) : list;
  }, [data, filter]);
  const counts = useMemo(() => { const c = Object.fromEntries(POSTURES.map((p) => [p.id, 0])) as Record<Posture, number>; for (const t of data?.targets ?? []) c[t.posture]++; return c; }, [data]);

  if (error) return <div className="card"><p className="empty">Could not load the portfolio: {error}</p></div>;
  if (!data) return <p className="empty">Loading…</p>;
  const actionable = data.targets.reduce((n, t) => n + t.byDecision.Act + t.byDecision.Attend, 0);
  const pending = data.targets.reduce((n, t) => n + t.pendingExceptions, 0);

  return (
    <div className="stack">
      <div className="app-head">
        <span className="icon-box big"><I.portfolio size={28} /></span>
        <div className="grow">
          <h1>Portfolio</h1>
          <div className="muted small">{data.targets.length} application{data.targets.length === 1 ? '' : 's'} · {actionable} finding{actionable === 1 ? '' : 's'} need action{pending ? ` · ${pending} exception${pending === 1 ? '' : 's'} awaiting approval` : ''}</div>
        </div>
      </div>

      <div className="posture-strip" role="group" aria-label="Applications by posture">
        {POSTURES.map((p) => (
          <button key={p.id} type="button" className={`posture-tile p-${p.cls}`} aria-pressed={filter === p.id} onClick={() => setFilter(filter === p.id ? null : p.id)} title={p.help}>
            <span className="posture-icon" aria-hidden="true">{p.icon}</span>
            <span className="posture-n">{counts[p.id]}</span>
            <span className="posture-l">{p.id}</span>
          </button>
        ))}
      </div>

      <div className="card table-wrap">
        <table className="tbl portfolio">
          <thead><tr><th>Application</th><th>Posture</th><th>Owner</th><th>Last scan</th><th className="num">Need action</th><th>Exposed surface</th><th>Trend</th><th className="num">Pending</th></tr></thead>
          <tbody>
            {rows.map((t) => <Row key={t.id} t={t} onOpen={() => onOpen(t.id)} />)}
            {!rows.length && <tr><td colSpan={8} className="empty">{filter ? `No application is ${filter.toLowerCase()}.` : 'No applications yet. Add one under Apps.'}</td></tr>}
          </tbody>
        </table>
      </div>
      <ul className="pf-cards" aria-label="Applications">
        {rows.map((t) => <Card key={t.id} t={t} onOpen={() => onOpen(t.id)} />)}
        {!rows.length && <li className="empty">{filter ? `No application is ${filter.toLowerCase()}.` : 'No applications yet.'}</li>}
      </ul>
      <p className="hint">Sorted by posture, then by the oldest finding past its SLA. Click an application to open its Overview.</p>
    </div>
  );
}

function PostureTag({ posture }: { posture: Posture }) {
  const p = POSTURES.find((x) => x.id === posture)!;
  return <span className={`posture-tag p-${p.cls}`}><span aria-hidden="true">{p.icon}</span> {posture}</span>;
}

function Row({ t, onOpen }: { t: PortfolioTarget; onOpen: () => void }) {
  const actionable = t.byDecision.Act + t.byDecision.Attend;
  return (
    <tr className="row" tabIndex={0} onClick={onOpen} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(); } }}>
      <td><span className="pkg">{t.name}</span><div className="muted small mono">{t.dir}</div></td>
      <td><PostureTag posture={t.posture} />{t.oldestPastSlaDays !== undefined && <div className="small past-text">{t.oldestPastSlaDays} day{t.oldestPastSlaDays === 1 ? '' : 's'} past SLA</div>}</td>
      <td>{t.owner || <span className="muted">unassigned</span>}</td>
      <td className="muted nowrap">{ago(t.lastScanAt)}</td>
      <td className="num"><strong>{actionable}</strong>{actionable > 0 && <div className="muted small nowrap">{t.byDecision.Act} now · {t.byDecision.Attend} next</div>}</td>
      <td className="nowrap">{t.exposedSurface.total ? <>{t.exposedSurface.open} of {t.exposedSurface.total} <span className="muted small">open routes</span></> : <span className="muted">—</span>}</td>
      <td><Sparkline values={t.trend} /></td>
      <td className="num">{t.pendingExceptions ? <span className="tag pending">{t.pendingExceptions}</span> : <span className="muted">0</span>}</td>
    </tr>
  );
}

function Card({ t, onOpen }: { t: PortfolioTarget; onOpen: () => void }) {
  const actionable = t.byDecision.Act + t.byDecision.Attend;
  return (
    <li>
      <button type="button" className="pf-card" onClick={onOpen}>
        <span className="pf-top"><span className="pkg">{t.name}</span><PostureTag posture={t.posture} /></span>
        <span className="pf-meta muted small">{t.owner || 'unassigned'} · {t.lastScanAt ? `scanned ${ago(t.lastScanAt)}` : 'never scanned'}{t.oldestPastSlaDays !== undefined ? <> · <span className="past-text">{t.oldestPastSlaDays} d past SLA</span></> : ''}</span>
        <span className="pf-bottom">
          <span><strong>{actionable}</strong> <span className="muted small">need action</span></span>
          <span>{t.exposedSurface.total ? <><strong>{t.exposedSurface.open}</strong><span className="muted small"> of {t.exposedSurface.total} open routes</span></> : null}</span>
          {t.pendingExceptions > 0 && <span className="tag pending">{t.pendingExceptions} pending</span>}
          <Sparkline values={t.trend} />
        </span>
      </button>
    </li>
  );
}

/** One series, actionable findings per scan, as a small inline line; the last point is marked. */
export function Sparkline({ values, width = 96, height = 26 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) return <span className="muted small">{values.length === 1 ? 'one scan' : '—'}</span>;
  const max = Math.max(1, ...values);
  const pad = 3;
  const x = (i: number) => pad + (i / (values.length - 1)) * (width - pad * 2);
  const y = (v: number) => height - pad - (v / max) * (height - pad * 2);
  const d = values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const last = values[values.length - 1]!;
  const first = values[0]!;
  const dir = last < first ? 'down' : last > first ? 'up' : 'flat';
  return (
    <svg className="spark" width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Actionable findings over ${values.length} scans: ${values.join(', ')}; trending ${dir}`}>
      <path d={d} fill="none" stroke="var(--ink-2)" strokeWidth="1.6" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={x(values.length - 1)} cy={y(last)} r="2.6" fill={dir === 'up' ? 'var(--c-act)' : dir === 'down' ? 'var(--c-good)' : 'var(--ink-2)'} />
    </svg>
  );
}
