import type { Finding, ScanDiff, ScanMeta, ScanReport } from '../api.ts';
import { StatTile } from '../components/StatTile.tsx';
import { TrendChart } from '../components/TrendChart.tsx';
import { Breakdown } from '../components/Breakdown.tsx';
import { DecisionBadge } from '../components/DecisionBadge.tsx';
import { advisoryName, dateTime, headline, pct } from '../format.ts';

interface Props {
  report: ScanReport;
  scans: ScanMeta[];
  diff?: ScanDiff;
  onOpenFinding: (f: Finding) => void;
}

export function Executive({ report, scans, diff, onOpenFinding }: Props) {
  const s = report.summary;
  const prev = diff?.previous?.summary;
  const d = (k: 'Act' | 'Attend') => (prev ? s.byDecision[k] - prev.byDecision[k] : undefined);
  const unauth = report.entryPoints.filter((e) => !e.authenticated).length;
  const top = report.findings.filter((f) => f.decision === 'Act' || f.decision === 'Attend').slice(0, 5);
  const actionable = s.byDecision.Act + s.byDecision.Attend;

  return (
    <div className="stack">
      <div className="page-head">
        <h1>{report.target.name ?? report.target.dir}</h1>
        <span className="meta">scanned {dateTime(report.generatedAt)} · NextFix {report.tool.version}</span>
      </div>

      <div className="grid kpis">
        <StatTile label="Fix now" value={s.byDecision.Act} delta={d('Act')} className={s.byDecision.Act ? 'accent-act' : ''} />
        <StatTile label="Fix next cycle" value={s.byDecision.Attend} delta={d('Attend')} />
        <StatTile label="Set aside, with evidence" value={pct(s.noiseRemoved)} sub delta={prev ? Math.round((s.noiseRemoved - prev.noiseRemoved) * 100) : undefined} unit=" pts" upIsGood />
        <StatTile label="Entry points without auth" value={`${unauth} of ${report.entryPoints.length}`} sub />
      </div>

      <div className="card">
        <p>
          Scanners raised <strong>{s.findings}</strong> findings across <strong>{s.components}</strong> components. <strong>{actionable}</strong> need
          action{actionable ? '' : ' — none right now'}. The rest are unreachable, unused, or not shipped, and each one carries a reason you can hand to an auditor.
        </p>
      </div>

      <div className="grid two">
        <div className="card">
          <div className="card-head"><h2>Actionable findings over time</h2><span className="hint">{scans.length} scan{scans.length === 1 ? '' : 's'}</span></div>
          <TrendChart scans={scans} />
        </div>
        <div className="card">
          <div className="card-head"><h2>Where the findings landed</h2></div>
          <Breakdown summary={s} />
        </div>
      </div>

      <div className="grid two">
        <div className="card">
          <div className="card-head"><h2>What to fix first</h2><span className="hint">top {top.length}</span></div>
          {top.length ? (
            <ul className="risk-list">
              {top.map((f) => (
                <li key={f.id}>
                  <button type="button" className="risk-item" onClick={() => onOpenFinding(f)}>
                    <DecisionBadge decision={f.decision} />
                    <span>
                      <div className="what">{f.component.name}@{f.component.version} · {advisoryName(f)}</div>
                      <div className="how">{headline(f)}</div>
                    </span>
                    <span className="fix">{f.advisory.fixedVersion ? `→ ${f.advisory.fixedVersion}` : 'no fix yet'}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">Nothing needs action. Keep scanning after each release.</p>
          )}
        </div>
        <div className="stack">
          <div className="card">
            <div className="card-head"><h2>Since last scan</h2>{diff?.previous && <span className="hint">{dateTime(diff.previous.createdAt)}</span>}</div>
            {diff?.previous ? <DiffSummary diff={diff} onOpenFinding={onOpenFinding} /> : <p className="empty">First scan of this target. Changes show up from the second scan on.</p>}
          </div>
          <div className="card">
            <div className="card-head"><h2>Exposure</h2></div>
            <dl className="kv">
              <dt>Network</dt>
              <dd>{report.exposure.network === 'published' ? `Published on port ${report.exposure.ports.join(', ')}` : report.exposure.network === 'local-only' ? 'Loopback only' : 'Unknown (no Dockerfile or compose ports)'}</dd>
              <dt>Entry points</dt>
              <dd>{report.entryPoints.length} HTTP routes, {unauth} without an auth guard</dd>
              <dt>Evidence</dt>
              <dd>{report.exposure.evidence.length ? report.exposure.evidence.join('; ') : '—'}</dd>
            </dl>
          </div>
        </div>
      </div>
    </div>
  );
}

function DiffSummary({ diff, onOpenFinding }: { diff: ScanDiff; onOpenFinding: (f: Finding) => void }) {
  const rows: { label: string; items: Finding[]; extra?: (f: Finding) => string }[] = [
    { label: 'New', items: diff.added },
    { label: 'Resolved', items: diff.resolved },
    { label: 'Changed decision', items: diff.changed.map((c) => c.finding), extra: (f) => { const c = diff.changed.find((x) => x.finding.id === f.id)!; return `${c.from} → ${c.to}`; } },
  ];
  if (rows.every((r) => !r.items.length)) return <p className="empty">No change in findings.</p>;
  return (
    <dl className="kv">
      {rows.map((r) => (
        <Row key={r.label} label={r.label} items={r.items} extra={r.extra} onOpenFinding={onOpenFinding} />
      ))}
    </dl>
  );
}

function Row({ label, items, extra, onOpenFinding }: { label: string; items: Finding[]; extra?: (f: Finding) => string; onOpenFinding: (f: Finding) => void }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>
        {items.length ? items.slice(0, 4).map((f) => (
          <div key={f.id}>
            <a href="#" onClick={(e) => { e.preventDefault(); onOpenFinding(f); }}>{f.component.name}@{f.component.version} {advisoryName(f)}</a>
            {extra && <span className="pill" style={{ marginLeft: 6 }}>{extra(f)}</span>}
          </div>
        )) : <span className="empty">none</span>}
        {items.length > 4 && <div className="empty">+{items.length - 4} more</div>}
      </dd>
    </>
  );
}
