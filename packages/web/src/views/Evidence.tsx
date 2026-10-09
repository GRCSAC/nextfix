import { useState } from 'react';
import type { ReachTier, ScanReport } from '../api.ts';
import { api } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { EVIDENCE_TIERS, advisoryName, dateTime } from '../format.ts';

/** Every set-aside finding with the sentence an auditor needs, grouped by the reason. */
export function Evidence({ report, scanId, query, go }: { report: ScanReport; scanId: number; query: Record<string, string>; go: (page: string, id?: string) => void }) {
  const [open, setOpen] = useState<ReachTier | 'all'>((query.tier as ReachTier) || 'all');
  const groups = EVIDENCE_TIERS.map((t) => ({ ...t, items: report.findings.filter((f) => f.reach.tier === t.tier) })).filter((g) => open === 'all' || g.tier === open);
  const total = report.findings.filter((f) => EVIDENCE_TIERS.some((t) => t.tier === f.reach.tier)).length;

  return (
    <div className="stack">
      <div className="filters">
        <button type="button" className="chip" aria-pressed={open === 'all'} onClick={() => setOpen('all')}>All set-asides <span className="n">{total}</span></button>
        {EVIDENCE_TIERS.map((t) => (
          <button key={t.tier} type="button" className="chip" aria-pressed={open === t.tier} onClick={() => setOpen(open === t.tier ? 'all' : t.tier)}>{t.label} <span className="n">{report.summary.byTier[t.tier]}</span></button>
        ))}
        <a className="btn small primary" href={api.vexUrl(scanId)} download><I.download /> Download VEX</a>
      </div>
      <p className="hint">Each entry is exported as an OpenVEX statement. Scanned {dateTime(report.generatedAt)}.</p>
      {groups.map((g) => (
        <section key={g.tier} className="card">
          <div className="card-head">
            <h2>{g.label}</h2>
            <span className="hint">{g.items.length} finding{g.items.length === 1 ? '' : 's'} · VEX <code>{g.justification}</code></span>
          </div>
          {g.items.length ? (
            <ul className="ev-items">
              {g.items.map((f) => (
                <li key={f.id}>
                  <button type="button" className="ev-item" onClick={() => go('findings', f.id)}>
                    <span className="grow">
                      <span className="pkg">{f.component.name}@{f.component.version}</span> · {advisoryName(f)} <span className="muted">· {f.advisory.summary}</span>
                      <div className="small muted">{f.why.find((w, i) => i === 1) ?? f.why[0]}</div>
                    </span>
                    <I.chevron className="muted" />
                  </button>
                </li>
              ))}
            </ul>
          ) : <p className="empty">None in this scan.</p>}
        </section>
      ))}
    </div>
  );
}
