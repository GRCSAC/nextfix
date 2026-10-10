import { useState } from 'react';
import type { Exception, ReachTier, ScanReport } from '../api.ts';
import { api } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { KindIcon } from '../components/ExceptionBox.tsx';
import { KIND_META, isAccepted } from '../exceptions.ts';
import { EVIDENCE_TIERS, advisoryName, dateTime, shortDate } from '../format.ts';

type Group = ReachTier | 'accepted' | 'all';

/** Every set-aside finding with the sentence an auditor needs, grouped by the reason; approved exceptions form their own group. */
export function Evidence({ report, scanId, query, exceptions, go }: { report: ScanReport; scanId: number; query: Record<string, string>; exceptions: Exception[]; go: (page: string, id?: string) => void }) {
  const [open, setOpen] = useState<Group>((query.tier as ReachTier) || 'all');
  const accepted = exceptions.filter((e) => isAccepted(e)).map((e) => ({ e, f: report.findings.find((f) => f.id === e.findingId) })).filter((x) => x.f);
  const acceptedIds = new Set(accepted.map((x) => x.e.findingId));
  const groups = EVIDENCE_TIERS.map((t) => ({ ...t, items: report.findings.filter((f) => f.reach.tier === t.tier && !acceptedIds.has(f.id)) })).filter((g) => open === 'all' || g.tier === open);
  const total = report.findings.filter((f) => EVIDENCE_TIERS.some((t) => t.tier === f.reach.tier) && !acceptedIds.has(f.id)).length + accepted.length;

  return (
    <div className="stack">
      <div className="filters">
        <button type="button" className="chip" aria-pressed={open === 'all'} onClick={() => setOpen('all')}>All evidence <span className="n">{total}</span></button>
        {EVIDENCE_TIERS.map((t) => (
          <button key={t.tier} type="button" className="chip" aria-pressed={open === t.tier} onClick={() => setOpen(open === t.tier ? 'all' : t.tier)}>{t.label} <span className="n">{report.findings.filter((f) => f.reach.tier === t.tier && !acceptedIds.has(f.id)).length}</span></button>
        ))}
        <button type="button" className="chip" aria-pressed={open === 'accepted'} onClick={() => setOpen(open === 'accepted' ? 'all' : 'accepted')}><I.user size={14} /> Accepted by a person <span className="n">{accepted.length}</span></button>
        <a className="btn small primary" href={api.vexUrl(scanId)} download><I.download /> Download VEX</a>
      </div>
      <p className="hint">Each entry is exported as an OpenVEX statement, including exceptions a person approved (with their reason as the impact statement). Scanned {dateTime(report.generatedAt)}.</p>
      {(open === 'all' || open === 'accepted') && (
        <section className="card">
          <div className="card-head">
            <h2>Accepted by a person</h2>
            <span className="hint">{accepted.length} finding{accepted.length === 1 ? '' : 's'} · VEX <code>not_affected</code> or <code>affected</code> with <code>action_statement</code></span>
          </div>
          {accepted.length ? (
            <ul className="ev-items">
              {accepted.map(({ e, f }) => (
                <li key={e.id}>
                  <button type="button" className="ev-item" onClick={() => go('findings', f!.id)}>
                    <span className="grow">
                      <span className="pkg">{f!.component.name}@{f!.component.version}</span> · {advisoryName(f!)} <span className="tag"><KindIcon kind={e.kind} size={12} /> {KIND_META[e.kind].label}</span>
                      <div className="small">{e.reason}</div>
                      <div className="small muted">Approved by {e.approvedBy ?? '—'} · proposed by {e.proposedBy} {shortDate(e.createdAt)} · {e.expiresAt ? `expires ${shortDate(e.expiresAt)}` : 'no expiry'}</div>
                    </span>
                    <I.chevron className="muted" />
                  </button>
                </li>
              ))}
            </ul>
          ) : <p className="empty">No approved exceptions. Set a finding aside from its detail page; an administrator approves it.</p>}
        </section>
      )}
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
