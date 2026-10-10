import { useEffect, useState } from 'react';
import type { AgeBucket, Decision, History, Redecide } from '../api.ts';
import { api } from '../api.ts';
import { DECISION_META, advisoryName, dateTime } from '../format.ts';
import { I } from './Icons.tsx';

type Go = (page: string, id?: string, query?: Record<string, string>) => void;

const BUCKETS: { key: AgeBucket; label: string }[] = [
  { key: '0-7', label: '0–7 days' },
  { key: '8-30', label: '8–30' },
  { key: '31-90', label: '31–90' },
  { key: '90+', label: 'over 90' },
];
const SLA_DECISIONS: Decision[] = ['Act', 'Attend'];

/** Open findings needing action by age against the SLA, median time to resolve, and the last 30 days' flow. */
export function AgeingPanel({ targetId, go }: { targetId: number; go: Go }) {
  const [h, setH] = useState<History | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const ctl = new AbortController();
    setH(null);
    setError(null);
    api.history(targetId, ctl.signal).then(setH).catch((e: unknown) => { if (!ctl.signal.aborted) setError(e instanceof Error ? e.message : String(e)); });
    return () => ctl.abort();
  }, [targetId]);
  if (error) return <p className="empty">Scan history is not available: {error}</p>;
  if (!h) return <p className="empty">Loading scan history…</p>;
  const sla = { Act: h.sla.slaActDays, Attend: h.sla.slaAttendDays } as Record<Decision, number>;
  const max = Math.max(1, ...SLA_DECISIONS.map((d) => BUCKETS.reduce((n, b) => n + (h.open[d]?.[b.key] ?? 0), 0)));
  return (
    <div className="ageing">
      {SLA_DECISIONS.map((d) => {
        const m = DECISION_META[d];
        const total = BUCKETS.reduce((n, b) => n + (h.open[d]?.[b.key] ?? 0), 0);
        const past = h.pastSla[d] ?? 0;
        return (
          <button key={d} type="button" className="age-row" onClick={() => go('findings', undefined, { decision: d })}>
            <span className="age-label"><span className={`tri d-${m.cls}`} aria-hidden="true">{m.icon}</span> {m.short} <span className="muted">SLA {sla[d]} days</span></span>
            <span className="age-bar" role="img" aria-label={`${total} open, ${past} past SLA`}>
              {BUCKETS.map((b) => {
                const n = h.open[d]?.[b.key] ?? 0;
                if (!n) return null;
                const pastBucket = daysOf(b.key) > sla[d];
                return <span key={b.key} className={`age-seg ${pastBucket ? 'past' : ''}`} style={{ width: `${(n / max) * 100}%`, background: m.color }} title={`${n} open for ${b.label}`} />;
              })}
            </span>
            <span className="age-note">{total} open{past ? <> · <strong className="past-text">{past} past SLA</strong></> : total ? ' · all within SLA' : ''}</span>
          </button>
        );
      })}
      <div className="age-foot">
        <span><strong>{h.medianDaysToResolve === null ? '—' : `${h.medianDaysToResolve} days`}</strong> median time to resolve (last 90 days)</span>
        <span><strong>{h.resolvedLast30}</strong> resolved and <strong>{h.introducedLast30}</strong> introduced in the last 30 days</span>
        <span className="muted small">Light segments are within the SLA, solid ones past it. SLA days are set in Settings.</span>
      </div>
    </div>
  );
}

/** Lower bound of an age bucket in days. */
function daysOf(b: AgeBucket): number {
  return b === '0-7' ? 0 : b === '8-30' ? 8 : b === '31-90' ? 31 : 91;
}

/** Re-runs only the decision step with current exploit data; nothing is stored, promotions are shown. */
export function RecheckButton({ targetId, go }: { targetId: number; go: Go }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Redecide | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.redecide(targetId));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="recheck">
      <button type="button" className="btn small" onClick={run} disabled={busy} title="Re-decide every finding with today's EPSS and KEV data, without re-scanning the code"><I.refresh /> {busy ? 'Checking…' : 'Re-check exploit data'}</button>
      {error && <span className="error">{error}</span>}
      {result && !result.changed.length && <span className="muted small">No decision changes with exploit data as of {dateTime(result.checkedAt)}.</span>}
      {result && result.changed.length > 0 && (
        <ul className="plain recheck-list">
          {result.changed.map((c) => (
            <li key={c.finding.id}><button type="button" className="link" onClick={() => go('findings', c.finding.id)}>{c.finding.component.name} · {advisoryName(c.finding)}</button> <span className="tag">{DECISION_META[c.from].short} → {DECISION_META[c.to].short}</span>{c.reasons[0] && <span className="muted small">{c.reasons[0]}</span>}</li>
          ))}
          <li className="muted small">Not stored: run Scan again to make these the new decisions.</li>
        </ul>
      )}
    </div>
  );
}
