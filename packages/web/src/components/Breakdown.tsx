import type { ScanSummary } from '../api.ts';
import { DECISIONS, DECISION_META, TIERS, TIER_SHORT } from '../format.ts';

const DECISION_COLOR = { Act: 'var(--st-critical)', Attend: 'var(--st-serious)', 'Track*': 'var(--st-warning)', Track: 'var(--st-good)' } as const;
const TIER_COLOR = ['var(--seq-6)', 'var(--seq-5)', 'var(--seq-4)', 'var(--seq-3)', 'var(--seq-2)', 'var(--seq-1)'];

/** Two stacked part-to-whole bars: where findings landed by decision, and why (reachability tier). */
export function Breakdown({ summary }: { summary: ScanSummary }) {
  const total = Math.max(1, summary.findings);
  return (
    <div className="stack">
      <div>
        <div className="stackbar" role="img" aria-label="Findings by decision">
          {DECISIONS.map((d) => summary.byDecision[d] > 0 && <span key={d} style={{ width: `${(summary.byDecision[d] / total) * 100}%`, background: DECISION_COLOR[d] }} title={`${d}: ${summary.byDecision[d]}`} />)}
        </div>
        <div className="bar-legend">
          <ul>
            {DECISIONS.map((d) => (
              <li key={d}><span><span className="sw legend-sw" style={{ background: DECISION_COLOR[d], display: 'inline-block', width: 10, height: 10, borderRadius: 3, marginRight: 6 }} />{DECISION_META[d].icon} {d} · {DECISION_META[d].short}</span><span className="n">{summary.byDecision[d]}</span></li>
            ))}
          </ul>
        </div>
      </div>
      <div>
        <div className="stackbar" role="img" aria-label="Findings by reachability">
          {TIERS.map((t, i) => summary.byTier[t] > 0 && <span key={t} style={{ width: `${(summary.byTier[t] / total) * 100}%`, background: TIER_COLOR[i] }} title={`${TIER_SHORT[t]}: ${summary.byTier[t]}`} />)}
        </div>
        <div className="bar-legend">
          <ul>
            {TIERS.map((t, i) => (
              <li key={t}><span><span style={{ background: TIER_COLOR[i], display: 'inline-block', width: 10, height: 10, borderRadius: 3, marginRight: 6 }} />{TIER_SHORT[t]}</span><span className="n">{summary.byTier[t]}</span></li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
