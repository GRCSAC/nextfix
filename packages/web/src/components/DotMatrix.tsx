import type { Decision, Finding } from '../api.ts';
import { BUCKET_ORDER, DECISION_META } from '../format.ts';

/** One dot per finding, grouped by decision. Capped so the grid stays readable. */
export function DotMatrix({ findings, max = 60 }: { findings: Finding[]; max?: number }) {
  const ordered = [...findings].sort((a, b) => BUCKET_ORDER.indexOf(a.decision) - BUCKET_ORDER.indexOf(b.decision));
  const shown = ordered.slice(0, max);
  const rest = ordered.length - shown.length;
  return (
    <div className="dots" aria-label={`${findings.length} findings by decision`}>
      {shown.map((f) => <span key={f.id} className={`dot d-${DECISION_META[f.decision as Decision].cls}`} title={`${f.decision}: ${f.component.name} ${f.advisory.cve ?? f.advisory.id}`} />)}
      {rest > 0 && <span className="dots-more">+{rest}</span>}
    </div>
  );
}
