import type { Decision } from '../api.ts';
import { DECISION_META } from '../format.ts';

export function DecisionBadge({ decision, short = false }: { decision: Decision; short?: boolean }) {
  const m = DECISION_META[decision];
  return (
    <span className={`badge ${m.cls}`} title={m.help}>
      <span className="dot" aria-hidden="true">{m.icon}</span>
      {short ? m.short : m.label}
    </span>
  );
}
