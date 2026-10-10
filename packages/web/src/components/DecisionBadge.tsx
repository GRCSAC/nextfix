import type { Decision } from '../api.ts';
import { DECISION_META } from '../format.ts';

/** `accepted` marks a finding a person set aside with an approved exception; it reads as Track with that label. */
export function DecisionBadge({ decision, short = false, accepted = false }: { decision: Decision; short?: boolean; accepted?: boolean }) {
  const m = DECISION_META[accepted ? 'Track' : decision];
  if (accepted) {
    return (
      <span className="badge aside accepted" title="A person set this finding aside with a reason; an administrator approved it.">
        <span className="dot-i" aria-hidden="true">✓</span>
        Set aside (accepted)
      </span>
    );
  }
  return (
    <span className={`badge ${m.cls}`} title={m.help}>
      <span className="dot-i" aria-hidden="true">{m.icon}</span>
      {short ? m.short : m.label}
    </span>
  );
}
