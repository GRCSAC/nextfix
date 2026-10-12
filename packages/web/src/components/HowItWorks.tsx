import { Modal } from './Modal.tsx';
import { DECISIONS, DECISION_META, TIERS, TIER_LABEL } from '../format.ts';
import { DecisionBadge } from './DecisionBadge.tsx';

export function HowItWorks({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="How NextFix decides" onClose={onClose} wide>
      <p className="lead">Scanners find vulnerabilities. NextFix works out which ones are <strong>reachable</strong> from an entry point, <strong>exposed</strong> to an attacker, and <strong>exploited</strong> in the wild, then hands down one of four decisions with the evidence attached.</p>
      <h3>Reachability, in seven tiers</h3>
      <ol className="tiers">
        {TIERS.map((t) => <li key={t}><strong>{TIER_LABEL[t]}</strong></li>)}
      </ol>
      <p className="hint">Confidence is shown with every tier: <em>confirmed</em> (hand-curated function data), <em>derived</em> (extracted from the fix commit), or <em>package-level</em> (no function data, so NextFix refuses to guess).</p>
      <h3>Four decisions</h3>
      <dl className="decisions">
        {DECISIONS.map((d) => (
          <div key={d}><dt><DecisionBadge decision={d} short /></dt><dd>{DECISION_META[d].help}</dd></div>
        ))}
      </dl>
      <p className="hint">Reachable and unauthenticated with active or likely exploitation, or with request data reaching a high-severity function, is <strong>Act</strong>. Reachable behind auth is <strong>Attend</strong>. Called but unreachable is <strong>Watch</strong>. Not shipped, not imported, or never called is <strong>Set aside</strong>, exported as a VEX <code>not_affected</code> statement with the standard justification.</p>
      <h3>Signals</h3>
      <ul className="plain">
        <li><strong>Exploitation:</strong> CISA KEV membership (active) and FIRST EPSS ≥ 10% (likely).</li>
        <li><strong>Exposure:</strong> Dockerfile <code>EXPOSE</code>, compose <code>ports:</code>, and whether the app binds to loopback.</li>
        <li><strong>Observed traffic:</strong> with access logs configured, requests per route over the last 30 days, split by public and internal addresses. Public traffic on an open route lifts a moderate finding to Act; a route nobody called holds a severity-only Act at Attend; both say so in the why.</li>
        <li><strong>Internet reach:</strong> public addresses in the logs, a declaration in <code>nextfix.config.json</code>, or infrastructure files (Terraform, CloudFormation, Kubernetes, compose bindings). An internal-only service holds a severity-only Act at Attend.</li>
        <li><strong>Request data:</strong> arguments that mention <code>req.*</code>, followed down the call chain.</li>
        <li><strong>Score:</strong> CVSS × reachability × exposure, plus EPSS and KEV. It orders findings; it never changes a decision.</li>
      </ul>
    </Modal>
  );
}
