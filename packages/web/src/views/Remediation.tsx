import { useMemo, useState } from 'react';
import type { Decision, Finding, ReachTier, ScanReport } from '../api.ts';
import { api } from '../api.ts';
import { DecisionBadge } from '../components/DecisionBadge.tsx';
import { PathDiagram } from '../components/PathDiagram.tsx';
import { DECISIONS, DECISION_META, TIERS, TIER_LABEL, TIER_SHORT, advisoryName, entryLabel, fixCommand, ticketMarkdown } from '../format.ts';

interface Props {
  report: ScanReport;
  scanId: number;
  selectedId?: string;
  onSelect: (id?: string) => void;
}

export function Remediation({ report, scanId, selectedId, onSelect }: Props) {
  const [decision, setDecision] = useState<Decision | 'all'>('all');
  const [tier, setTier] = useState<ReachTier | 'all'>('all');
  const [q, setQ] = useState('');

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return report.findings.filter((f) =>
      (decision === 'all' || f.decision === decision) &&
      (tier === 'all' || f.reach.tier === tier) &&
      (!needle || `${f.component.name} ${advisoryName(f)} ${f.advisory.id} ${f.advisory.summary} ${entryLabel(f) ?? ''}`.toLowerCase().includes(needle)),
    );
  }, [report, decision, tier, q]);

  const selected = selectedId ? report.findings.find((f) => f.id === selectedId) : undefined;
  const counts = DECISIONS.reduce((m, d) => ({ ...m, [d]: report.summary.byDecision[d] }), {} as Record<Decision, number>);

  return (
    <div className="stack">
      <div className="page-head">
        <h1>Remediation queue</h1>
        <span className="meta">{report.target.name ?? report.target.dir} · {rows.length} of {report.findings.length} findings</span>
      </div>
      <div className="filters" role="group" aria-label="Filters">
        <button type="button" className="chip" aria-pressed={decision === 'all'} onClick={() => setDecision('all')}>All <span className="n">{report.findings.length}</span></button>
        {DECISIONS.map((d) => (
          <button key={d} type="button" className="chip" aria-pressed={decision === d} onClick={() => setDecision(decision === d ? 'all' : d)} title={DECISION_META[d].help}>
            <span aria-hidden="true">{DECISION_META[d].icon}</span> {d} <span className="n">{counts[d]}</span>
          </button>
        ))}
        <select aria-label="Reachability" value={tier} onChange={(e) => setTier(e.target.value as ReachTier | 'all')}>
          <option value="all">Any reachability</option>
          {TIERS.map((t) => <option key={t} value={t}>{TIER_SHORT[t]} ({report.summary.byTier[t]})</option>)}
        </select>
        <input type="search" placeholder="Search package, CVE, route…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search findings" />
        <a className="btn small" href={api.vexUrl(scanId)} download>Download VEX</a>
      </div>

      <div className={`workbench ${selected ? 'with-detail' : ''}`}>
        <div className="card table-wrap">
          <table className="queue">
            <thead>
              <tr>
                <th>Decision</th><th className="num">Score</th><th>Package</th><th>Advisory</th><th className="hide-sm">Reach</th><th className="hide-sm">Entry</th><th className="hide-sm">Fix</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} className="row" aria-selected={selected?.id === f.id} onClick={() => onSelect(f.id)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(f.id); } }}>
                  <td><DecisionBadge decision={f.decision} /></td>
                  <td className="num">{f.score}</td>
                  <td className="pkg">{f.component.name}<span className="dim">@{f.component.version}</span></td>
                  <td>{advisoryName(f)}<div className="dim" style={{ fontSize: '0.82rem' }}>{f.advisory.summary}</div></td>
                  <td className="hide-sm">{TIER_SHORT[f.reach.tier]}</td>
                  <td className="hide-sm mono" style={{ fontSize: '0.82rem' }}>{entryLabel(f) ?? <span className="dim">—</span>}</td>
                  <td className="hide-sm">{f.advisory.fixedVersion ? `→ ${f.advisory.fixedVersion}` : <span className="dim">no fix</span>}</td>
                </tr>
              ))}
              {!rows.length && <tr><td colSpan={7} className="empty">Nothing matches these filters.</td></tr>}
            </tbody>
          </table>
        </div>
        {selected && <Detail f={selected} scanId={scanId} targetName={report.target.name ?? report.target.dir} onClose={() => onSelect(undefined)} />}
      </div>
    </div>
  );
}

function Detail({ f, scanId, targetName, onClose }: { f: Finding; scanId: number; targetName: string; onClose: () => void }) {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = async (what: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
      setTimeout(() => setCopied(null), 1600);
    } catch {
      setCopied('failed');
    }
  };
  const cmd = fixCommand(f);
  const path = f.reach.paths.find((p) => !p.entry.authenticated) ?? f.reach.paths[0];

  return (
    <aside className="card detail" aria-label="Finding detail">
      <div className="detail-head">
        <div>
          <DecisionBadge decision={f.decision} short />
          <div className="detail-title" style={{ marginTop: 6 }}>{f.component.name}@{f.component.version} · {advisoryName(f)}</div>
          <div className="detail-sub">{f.advisory.summary}{f.advisory.cvssScore !== undefined && ` · CVSS ${f.advisory.cvssScore.toFixed(1)}`}{f.advisory.severityLabel && ` ${f.advisory.severityLabel}`} · score {f.score}</div>
        </div>
        <button type="button" className="btn ghost small" onClick={onClose} aria-label="Close">✕</button>
      </div>

      <section>
        <h3>Why</h3>
        <ul className="why">{f.why.map((w, i) => <li key={i}>{w}</li>)}</ul>
      </section>

      <section>
        <h3>Reachability · {TIER_LABEL[f.reach.tier]} · confidence {f.reach.confidence}</h3>
        {path ? <PathDiagram path={path} pkg={f.component.name} /> : f.reach.callSites.length ? (
          <ul className="refs">{f.reach.callSites.map((c, i) => <li key={i}><code>{c.text}()</code> at {c.file}:{c.line}</li>)}</ul>
        ) : (
          <p className="empty">{f.reach.importedIn.length ? `Imported in ${f.reach.importedIn.join(', ')}.` : 'Not imported by any source file.'}</p>
        )}
        {f.reach.paths.length > 1 && <p className="empty" style={{ marginTop: 6 }}>{f.reach.paths.length} entry points reach this call; the unauthenticated one is shown.</p>}
      </section>

      <section>
        <h3>Fix</h3>
        <div className="fixbox">
          {f.fix ?? 'No fixed version is published yet. Mitigate at the entry point and re-check on the next scan.'}
          {cmd && <code>{cmd}</code>}
        </div>
        <div className="actions">
          {cmd && <button type="button" className="btn small" onClick={() => copy('cmd', cmd)}>{copied === 'cmd' ? 'Copied' : 'Copy command'}</button>}
          <button type="button" className="btn small primary" onClick={() => copy('ticket', ticketMarkdown(f, targetName))}>{copied === 'ticket' ? 'Copied' : 'Copy as ticket'}</button>
          <a className="btn small" href={api.vexUrl(scanId)} download>VEX for this scan</a>
          {copied === 'failed' && <span className="error">Clipboard blocked by the browser.</span>}
        </div>
      </section>

      {f.advisory.references.length > 0 && (
        <section>
          <h3>References</h3>
          <ul className="refs">{f.advisory.references.slice(0, 6).map((r) => <li key={r}><a href={r} target="_blank" rel="noreferrer">{r}</a></li>)}</ul>
        </section>
      )}
    </aside>
  );
}
