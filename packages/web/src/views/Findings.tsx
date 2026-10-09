import { useEffect, useMemo, useState } from 'react';
import type { Decision, Finding, ReachTier, ScanReport } from '../api.ts';
import { api } from '../api.ts';
import { DecisionBadge } from '../components/DecisionBadge.tsx';
import { PathDiagram } from '../components/PathDiagram.tsx';
import { I } from '../components/Icons.tsx';
import { DECISIONS, DECISION_META, TIERS, TIER_LABEL, TIER_SHORT, advisoryName, bestPath, entryLabel, fixCommand, severity, ticketMarkdown } from '../format.ts';

interface Props {
  report: ScanReport;
  scanId: number;
  selectedId?: string;
  query: Record<string, string>;
  onSelect: (id?: string) => void;
}

export function Findings({ report, scanId, selectedId, query, onSelect }: Props) {
  const [decision, setDecision] = useState<Decision | 'all'>((query.decision as Decision) || 'all');
  const [tier, setTier] = useState<ReachTier | 'all'>((query.tier as ReachTier) || 'all');
  const [q, setQ] = useState(query.q ?? '');
  useEffect(() => { if (query.decision) setDecision(query.decision as Decision); }, [query.decision]);
  useEffect(() => { if (query.tier) setTier(query.tier as ReachTier); }, [query.tier]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return report.findings.filter((f) =>
      (decision === 'all' || f.decision === decision) &&
      (tier === 'all' || f.reach.tier === tier) &&
      (!needle || `${f.component.name} ${advisoryName(f)} ${f.advisory.id} ${f.advisory.summary} ${entryLabel(f) ?? ''}`.toLowerCase().includes(needle)),
    );
  }, [report, decision, tier, q]);

  const selected = selectedId ? report.findings.find((f) => f.id === selectedId) : undefined;

  return (
    <div className="stack">
      <div className="filters" role="group" aria-label="Filters">
        <button type="button" className="chip" aria-pressed={decision === 'all'} onClick={() => setDecision('all')}>All <span className="n">{report.findings.length}</span></button>
        {DECISIONS.map((d) => (
          <button key={d} type="button" className={`chip d-${DECISION_META[d].cls}`} aria-pressed={decision === d} onClick={() => setDecision(decision === d ? 'all' : d)} title={DECISION_META[d].help}>
            <span aria-hidden="true">{DECISION_META[d].icon}</span> {DECISION_META[d].short} <span className="n">{report.summary.byDecision[d]}</span>
          </button>
        ))}
        <select aria-label="Reachability" value={tier} onChange={(e) => setTier(e.target.value as ReachTier | 'all')}>
          <option value="all">Any reachability</option>
          {TIERS.map((t) => <option key={t} value={t}>{TIER_SHORT[t]} ({report.summary.byTier[t]})</option>)}
        </select>
        <input type="search" placeholder="Search package, CVE, route…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search findings" />
        <a className="btn small" href={api.vexUrl(scanId)} download><I.download /> VEX</a>
      </div>

      <div className={`workbench ${selected ? 'with-detail' : ''}`}>
        <div className="card table-wrap">
          <table className="tbl queue">
            <thead>
              <tr><th>Decision</th><th className="num">Score</th><th>Component</th><th>Advisory</th><th className="hide-sm">Severity</th><th className="hide-sm">Reach</th><th className="hide-sm">Entry point</th><th className="hide-sm">Fix</th></tr>
            </thead>
            <tbody>
              {rows.map((f) => {
                const sev = severity(f);
                return (
                  <tr key={f.id} className="row" aria-selected={selected?.id === f.id} onClick={() => onSelect(f.id)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(f.id); } }}>
                    <td><DecisionBadge decision={f.decision} short /></td>
                    <td className="num">{f.score}</td>
                    <td className="pkg">{f.component.name}<span className="muted">@{f.component.version}</span></td>
                    <td>{advisoryName(f)}<div className="muted small">{f.advisory.summary}</div></td>
                    <td className="hide-sm"><span className={`sev ${sev.cls}`}>{sev.label}</span></td>
                    <td className="hide-sm">{TIER_SHORT[f.reach.tier]}</td>
                    <td className="hide-sm mono small">{entryLabel(f) ?? <span className="muted">—</span>}</td>
                    <td className="hide-sm">{f.advisory.fixedVersion ? `→ ${f.advisory.fixedVersion}` : <span className="muted">no fix</span>}</td>
                  </tr>
                );
              })}
              {!rows.length && <tr><td colSpan={8} className="empty">Nothing matches these filters.</td></tr>}
            </tbody>
          </table>
        </div>
        {selected && <Detail f={selected} scanId={scanId} targetName={report.target.name ?? report.target.dir} onClose={() => onSelect(undefined)} />}
      </div>
    </div>
  );
}

function shortCommit(url: string): string {
  const m = /\/(?:commit|commits)\/([0-9a-f]{7,40})/i.exec(url);
  if (m) return m[1]!.slice(0, 10);
  const pr = /\/pull\/(\d+)/.exec(url);
  if (pr) return `PR #${pr[1]}`;
  return url.replace(/^https?:\/\/github\.com\//, '');
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
  const path = bestPath(f);
  const sev = severity(f);

  return (
    <aside className="card detail" aria-label="Finding detail">
      <div className="detail-head">
        <div>
          <DecisionBadge decision={f.decision} short />
          <div className="detail-title">{f.component.name}@{f.component.version} · {advisoryName(f)}</div>
          <div className="detail-sub">{f.advisory.summary} · <span className={`sev ${sev.cls}`}>{sev.label}</span>{f.advisory.cvssScore !== undefined && ` CVSS ${f.advisory.cvssScore.toFixed(1)}`} · score {f.score}</div>
        </div>
        <button type="button" className="btn ghost icon" onClick={onClose} aria-label="Close"><I.close /></button>
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
        {f.reach.paths.length > 1 && <p className="empty">{f.reach.paths.length} entry points reach this call, {f.reach.paths.filter((p) => p.userInput).length} carrying request data; the worst case is shown.</p>}
      </section>

      {f.symbols && (
        <section>
          <h3>Function data · {f.symbols.source}{f.symbols.reviewed ? ' · reviewed' : ''}</h3>
          <p className="small">
            Vulnerable function{f.symbols.symbols.length === 1 ? '' : 's'}: <code>{f.symbols.symbols.join(', ')}</code>
            {f.symbols.receiver && <span className="muted"> on {f.symbols.receiver}</span>}
          </p>
          {f.symbols.evidence ? (
            <p className="small muted">
              Derived from the fix commit <a href={f.symbols.evidence.commits[0]} target="_blank" rel="noreferrer">{shortCommit(f.symbols.evidence.commits[0] ?? '')}</a>, which changed <code>{f.symbols.evidence.changedFunctions.join(', ')}</code> in {f.symbols.evidence.files.join(', ')}.
              {!f.symbols.evidence.repoMatch && ' The fix repository name does not match the package; check it.'}
              {' '}Review with <code>nextfix symbols confirm {f.advisory.id} {f.component.name}</code>.
            </p>
          ) : (
            <p className="small muted">Hand-curated from the advisory{f.symbols.references?.[0] ? <> (<a href={f.symbols.references[0]} target="_blank" rel="noreferrer">source</a>)</> : null}.</p>
          )}
        </section>
      )}

      <section>
        <h3>Fix</h3>
        <div className="fixbox">
          {f.fix ?? 'No fixed version is published yet. Mitigate at the entry point and re-check on the next scan.'}
          {cmd && <code>{cmd}</code>}
        </div>
        <div className="actions">
          {cmd && <button type="button" className="btn small" onClick={() => copy('cmd', cmd)}>{copied === 'cmd' ? <><I.check /> Copied</> : 'Copy command'}</button>}
          <button type="button" className="btn small primary" onClick={() => copy('ticket', ticketMarkdown(f, targetName))}>{copied === 'ticket' ? <><I.check /> Copied</> : 'Copy as ticket'}</button>
          <a className="btn small" href={api.vexUrl(scanId)} download><I.download /> VEX</a>
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
