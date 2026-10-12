import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { Decision, Exception, Finding, FullFinding, Integrations, ReachTier, Role, ScanReport, TicketKind, TicketMap } from '../api.ts';
import { api } from '../api.ts';
import { DecisionBadge } from '../components/DecisionBadge.tsx';
import { ExceptionBox } from '../components/ExceptionBox.tsx';
import { PathDiagram } from '../components/PathDiagram.tsx';
import { I } from '../components/Icons.tsx';
import { DECISIONS, DECISION_META, TIERS, TIER_LABEL, TIER_SHORT, advisoryName, bestPath, compact, entryLabel, fixCommand, severity, shortDate, ticketMarkdown, trafficPhrase } from '../format.ts';
import { hasTraffic, windowPhrase } from '../analytics.ts';

interface Props {
  report: ScanReport;
  /** Finding id → first seen, from the scan history. */
  firstSeen: Record<string, string>;
  scanId: number;
  targetId: number;
  selectedId?: string;
  /** Filters come from the hash: decision, tier, q. */
  query: Record<string, string>;
  tickets: TicketMap;
  integrations: Integrations;
  role: Role;
  /** Newest exception per finding, and the findings whose approved exception took them out of the queue. */
  exceptions: Record<string, Exception>;
  accepted: Set<string>;
  onSelect: (id?: string) => void;
  /** Writes filters back to the hash; `replace` for keystrokes so Back skips them. */
  onQuery: (query: Record<string, string>, replace?: boolean) => void;
  onTicketsChange: () => void;
  onExceptionsChange: () => void;
}

const KIND_LABEL: Record<TicketKind, string> = { github: 'GitHub issue', jira: 'Jira issue' };
type TrafficFilter = 'all' | 'public' | 'internal' | 'cold';
const TRAFFIC_FILTERS: { id: TrafficFilter; label: string }[] = [
  { id: 'all', label: 'Any traffic' },
  { id: 'public', label: 'Called from the internet' },
  { id: 'internal', label: 'Internal traffic only' },
  { id: 'cold', label: 'Nobody called it' },
];
/** The worst-case route's traffic: public on an open route beats anything, then any requests, then quiet. */
function trafficClass(f: Finding): TrafficFilter | undefined {
  const ts = f.reach.paths.map((p) => p.entry.traffic).filter((t): t is NonNullable<typeof t> => !!t);
  if (!ts.length) return undefined;
  if (f.reach.paths.some((p) => !p.entry.authenticated && (p.entry.traffic?.public ?? 0) > 0)) return 'public';
  if (ts.some((t) => t.requests > 0)) return 'internal';
  return 'cold';
}
function bestTraffic(f: Finding) {
  const p = bestPath(f);
  return p?.entry.traffic;
}
const PHONE = '(max-width: 760px)';
const SHEET = '(max-width: 1100px)';

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => typeof matchMedia === 'function' && matchMedia(query).matches);
  useEffect(() => {
    if (typeof matchMedia !== 'function') return;
    const mq = matchMedia(query);
    const update = () => setMatches(mq.matches);
    update();
    mq.addEventListener('change', update);
    return () => mq.removeEventListener('change', update);
  }, [query]);
  return matches;
}

export function Findings({ report, firstSeen, scanId, targetId, selectedId, query, tickets, integrations, role, exceptions, accepted, onSelect, onQuery, onTicketsChange, onExceptionsChange }: Props) {
  const decision: Decision | 'all' = DECISIONS.includes(query.decision as Decision) ? (query.decision as Decision) : 'all';
  const tier: ReachTier | 'all' = TIERS.includes(query.tier as ReachTier) ? (query.tier as ReachTier) : 'all';
  const q = query.q ?? '';
  const observed = hasTraffic(report);
  const traffic: TrafficFilter = observed && TRAFFIC_FILTERS.some((t) => t.id === query.traffic) ? (query.traffic as TrafficFilter) : 'all';
  const days = report.traffic?.windowDays ?? 30;
  const setFilter = (patch: Record<string, string>, replace = false) => onQuery({ ...query, ...patch }, replace);
  const [bulk, setBulk] = useState<string | null>(null);
  const phone = useMediaQuery(PHONE);
  const canTicket = role !== 'viewer';

  const kinds = canTicket ? (['github', 'jira'] as TicketKind[]).filter((k) => integrations[k]) : [];
  const actionableWithout = (kind: TicketKind) => report.findings.filter((f) => (f.decision === 'Act' || f.decision === 'Attend') && !tickets[f.id]?.some((t) => t.kind === kind));
  const createBulk = async (kind: TicketKind) => {
    const list = actionableWithout(kind);
    if (!list.length) return;
    if (!window.confirm(`Create ${list.length} ${KIND_LABEL[kind]}${list.length === 1 ? '' : 's'} for every Fix now and Fix next cycle finding without one?`)) return;
    setBulk(`Creating ${list.length} ${KIND_LABEL[kind]}s…`);
    try {
      const r = await api.createTickets(targetId, scanId, kind, list.map((f) => f.id));
      const ok = r.results.filter((x) => x.url && !x.skipped).length;
      const failed = r.results.filter((x) => x.error);
      setBulk(`${ok} created${failed.length ? `, ${failed.length} failed: ${failed[0]!.error}` : ''}`);
      onTicketsChange();
    } catch (e) {
      setBulk(e instanceof Error ? e.message : String(e));
    }
  };

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return report.findings.filter((f) =>
      (decision === 'all' || f.decision === decision) &&
      (tier === 'all' || f.reach.tier === tier) &&
      (traffic === 'all' || trafficClass(f) === traffic) &&
      (!needle || `${f.component.name} ${advisoryName(f)} ${f.advisory.id} ${f.advisory.summary} ${entryLabel(f) ?? ''}`.toLowerCase().includes(needle)),
    );
  }, [report, decision, tier, traffic, q]);

  const selected = selectedId ? report.findings.find((f) => f.id === selectedId) : undefined;

  return (
    <div className="stack">
      <div className="filters" role="group" aria-label="Filters">
        <button type="button" className="chip" aria-pressed={decision === 'all'} onClick={() => setFilter({ decision: '' })}>All <span className="n">{report.findings.length}</span></button>
        {DECISIONS.map((d) => (
          <button key={d} type="button" className={`chip d-${DECISION_META[d].cls}`} aria-pressed={decision === d} onClick={() => setFilter({ decision: decision === d ? '' : d })} title={DECISION_META[d].help}>
            <span aria-hidden="true">{DECISION_META[d].icon}</span> {DECISION_META[d].short} <span className="n">{report.summary.byDecision[d]}</span>
          </button>
        ))}
        <select aria-label="Reachability" value={tier} onChange={(e) => setFilter({ tier: e.target.value === 'all' ? '' : e.target.value })}>
          <option value="all">Any reachability</option>
          {TIERS.map((t) => <option key={t} value={t}>{TIER_SHORT[t]} ({report.summary.byTier[t]})</option>)}
        </select>
        {observed && (
          <select aria-label="Observed traffic" value={traffic} onChange={(e) => setFilter({ traffic: e.target.value === 'all' ? '' : e.target.value })}>
            {TRAFFIC_FILTERS.map((t) => <option key={t.id} value={t.id}>{t.label}{t.id !== 'all' ? ` (${report.findings.filter((f) => trafficClass(f) === t.id).length})` : ''}</option>)}
          </select>
        )}
        <input type="search" placeholder="Search package, CVE, route…" value={q} onChange={(e) => setFilter({ q: e.target.value }, true)} aria-label="Search findings" />
        <a className="btn small" href={api.vexUrl(scanId)} download><I.download /> VEX</a>
        {kinds.map((k) => {
          const n = actionableWithout(k).length;
          return <button key={k} type="button" className="btn small" disabled={!n || !!bulk?.startsWith('Creating')} onClick={() => createBulk(k)} title={`Create a ${KIND_LABEL[k]} for every Fix now / Fix next cycle finding that has none`}>{KIND_LABEL[k]}s for actionable <span className="n">{n}</span></button>;
        })}
      </div>
      {bulk && <div className="banner" role="status">{bulk} <button type="button" className="btn ghost small" onClick={() => setBulk(null)} aria-label="Dismiss"><I.close /></button></div>}

      <div className={`workbench ${selected ? 'with-detail' : ''}`}>
        {phone ? (
          <ul className="queue-cards" aria-label="Findings">
            {rows.map((f) => {
              const sev = severity(f);
              return (
                <li key={f.id}>
                  <button type="button" className="qcard" aria-pressed={selected?.id === f.id} onClick={() => onSelect(f.id)}>
                    <span className="qcard-top"><DecisionBadge decision={f.decision} short accepted={accepted.has(f.id)} /><span className="qcard-pkg">{f.component.name}<span className="muted">@{f.component.version}</span></span></span>
                    <span className="qcard-score" aria-label={`Score ${f.score}`}>{f.score}</span>
                    <span className="qcard-adv">{advisoryName(f)}<span className="muted">{f.advisory.summary}</span></span>
                    <span className="qcard-meta">
                      <span className={`sev ${sev.cls}`}>{sev.label}</span>
                      <span>{TIER_SHORT[f.reach.tier]}</span>
                      {observed && bestTraffic(f) && <span className={`traffic-tag ${trafficClass(f)}`}>{trafficPhrase(bestTraffic(f), days)}</span>}
                      {f.advisory.fixedVersion ? <span className="qcard-fix">→ {f.advisory.fixedVersion}</span> : <span className="muted">no fix</span>}
                      {(tickets[f.id] ?? []).map((t) => <span key={t.kind} className="ticket-link">{t.key}</span>)}
                    </span>
                  </button>
                </li>
              );
            })}
            {!rows.length && <li className="empty">Nothing matches these filters.</li>}
          </ul>
        ) : (
          <div className="card table-wrap">
            <table className="tbl queue">
              <thead>
                <tr><th>Decision</th><th className="num">Score</th><th>Component</th><th>Advisory</th><th>Severity</th><th>Reach</th><th>Entry point</th><th>Fix</th><th>Ticket</th></tr>
              </thead>
              <tbody>
                {rows.map((f) => {
                  const sev = severity(f);
                  return (
                    <tr key={f.id} className="row" aria-selected={selected?.id === f.id} onClick={() => onSelect(f.id)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(f.id); } }}>
                      <td><DecisionBadge decision={f.decision} short accepted={accepted.has(f.id)} />{exceptions[f.id]?.status === 'pending' && <div className="small pending-text">exception pending</div>}</td>
                      <td className="num">{f.score}</td>
                      <td className="pkg">{f.component.name}<span className="muted">@{f.component.version}</span></td>
                      <td>{advisoryName(f)}<div className="muted small">{f.advisory.summary}</div></td>
                      <td><span className={`sev ${sev.cls}`}>{sev.label}</span></td>
                      <td>{TIER_SHORT[f.reach.tier]}</td>
                      <td className="mono small">{entryLabel(f) ?? <span className="muted">—</span>}{observed && bestTraffic(f) && <div className={`traffic-tag ${trafficClass(f)}`}>{trafficPhrase(bestTraffic(f), days)}</div>}</td>
                      <td>{f.advisory.fixedVersion ? `→ ${f.advisory.fixedVersion}` : <span className="muted">no fix</span>}</td>
                      <td>{(tickets[f.id] ?? []).map((t) => <a key={t.kind} className="ticket-link" href={t.url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>{t.key}</a>)}</td>
                    </tr>
                  );
                })}
                {!rows.length && <tr><td colSpan={9} className="empty">Nothing matches these filters.</td></tr>}
              </tbody>
            </table>
          </div>
        )}
        {selected && <Detail f={selected} report={report} firstSeenAt={firstSeen[selected.id]} scanId={scanId} targetId={targetId} targetName={report.target.name ?? report.target.dir} tickets={tickets[selected.id] ?? []} kinds={kinds} role={role} exception={exceptions[selected.id]} accepted={accepted.has(selected.id)} onTicketsChange={onTicketsChange} onExceptionsChange={onExceptionsChange} onClose={() => onSelect(undefined)} />}
      </div>
    </div>
  );
}

/** Advisory data is not ours: only http(s) URLs become links, anything else is shown as text. */
function SafeLink({ href, children }: { href?: string; children: ReactNode }) {
  if (!href || !/^https?:\/\//i.test(href)) return <span>{children}</span>;
  return <a href={href} target="_blank" rel="noreferrer">{children}</a>;
}

function shortCommit(url: string): string {
  const m = /\/(?:commit|commits)\/([0-9a-f]{7,40})/i.exec(url);
  if (m) return m[1]!.slice(0, 10);
  const pr = /\/pull\/(\d+)/.exec(url);
  if (pr) return `PR #${pr[1]}`;
  return url.replace(/^https?:\/\/github\.com\//, '');
}

interface DetailProps {
  f: Finding;
  report: ScanReport;
  firstSeenAt?: string;
  scanId: number;
  targetId: number;
  targetName: string;
  tickets: { kind: TicketKind; key: string; url: string }[];
  kinds: TicketKind[];
  role: Role;
  exception?: Exception;
  accepted: boolean;
  onTicketsChange: () => void;
  onExceptionsChange: () => void;
  onClose: () => void;
}

/**
 * The list row is enough to draw the panel; the full finding (advisory text, every reference)
 * is fetched when it opens. Below 1100 px the panel is a full-height sheet: focus moves to
 * Close, Escape and the backdrop close it, and focus returns to the row afterwards.
 */
function Detail({ f, report, firstSeenAt, scanId, targetId, targetName, tickets, kinds, role, exception, accepted, onTicketsChange, onExceptionsChange, onClose }: DetailProps) {
  const [copied, setCopied] = useState<string | null>(null);
  const [creating, setCreating] = useState<TicketKind | null>(null);
  const [ticketError, setTicketError] = useState<string | null>(null);
  const [full, setFull] = useState<FullFinding | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const sheet = useMediaQuery(SHEET);
  const closeRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    setFull(null);
    setLoadError(null);
    const ac = new AbortController();
    api.finding(scanId, f.id, ac.signal).then(setFull).catch((e) => { if (!ac.signal.aborted) setLoadError(e instanceof Error ? e.message : String(e)); });
    return () => ac.abort();
  }, [scanId, f.id]);

  useEffect(() => {
    if (!sheet) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCloseRef.current();
      }
    };
    document.addEventListener('keydown', onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = previousOverflow;
      if (opener && opener.isConnected) opener.focus();
    };
  }, [sheet, f.id]);

  const createOne = async (kind: TicketKind) => {
    setCreating(kind);
    setTicketError(null);
    try {
      const r = await api.createTickets(targetId, scanId, kind, [f.id]);
      const res = r.results[0];
      if (res?.error) setTicketError(res.error);
      onTicketsChange();
    } catch (e) {
      setTicketError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(null);
    }
  };
  const copy = async (what: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
      setTimeout(() => setCopied(null), 1600);
    } catch {
      setCopied('failed');
    }
  };
  const data: Finding = full ?? f;
  const cmd = fixCommand(data);
  const path = bestPath(data);
  const sev = severity(data);
  const title = `${f.component.name}@${f.component.version} · ${advisoryName(f)}`;
  const references = data.advisory.references ?? [];

  return (
    <>
      {sheet && <div className="sheet-backdrop" onClick={() => onCloseRef.current()} role="presentation" />}
      <aside className="card detail" role={sheet ? 'dialog' : undefined} aria-modal={sheet || undefined} aria-label={title}>
        <div className="detail-head">
          <div>
            <DecisionBadge decision={f.decision} short accepted={accepted} />
            <div className="detail-title">{title}</div>
            <div className="detail-sub">{f.advisory.summary} · <span className={`sev ${sev.cls}`}>{sev.label}</span>{f.advisory.cvssScore !== undefined && ` CVSS ${f.advisory.cvssScore.toFixed(1)}`} · score {f.score}{firstSeenAt && <span className="first-seen"> · first seen {shortDate(firstSeenAt)}</span>}</div>
          </div>
          <button ref={closeRef} type="button" className="btn ghost icon" onClick={onClose} aria-label="Close"><I.close /></button>
        </div>

        <section>
          <h3>Why</h3>
          <ul className="why">{data.why.map((w, i) => <li key={i}>{w}</li>)}</ul>
        </section>

        <section>
          <h3>Reachability · {TIER_LABEL[data.reach.tier]} · confidence {data.reach.confidence}</h3>
          {path ? <PathDiagram path={path} pkg={data.component.name} /> : data.reach.callSites.length ? (
            <ul className="refs">{data.reach.callSites.map((c, i) => <li key={i}><code>{c.text}()</code> at {c.file}:{c.line}</li>)}</ul>
          ) : (
            <p className="empty">{data.reach.tier === 'image-only' ? `Present in ${data.component.image ?? 'the container image'}${data.component.path && data.component.path !== data.component.name ? ` as ${(data.component.paths ?? [data.component.path]).join(', ')}` : ''}; the application code does not import it and NextFix does not trace code paths inside images.` : data.reach.importedIn.length ? `Imported in ${data.reach.importedIn.join(', ')}.` : 'Not imported by any source file.'}</p>
          )}
          {data.reach.paths.length > 1 && <p className="empty">{data.reach.paths.length} entry points reach this call, {data.reach.paths.filter((p) => p.userInput).length} carrying request data; the worst case is shown.</p>}
        </section>

        {report.traffic && data.reach.paths.length > 0 && (
          <section>
            <h3>Observed traffic · {windowPhrase(report) || `${report.traffic.windowDays} days`}</h3>
            {hasTraffic(report) ? (
              <table className="tbl mini">
                <thead><tr><th>Route</th><th className="num">Requests</th><th className="num">Public</th><th className="num">Internal</th><th>Last seen</th></tr></thead>
                <tbody>
                  {data.reach.paths.map((p) => (
                    <tr key={`${p.entry.method} ${p.entry.path}`}>
                      <td className="mono small">{p.entry.method} {p.entry.path}{p.entry.authenticated ? <span className="muted"> · login</span> : null}</td>
                      <td className="num">{compact(p.entry.traffic?.requests ?? 0)}</td>
                      <td className={`num ${(p.entry.traffic?.public ?? 0) > 0 ? 'traffic-public' : ''}`}>{compact(p.entry.traffic?.public ?? 0)}</td>
                      <td className="num">{compact(p.entry.traffic?.internal ?? 0)}</td>
                      <td className="small muted">{p.entry.traffic?.lastSeenAt ? shortDate(p.entry.traffic.lastSeenAt) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <p className="empty">The configured logs held no requests that could be read.</p>}
            {report.traffic.stale && <p className="hint">The logs end more than a month before this scan; quiet routes do not lower the decision.</p>}
          </section>
        )}

        {data.symbols && (
          <section>
            <h3>Function data · {data.symbols.source}{data.symbols.reviewed ? ' · reviewed' : ''}</h3>
            <p className="small">
              Vulnerable function{data.symbols.symbols.length === 1 ? '' : 's'}: <code>{data.symbols.symbols.join(', ')}</code>
              {data.symbols.receiver && <span className="muted"> on {data.symbols.receiver}</span>}
            </p>
            {data.symbols.evidence ? (
              <p className="small muted">
                Derived from the fix commit <SafeLink href={data.symbols.evidence.commits[0]}>{shortCommit(data.symbols.evidence.commits[0] ?? '')}</SafeLink>, which changed <code>{data.symbols.evidence.changedFunctions.join(', ')}</code> in {data.symbols.evidence.files.join(', ')}.
                {!data.symbols.evidence.repoMatch && ' The fix repository name does not match the package; check it.'}
                {' '}Review with <code>nextfix symbols confirm {data.advisory.id} {data.component.name}</code>.
              </p>
            ) : (
              <p className="small muted">Hand-curated from the advisory{data.symbols.references?.[0] ? <> (<SafeLink href={data.symbols.references[0]}>source</SafeLink>)</> : null}.</p>
            )}
          </section>
        )}

        <section>
          <h3>Fix</h3>
          <div className="fixbox">
            {data.fix ?? 'No fixed version is published yet. Mitigate at the entry point and re-check on the next scan.'}
            {cmd && <code>{cmd}</code>}
          </div>
          <div className="actions">
            {cmd && <button type="button" className="btn small" onClick={() => copy('cmd', cmd)}>{copied === 'cmd' ? <><I.check /> Copied</> : 'Copy command'}</button>}
            <button type="button" className="btn small primary" onClick={() => copy('ticket', ticketMarkdown(data, targetName))}>{copied === 'ticket' ? <><I.check /> Copied</> : 'Copy as ticket'}</button>
            {kinds.map((k) => {
              const t = tickets.find((x) => x.kind === k);
              return t ? (
                <a key={k} className="btn small" href={t.url} target="_blank" rel="noreferrer"><I.check /> {KIND_LABEL[k]} {t.key}</a>
              ) : (
                <button key={k} type="button" className="btn small" disabled={creating !== null} onClick={() => createOne(k)}>{creating === k ? 'Creating…' : `Create ${KIND_LABEL[k]}`}</button>
              );
            })}
            <a className="btn small" href={api.vexUrl(scanId)} download><I.download /> VEX</a>
            {copied === 'failed' && <span className="error">Clipboard blocked by the browser.</span>}
            {ticketError && <span className="error">{ticketError}</span>}
          </div>
          {!kinds.length && role !== 'viewer' && <p className="hint">Connect GitHub Issues or Jira under Settings → Integrations to create tickets from here.</p>}
        </section>

        <ExceptionBox findingId={f.id} targetId={targetId} role={role} exception={exception} onChange={onExceptionsChange} />

        {full?.advisory.details && (
          <section>
            <h3>Advisory</h3>
            <details>
              <summary>Show the advisory text</summary>
              <p className="detail-text">{full.advisory.details}</p>
            </details>
          </section>
        )}

        {references.length > 0 && (
          <section>
            <h3>References{!full && !loadError ? <span className="muted"> · loading</span> : null}</h3>
            <ul className="refs">{references.map((r) => <li key={r}><SafeLink href={r}>{r}</SafeLink></li>)}</ul>
            {loadError && <p className="hint">Could not load the full finding: {loadError}</p>}
          </section>
        )}
      </aside>
    </>
  );
}
