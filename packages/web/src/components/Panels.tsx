import type { Decision, ScanReport } from '../api.ts';
import { DECISIONS, DECISION_META, advisoryName, compact, dateTime, pct, shortDate, trafficPhrase } from '../format.ts';
import type { SurfaceChange } from '../api.ts';
import { MATRIX_COLS, MATRIX_ROWS, cellLabel, type Bridge, type Decide, type FunnelRow, type MatrixCell, type SurfaceTile, type TrafficView, type Upgrade, type Verdict } from '../analytics.ts';
import { KIND_META } from '../exceptions.ts';
import { I } from './Icons.tsx';

type Go = (page: string, id?: string, query?: Record<string, string>) => void;

const POSTURE_CLASS: Record<Verdict['posture'], string> = { Exposed: 'act', Attention: 'attend', Contained: 'watch', Clean: 'good' };
const POSTURE_ICON: Record<Verdict['posture'], string> = { Exposed: '▲', Attention: '●', Contained: '◐', Clean: '✓' };

const REACH_META = {
  internet: { label: 'Internet-facing', cls: 'act' },
  internal: { label: 'Not reachable from the internet', cls: 'good' },
  unknown: { label: 'Internet reach not confirmed', cls: 'muted' },
} as const;

/** The exposure line under the verdict: how far the service is from the internet, and what said so. */
export function ReachLine({ report, go }: { report: ScanReport; go: Go }) {
  const x = report.exposure;
  const reach = x.reach ?? 'unknown';
  const m = REACH_META[reach];
  const evidence = reach === 'unknown' ? (x.network === 'published' ? `network-published (${x.evidence.join('; ')}), but nothing says whether the internet reaches it` : x.network === 'local-only' ? 'binds to loopback only' : 'no access logs, infrastructure files or declaration found') : (x.reachEvidence ?? []).join('; ');
  return (
    <p className={`verdict-reach r-${m.cls}`}>
      <span className="reach-dot" aria-hidden="true" />
      <strong>{m.label}</strong>
      {evidence && <span className="muted"> · {evidence}</span>}
      {reach === 'unknown' && <> · <button type="button" className="link" onClick={() => go('apps')}>add access logs</button></>}
    </p>
  );
}

/** One state, one sentence, and the rule that produced it. */
export function VerdictCard({ v, go, report }: { v: Verdict; go: Go; report?: ScanReport }) {
  return (
    <section className={`card verdict p-${POSTURE_CLASS[v.posture]}`} aria-label="Posture">
      <div className="verdict-state">
        <span className="verdict-icon" aria-hidden="true">{POSTURE_ICON[v.posture]}</span>
        <span className="verdict-label">Posture</span>
        <span className="verdict-word">{v.posture}</span>
      </div>
      <div className="verdict-body">
        <p className="verdict-head">{v.headline}</p>
        {v.detail && (
          v.findingId ? <button type="button" className="verdict-detail link" onClick={() => go('findings', v.findingId)}>{v.detail} <I.arrow /></button> : <p className="verdict-detail">{v.detail}</p>
        )}
        {report && <ReachLine report={report} go={go} />}
        <p className="verdict-rule">{v.rule}</p>
      </div>
    </section>
  );
}

/** What a scanner shows on the left, what matters on the right, and what each step removed. */
export function FunnelChart({ rows, go }: { rows: FunnelRow[]; go: Go }) {
  const max = Math.max(1, rows[0]?.count ?? 1);
  return (
    <div className="funnel" role="table" aria-label="Evidence funnel">
      {rows.map((r) => (
        <div key={r.key} className="funnel-row" role="row">
          <span className="funnel-label" role="cell">{r.label}</span>
          <span className="funnel-bar" role="cell">
            <span className="funnel-fill" style={{ width: `${Math.max(1.5, (r.count / max) * 100)}%`, background: r.color }} />
            <span className="funnel-n">{r.count}</span>
          </span>
          <span className="funnel-note" role="cell">
            {r.removed && r.removed.count > 0 ? (
              r.removed.tier ? <button type="button" className="link" onClick={() => go('findings', undefined, { tier: r.removed!.tier!, ...(r.removed!.query ?? {}) })}>{r.removed.note}</button> : r.removed.note
            ) : r.removed ? <span className="muted">none removed</span> : <span className="muted">what a scanner reports</span>}
          </span>
        </div>
      ))}
    </div>
  );
}

/** Reachability rows against exploitation columns; the decision follows from the cell. */
export function MatrixChart({ cells, go }: { cells: MatrixCell[]; go: Go }) {
  const cell = (row: string, col: string) => cells.find((c) => c.row === row && c.col === col)!;
  return (
    <div className="matrix-wrap">
      <div className="matrix" role="table" aria-label="Reachability against exploitation">
        <div className="matrix-corner" role="columnheader" />
        {MATRIX_COLS.map((c) => <div key={c.key} className="matrix-col" role="columnheader">{c.label}</div>)}
        {MATRIX_ROWS.map((r) => (
          <div key={r.key} className="matrix-line" role="row">
            <div className="matrix-rowh" role="rowheader">{r.label}</div>
            {MATRIX_COLS.map((c) => {
              const k = cell(r.key, c.key);
              const cls = k.worst ? `d-${DECISION_META[k.worst].cls}` : 'empty';
              return k.findings.length ? (
                <button key={c.key} type="button" className={`matrix-cell ${cls}`} role="cell" onClick={() => go('findings', undefined, r.tier ? { tier: r.tier } : {})} title={`${r.label} · ${c.label}`}>
                  <span className="matrix-cell-n">{k.findings.length}</span>
                  <span className="matrix-cell-l">{cellLabel(k).replace(/^\d+ · /, '')}</span>
                </button>
              ) : (
                <div key={c.key} className="matrix-cell empty" role="cell"><span className="matrix-cell-n muted">0</span></div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

/** Upgrades ranked by what they close, segmented by urgency. */
export function LeverageChart({ ups, go }: { ups: Upgrade[]; go: Go }) {
  const max = Math.max(1, ...ups.map((u) => u.closes.length));
  return (
    <div className="lever" role="table" aria-label="Upgrades ranked by findings closed">
      {ups.map((u) => (
        <button key={u.key} type="button" className="lever-row" role="row" onClick={() => go('findings', undefined, { q: u.name })}>
          <span className="lever-label" role="cell">
            <span className="pkg">{u.name}</span> <span className="muted">{u.version} → {u.target}</span>
            {u.inImage ? <span className="tag">in image</span> : !u.direct ? <span className="tag">transitive</span> : null}
          </span>
          <span className="lever-bar" role="cell" aria-label={`${u.closes.length} findings`}>
            {DECISIONS.map((d) => u.byDecision[d] > 0 && <span key={d} className="lever-seg" style={{ width: `${(u.byDecision[d] / max) * 100}%`, background: DECISION_META[d].color }} title={`${u.byDecision[d]} ${DECISION_META[d].short}`} />)}
            <span className="lever-n">{u.closes.length}</span>
          </span>
          <span className="lever-note muted" role="cell">{u.actionable ? `${u.actionable} need${u.actionable === 1 ? 's' : ''} action` : 'none need action'}</span>
        </button>
      ))}
    </div>
  );
}

/** Previous scan → new, resolved, re-decided → this scan, then the items by name. */
export function BridgeChart({ b, go }: { b: Bridge; go: Go }) {
  if (!b.previous) return <p className="empty">First scan of this application. The next scan shows what changed.</p>;
  const noChange = !b.added.length && !b.resolved.length && !b.escalated.length && !b.deescalated.length;
  const max = Math.max(1, b.previous.findings, b.current, b.added.length, b.resolved.length);
  const h = (n: number) => `${Math.max(n ? 6 : 0, (n / max) * 100)}%`;
  const col = (label: string, n: number, sign: string, cls: string, note?: string) => (
    <div className={`bridge-col ${cls}`}>
      <div className="bridge-track"><div className="bridge-bar" style={{ height: h(n) }} /></div>
      <div className="bridge-n">{sign}{n}</div>
      <div className="bridge-l">{label}</div>
      {note && <div className="bridge-note muted small">{note}</div>}
    </div>
  );
  return (
    <div className="bridge-wrap">
      {noChange && <p className="bridge-same">{b.surface.length ? `No finding changed since ${dateTime(b.previous.at)}, but the surface did.` : `No change since ${dateTime(b.previous.at)}.`}</p>}
      <div className="bridge" role="img" aria-label={`From ${b.previous.findings} findings to ${b.current}: ${b.added.length} new, ${b.resolved.length} resolved, ${b.escalated.length} escalated, ${b.deescalated.length} de-escalated`}>
        {col('Previous scan', b.previous.findings, '', 'neutral', dateTime(b.previous.at))}
        {col('New', b.added.length, '+', 'act')}
        {col('Resolved', b.resolved.length, '−', 'good')}
        {col('Escalated', b.escalated.length, '↑', 'attend')}
        {col('De-escalated', b.deescalated.length, '↓', 'aside')}
        {col('This scan', b.current, '', 'neutral')}
      </div>
      {!noChange && (
        <div className="bridge-lists">
          <ChangeList title="New" items={b.added.map((f) => ({ id: f.id, text: `${f.component.name}@${f.component.version} · ${advisoryName(f)}`, tag: DECISION_META[f.decision].short }))} go={go} />
          <ChangeList title="Resolved" items={b.resolved.map((f) => ({ id: undefined, text: `${f.component.name}@${f.component.version} · ${advisoryName(f)}`, tag: f.advisory.fixedVersion ? `fix ${f.advisory.fixedVersion}` : undefined }))} go={go} />
          <ChangeList title="Re-decided" items={[...b.escalated, ...b.deescalated].map((c) => ({ id: c.finding.id, text: `${c.finding.component.name} · ${advisoryName(c.finding)}`, tag: `${DECISION_META[c.from].short} → ${DECISION_META[c.to].short}${c.reasons?.length ? ` · ${c.reasons[0]}` : ''}` }))} go={go} />
        </div>
      )}
      <SurfaceChanges changes={b.surface} go={go} />
    </div>
  );
}

const LEVEL_META: Record<SurfaceChange['level'], { icon: string; cls: string; label: string }> = {
  act: { icon: '▲', cls: 'act', label: 'widens the surface where it hurts' },
  attend: { icon: '●', cls: 'attend', label: 'widens the surface' },
  info: { icon: '○', cls: 'muted', label: 'changed' },
  good: { icon: '✓', cls: 'good', label: 'narrows the surface' },
};

/** Routes, guards, exposure, traffic and links that changed between the two scans; findings are counted, not the other way round. */
export function SurfaceChanges({ changes, go }: { changes: SurfaceChange[]; go: Go }) {
  if (!changes.length) return null;
  const widening = changes.filter((c) => c.level === 'act' || c.level === 'attend').length;
  return (
    <div className="surface-changes">
      <h3>Attack surface <span className="muted">{changes.length} change{changes.length === 1 ? '' : 's'}{widening ? ` · ${widening} widening` : ''}</span></h3>
      <ul className="plain">
        {changes.slice(0, 8).map((c, i) => {
          const m = LEVEL_META[c.level];
          return (
            <li key={i} className={`surface-change l-${m.cls}`}>
              <span className={`tri d-${m.cls}`} aria-hidden="true">{m.icon}</span>
              {c.route && c.findings ? <button type="button" className="link" onClick={() => go('findings', undefined, { q: c.route!.split(' ')[1] ?? c.route })}>{c.text}</button> : <span>{c.text}</span>}
              <span className="sr-only"> ({m.label})</span>
            </li>
          );
        })}
        {changes.length > 8 && <li className="muted small">and {changes.length - 8} more</li>}
      </ul>
    </div>
  );
}

function ChangeList({ title, items, go }: { title: string; items: { id?: string; text: string; tag?: string }[]; go: Go }) {
  if (!items.length) return null;
  return (
    <div className="change-list">
      <h3>{title} <span className="muted">{items.length}</span></h3>
      <ul className="plain">
        {items.slice(0, 5).map((it, i) => (
          <li key={i}>{it.id ? <button type="button" className="link" onClick={() => go('findings', it.id)}>{it.text}</button> : it.text}{it.tag && <span className="tag">{it.tag}</span>}</li>
        ))}
        {items.length > 5 && <li className="muted small">and {items.length - 5} more</li>}
      </ul>
    </div>
  );
}

/** Entry points as tiles sized by what they reach; clean ones collapse into a count. */
export function SurfaceTiles({ tiles, go, days = 30 }: { tiles: SurfaceTile[]; go: Go; days?: number }) {
  const hot = tiles.filter((t) => t.findings.length);
  const clean = tiles.filter((t) => !t.findings.length);
  const cleanOpen = clean.filter((t) => !t.entry.authenticated).length;
  const cleanCalled = clean.filter((t) => (t.traffic?.requests ?? 0) > 0).length;
  const observed = tiles.some((t) => t.traffic);
  const size = (n: number) => (n >= 3 ? 'big' : n === 2 ? 'mid' : 'small');
  return (
    <div className="surface">
      {hot.map((t) => (
        <button key={`${t.entry.method} ${t.entry.path} ${t.entry.file}:${t.entry.line}`} type="button" className={`tile ${size(t.findings.length)} d-${t.worst ? DECISION_META[t.worst].cls : 'good'}${t.traffic && !t.traffic.requests ? ' quiet' : ''}`} onClick={() => go('findings', undefined, { q: t.entry.path })}>
          <span className="tile-route mono">{t.entry.method} {t.entry.path}</span>
          <span className="tile-line">{t.entry.authenticated ? 'behind a login' : 'open'} · {t.findings.length} finding{t.findings.length === 1 ? '' : 's'}{t.worst ? ` · ${DECISION_META[t.worst].short}` : ''}</span>
          {t.userInput && <span className="tile-line">request data reaches a vulnerable call</span>}
          {t.traffic && <span className={`tile-line tile-traffic ${t.traffic.public ? 'seen' : t.traffic.requests ? 'internal' : 'quiet'}`}>{t.traffic.public ? '● ' : t.traffic.requests ? '◐ ' : '○ '}{trafficPhrase(t.traffic, days)}</span>}
          <span className="tile-foot small">{[...new Set(t.findings.map((f) => f.component.name))].slice(0, 3).join(', ')}</span>
        </button>
      ))}
      {clean.length > 0 && (
        <div className="tile clean small">
          <span className="tile-route">{clean.length} clean route{clean.length === 1 ? '' : 's'}</span>
          <span className="tile-line">{cleanOpen} open, {clean.length - cleanOpen} behind a login</span>
          <span className="tile-foot small">no vulnerable call reachable{observed ? ` · ${cleanCalled} called in ${days} d` : ''}</span>
        </div>
      )}
      {!tiles.length && <p className="empty">No HTTP entry points were found in this project.</p>}
    </div>
  );
}

/**
 * What the access logs say: the window, the busiest routes split public/internal with the worst
 * decision behind each, the open routes nobody called, and the files that were read.
 */
export function TrafficPanel({ v, report, go }: { v: TrafficView; report: ScanReport; go: Go }) {
  if (!v.configured) {
    return (
      <div className="traffic-empty">
        <p>No access logs yet. Today the exposure column is <strong>inferred</strong> from Dockerfile, compose and the code's auth guards.</p>
        <p>Point NextFix at the proxy or load-balancer logs it already has and the column becomes <strong>observed</strong>: routes the internet is actually calling rise, routes nobody has called in a month fall, and every finding says how many requests reached it. Nothing is installed; the logs are read on this machine and only the counts are kept.</p>
        <div className="actions"><button type="button" className="btn small" onClick={() => go('apps')}><I.list /> Add access logs</button></div>
      </div>
    );
  }
  if (!v.observed) return <div className="traffic-empty"><p>{v.sentence}</p><p className="muted small">{v.detail}</p><p className="hint">Supported: nginx and Apache combined logs, AWS ALB logs, JSON lines (Caddy, Cloudflare Logpush, Traefik, pino). Compressed rotations are skipped.</p></div>;
  const top = v.routes.slice(0, 8);
  const max = Math.max(1, ...top.map((r) => r.traffic.requests));
  return (
    <div className="traffic">
      <p className="traffic-sentence">{v.sentence}</p>
      {v.detail && <p className="muted small">{v.detail}</p>}
      <div className="traffic-rows" role="table" aria-label="Routes by observed requests">
        {top.map((r) => (
          <button key={`${r.entry.method} ${r.entry.path}`} type="button" className="traffic-row" role="row" onClick={() => go('findings', undefined, { q: r.entry.path })}>
            <span className="traffic-route mono" role="cell"><span className={`tri d-${r.worst ? DECISION_META[r.worst].cls : 'good'}`} aria-hidden="true">{r.worst ? DECISION_META[r.worst].icon : '✓'}</span> {r.entry.method} {r.entry.path}{r.entry.authenticated ? <span className="muted"> · login</span> : null}</span>
            <span className="traffic-bar" role="cell" aria-label={`${r.traffic.requests} requests, ${r.traffic.public} public`}>
              {r.traffic.public > 0 && <span className="traffic-seg public" style={{ width: `${(r.traffic.public / max) * 100}%` }} />}
              {r.traffic.internal > 0 && <span className="traffic-seg internal" style={{ width: `${(r.traffic.internal / max) * 100}%` }} />}
              <span className="traffic-n">{compact(r.traffic.requests)}</span>
            </span>
            <span className="traffic-note muted" role="cell">{r.traffic.public ? `${compact(r.traffic.public)} public` : 'internal only'}{r.findings.length ? ` · ${r.findings.length} finding${r.findings.length === 1 ? '' : 's'}` : ' · clean'}</span>
          </button>
        ))}
      </div>
      <div className="traffic-legend muted small"><span><i className="traffic-seg public" /> public addresses</span><span><i className="traffic-seg internal" /> internal addresses</span>{v.routes.length > top.length && <span>{v.routes.length - top.length} more routes took requests</span>}</div>
      {v.quiet.length > 0 && (
        <div className="traffic-quiet">
          <h3>Open routes nobody called{v.stale ? '' : ', still reaching vulnerable code'}</h3>
          <ul className="plain">
            {v.quiet.slice(0, 6).map((r) => (
              <li key={`${r.entry.method} ${r.entry.path}`}><button type="button" className="link mono" onClick={() => go('findings', undefined, { q: r.entry.path })}>{r.entry.method} {r.entry.path}</button> <span className="muted small">{r.findings.length} finding{r.findings.length === 1 ? '' : 's'}{r.worst ? ` · ${DECISION_META[r.worst].short}` : ''}</span></li>
            ))}
            {v.quiet.length > 6 && <li className="muted small">and {v.quiet.length - 6} more</li>}
          </ul>
          <p className="hint">{v.stale ? 'The logs are stale, so these are reported without lowering a decision.' : 'A severity-only Fix now on one of these is held at Fix next cycle until a request arrives or exploit data changes; the finding says so.'}</p>
        </div>
      )}
      <p className="traffic-files muted small">Read: {v.files.map((f) => `${f.path} (${f.format}${f.lines ? `, ${compact(f.lines)} lines, ${compact(f.matched)} on known routes` : ''})`).join(' · ')}{report.traffic?.to ? ` · newest line ${shortDate(report.traffic.to)}` : ''}</p>
    </div>
  );
}

/** The four decisions, once, as the work queue. */
export function WorkQueue({ report, prev, go }: { report: ScanReport; prev?: Record<Decision, number>; go: Go }) {
  return (
    <div className="workq" role="list">
      {DECISIONS.map((d) => {
        const n = report.summary.byDecision[d];
        const delta = prev ? n - prev[d] : undefined;
        const m = DECISION_META[d];
        return (
          <button key={d} type="button" role="listitem" className={`workq-tile d-${m.cls}`} onClick={() => (d === 'Track' ? go('evidence') : go('findings', undefined, { decision: d }))}>
            <span className="workq-icon" aria-hidden="true">{m.icon}</span>
            <span className="workq-n">{n}</span>
            <span className="workq-l">{m.short}</span>
            <span className="workq-h">{m.help}</span>
            {delta !== undefined && delta !== 0 && <span className="workq-delta">{delta > 0 ? '+' : ''}{delta} since last scan</span>}
            <span className="sr-only">{report.findings.length ? pct(n / report.findings.length) : ''}</span>
          </button>
        );
      })}
    </div>
  );
}

/** Pending approvals, exceptions about to expire, and routes whose exposure is unconfirmed; each row opens the finding. */
export function DecidePanel({ d, report, go }: { d: Decide; report: ScanReport; go: Go }) {
  const name = (id: string) => { const f = report.findings.find((x) => x.id === id); return f ? `${f.component.name} · ${advisoryName(f)}` : id.split('|')[1] ?? id; };
  const total = d.pending.length + d.expiring.length + d.routes.length;
  if (!total) return <p className="empty">Nothing waits on a person: no proposals pending, no exceptions expiring in the next 30 days, no routes to confirm.</p>;
  const days = (iso: string) => Math.max(0, Math.ceil((Date.parse(iso) - Date.now()) / 86_400_000));
  return (
    <div className="decide">
      {d.pending.length > 0 && (
        <div className="decide-group">
          <h3><span className="tri d-attend" aria-hidden="true">●</span> {d.pending.length} awaiting approval</h3>
          <ul className="plain">{d.pending.map((e) => <li key={e.id}><button type="button" className="link" onClick={() => go('findings', e.findingId)}>{name(e.findingId)}</button> <span className="tag">{KIND_META[e.kind].label}</span> <span className="muted small">by {e.proposedBy}</span></li>)}</ul>
        </div>
      )}
      {d.expiring.length > 0 && (
        <div className="decide-group">
          <h3><span className="tri d-aside" aria-hidden="true">○</span> {d.expiring.length} expiring within 30 days</h3>
          <ul className="plain">{d.expiring.map((e) => <li key={e.id}><button type="button" className="link" onClick={() => go('findings', e.findingId)}>{name(e.findingId)}</button> <span className="tag">{KIND_META[e.kind].label}</span> <span className="muted small">{days(e.expiresAt!)} day{days(e.expiresAt!) === 1 ? '' : 's'} left</span></li>)}</ul>
        </div>
      )}
      {d.routes.length > 0 && (
        <div className="decide-group">
          <h3><span className="tri d-act" aria-hidden="true">▲</span> {d.routes.length} route{d.routes.length === 1 ? '' : 's'} to confirm as public</h3>
          <ul className="plain">{d.routes.map((t) => <li key={`${t.entry.method} ${t.entry.path}`}><button type="button" className="link mono" onClick={() => go('findings', undefined, { q: t.entry.path })}>{t.entry.method} {t.entry.path}</button> <span className="muted small">no login · {t.findings.length} finding{t.findings.length === 1 ? '' : 's'} · network exposure not confirmed</span></li>)}</ul>
        </div>
      )}
    </div>
  );
}
