import type { Decision, ScanReport } from '../api.ts';
import { DECISIONS, DECISION_META, advisoryName, dateTime, pct } from '../format.ts';
import { MATRIX_COLS, MATRIX_ROWS, cellLabel, type Bridge, type FunnelRow, type MatrixCell, type SurfaceTile, type Upgrade, type Verdict } from '../analytics.ts';
import { I } from './Icons.tsx';

type Go = (page: string, id?: string, query?: Record<string, string>) => void;

const POSTURE_CLASS: Record<Verdict['posture'], string> = { Exposed: 'act', Attention: 'attend', Contained: 'watch', Clean: 'good' };
const POSTURE_ICON: Record<Verdict['posture'], string> = { Exposed: '▲', Attention: '●', Contained: '◐', Clean: '✓' };

/** One state, one sentence, and the rule that produced it. */
export function VerdictCard({ v, go }: { v: Verdict; go: Go }) {
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
              r.removed.tier ? <button type="button" className="link" onClick={() => go('findings', undefined, { tier: r.removed!.tier! })}>{r.removed.note}</button> : r.removed.note
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
      {noChange && <p className="bridge-same">No change since {dateTime(b.previous.at)}.</p>}
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
export function SurfaceTiles({ tiles, go }: { tiles: SurfaceTile[]; go: Go }) {
  const hot = tiles.filter((t) => t.findings.length);
  const clean = tiles.filter((t) => !t.findings.length);
  const cleanOpen = clean.filter((t) => !t.entry.authenticated).length;
  const size = (n: number) => (n >= 3 ? 'big' : n === 2 ? 'mid' : 'small');
  return (
    <div className="surface">
      {hot.map((t) => (
        <button key={`${t.entry.method} ${t.entry.path} ${t.entry.file}:${t.entry.line}`} type="button" className={`tile ${size(t.findings.length)} d-${t.worst ? DECISION_META[t.worst].cls : 'good'}`} onClick={() => go('findings', undefined, { q: t.entry.path })}>
          <span className="tile-route mono">{t.entry.method} {t.entry.path}</span>
          <span className="tile-line">{t.entry.authenticated ? 'behind a login' : 'open'} · {t.findings.length} finding{t.findings.length === 1 ? '' : 's'}{t.worst ? ` · ${DECISION_META[t.worst].short}` : ''}</span>
          {t.userInput && <span className="tile-line">request data reaches a vulnerable call</span>}
          <span className="tile-foot small">{[...new Set(t.findings.map((f) => f.component.name))].slice(0, 3).join(', ')}</span>
        </button>
      ))}
      {clean.length > 0 && (
        <div className="tile clean small">
          <span className="tile-route">{clean.length} clean route{clean.length === 1 ? '' : 's'}</span>
          <span className="tile-line">{cleanOpen} open, {clean.length - cleanOpen} behind a login</span>
          <span className="tile-foot small">no vulnerable call reachable</span>
        </div>
      )}
      {!tiles.length && <p className="empty">No HTTP entry points were found in this project.</p>}
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
