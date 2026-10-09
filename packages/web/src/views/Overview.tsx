import { useState } from 'react';
import type { Decision, EntryPoint, Finding, ScanDiff, ScanMeta, ScanReport } from '../api.ts';
import { Donut } from '../components/Donut.tsx';
import { DotMatrix } from '../components/DotMatrix.tsx';
import { TrendChart } from '../components/TrendChart.tsx';
import { Modal } from '../components/Modal.tsx';
import { HowItWorks } from '../components/HowItWorks.tsx';
import { I } from '../components/Icons.tsx';
import { BUCKET_ORDER, DECISION_META, EVIDENCE_TIERS, STATE_LABEL, STATE_ORDER, advisoryName, componentStates, entryLabel, pct, recommendation, severity, type ComponentState } from '../format.ts';

interface Props {
  report: ScanReport;
  scans: ScanMeta[];
  diff?: ScanDiff;
  go: (page: string, id?: string, query?: Record<string, string>) => void;
}

const STATE_COLOR: Record<ComponentState, string> = {
  reachable: 'var(--c-act)',
  'called-unreached': 'var(--c-attend)',
  'imported-unknown-symbol': 'var(--c-watch)',
  'imported-not-called': 'var(--seq-4)',
  unused: 'var(--seq-2)',
  'dev-only': 'var(--muted)',
  clean: 'var(--c-good)',
};

export function Overview({ report, scans, diff, go }: Props) {
  const [range, setRange] = useState(6);
  const [howOpen, setHowOpen] = useState(false);
  const [epOpen, setEpOpen] = useState(false);
  const s = report.summary;
  const total = Math.max(1, s.findings);
  const top = report.findings.filter((f) => f.decision === 'Act' || f.decision === 'Attend').slice(0, 5);
  const unauth = report.entryPoints.filter((e) => !e.authenticated);
  const states = componentStates(report);
  const prev = diff?.previous?.summary;

  const bucket = (d: Decision) => ({ n: s.byDecision[d], p: pct(s.byDecision[d] / total), m: DECISION_META[d] });

  return (
    <div className="stack">
      <div className="grid ov1">
        {/* Scan overview */}
        <section className="card">
          <h2>Scan overview</h2>
          <div className="ov-total">
            <div className="hero-num">{s.findings}</div>
            <div className="hero-cap">Total findings<br /><span className="muted">across {s.components} components</span></div>
            <DotMatrix findings={report.findings} />
          </div>
          <div className="mini-grid">
            {BUCKET_ORDER.map((d) => {
              const b = bucket(d);
              const delta = prev ? s.byDecision[d] - prev.byDecision[d] : undefined;
              return (
                <button key={d} type="button" className={`mini d-${b.m.cls}`} onClick={() => go('findings', undefined, { decision: d })}>
                  <span className="mini-n">{b.n}</span>
                  <span className="mini-l">{b.m.short}</span>
                  {delta !== undefined && delta !== 0 && <span className="mini-delta">{delta > 0 ? '+' : ''}{delta} vs last</span>}
                  <I.chevron className="mini-ch" />
                </button>
              );
            })}
          </div>
        </section>

        {/* Command center */}
        <section className="card cc-card">
          <div className="card-head">
            <div>
              <h2>Remediation command center</h2>
              <p className="sub">Triage findings and drive them to resolution.</p>
            </div>
            <button type="button" className="btn small" onClick={() => setHowOpen(true)}><I.info /> How it works</button>
          </div>
          <div className="cc">
            <div className="cc-mid">
              <Donut
                glow
                size={220}
                slices={BUCKET_ORDER.map((d) => ({ key: d, value: s.byDecision[d], color: DECISION_META[d].color, label: DECISION_META[d].short }))}
                total={s.findings}
                title="Findings"
                subtitle={`${s.components} components`}
              />
            </div>
            <div className="cc-quads">
              <Quadrant d="Act" b={bucket('Act')} icon={<I.alert />} onClick={() => go('findings', undefined, { decision: 'Act' })} />
              <Quadrant d="Attend" b={bucket('Attend')} icon={<I.clock />} onClick={() => go('findings', undefined, { decision: 'Attend' })} />
              <Quadrant d="Track" b={bucket('Track')} icon={<I.doc />} onClick={() => go('evidence')} />
              <Quadrant d="Track*" b={bucket('Track*')} icon={<I.eye />} onClick={() => go('findings', undefined, { decision: 'Track*' })} />
            </div>
          </div>
        </section>

        {/* Entry points */}
        <section className="card">
          <div className="card-head">
            <h2>Entry points without authentication</h2>
            <span className="hint strong">{unauth.length} of {report.entryPoints.length}</span>
          </div>
          <p className="sub">Public entry points that do not require auth.</p>
          <ol className="ep-list">
            {[...report.entryPoints].sort((a, b) => Number(a.authenticated) - Number(b.authenticated)).slice(0, 5).map((e, i) => <EntryRow key={`${e.method}${e.path}${i}`} e={e} n={i + 1} />)}
          </ol>
          <div className="card-foot">
            <button type="button" className="btn small" onClick={() => setEpOpen(true)}>View all entry points <I.arrow /></button>
          </div>
        </section>
      </div>

      <div className="grid ov2">
        <section className="card">
          <div className="card-head">
            <h2>Actionable findings over time</h2>
            <select aria-label="Range" value={range} onChange={(e) => setRange(Number(e.target.value))}>
              <option value={6}>Last 6 scans</option>
              <option value={12}>Last 12 scans</option>
              <option value={0}>All scans</option>
            </select>
          </div>
          <TrendChart scans={range ? scans.slice(-range) : scans} />
        </section>

        <section className="card">
          <h2>Where the findings landed</h2>
          <div className="stackbar" role="img" aria-label="Findings by decision">
            {BUCKET_ORDER.map((d) => s.byDecision[d] > 0 && <span key={d} style={{ width: `${(s.byDecision[d] / total) * 100}%`, background: DECISION_META[d].color }} title={`${DECISION_META[d].short}: ${s.byDecision[d]}`} />)}
          </div>
          <div className="bar-total">{s.findings} findings</div>
          <ul className="legend-list">
            {BUCKET_ORDER.map((d) => (
              <li key={d}>
                <span><span className="sw" style={{ background: DECISION_META[d].color }} />{DECISION_META[d].label} · {DECISION_META[d].short}</span>
                <span className="n">{s.byDecision[d]}</span>
                <span className="n muted">{pct(s.byDecision[d] / total)}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="card">
          <h2>Component states</h2>
          <div className="cs">
            <Donut size={150} thickness={16} slices={STATE_ORDER.map((st) => ({ key: st, value: states[st], color: STATE_COLOR[st], label: STATE_LABEL[st] }))} total={s.components} title="Components" />
            <ul className="legend-list compact">
              {STATE_ORDER.map((st) => (
                <li key={st}><span><span className="sw" style={{ background: STATE_COLOR[st] }} />{STATE_LABEL[st]}</span><span className="n">{states[st]}</span></li>
              ))}
            </ul>
          </div>
        </section>
      </div>

      <div className="grid ov3">
        <section className="card">
          <div className="card-head">
            <div><h2>What to fix first</h2><p className="sub">Top prioritized findings to reduce risk.</p></div>
            <button type="button" className="btn small" onClick={() => go('findings')}>View all findings <I.arrow /></button>
          </div>
          {top.length ? (
            <div className="table-wrap">
              <table className="tbl">
                <thead><tr><th>#</th><th>Finding</th><th>Component</th><th>Severity</th><th>Entry point</th><th>Recommendation</th><th /></tr></thead>
                <tbody>
                  {top.map((f, i) => {
                    const sev = severity(f);
                    return (
                      <tr key={f.id} className="row" onClick={() => go('findings', f.id)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') go('findings', f.id); }}>
                        <td className="num muted">{i + 1}</td>
                        <td><span className={`tri d-${DECISION_META[f.decision].cls}`} aria-hidden="true">{DECISION_META[f.decision].icon}</span> {f.advisory.summary || advisoryName(f)}<div className="muted small">{advisoryName(f)}</div></td>
                        <td className="mono">{f.component.name}@{f.component.version}</td>
                        <td><span className={`sev ${sev.cls}`}>{sev.label}</span></td>
                        <td className="mono">{entryLabel(f) ?? <span className="muted">—</span>}</td>
                        <td>{recommendation(f)}</td>
                        <td className="muted"><I.chevron /></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : <p className="empty">Nothing needs action. Keep scanning after each release.</p>}
        </section>

        <section className="card">
          <div className="card-head">
            <div className="with-icon"><span className="icon-box"><I.evidence size={22} /></span><div><h2>Evidence &amp; exceptions</h2><p className="sub">Audit-defensible set-asides with supporting evidence.</p></div></div>
            <button type="button" className="btn small" onClick={() => go('evidence')}>View all <I.arrow /></button>
          </div>
          <ul className="ev-list">
            {EVIDENCE_TIERS.map((t) => {
              const n = s.byTier[t.tier];
              return (
                <li key={t.tier}>
                  <button type="button" className="ev-row" onClick={() => go('evidence', undefined, { tier: t.tier })}>
                    <I.doc className="muted" /><span className="grow">{t.label}</span><span className="muted">{n} finding{n === 1 ? '' : 's'}</span><I.chevron className="muted" />
                  </button>
                </li>
              );
            })}
          </ul>
        </section>
      </div>

      {howOpen && <HowItWorks onClose={() => setHowOpen(false)} />}
      {epOpen && (
        <Modal title={`Entry points (${report.entryPoints.length})`} onClose={() => setEpOpen(false)}>
          <ol className="ep-list">
            {[...report.entryPoints].sort((a, b) => Number(a.authenticated) - Number(b.authenticated)).map((e, i) => <EntryRow key={`${e.method}${e.path}${i}`} e={e} n={i + 1} file />)}
          </ol>
        </Modal>
      )}
    </div>
  );
}

function Quadrant({ d, b, icon, onClick }: { d: Decision; b: { n: number; p: string; m: (typeof DECISION_META)[Decision] }; icon: React.ReactNode; onClick: () => void }) {
  return (
    <button type="button" className={`quad d-${b.m.cls}`} onClick={onClick}>
      <span className="quad-icon">{icon}</span>
      <span className="quad-body">
        <span className="quad-n">{b.n} <span className="quad-p">{b.p}</span></span>
        <span className="quad-l">{b.m.short}</span>
        <span className="quad-h">{b.m.help}</span>
      </span>
      <span className="quad-go" aria-hidden="true"><I.arrow /></span>
      <span className="sr-only">{d}</span>
    </button>
  );
}

function EntryRow({ e, n, file }: { e: EntryPoint; n: number; file?: boolean }) {
  return (
    <li className="ep">
      <span className="ep-n muted">{n}</span>
      <span className={`ep-dot ${e.authenticated ? 'ok' : 'warn'}`} aria-hidden="true" />
      <span className="ep-m mono">{e.method}</span>
      <span className="ep-p mono">{e.path}{file && <span className="muted small"> · {e.file}:{e.line}</span>}</span>
      <span className={`tag ${e.authenticated ? 'ok' : 'warn'}`}>{e.authenticated ? 'Auth required' : 'No auth'}</span>
    </li>
  );
}
