import { useMemo, useState } from 'react';
import type { Exception, ScanDiff, ScanMeta, ScanReport } from '../api.ts';
import { TrendChart } from '../components/TrendChart.tsx';
import { HowItWorks } from '../components/HowItWorks.tsx';
import { BridgeChart, DecidePanel, FunnelChart, LeverageChart, MatrixChart, SurfaceTiles, TrafficPanel, VerdictCard, WorkQueue } from '../components/Panels.tsx';
import { I } from '../components/Icons.tsx';
import { AgeingPanel, RecheckButton } from '../components/Ageing.tsx';
import { EVIDENCE_TIERS } from '../format.ts';
import { bridge, decide, funnel, leverageSentence, matrix, ratios, surface, trafficView, upgrades, verdict } from '../analytics.ts';
import '../overview.css';

interface Props {
  report: ScanReport;
  targetId: number;
  scans: ScanMeta[];
  diff?: ScanDiff;
  exceptions: Exception[];
  /** Findings a person set aside; they are already counted as Track in `report`. */
  accepted: Set<string>;
  go: (page: string, id?: string, query?: Record<string, string>) => void;
}

/**
 * One question per panel: are we OK (verdict, funnel), what changed (bridge), what is being
 * done and how (work queue, fix leverage), where would an attacker get in (surface), and how
 * the decisions follow (matrix). The four decision counts appear once, as the work queue.
 */
export function Overview({ report, targetId, scans, diff, exceptions, accepted, go }: Props) {
  const [range, setRange] = useState(6);
  const [howOpen, setHowOpen] = useState(false);
  const v = useMemo(() => verdict(report), [report]);
  const dec = useMemo(() => decide(exceptions, report), [exceptions, report]);
  const rows = useMemo(() => funnel(report), [report]);
  const rat = useMemo(() => ratios(report), [report]);
  const cells = useMemo(() => matrix(report), [report]);
  const ups = useMemo(() => upgrades(report), [report]);
  const tiles = useMemo(() => surface(report), [report]);
  const br = useMemo(() => bridge(report, diff), [report, diff]);
  const tv = useMemo(() => trafficView(report), [report]);
  const s = report.summary;

  return (
    <div className="stack overview">
      <VerdictCard v={v} go={go} report={report} />

      <div className="grid ov-a">
        <section className="card">
          <div className="card-head">
            <div><h2>From {s.findings} advisor{s.findings === 1 ? 'y' : 'ies'} to {rows[rows.length - 1]?.count ?? 0} that matter{(rows[rows.length - 1]?.count ?? 0) === 1 ? 's' : ''}</h2><p className="sub">Each row is a filter NextFix applied; the note says what it removed and why.</p></div>
            <div className="actions">
              <button type="button" className="btn small" onClick={() => setHowOpen(true)}><I.info /> How it works</button>
              <button type="button" className="btn small no-print" onClick={() => window.print()}><I.download /> Print summary</button>
            </div>
          </div>
          <FunnelChart rows={rows} go={go} />
          <div className="ratios">
            {rat.map((r) => <div key={r.label} className="ratio"><span className="ratio-v">{r.value}</span><span className="ratio-l">{r.label}</span><span className="ratio-n muted small">{r.note}</span></div>)}
          </div>
        </section>
        <section className="card">
          <div className="card-head"><div><h2>What changed</h2><p className="sub">Since the previous scan of this application.</p></div></div>
          <BridgeChart b={br} go={go} />
          <RecheckButton targetId={targetId} go={go} />
        </section>
      </div>

      <section className="card">
        <div className="card-head">
          <div className="with-icon"><span className="icon-box"><I.decide size={22} /></span><div><h2>Decide</h2><p className="sub">What waits on a person: proposals to approve, exceptions about to run out, and routes whose exposure is not confirmed.</p></div></div>
          {accepted.size > 0 && <button type="button" className="btn small" onClick={() => go('evidence')}>{accepted.size} set aside by a person <I.arrow /></button>}
        </div>
        <DecidePanel d={dec} report={report} go={go} />
      </section>

      <section className="card">
        <div className="card-head"><div><h2>The work queue</h2><p className="sub">Every finding lands in exactly one of these.{accepted.size > 0 ? ` ${accepted.size} set aside by a person count under Set aside.` : ''}</p></div></div>
        <WorkQueue report={report} prev={diff?.previous?.summary.byDecision} go={go} />
      </section>

      <section className="card">
        <div className="card-head"><div><h2>Is it fast enough</h2><p className="sub">Open findings that need action, by how long they have been open, against the SLA.</p></div></div>
        <AgeingPanel targetId={targetId} go={go} />
      </section>

      <div className="grid ov-b">
        <section className="card">
          <div className="card-head"><div><h2>Shortest path to green</h2><p className="sub">{leverageSentence(report, ups)}</p></div></div>
          {ups.length ? <LeverageChart ups={ups.slice(0, 6)} go={go} /> : <p className="empty">No published fixes to rank yet.</p>}
        </section>
        <section className="card">
          <div className="card-head"><div><h2>Where an attacker gets in</h2><p className="sub">Entry points sized by what they reach; colour is the worst decision behind them{tv.observed ? ', and what the logs saw on each' : ''}.</p></div></div>
          <SurfaceTiles tiles={tiles} go={go} days={tv.days} />
        </section>
      </div>

      <section className="card">
        <div className="card-head">
          <div className="with-icon"><span className="icon-box"><I.eye size={22} /></span><div><h2>What the logs say</h2><p className="sub">{tv.observed ? 'Requests the access logs recorded per route: exposure observed, not inferred.' : 'Observed traffic replaces inferred exposure once the access logs are read.'}</p></div></div>
        </div>
        <TrafficPanel v={tv} report={report} go={go} />
      </section>

      <div className="grid ov-c">
        <section className="card">
          <div className="card-head"><div><h2>Why each decision</h2><p className="sub">How close an attacker is to the code, against what the world knows about exploitation.</p></div></div>
          <MatrixChart cells={cells} go={go} />
        </section>
        <section className="card">
          <div className="card-head">
            <div><h2>Actionable findings over time</h2><p className="sub">Fix now and Fix next cycle per scan.</p></div>
            <select aria-label="Range" value={range} onChange={(e) => setRange(Number(e.target.value))}>
              <option value={6}>Last 6 scans</option>
              <option value={12}>Last 12 scans</option>
              <option value={0}>All scans</option>
            </select>
          </div>
          <TrendChart scans={range ? scans.slice(-range) : scans} />
          <div className="card-head" style={{ marginTop: 18 }}>
            <div className="with-icon"><span className="icon-box"><I.evidence size={22} /></span><div><h2>Evidence for auditors</h2><p className="sub">Every set-aside carries a VEX statement with its justification.</p></div></div>
            <button type="button" className="btn small" onClick={() => go('evidence')}>Open <I.arrow /></button>
          </div>
          <ul className="ev-list">
            {EVIDENCE_TIERS.map((t) => {
              const n = s.byTier[t.tier] ?? 0;
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
    </div>
  );
}
