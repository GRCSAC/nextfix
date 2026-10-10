import type { ScanMeta, ScanReport } from '../api.ts';
import { api } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { dateTime, pct } from '../format.ts';

export function Reports({ report, scans, scanId }: { report: ScanReport; scans: ScanMeta[]; scanId: number }) {
  return (
    <div className="stack">
      <div className="grid two">
        <section className="card">
          <h2>Export this scan</h2>
          <p className="sub">{report.target.name ?? report.target.dir} · {dateTime(report.generatedAt)}</p>
          <div className="actions">
            <a className="btn primary" href={api.vexUrl(scanId)} download><I.download /> OpenVEX document</a>
            <a className="btn" href={api.reportUrl(scanId)} download={`${(report.target.name ?? 'app').replace(/[^\w.-]+/g, '_')}-${report.generatedAt.slice(0, 10)}.nextfix.json`}><I.download /> Full JSON report</a>
          </div>
          <p className="hint">The VEX file carries a <code>not_affected</code> statement with the standard justification for every set-aside, and an <code>affected</code> statement with the fix for everything else. Dependency-Track, GUAC and most SBOM tools accept it.</p>
        </section>
        <section className="card">
          <h2>Scan history</h2>
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr><th>When</th><th className="num">Findings</th><th className="num">Fix now</th><th className="num">Next cycle</th><th className="num">No action needed</th><th>NextFix</th></tr></thead>
              <tbody>
                {[...scans].reverse().map((s) => (
                  <tr key={s.id} className={s.id === scanId ? 'current' : ''}>
                    <td>{dateTime(s.createdAt)}{s.id === scanId && <span className="tag ok" style={{ marginLeft: 6 }}>current</span>}</td>
                    <td className="num">{s.summary.findings}</td>
                    <td className="num">{s.summary.byDecision.Act}</td>
                    <td className="num">{s.summary.byDecision.Attend}</td>
                    <td className="num">{pct(s.summary.noiseRemoved)}</td>
                    <td className="muted">{s.toolVersion}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
