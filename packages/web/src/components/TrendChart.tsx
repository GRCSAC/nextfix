import { useState } from 'react';
import type { ScanMeta } from '../api.ts';
import { shortDate, dateTime } from '../format.ts';

const W = 640;
const H = 200;
const PAD = { l: 30, r: 26, t: 10, b: 26 };

/** Act and Attend counts per scan: two status series, direct-labelled at the end, legend on top. */
export function TrendChart({ scans }: { scans: ScanMeta[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const pts = scans.map((s) => ({ t: s.createdAt, act: s.summary.byDecision.Act, attend: s.summary.byDecision.Attend }));
  if (!pts.length) return <div className="empty">No scans yet.</div>;

  const max = Math.max(1, ...pts.map((p) => Math.max(p.act, p.attend)));
  const yMax = niceMax(max);
  const innerW = W - PAD.l - PAD.r;
  const innerH = H - PAD.t - PAD.b;
  const x = (i: number) => PAD.l + (pts.length === 1 ? innerW / 2 : (i / (pts.length - 1)) * innerW);
  const y = (v: number) => PAD.t + innerH - (v / yMax) * innerH;
  const ticks = yMax <= 4 ? Array.from({ length: yMax + 1 }, (_, i) => i) : [0, yMax / 2, yMax];
  const line = (key: 'act' | 'attend') => pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join(' ');
  const series: { key: 'act' | 'attend'; label: string; color: string }[] = [
    { key: 'act', label: 'Fix now', color: 'var(--c-act)' },
    { key: 'attend', label: 'Fix next cycle', color: 'var(--c-attend)' },
  ];
  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W;
    let best = 0;
    for (let i = 1; i < pts.length; i++) if (Math.abs(x(i) - px) < Math.abs(x(best) - px)) best = i;
    setHover(best);
  };
  const labelEvery = Math.max(1, Math.ceil(pts.length / 6));

  return (
    <div className="chart">
      <div className="legend" role="list">
        {series.map((s) => <span key={s.key} role="listitem"><span className="sw" style={{ background: s.color }} />{s.label}</span>)}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Fix-now and fix-next-cycle findings per scan" onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(t)} y2={y(t)} stroke="var(--grid)" strokeWidth="1" />
            <text x={PAD.l - 8} y={y(t) + 4} fontSize="11" fill="var(--muted)" textAnchor="end" style={{ fontVariantNumeric: 'tabular-nums' }}>{t}</text>
          </g>
        ))}
        {pts.map((p, i) => (i % labelEvery === 0 || i === pts.length - 1) && (
          <text key={p.t} x={x(i)} y={H - 6} fontSize="11" fill="var(--muted)" textAnchor={i === 0 ? 'start' : i === pts.length - 1 ? 'end' : 'middle'}>{shortDate(p.t)}</text>
        ))}
        {hover !== null && <line x1={x(hover)} x2={x(hover)} y1={PAD.t} y2={y(0)} stroke="var(--axis)" strokeWidth="1" />}
        {series.map((s) => (
          <g key={s.key}>
            {pts.length > 1 && <path d={line(s.key)} fill="none" stroke={s.color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />}
            {pts.map((p, i) => <circle key={i} cx={x(i)} cy={y(p[s.key])} r={hover === i ? 5 : 4} fill={s.color} stroke="var(--surface)" strokeWidth="2" />)}
            <text x={x(pts.length - 1) + 9} y={y(pts[pts.length - 1]![s.key]) + 4} fontSize="11" fill="var(--ink-2)" style={{ fontVariantNumeric: 'tabular-nums' }}>{pts[pts.length - 1]![s.key]}</text>
          </g>
        ))}
        <rect x={0} y={0} width={W} height={H} fill="transparent" />
      </svg>
      {hover !== null && (
        <div className="tooltip" style={{ left: `${(x(hover) / W) * 100}%`, top: `${((y(Math.max(pts[hover]!.act, pts[hover]!.attend)) + 36) / H) * 100}%` }}>
          {dateTime(pts[hover]!.t)} · fix now {pts[hover]!.act} · next cycle {pts[hover]!.attend}
        </div>
      )}
      {pts.length === 1 && <p className="empty">The trend builds as you scan again.</p>}
    </div>
  );
}

function niceMax(v: number): number {
  if (v <= 2) return 2;
  if (v <= 4) return 4;
  if (v <= 6) return 6;
  if (v <= 10) return 10;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  return Math.ceil(v / p) * p;
}
