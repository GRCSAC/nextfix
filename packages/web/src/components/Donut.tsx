export interface Slice { key: string; value: number; color: string; label: string }

/** Ring chart with 2px surface gaps between slices and a centred figure. */
export function Donut({ slices, total, title, subtitle, size = 200, thickness = 22, glow }: { slices: Slice[]; total: number; title: string; subtitle?: string; size?: number; thickness?: number; glow?: boolean }) {
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const sum = Math.max(1, slices.reduce((a, s) => a + s.value, 0));
  let offset = 0;
  const gap = slices.filter((s) => s.value > 0).length > 1 ? 2 : 0;
  return (
    <svg className={`donut ${glow ? 'glow' : ''}`} width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${title}: ${slices.map((s) => `${s.label} ${s.value}`).join(', ')}`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--ring-track)" strokeWidth={thickness} />
      {slices.map((s) => {
        if (s.value <= 0) return null;
        const len = (s.value / sum) * c;
        const el = (
          <circle key={s.key} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={s.color} strokeWidth={thickness}
            strokeDasharray={`${Math.max(0, len - gap)} ${c - Math.max(0, len - gap)}`} strokeDashoffset={-offset} transform={`rotate(-90 ${size / 2} ${size / 2})`}>
            <title>{s.label}: {s.value}</title>
          </circle>
        );
        offset += len;
        return el;
      })}
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" className="donut-value" dy={subtitle ? -8 : 0}>{total}</text>
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" className="donut-title" dy={subtitle ? 16 : 20}>{title}</text>
      {subtitle && <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" className="donut-sub" dy={32}>{subtitle}</text>}
    </svg>
  );
}
