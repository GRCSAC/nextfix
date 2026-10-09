export interface StatTileProps {
  label: string;
  value: string | number;
  /** Signed change vs the previous scan. `upIsGood` decides the colour. */
  delta?: number;
  /** Unit appended to the delta number, e.g. " pts". */
  unit?: string;
  deltaLabel?: string;
  upIsGood?: boolean;
  sub?: boolean;
  className?: string;
}

export function StatTile({ label, value, delta, unit = '', deltaLabel = 'vs last scan', upIsGood = false, sub, className = '' }: StatTileProps) {
  let deltaEl: React.ReactNode = null;
  if (delta !== undefined) {
    const cls = delta === 0 ? '' : (delta > 0) === upIsGood ? 'good' : 'bad';
    const sign = delta > 0 ? '+' : '';
    deltaEl = <div className={`delta ${cls}`}>{delta === 0 ? 'no change' : `${sign}${delta}${unit}`} {deltaLabel}</div>;
  }
  return (
    <div className={`card tile ${className}`}>
      <div className="label">{label}</div>
      <div className={`value ${sub ? 'sub' : ''}`}>{value}</div>
      {deltaEl}
    </div>
  );
}
