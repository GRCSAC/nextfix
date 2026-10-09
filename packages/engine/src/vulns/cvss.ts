/** CVSS v3.x base score from a vector string. Returns undefined for anything else (v2, v4). */
export function cvss3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m = new Map<string, string>();
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':');
    if (k && v) m.set(k, v);
  }
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.get('AV') ?? ''];
  const AC = { L: 0.77, H: 0.44 }[m.get('AC') ?? ''];
  const UI = { N: 0.85, R: 0.62 }[m.get('UI') ?? ''];
  const S = m.get('S');
  const changed = S === 'C';
  const PR = changed
    ? { N: 0.85, L: 0.68, H: 0.5 }[m.get('PR') ?? '']
    : { N: 0.85, L: 0.62, H: 0.27 }[m.get('PR') ?? ''];
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const C = cia[m.get('C') as keyof typeof cia];
  const I = cia[m.get('I') as keyof typeof cia];
  const A = cia[m.get('A') as keyof typeof cia];
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined) || !S) return undefined;

  const iss = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * AV! * AC! * PR! * UI!;
  if (impact <= 0) return 0;
  const raw = changed ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return roundUp1(raw);
}

function roundUp1(x: number): number {
  const i = Math.round(x * 100_000);
  return i % 10_000 === 0 ? i / 100_000 : (Math.floor(i / 10_000) + 1) / 10;
}

export function severityLabelFromScore(score: number | undefined): string | undefined {
  if (score === undefined) return undefined;
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}
