/** Minimal PEP 440 ordering: epoch, release segments, pre/post/dev tags. Enough for "is fix > installed". */
interface Parsed {
  epoch: number;
  release: number[];
  pre?: [string, number];
  post?: number;
  dev?: number;
}

const PRE_ORDER: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, rc: 2, c: 2, pre: 2, preview: 2 };

export function parsePep440(v: string): Parsed | undefined {
  const m = /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[._-]?(a|alpha|b|beta|rc|c|pre|preview)[._-]?(\d*))?(?:[._-]?(?:post|rev|r)[._-]?(\d*)|-(\d+))?(?:[._-]?dev[._-]?(\d*))?(?:\+.*)?$/i.exec(v.trim());
  if (!m) return undefined;
  const p: Parsed = { epoch: m[1] ? Number(m[1]) : 0, release: m[2]!.split('.').map(Number) };
  if (m[3]) p.pre = [m[3].toLowerCase(), m[4] ? Number(m[4]) : 0];
  if (m[5] !== undefined || m[6] !== undefined) p.post = Number(m[5] || m[6] || 0);
  if (m[7] !== undefined) p.dev = m[7] ? Number(m[7]) : 0;
  return p;
}

export function comparePep440(a: string, b: string): number {
  const pa = parsePep440(a);
  const pb = parsePep440(b);
  if (!pa || !pb) return a.localeCompare(b);
  if (pa.epoch !== pb.epoch) return pa.epoch - pb.epoch;
  const n = Math.max(pa.release.length, pb.release.length);
  for (let i = 0; i < n; i++) {
    const d = (pa.release[i] ?? 0) - (pb.release[i] ?? 0);
    if (d) return d;
  }
  // dev < pre < final < post
  const rank = (p: Parsed) => (p.dev !== undefined && !p.pre && p.post === undefined ? 0 : p.pre ? 1 : p.post !== undefined ? 3 : 2);
  const ra = rank(pa);
  const rb = rank(pb);
  if (ra !== rb) return ra - rb;
  if (pa.pre && pb.pre) {
    const d = (PRE_ORDER[pa.pre[0]] ?? 0) - (PRE_ORDER[pb.pre[0]] ?? 0);
    if (d) return d;
    if (pa.pre[1] !== pb.pre[1]) return pa.pre[1] - pb.pre[1];
  }
  if (pa.post !== undefined && pb.post !== undefined && pa.post !== pb.post) return pa.post - pb.post;
  if (pa.dev !== undefined && pb.dev !== undefined && pa.dev !== pb.dev) return pa.dev - pb.dev;
  if (pa.dev !== undefined && pb.dev === undefined) return -1;
  if (pa.dev === undefined && pb.dev !== undefined) return 1;
  return 0;
}

export function validPep440(v: string): boolean {
  return parsePep440(v) !== undefined;
}
