import { Cache, DAY } from './cache.ts';
import { USER_AGENT } from '../version.ts';

export interface EpssScore {
  score: number;
  percentile: number;
}

/** FIRST EPSS: probability of exploitation in the next 30 days. */
export async function fetchEpss(cves: string[], cache: Cache, offline = false): Promise<Map<string, EpssScore>> {
  const out = new Map<string, EpssScore>();
  const pending: string[] = [];
  for (const cve of new Set(cves)) {
    const cached = cache.get<EpssScore | null>(`epss:${cve}`, offline);
    if (cached !== undefined) {
      if (cached) out.set(cve, cached);
    } else pending.push(cve);
  }
  if (offline || !pending.length) return out;

  for (let i = 0; i < pending.length; i += 100) {
    const chunk = pending.slice(i, i + 100);
    const url = `https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`;
    const res = await fetch(url, { headers: { 'user-agent': USER_AGENT } });
    if (!res.ok) throw new Error(`EPSS lookup failed: ${res.status}`);
    const json = (await res.json()) as { data?: { cve: string; epss: string; percentile: string }[] };
    const got = new Set<string>();
    for (const d of json.data ?? []) {
      const s = { score: Number(d.epss), percentile: Number(d.percentile) };
      out.set(d.cve, s);
      cache.set(`epss:${d.cve}`, s, DAY);
      got.add(d.cve);
    }
    for (const cve of chunk) if (!got.has(cve)) cache.set(`epss:${cve}`, null, DAY);
  }
  return out;
}
