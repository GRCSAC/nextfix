import semver from 'semver';
import type { Advisory, Component } from '../types.ts';
import { Cache, DAY } from './cache.ts';
import { cvss3BaseScore, severityLabelFromScore } from './cvss.ts';
import { USER_AGENT } from '../version.ts';

const OSV = 'https://api.osv.dev/v1';

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: { type: string; events: { introduced?: string; fixed?: string; last_affected?: string }[] }[];
  }[];
  references?: { type?: string; url: string }[];
}

export interface OsvOptions {
  cache: Cache;
  offline?: boolean;
  log?: (msg: string) => void;
}

/** Looks up advisories for every component. Returns a map keyed by purl. */
export async function fetchAdvisories(components: Component[], opts: OsvOptions): Promise<Map<string, Advisory[]>> {
  const out = new Map<string, Advisory[]>();
  const idsByPurl = new Map<string, { id: string; modified?: string }[]>();

  // 1. Which components have any advisories? (batch query)
  const pending: Component[] = [];
  for (const c of components) {
    const cached = opts.cache.get<{ id: string; modified?: string }[]>(`osv:query:${c.purl}`, opts.offline);
    if (cached) idsByPurl.set(c.purl, cached);
    else pending.push(c);
  }
  if (pending.length && opts.offline) {
    throw new Error(`Offline mode: ${pending.length} component(s) have no cached OSV result (e.g. ${pending[0]!.purl}).`);
  }
  for (let i = 0; i < pending.length; i += 500) {
    const chunk = pending.slice(i, i + 500);
    opts.log?.(`OSV: querying ${chunk.length} component(s)…`);
    const body = {
      queries: chunk.map((c) => ({ package: { name: c.name, ecosystem: 'npm' }, version: c.version })),
    };
    const res = await fetch(`${OSV}/querybatch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': USER_AGENT },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`OSV querybatch failed: ${res.status} ${res.statusText}`);
    const json = (await res.json()) as { results: { vulns?: { id: string; modified?: string }[] }[] };
    json.results.forEach((r, idx) => {
      const c = chunk[idx]!;
      const vulns = r.vulns ?? [];
      idsByPurl.set(c.purl, vulns);
      opts.cache.set(`osv:query:${c.purl}`, vulns, DAY);
    });
  }

  // 2. Fetch each advisory once.
  const vulnCache = new Map<string, OsvVuln>();
  async function getVuln(id: string, modified?: string): Promise<OsvVuln> {
    const key = `osv:vuln:${id}`;
    const cached = opts.cache.get<OsvVuln>(key, opts.offline);
    if (cached && (!modified || cached.modified === modified)) return cached;
    if (opts.offline) {
      if (cached) return cached;
      throw new Error(`Offline mode: advisory ${id} is not cached.`);
    }
    const res = await fetch(`${OSV}/vulns/${encodeURIComponent(id)}`, { headers: { 'user-agent': USER_AGENT } });
    if (!res.ok) throw new Error(`OSV vuln ${id} failed: ${res.status}`);
    const v = (await res.json()) as OsvVuln;
    opts.cache.set(key, v, 7 * DAY);
    return v;
  }

  for (const c of components) {
    const refs = idsByPurl.get(c.purl) ?? [];
    if (!refs.length) continue;
    const advisories: Advisory[] = [];
    for (const ref of refs) {
      let v = vulnCache.get(ref.id);
      if (!v) {
        v = await getVuln(ref.id, ref.modified);
        vulnCache.set(ref.id, v);
      }
      advisories.push(toAdvisory(v, c));
    }
    // Prefer GHSA ids (they carry the CVE as alias); drop duplicates that alias each other.
    out.set(c.purl, dedupe(advisories));
  }
  return out;
}

function toAdvisory(v: OsvVuln, c: Component): Advisory {
  const aliases = v.aliases ?? [];
  const cve = [v.id, ...aliases].find((a) => a.startsWith('CVE-'));
  const vec = v.severity?.find((s) => s.type === 'CVSS_V3')?.score ?? v.severity?.[0]?.score;
  const score = vec ? cvss3BaseScore(vec) : undefined;
  return {
    id: v.id,
    aliases,
    cve,
    summary: v.summary ?? '',
    details: v.details ?? '',
    published: v.published,
    modified: v.modified,
    severityLabel: v.database_specific?.severity?.toUpperCase() ?? severityLabelFromScore(score),
    cvssVector: vec,
    cvssScore: score,
    fixedVersion: lowestFix(v, c),
    references: (v.references ?? []).map((r) => r.url),
    typedReferences: (v.references ?? []).map((r) => ({ type: r.type, url: r.url })),
  };
}

function lowestFix(v: OsvVuln, c: Component): string | undefined {
  let best: string | undefined;
  for (const a of v.affected ?? []) {
    if (a.package?.ecosystem !== 'npm' || a.package.name !== c.name) continue;
    for (const r of a.ranges ?? []) {
      for (const e of r.events) {
        const f = e.fixed && semver.valid(e.fixed);
        if (f && semver.gt(f, c.version) && (!best || semver.lt(f, best))) best = f;
      }
    }
  }
  return best;
}

function dedupe(list: Advisory[]): Advisory[] {
  const seen = new Set<string>();
  const out: Advisory[] = [];
  // GHSA first so the CVE-only duplicates get dropped.
  for (const a of [...list].sort((x, y) => (x.id.startsWith('GHSA') ? -1 : 1) - (y.id.startsWith('GHSA') ? -1 : 1))) {
    const keys = [a.id, ...a.aliases];
    if (keys.some((k) => seen.has(k))) continue;
    keys.forEach((k) => seen.add(k));
    out.push(a);
  }
  return out;
}
