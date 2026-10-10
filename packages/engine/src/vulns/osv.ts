import type { Advisory, Component } from '../types.ts';
import { compareVersions, osvQueryable, osvVersion, validVersion } from './ecosystems.ts';
import { normalizePyName } from '../inventory/python.ts';
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
    if (!osvQueryable(c.ecosystem)) continue;
    const cached = opts.cache.get<{ id: string; modified?: string }[]>(queryKey(c), opts.offline);
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
      queries: chunk.map((c) => ({ package: { name: c.name, ecosystem: c.ecosystem }, version: osvVersion(c.ecosystem, c.version) })),
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
      opts.cache.set(queryKey(c), vulns, DAY);
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
    if (res.status === 404) {
      const missing: OsvVuln = { id, modified: 'missing' };
      opts.cache.set(key, missing, 7 * DAY);
      return missing;
    }
    if (!res.ok) throw new Error(`OSV vuln ${id} failed: ${res.status}`);
    const v = (await res.json()) as OsvVuln;
    opts.cache.set(key, v, 7 * DAY);
    return v;
  }

  // Distribution advisories (DEBIAN-, UBUNTU-, ALPINE-…) often carry no severity or summary of
  // their own; the CVE record in OSV does. Fill the gaps from it when possible.
  async function enrich(v: OsvVuln): Promise<OsvVuln> {
    const cve = cveOf(v);
    if (!cve || cve === v.id || (v.severity?.length && v.summary)) return v;
    let rec = vulnCache.get(cve);
    if (!rec) {
      try {
        rec = await getVuln(cve);
      } catch {
        return v;
      }
      vulnCache.set(cve, rec);
    }
    if (rec.modified === 'missing') return v;
    return { ...v, severity: v.severity?.length ? v.severity : rec.severity, summary: v.summary || rec.summary, details: v.details || rec.details };
  }

  for (const c of components) {
    const refs = idsByPurl.get(c.purl) ?? [];
    if (!refs.length) continue;
    const advisories: Advisory[] = [];
    for (const ref of refs) {
      let v = vulnCache.get(ref.id);
      if (!v) {
        v = await enrich(await getVuln(ref.id, ref.modified));
        vulnCache.set(ref.id, v);
      }
      advisories.push(toAdvisory(v, c));
    }
    // Prefer GHSA ids (they carry the CVE as alias); drop duplicates that alias each other.
    out.set(c.purl, dedupe(advisories));
  }
  return out;
}

/** npm and PyPI keep their purl-based cache keys; everything else is keyed by what is actually queried. */
function queryKey(c: Component): string {
  return c.ecosystem === 'npm' || c.ecosystem === 'PyPI' ? `osv:query:${c.purl}` : `osv:query:${c.ecosystem}|${c.name}|${c.version}`;
}

/** The CVE behind an advisory: a CVE alias, or the CVE embedded in a distribution id (`DEBIAN-CVE-2023-5678`). */
function cveOf(v: OsvVuln): string | undefined {
  for (const id of [v.id, ...(v.aliases ?? [])]) {
    const m = /(?:^|-)(CVE-\d{4}-\d{4,})$/.exec(id);
    if (m) return m[1];
  }
  return undefined;
}

function toAdvisory(v: OsvVuln, c: Component): Advisory {
  const aliases = v.aliases ?? [];
  const cve = cveOf(v);
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
  const py = c.ecosystem === 'PyPI';
  const sameName = (n: string | undefined) => (py ? normalizePyName(n ?? '') === c.name : n === c.name);
  // A component queried without a release suffix (`Debian`) matches any release's entry.
  const sameEco = (e: string | undefined) => e === c.ecosystem || (!!e && !c.ecosystem.includes(':') && e.split(':')[0] === c.ecosystem);
  const gt = (a: string, b: string) => compareVersions(c.ecosystem, a, b) > 0;
  const lt = (a: string, b: string) => compareVersions(c.ecosystem, a, b) < 0;
  for (const a of v.affected ?? []) {
    if (!sameEco(a.package?.ecosystem) || !sameName(a.package?.name)) continue;
    for (const r of a.ranges ?? []) {
      for (const e of r.events) {
        const f = e.fixed && validVersion(c.ecosystem, e.fixed) ? e.fixed : undefined;
        if (f && gt(f, c.version) && (!best || lt(f, best))) best = f;
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
