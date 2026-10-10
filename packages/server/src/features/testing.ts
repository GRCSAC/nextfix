import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../store.ts';
import type { Finding, ScanReport } from '../../../engine/src/types.ts';
import { applyFeatureMigrations } from './all.ts';
import type { RouteUser } from './core.ts';

/* Fixtures the feature tests share: a temp database with the store's schema plus the feature tables, and small reports. */

export const DAY_MS = 86_400_000;
export const ago = (days: number, from = Date.now()) => new Date(from - days * DAY_MS).toISOString();

export const VIEWER: RouteUser = { id: 1, username: 'vera', role: 'viewer' };
export const ANALYST: RouteUser = { id: 2, username: 'ana', role: 'analyst' };
export const ADMIN: RouteUser = { id: 3, username: 'root', role: 'admin' };

/** A store on a temp file (its migrations applied) and a second handle on the same file for the features. */
export function openDb(): { store: Store; db: DatabaseSync; dir: string; close(): void } {
  const dir = mkdtempSync(join(tmpdir(), 'nextfix-features-'));
  const path = join(dir, 'test.sqlite');
  const store = new Store(path);
  const db = new DatabaseSync(path);
  db.exec('PRAGMA foreign_keys = ON');
  applyFeatureMigrations(db);
  return {
    store,
    db,
    dir,
    close() {
      db.close();
      store.close();
    },
  };
}

export const LODASH = 'pkg:npm/lodash@4.17.15|GHSA-35jh-r3h4-6jhm';

export function fakeReport(name = 'express-shop', dir = `C:/x/${name}`): ScanReport {
  const component = { ecosystem: 'npm' as const, name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', dev: false, optional: false, direct: true, path: 'node_modules/lodash' };
  const advisory = { id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], cve: 'CVE-2021-23337', summary: 'Command Injection in lodash', details: '', cvssScore: 7.2, severityLabel: 'HIGH', fixedVersion: '4.17.21', references: ['https://github.com/advisories/GHSA-35jh-r3h4-6jhm'] };
  const entry = { method: 'POST', path: '/preview', file: 'src/app.js', line: 12, authenticated: false, guards: [], mounted: true, handlerIds: ['h'] };
  const other = { method: 'GET', path: '/health', file: 'src/app.js', line: 20, authenticated: false, guards: [], mounted: true, handlerIds: ['hh'] };
  const finding: Finding = {
    id: `${component.purl}|${advisory.id}`,
    component,
    advisory,
    reach: { tier: 'reachable', confidence: 'confirmed', importedIn: ['src/services/render.js'], callSites: [], paths: [{ entry, hops: [], callSite: { file: 'src/services/render.js', line: 6, col: 20, text: '_.template', symbol: 'template', userInput: true }, userInput: true, inputSource: 'req.body.template', taintedArgument: { index: 0, text: 'source' } }] },
    exposure: { network: 'published', ports: [3000], evidence: ['Dockerfile: EXPOSE 3000'] },
    epss: { score: 0.42, percentile: 0.97, cve: 'CVE-2021-23337' },
    exploitation: 'likely',
    decision: 'Act',
    score: 81,
    why: ['lodash 4.17.15 is affected by CVE-2021-23337: Command Injection in lodash (CVSS 7.2 HIGH).', 'Reachable: POST /preview → _.template() at src/services/render.js:6.'],
    fix: 'Upgrade lodash 4.17.15 → 4.17.21',
  };
  return {
    tool: { name: 'NextFix', version: '0.0.0-test' },
    target: { dir, name },
    generatedAt: new Date().toISOString(),
    summary: { components: 1, advisories: 1, findings: 1, byDecision: { Act: 1, Attend: 0, 'Track*': 0, Track: 0 }, byTier: { reachable: 1, 'called-unreached': 0, 'imported-unknown-symbol': 0, 'image-only': 0, 'imported-not-called': 0, unused: 0, 'dev-only': 0 }, noiseRemoved: 0 },
    exposure: finding.exposure,
    entryPoints: [entry, other],
    components: [component],
    findings: [finding],
  };
}

/** A report whose findings are copies of the fake finding under the given ids, stamped at `at`, with the summary recomputed. */
export function reportWith(ids: string[], at: string, patch: (f: Finding, i: number) => void = () => {}, name?: string): ScanReport {
  const base = fakeReport(name);
  const template = base.findings[0]!;
  base.findings = ids.map((id, i) => {
    const f = structuredClone(template);
    f.id = id;
    f.advisory = { ...f.advisory, id: id.split('|')[1] ?? f.advisory.id };
    patch(f, i);
    return f;
  });
  base.summary.findings = base.findings.length;
  base.summary.byDecision = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 };
  for (const f of base.findings) base.summary.byDecision[f.decision]++;
  base.generatedAt = at;
  return base;
}
