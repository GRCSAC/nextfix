import { resolve } from 'node:path';
import { readNpmLock } from './inventory/npm-lock.ts';
import { Cache } from './vulns/cache.ts';
import { fetchAdvisories } from './vulns/osv.ts';
import { fetchEpss } from './vulns/epss.ts';
import { fetchKev } from './vulns/kev.ts';
import { SymbolDb } from './vulns/symbols.ts';
import { analyzeProject } from './graph/js/project.ts';
import { assessReach } from './reach/reachability.ts';
import { analyzeExposure } from './exposure/docker.ts';
import { decide } from './decide/ssvc.ts';
import { toolVersion } from './version.ts';
import type { Decision, Finding, ReachTier, ScanReport } from './types.ts';

export interface ScanOptions {
  offline?: boolean;
  cachePath?: string;
  log?: (msg: string) => void;
}

const DECISION_ORDER: Decision[] = ['Act', 'Attend', 'Track*', 'Track'];

export async function scan(dir: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const rootDir = resolve(dir);
  const log = opts.log ?? (() => {});
  const cache = new Cache(opts.cachePath);
  try {
    log('Inventory: reading package-lock.json');
    const inv = readNpmLock(rootDir);
    log(`Inventory: ${inv.components.length} components`);

    log('Code: building call graph and entry points');
    const graph = analyzeProject(rootDir);
    log(`Code: ${graph.modules.size} modules, ${graph.functions.size} functions, ${graph.entryPoints.length} entry points`);

    const exposure = analyzeExposure(rootDir, graph.listenLocalOnly);

    log('Advisories: OSV');
    const advisories = await fetchAdvisories(inv.components, { cache, offline: opts.offline, log });
    const cves = [...advisories.values()].flat().map((a) => a.cve).filter((x): x is string => !!x);
    log(`Advisories: ${[...advisories.values()].flat().length} across ${advisories.size} components; EPSS + KEV for ${cves.length} CVEs`);
    const [epss, kev] = await Promise.all([fetchEpss(cves, cache, opts.offline), fetchKev(cache, opts.offline)]);
    const symbols = SymbolDb.load();

    const findings: Finding[] = [];
    for (const c of inv.components) {
      for (const a of advisories.get(c.purl) ?? []) {
        const sym = symbols.lookup([a.id, ...a.aliases], c.name);
        const reach = assessReach(graph, c, sym);
        const partial = {
          id: `${c.purl}|${a.id}`,
          component: c,
          advisory: a,
          symbols: sym,
          reach,
          exposure,
          epss: a.cve ? epss.get(a.cve) : undefined,
          kev: a.cve ? kev.get(a.cve) : undefined,
        };
        findings.push({ ...partial, ...decide(partial) });
      }
    }
    findings.sort((x, y) => DECISION_ORDER.indexOf(x.decision) - DECISION_ORDER.indexOf(y.decision) || y.score - x.score || x.component.name.localeCompare(y.component.name));

    const byDecision = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 } as Record<Decision, number>;
    const byTier = { reachable: 0, 'called-unreached': 0, 'imported-unknown-symbol': 0, 'imported-not-called': 0, unused: 0, 'dev-only': 0 } as Record<ReachTier, number>;
    for (const f of findings) {
      byDecision[f.decision]++;
      byTier[f.reach.tier]++;
    }
    const actionable = byDecision.Act + byDecision.Attend;

    return {
      tool: { name: 'NextFix', version: toolVersion() },
      target: { dir: rootDir, name: inv.projectName, version: inv.projectVersion },
      generatedAt: new Date().toISOString(),
      summary: {
        components: inv.components.length,
        advisories: [...advisories.values()].flat().length,
        findings: findings.length,
        byDecision,
        byTier,
        noiseRemoved: findings.length ? (findings.length - actionable) / findings.length : 0,
      },
      exposure,
      entryPoints: graph.entryPoints,
      components: inv.components,
      findings,
    };
  } finally {
    cache.close();
  }
}
