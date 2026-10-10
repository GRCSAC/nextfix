import { existsSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { readNpmLock } from './inventory/npm-lock.ts';
import { hasPythonProject, readPythonDeps } from './inventory/python.ts';
import { componentKey, configImageProblem, configSbomProblem, detectSbomFiles, readContainerInventory } from './inventory/container.ts';
import { analyzePythonProject } from './graph/py/project.ts';
import { mergeGraphs } from './graph/merge.ts';
import type { Component } from './types.ts';
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
import { asList, loadConfig } from './config.ts';
import { DerivedStore } from './symbols/store.ts';
import { deriveSymbols } from './symbols/derive.ts';
import type { Advisory, Decision, Finding, ImageInventory, ReachResult, ReachTier, ScanReport } from './types.ts';

export interface ScanOptions {
  offline?: boolean;
  cachePath?: string;
  /** Derive vulnerable symbols from fix commits for advisories without data (default true). */
  derive?: boolean;
  /** Stop deriving after this many milliseconds; the rest is picked up on the next scan (default 90 s). */
  deriveBudgetMs?: number;
  /** Advisories derived in parallel (default 4). */
  deriveConcurrency?: number;
  githubToken?: string;
  /** Container images to inventory with syft, in addition to `image` in nextfix.config.json. */
  images?: string[];
  /** SBOM files to read, in addition to `sbom` in the config and any `*.cdx.json` / `*.spdx.json` at the root. */
  sboms?: string[];
  log?: (msg: string) => void;
}

const IMAGE_ONLY: ReachResult = { tier: 'image-only', confidence: 'package-level', importedIn: [], callSites: [], paths: [] };

/**
 * An advisory can cover several CVEs (a Debian DSA, a GHSA with two CVE aliases). Exploitation
 * evidence is taken across all of them: KEV on any, and the highest EPSS.
 */
function exploitationFor(a: Advisory, epss: Map<string, { score: number; percentile: number }>, kev: Map<string, { dateAdded: string; ransomware: boolean }>): Pick<Finding, 'epss' | 'kev'> {
  const ids = a.cves?.length ? a.cves : a.cve ? [a.cve] : [];
  let best: Finding['epss'];
  let hit: Finding['kev'];
  for (const cve of ids) {
    const e = epss.get(cve);
    if (e && (!best || e.score > best.score)) best = { ...e, cve };
    const k = kev.get(cve);
    if (k && !hit) hit = { ...k, cve };
  }
  return { epss: best, kev: hit };
}

const DECISION_ORDER: Decision[] = ['Act', 'Attend', 'Track*', 'Track'];

export async function scan(dir: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const rootDir = resolve(dir);
  const log = opts.log ?? (() => {});
  const cache = new Cache(opts.cachePath);
  try {
    const config = loadConfig(rootDir);
    const hasNode = existsSync(join(rootDir, 'package-lock.json'));
    const hasPy = hasPythonProject(rootDir);
    // Values from the project's own config are treated as untrusted: they cannot point syft at the
    // host or read files outside the project. The user's command line can.
    const configImages = asList(config.image).filter((ref) => {
      const problem = configImageProblem(ref);
      if (problem) log(`Config: image "${ref}" ignored: ${problem}`);
      return !problem;
    });
    const configSboms = asList(config.sbom).filter((file) => {
      const problem = configSbomProblem(rootDir, file);
      if (problem) log(`Config: sbom "${file}" ignored: ${problem}`);
      return !problem;
    });
    const imageRefs = [...new Set([...configImages, ...(opts.images ?? [])])];
    const sbomFiles = [...new Set([...configSboms, ...(opts.sboms ?? []), ...detectSbomFiles(rootDir)])];
    if (!hasNode && !hasPy && !imageRefs.length && !sbomFiles.length) throw new Error(`No package-lock.json, Python requirements/lockfile, SBOM or container image for ${rootDir}.`);

    const components: Component[] = [];
    let projectName: string | undefined;
    let projectVersion: string | undefined;
    if (hasNode) {
      log('Inventory: reading package-lock.json');
      const inv = readNpmLock(rootDir);
      components.push(...inv.components);
      projectName = inv.projectName;
      projectVersion = inv.projectVersion;
      log(`Inventory: ${inv.components.length} npm components`);
    }
    if (hasPy) {
      const pyInv = readPythonDeps(rootDir);
      components.push(...pyInv.components);
      log(`Inventory: ${pyInv.components.length} PyPI components from ${pyInv.sources.join(', ')}`);
    }
    let images: ImageInventory[] | undefined;
    if (imageRefs.length || sbomFiles.length) {
      const ci = await readContainerInventory(rootDir, { images: imageRefs, sboms: sbomFiles, syftPath: config.syft, log });
      const have = new Map(components.map((c) => [componentKey(c), c]));
      let added = 0;
      for (const c of ci.components) {
        const existing = have.get(componentKey(c));
        if (existing) {
          existing.image = c.image;
          continue;
        }
        have.set(componentKey(c), c);
        components.push(c);
        added++;
      }
      images = ci.images;
      log(`Inventory: ${added} components from ${ci.images.filter((i) => !i.error).length} image(s)/SBOM(s), ${ci.components.length - added} already in the lockfile`);
    }
    const inv = { components, projectName: projectName ?? basename(rootDir), projectVersion };
    const lockfileNames = new Set(components.filter((c) => c.origin !== 'image').map((c) => c.name));

    log('Code: building call graph and entry points');
    let graph = analyzeProject(rootDir, config);
    if (hasPy) {
      const installed = new Set(components.filter((c) => c.ecosystem === 'PyPI').map((c) => c.name));
      const pyGraph = await analyzePythonProject(rootDir, { installed, authGuards: config.authGuards, ignore: config.ignore, internalRoutes: config.internalRoutes });
      graph = hasNode ? mergeGraphs(graph, pyGraph) : mergeGraphs(pyGraph, graph);
    }
    log(`Code: ${graph.modules.size} modules, ${graph.functions.size} functions, ${graph.entryPoints.length} entry points`);

    const exposure = analyzeExposure(rootDir, graph.listenLocalOnly);

    log('Advisories: OSV');
    const advisories = await fetchAdvisories(inv.components, { cache, offline: opts.offline, log });
    const cves = [...new Set([...advisories.values()].flat().flatMap((a) => a.cves ?? (a.cve ? [a.cve] : [])))];
    log(`Advisories: ${[...advisories.values()].flat().length} across ${advisories.size} components; EPSS + KEV for ${cves.length} CVEs`);
    const [epss, kev] = await Promise.all([fetchEpss(cves, cache, opts.offline), fetchKev(cache, opts.offline)]);

    const store = new DerivedStore(cache);
    const symbols = SymbolDb.load(undefined, store.all());

    // Derive function-level data for advisories that have none, from their fix commits.
    if (opts.derive !== false) {
      let derived = 0;
      let skipped = 0;
      let deferred = 0;
      let stopped = false;
      const token = opts.githubToken ?? process.env.GITHUB_TOKEN;
      const budget = opts.deriveBudgetMs ?? 90_000;
      const started = Date.now();
      const queue: { c: Component; a: (typeof findings)[number]['advisory'] }[] = [];
      for (const c of inv.components) {
        if (c.ecosystem !== 'npm' && c.ecosystem !== 'PyPI') continue;
        for (const a of advisories.get(c.purl) ?? []) if (!symbols.lookup([a.id, ...a.aliases], c.name)) queue.push({ c, a });
      }
      // Several advisories at once: derivation is bound by GitHub fetch latency, not CPU.
      const worker = async () => {
        while (queue.length && !stopped) {
          const { c, a } = queue.shift()!;
          if (Date.now() - started > budget) {
            deferred++;
            continue;
          }
          // Derivation is enrichment: a network or GitHub error skips this advisory, never the scan.
          let out: Awaited<ReturnType<typeof deriveSymbols>>;
          try {
            out = await deriveSymbols(a, c.name, { cache, offline: opts.offline, token, store, log, typedReferences: a.typedReferences, ecosystem: c.ecosystem as 'npm' | 'PyPI' });
          } catch (err) {
            out = { reason: `fetch failed: ${err instanceof Error ? err.message : String(err)}` };
          }
          if (out.entry) {
            if (!out.cached) derived++;
            symbols.add(out.entry);
          } else {
            skipped++;
            if (process.env.NEXTFIX_DEBUG || out.reason?.startsWith('fetch failed')) log(`Symbols: ${a.id} ${c.name}: ${out.reason}${out.cached ? ' (cached)' : ''}`);
            if (out.reason?.includes('rate limit')) {
              log(`Symbols: ${out.reason}; stopping derivation for this scan`);
              stopped = true;
            }
          }
        }
      };
      await Promise.all(Array.from({ length: opts.deriveConcurrency ?? 4 }, worker));
      log(`Symbols: ${derived} newly derived from fix commits, ${skipped} advisories without usable fix data${deferred ? `, ${deferred} deferred to the next scan (time budget)` : ''}`);
    }

    const findings: Finding[] = [];
    void (findings as unknown);
    for (const c of inv.components) {
      for (const a of advisories.get(c.purl) ?? []) {
        const sym = symbols.lookup([a.id, ...a.aliases], c.name);
        // A package that exists only in the image is analysed through the code graph only when the
        // application imports it and the lockfile has no copy of its own (the app resolves its own
        // copy, so an image copy at another version is never the one the code runs). OS packages and
        // tooling inside the image get no call-path claim.
        const codeUsed = (c.ecosystem === 'npm' || c.ecosystem === 'PyPI') && graph.packagesImported.has(c.name) && !lockfileNames.has(c.name);
        const reach = c.origin === 'image' && !codeUsed ? IMAGE_ONLY : assessReach(graph, c, sym);
        const partial = {
          id: `${c.purl}|${a.id}`,
          component: c,
          advisory: a,
          symbols: sym,
          reach,
          exposure,
          ...exploitationFor(a, epss, kev),
        };
        findings.push({ ...partial, ...decide(partial) });
      }
    }
    findings.sort((x, y) => DECISION_ORDER.indexOf(x.decision) - DECISION_ORDER.indexOf(y.decision) || y.score - x.score || x.component.name.localeCompare(y.component.name));

    const byDecision = { Act: 0, Attend: 0, 'Track*': 0, Track: 0 } as Record<Decision, number>;
    const byTier = { reachable: 0, 'called-unreached': 0, 'imported-unknown-symbol': 0, 'image-only': 0, 'imported-not-called': 0, unused: 0, 'dev-only': 0 } as Record<ReachTier, number>;
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
      images,
      findings,
    };
  } finally {
    cache.close();
  }
}
