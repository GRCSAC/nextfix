import { existsSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { hasNodeProject, readNodeInventory } from './inventory/node.ts';
import { hasPythonProject, readPythonDeps } from './inventory/python.ts';
import { hasGoProject, purlForGo, readGoDeps } from './inventory/go.ts';
import { componentKey, configImageProblem, configSbomProblem, detectSbomFiles, readContainerInventory } from './inventory/container.ts';
import { analyzePythonProject } from './graph/py/project.ts';
import { analyzeGoProject } from './graph/go/project.ts';
import { pathBase } from './graph/go/analyze.ts';
import { mergeGraphs } from './graph/merge.ts';
import type { ProjectGraph } from './graph/js/project.ts';
import { frameSymbol, goIdFor, projectCallSite, runGovulncheck, type GovulncheckResult } from './govuln/govulncheck.ts';
import type { CallSiteRef, Component, SymbolEntry } from './types.ts';
import { Cache } from './vulns/cache.ts';
import { fetchAdvisories } from './vulns/osv.ts';
import { fetchEpss } from './vulns/epss.ts';
import { fetchKev } from './vulns/kev.ts';
import { SymbolDb } from './vulns/symbols.ts';
import { analyzeProject } from './graph/js/project.ts';
import { assessReach } from './reach/reachability.ts';
import { analyzeExposure } from './exposure/docker.ts';
import { observeTraffic } from './exposure/traffic.ts';
import { decide } from './decide/ssvc.ts';
import { toolVersion } from './version.ts';
import { asList, configLogProblem, loadConfig } from './config.ts';
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
  /** Access logs to count requests from, in addition to `accessLogs` in nextfix.config.json (files or folders; may be absolute). */
  accessLogs?: string[];
  /** Days of logs to count (default: the config's trafficWindowDays, else 30). */
  trafficWindowDays?: number;
  log?: (msg: string) => void;
  /** Aborting it stops the scan at the next stage boundary (or finding) with an error whose message starts with "Scan cancelled". */
  signal?: AbortSignal;
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

/**
 * What the access logs say about internet reach: requests from public addresses settle it;
 * a window of at least two weeks with internal addresses only, on logs that are current and
 * that cover this service's routes, says the service is internal. Infrastructure files decide
 * the rest (exposure/infra.ts), and observation outranks them.
 */
function applyObservedReach(exposure: ScanReport['exposure'], t: NonNullable<ScanReport['traffic']>): void {
  const days = t.windowDays;
  const to = (t.to ?? '').slice(0, 10);
  if (t.public > 0) {
    exposure.reach = 'internet';
    exposure.reachEvidence = [`access logs: ${t.public.toLocaleString('en-US')} request${t.public === 1 ? '' : 's'} from public addresses in the ${days} days to ${to}`, ...(exposure.reachEvidence ?? [])];
    return;
  }
  if (!t.stale && days >= 14 && t.routesSeen > 0 && exposure.reach !== 'internet') {
    exposure.reach = 'internal';
    exposure.reachEvidence = [`access logs: ${t.requests.toLocaleString('en-US')} requests in the ${days} days to ${to}, none from a public address`, ...(exposure.reachEvidence ?? [])];
  }
}

// ---------------------------------------------------------------------------------------------
// Go reachability

/** Files of the graph that import any package of a Go module (`net/http` and `os` belong to `stdlib`). */
function goImportedIn(graph: ProjectGraph, module: string): string[] {
  const files = new Set<string>();
  for (const [pkg, where] of graph.packagesImported) {
    const inModule = module === 'stdlib' ? !pkg.split('/')[0]!.includes('.') : pkg === module || pkg.startsWith(module + '/');
    if (inModule) for (const f of where) files.add(f);
  }
  return [...files].sort();
}

/**
 * Vulnerable symbols of one advisory for one module, from the OSV data govulncheck carries. Go
 * call sites are recorded per module with the bare name as the symbol and the package-qualified
 * spellings (`http.Get`, `http.Header.Get`) as alternatives, so the entry uses the qualified
 * form: `Get` from net/http must not answer for `Values.Get` from net/url in the same module.
 */
function goSymbolEntry(gv: GovulncheckResult, goId: string, ids: string[], module: string): SymbolEntry | undefined {
  const pkgs = (gv.symbols.get(goId)?.packages ?? []).filter((p) => p.module === module && p.symbols.length);
  if (!pkgs.length) return undefined;
  const symbols = [...new Set(pkgs.flatMap((p) => p.symbols.map((s) => `${pathBase(p.path)}.${s}`)))];
  return { ids, ecosystem: 'Go', package: module, symbols, source: 'advisory', confidence: 'confirmed', note: 'Vulnerable symbols from the Go vulnerability database (vuln.go.dev).' };
}

/** Reachability through the project's Go call graph. */
function goGraphReach(graph: ProjectGraph, c: Component, entry: SymbolEntry | undefined, importedIn: string[]): ReachResult {
  if (!entry) return { tier: importedIn.length ? 'imported-unknown-symbol' : 'unused', confidence: 'package-level', importedIn, callSites: [], paths: [] };
  return assessReach(graph, c, entry);
}

/**
 * Reachability from govulncheck's verdict for the advisory on this module: a symbol called from
 * the program's entry points counts as called-unreached (no HTTP route was traced to it), an
 * imported vulnerable package as imported-not-called, a required module as unused.
 */
function goVerdictReach(gv: GovulncheckResult, goId: string | undefined, c: Component, entry: SymbolEntry | undefined, importedIn: string[]): ReachResult {
  const base: ReachResult = { tier: 'unused', confidence: 'package-level', importedIn, callSites: [], paths: [] };
  // The Go vulnerability database has no entry for this advisory, so govulncheck had nothing to
  // say: a module go.mod requires is in the build and cannot be ruled out; one only go.sum lists is not built.
  if (!goId) {
    if (importedIn.length) return { ...base, tier: 'imported-unknown-symbol' };
    return c.path === 'go.sum' ? base : { ...base, tier: 'imported-unknown-symbol', importedIn: ['go.mod'] };
  }
  const verdict = gv.verdicts.get(goId);
  const level = verdict?.byModule[c.name];
  // govulncheck knows the advisory and reported nothing for this module: no package of the program loads it.
  if (!verdict || !level) return importedIn.length ? { ...base, tier: 'imported-unknown-symbol' } : base;
  // Where the import shows: the graph's files when it has them, else the vulnerable packages govulncheck saw imported.
  const where = importedIn.length ? importedIn : verdict.packages[c.name] ?? [];
  if (level === 'required') return { ...base, confidence: 'confirmed' };
  if (level === 'imported') return { ...base, tier: entry ? 'imported-not-called' : 'imported-unknown-symbol', confidence: entry ? 'confirmed' : 'package-level', importedIn: where };
  const callSites: CallSiteRef[] = [];
  const seen = new Set<string>();
  for (const trace of verdict.trace) {
    const first = trace[0];
    if (!first || first.module !== c.name) continue;
    const symbol = frameSymbol(first);
    const site = projectCallSite(trace);
    const ref: CallSiteRef = site ? { file: site.file, line: site.line, col: site.col, text: symbol, symbol, userInput: false } : { file: 'go.mod', line: 0, col: 0, text: symbol, symbol, userInput: false };
    const key = `${ref.file}:${ref.line}:${symbol}`;
    if (seen.has(key)) continue;
    seen.add(key);
    callSites.push(ref);
  }
  return { ...base, tier: 'called-unreached', confidence: 'confirmed', importedIn: where, callSites };
}

/**
 * Decides reach for one advisory on one Go module. The project call graph answers when it found
 * entry points; otherwise govulncheck's verdict does; with neither, NextFix cannot rule the call
 * out and says so (imported-unknown-symbol) rather than filing the module as unused.
 */
function goReach(graph: ProjectGraph, graphUsable: boolean, gv: GovulncheckResult | undefined, c: Component, ids: string[], curated: SymbolEntry | undefined): { reach: ReachResult; symbols?: SymbolEntry } {
  const goId = gv ? goIdFor(gv, ids) : undefined;
  const symbolsEntry = curated ?? (gv && goId ? goSymbolEntry(gv, goId, ids, c.name) : undefined);
  const importedIn = goImportedIn(graph, c.name);
  const verdictLevel = goId ? gv?.verdicts.get(goId)?.byModule[c.name] : undefined;
  if (c.dev) return { reach: { tier: 'dev-only', confidence: 'package-level', importedIn, callSites: [], paths: [] }, symbols: symbolsEntry };
  if (graphUsable) {
    const reach = goGraphReach(graph, c, symbolsEntry, importedIn);
    // The graph sees the project's own calls only. When govulncheck, which follows calls inside the
    // dependencies too, saw the symbol called (or a package imported the graph did not parse), its
    // whole-program view wins over a weaker graph verdict.
    const graphBeaten = (verdictLevel === 'called' && reach.tier !== 'reachable' && reach.tier !== 'called-unreached') || (verdictLevel === 'imported' && reach.tier === 'unused');
    if (!graphBeaten || !gv || gv.error) return { reach, symbols: symbolsEntry };
  }
  if (gv && !gv.error) return { reach: goVerdictReach(gv, goId, c, symbolsEntry, importedIn), symbols: symbolsEntry };
  // No govulncheck and no entry points: a module go.mod requires cannot be ruled out; one only go.sum lists is not built.
  const unknown = importedIn.length > 0 || c.path !== 'go.sum';
  return { reach: { tier: unknown ? 'imported-unknown-symbol' : 'unused', confidence: 'package-level', importedIn: importedIn.length ? importedIn : unknown ? ['go.mod'] : [], callSites: [], paths: [] }, symbols: symbolsEntry };
}

export async function scan(dir: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const rootDir = resolve(dir);
  const log = opts.log ?? (() => {});
  const checkAbort = () => {
    if (opts.signal?.aborted) throw new Error('Scan cancelled');
  };
  checkAbort();
  const cache = new Cache(opts.cachePath);
  try {
    const config = loadConfig(rootDir);
    const hasNode = hasNodeProject(rootDir);
    const hasPy = hasPythonProject(rootDir);
    const hasGo = hasGoProject(rootDir);
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
    if (!hasNode && !hasPy && !hasGo && !imageRefs.length && !sbomFiles.length) throw new Error(`No package-lock.json, yarn.lock or pnpm-lock.yaml, Python requirements/lockfile, go.mod, SBOM or container image for ${rootDir}.`);

    checkAbort();
    const components: Component[] = [];
    let projectName: string | undefined;
    let projectVersion: string | undefined;
    if (hasNode) {
      const inv = readNodeInventory(rootDir);
      log(`Inventory: reading ${inv.sources.join(', ')}`);
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
    if (hasGo) {
      const goInv = readGoDeps(rootDir);
      components.push(...goInv.components);
      projectName ??= goInv.module;
      log(`Inventory: ${goInv.components.length} Go components from ${goInv.sources.join(', ')}${goInv.localReplacements.length ? ` (${goInv.localReplacements.length} replaced by local directories, not inventoried)` : ''}`);
    }
    let images: ImageInventory[] | undefined;
    if (imageRefs.length || sbomFiles.length) {
      checkAbort();
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

    // govulncheck builds the whole program, so it starts now and is collected before the advisories
    // are looked up: the toolchain it reports is the standard library version that is actually in play.
    let govulncheck: Promise<GovulncheckResult> | undefined;
    if (hasGo && !opts.offline) {
      log('Go: running govulncheck');
      govulncheck = runGovulncheck(rootDir);
    }

    checkAbort();
    log('Code: building call graph and entry points');
    let graph = analyzeProject(rootDir, config);
    if (hasPy) {
      checkAbort();
      const installed = new Set(components.filter((c) => c.ecosystem === 'PyPI').map((c) => c.name));
      const pyGraph = await analyzePythonProject(rootDir, { installed, authGuards: config.authGuards, ignore: config.ignore, internalRoutes: config.internalRoutes });
      graph = hasNode ? mergeGraphs(graph, pyGraph) : mergeGraphs(pyGraph, graph);
    }
    // The Go graph decides Go reachability only once it finds entry points; until then govulncheck does.
    let goGraphUsable = false;
    if (hasGo) {
      checkAbort();
      const installed = new Set(components.filter((c) => c.ecosystem === 'Go').map((c) => c.name));
      const goGraph = await analyzeGoProject(rootDir, { installed, authGuards: config.authGuards, ignore: config.ignore, internalRoutes: config.internalRoutes });
      goGraphUsable = goGraph.entryPoints.length > 0;
      graph = hasNode || hasPy ? mergeGraphs(graph, goGraph) : mergeGraphs(goGraph, graph);
    }
    log(`Code: ${graph.modules.size} modules, ${graph.functions.size} functions, ${graph.entryPoints.length} entry points`);

    checkAbort();
    const exposure = analyzeExposure(rootDir, graph.listenLocalOnly);

    // Observed traffic: the access logs, counted against the entry points. Config paths stay inside
    // the project; the caller's paths (command line, application settings) may point anywhere.
    const configLogs = asList(config.accessLogs).filter((file) => {
      const problem = configLogProblem(rootDir, file);
      if (problem) log(`Config: accessLogs "${file}" ignored: ${problem}`);
      return !problem;
    });
    const logSources = [...new Set([...configLogs, ...(opts.accessLogs ?? [])])];
    let traffic: ScanReport['traffic'];
    if (logSources.length) {
      checkAbort();
      log(`Traffic: reading ${logSources.length} access log source${logSources.length === 1 ? '' : 's'}`);
      const observed = await observeTraffic(rootDir, logSources, graph.entryPoints, { windowDays: opts.trafficWindowDays ?? config.trafficWindowDays, log });
      graph.entryPoints.forEach((e, i) => {
        e.traffic = observed.perEntry[i];
      });
      traffic = observed.summary;
      if (observed.summary.requests > 0) {
        exposure.observed = observed.observed;
        applyObservedReach(exposure, observed.summary);
      }
    }

    let gv: GovulncheckResult | undefined;
    let goAnalysis: ScanReport['goAnalysis'];
    if (hasGo) {
      gv = govulncheck ? await govulncheck : undefined;
      checkAbort();
      if (gv?.error) log(`Go: ${gv.error}`);
      else if (gv) {
        const called = [...gv.verdicts.values()].filter((v) => v.level === 'called').length;
        log(`Go: govulncheck (go ${gv.goVersion ?? '?'}): ${gv.verdicts.size} advisories in the build, ${called} with a vulnerable symbol called`);
        // The standard library that was analysed is the toolchain's, not the floor go.mod declares.
        const std = components.find((c) => c.ecosystem === 'Go' && c.name === 'stdlib' && c.origin !== 'image');
        if (std && gv.goVersion && std.version !== gv.goVersion) {
          std.version = gv.goVersion;
          std.purl = purlForGo('stdlib', gv.goVersion);
        }
      }
      goAnalysis = goGraphUsable ? 'call-graph' : gv && !gv.error ? 'govulncheck' : 'none';
    }

    log('Advisories: OSV');
    const advisories = await fetchAdvisories(inv.components, { cache, offline: opts.offline, log });
    const cves = [...new Set([...advisories.values()].flat().flatMap((a) => a.cves ?? (a.cve ? [a.cve] : [])))];
    log(`Advisories: ${[...advisories.values()].flat().length} across ${advisories.size} components; EPSS + KEV for ${cves.length} CVEs`);
    checkAbort();
    const [epss, kev] = await Promise.all([fetchEpss(cves, cache, opts.offline), fetchKev(cache, opts.offline)]);

    checkAbort();
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
          checkAbort();
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
      checkAbort();
      log(`Symbols: ${derived} newly derived from fix commits, ${skipped} advisories without usable fix data${deferred ? `, ${deferred} deferred to the next scan (time budget)` : ''}`);
    }

    const findings: Finding[] = [];
    void (findings as unknown);
    for (const c of inv.components) {
      for (const a of advisories.get(c.purl) ?? []) {
        checkAbort();
        const ids = [a.id, ...a.aliases];
        let sym = symbols.lookup(ids, c.name);
        let reach: ReachResult;
        if (c.ecosystem === 'Go' && c.origin !== 'image') {
          const go = goReach(graph, goGraphUsable, gv, c, ids, sym);
          sym = go.symbols;
          reach = go.reach;
        } else {
          // A package that exists only in the image is analysed through the code graph only when the
          // application imports it and the lockfile has no copy of its own (the app resolves its own
          // copy, so an image copy at another version is never the one the code runs). OS packages and
          // tooling inside the image get no call-path claim.
          const codeUsed = (c.ecosystem === 'npm' || c.ecosystem === 'PyPI') && graph.packagesImported.has(c.name) && !lockfileNames.has(c.name);
          reach = c.origin === 'image' && !codeUsed ? IMAGE_ONLY : assessReach(graph, c, sym);
        }
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
    checkAbort();
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
        advisories: new Set([...advisories.values()].flat().map((a) => a.id)).size,
        findings: findings.length,
        byDecision,
        byTier,
        noiseRemoved: findings.length ? (findings.length - actionable) / findings.length : 0,
      },
      exposure,
      entryPoints: graph.entryPoints,
      traffic,
      components: inv.components,
      images,
      goAnalysis,
      govulncheckError: gv?.error,
      findings,
    };
  } finally {
    cache.close();
  }
}
