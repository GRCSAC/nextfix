import type { Advisory, SymbolEntry } from '../types.ts';
import { DAY } from '../vulns/cache.ts';
import { isPython, parseUnifiedDiff, sourceFiles } from './diff.ts';
import { fixCandidates, diffUrl, rawRef, type FixCandidate } from './fixcommits.ts';
import { fetchDiff, fetchRaw, RateLimited, type GitHubOptions } from './github.ts';
import { analyzeFile, enclosingAll, enclosingTopLevel, resolvePublic, type FileFacts } from './functions.ts';
import { analyzePyFile } from './pyfunctions.ts';
import { PackageGraph, entryCandidates, findPackage, findPythonPackage, pyAdapter, resolveAcrossFiles } from './package.ts';
import type { DerivedStore } from './store.ts';

export interface DeriveOptions extends GitHubOptions {
  store: DerivedStore;
  /** Advisory references with their OSV type, when available. */
  typedReferences?: { type?: string; url: string }[];
  force?: boolean;
}

export interface DeriveOutcome {
  entry?: SymbolEntry;
  reason?: string;
  /** Derivation was skipped because an earlier attempt failed recently. */
  cached?: boolean;
}

const MAX_FILES = 12;
const MAX_ENTRY_TRIES = 4;

/**
 * Derives the vulnerable symbols for one advisory on one package from its fix commit(s):
 * diff → touched lines → enclosing functions → public surface of that file → carried up the
 * package's import graph to the entry file's public names.
 */
export async function deriveSymbols(advisory: Advisory, pkg: string, opts: DeriveOptions & { ecosystem?: 'npm' | 'PyPI' }): Promise<DeriveOutcome> {
  const ids = [advisory.id, ...advisory.aliases];
  const ecosystem = opts.ecosystem ?? 'npm';
  const analyze = (text: string, path: string): FileFacts | Promise<FileFacts> => (isPython(path) ? analyzePyFile(text, path) : analyzeFile(text, path));
  if (!opts.force) {
    const existing = opts.store.get(advisory.id, pkg);
    if (existing) return { entry: existing, cached: true };
    const failed = opts.store.failedReason(advisory.id, pkg);
    if (failed) return { reason: failed, cached: true };
  }

  const candidates = fixCandidates(opts.typedReferences ?? advisory.references, pkg);
  if (!candidates.length) return fail(opts, advisory, pkg, 'no GitHub fix commit, pull request or compare link in the advisory references');

  const symbols = new Map<string, string>();
  const changed = new Set<string>();
  const files = new Set<string>();
  const used: string[] = [];
  let repoMatch = false;
  let internalOnly = false;
  let defaultCallable = false;
  let moduleLevel = false;
  let entryPath: string | undefined;

  try {
    for (const c of candidates) {
      const diffText = await fetchDiff(diffUrl(c), opts);
      if (!diffText) continue;
      const touched = sourceFiles(parseUnifiedDiff(diffText)).filter((f) => (ecosystem === 'PyPI') === isPython(f.path)).slice(0, MAX_FILES);
      if (!touched.length) continue;
      used.push(c.url);
      repoMatch ||= c.repoMatch;

      /** per touched file: tainted local names for the cross-file pass */
      const startLocals = new Map<string, Set<string>>();
      for (const f of touched) {
        const text = await fetchRaw(c.owner, c.repo, rawRef(c), f.path, opts);
        if (!text) continue;
        const facts = await analyze(text, f.path);
        defaultCallable ||= facts.defaultIsFunction;
        const locals = new Set<string>();
        let hit = false;
        for (const h of f.hunks) {
          for (const ln of h.touchedNewLines) {
            const chain = enclosingAll(facts, ln);
            if (!chain.length) {
              // Module-level change (a regex table, a constant): taint the declaration it sits in.
              const top = enclosingTopLevel(facts, ln);
              if (top) locals.add(top.name);
              hit = true;
              moduleLevel = true;
              continue;
            }
            hit = true;
            const named = chain.find((fn) => !fn.name.startsWith('<anon'));
            if (named) {
              changed.add(named.name);
              locals.add(named.name);
              if (named.className) locals.add(named.className);
            }
            let resolved = false;
            for (const fn of chain) {
              const pubs = resolvePublic(facts, fn);
              if (!pubs.size) continue;
              for (const [p, via] of pubs) if (!symbols.has(p)) symbols.set(p, via);
              resolved = true;
              break;
            }
            if (!resolved) internalOnly = true;
          }
        }
        if (hit) {
          files.add(f.path);
          if (!locals.size) for (const local of facts.publicByName.values()) locals.add(local);
          startLocals.set(f.path, locals);
        }
      }

      // Cross-file: carry the tainted names up to the package entry's public surface.
      if (startLocals.size) {
        const fetchText = (p: string) => fetchRaw(c.owner, c.repo, rawRef(c), p, opts);
        const first = [...startLocals.keys()][0]!;
        if (ecosystem === 'PyPI') {
          const exists = async (p: string) => (await fetchText(p)) !== undefined;
          const found = await findPythonPackage(exists, first);
          if (found) {
            // Python packages are large (Django: hundreds of modules); 60 prioritised files is enough
            // to reach a package __init__ chain and keeps a derivation to a few seconds.
            const graph = new PackageGraph(fetchText, 60, pyAdapter(found.packageRoot, analyze));
            let any = false;
            for (const [path, locals] of startLocals) {
              const r = await resolveAcrossFiles(graph, found.entry, path, locals);
              if (!r) continue;
              any = true;
              for (const [s, via] of r.symbols) if (!symbols.has(s) || symbols.get(s)!.startsWith('caller:')) symbols.set(s, `entry:${via}`);
            }
            if (any) entryPath = found.entry;
          }
        } else {
          const found = await findPackage({ fetchText }, first, pkg);
          if (found) {
            const graph = new PackageGraph(fetchText, 200);
            const prefix = found.dir ? `${found.dir}/` : '';
            let tries = 0;
            for (const cand of entryCandidates(found.pkg, pkg)) {
              const entry = prefix + cand;
              if (!(await graph.exists(entry))) continue;
              if (++tries > MAX_ENTRY_TRIES) break;
              let any = false;
              for (const [path, locals] of startLocals) {
                const r = await resolveAcrossFiles(graph, entry, path, locals);
                if (!r) continue;
                any = true;
                for (const [s, via] of r.symbols) if (!symbols.has(s) || symbols.get(s)!.startsWith('caller:')) symbols.set(s, `entry:${via}`);
              }
              if (any) {
                entryPath = entry;
                break;
              }
            }
          }
        }
      }
      if (symbols.size) break; // the best-ranked commit that yields symbols wins
    }
  } catch (err) {
    if (err instanceof RateLimited) return { reason: err.message };
    throw err;
  }

  if (!used.length) return fail(opts, advisory, pkg, `fix links found but no diff could be fetched or it touched no ${ecosystem === 'PyPI' ? 'Python' : 'JavaScript'} source (tests, docs or native code only)`);
  if (!symbols.size && (changed.size || moduleLevel) && defaultCallable) symbols.set('default', moduleLevel && !changed.size ? 'module-level-change' : 'package-is-one-function');
  if (!symbols.size) return fail(opts, advisory, pkg, changed.size ? `fix changed internal function(s) ${[...changed].join(', ')} that no entry-file export reaches` : 'fix touched no function bodies and could not be traced to an entry export');

  const entry: SymbolEntry = {
    ids,
    ecosystem,
    package: pkg,
    symbols: [...symbols.keys()].sort(),
    source: 'derived',
    confidence: 'derived',
    references: used,
    note: internalOnly && !entryPath ? 'Some changed functions had no public caller in their file; coverage may be partial.' : undefined,
    evidence: {
      commits: used,
      files: [...files],
      changedFunctions: changed.size ? [...changed] : moduleLevel ? ['<module scope>'] : [],
      resolvedVia: Object.fromEntries(symbols),
      repoMatch,
      entry: entryPath,
      derivedAt: new Date().toISOString(),
    },
  };
  opts.store.clearFailed(advisory.id, pkg);
  opts.store.put(entry);
  return { entry };
}

function fail(opts: DeriveOptions, advisory: Advisory, pkg: string, reason: string): DeriveOutcome {
  opts.store.markFailed(advisory.id, pkg, reason, 7 * DAY);
  return { reason };
}

export type { FixCandidate };
