import type { Advisory, SymbolEntry } from '../types.ts';
import { DAY } from '../vulns/cache.ts';
import { parseUnifiedDiff, sourceFiles } from './diff.ts';
import { fixCandidates, diffUrl, rawRef, type FixCandidate } from './fixcommits.ts';
import { fetchDiff, fetchRaw, RateLimited, type GitHubOptions } from './github.ts';
import { analyzeFile, enclosingAll, resolvePublic } from './functions.ts';
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

/**
 * Derives the vulnerable symbols for one advisory on one package from its fix commit(s):
 * diff → touched lines → enclosing functions → public symbols of that file.
 */
export async function deriveSymbols(advisory: Advisory, pkg: string, opts: DeriveOptions): Promise<DeriveOutcome> {
  const ids = [advisory.id, ...advisory.aliases];
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

  try {
    for (const c of candidates) {
      const diffText = await fetchDiff(diffUrl(c), opts);
      if (!diffText) continue;
      const touched = sourceFiles(parseUnifiedDiff(diffText)).slice(0, MAX_FILES);
      if (!touched.length) continue;
      used.push(c.url);
      repoMatch ||= c.repoMatch;
      for (const f of touched) {
        const text = await fetchRaw(c.owner, c.repo, rawRef(c), f.path, opts);
        if (!text) continue;
        const facts = analyzeFile(text, f.path);
        defaultCallable ||= facts.defaultIsFunction;
        let hit = false;
        for (const h of f.hunks) {
          for (const ln of h.touchedNewLines) {
            const chain = enclosingAll(facts, ln);
            if (!chain.length) {
              // Module-level change (a regex table, a constant). When the package is one callable,
              // that callable is what reaches it.
              if (facts.defaultIsFunction) {
                hit = true;
                moduleLevel = true;
              }
              continue;
            }
            hit = true;
            // Record the innermost named function; resolve outward until something public is reached
            // (a change inside a nested callback belongs to the function that owns the callback).
            const named = chain.find((fn) => !fn.name.startsWith('<anon'));
            if (named) changed.add(named.name);
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
        if (hit) files.add(f.path);
      }
      if (symbols.size) break; // the best-ranked commit that yields symbols wins
    }
  } catch (err) {
    if (err instanceof RateLimited) return { reason: err.message };
    throw err;
  }

  if (!used.length) return fail(opts, advisory, pkg, 'fix links found but no diff could be fetched or it touched only tests/docs');
  if (!symbols.size && (changed.size || moduleLevel) && defaultCallable) symbols.set('default', moduleLevel && !changed.size ? 'module-level-change' : 'package-is-one-function');
  if (!symbols.size) return fail(opts, advisory, pkg, changed.size ? `fix changed internal function(s) ${[...changed].join(', ')} with no public caller in the same file` : 'fix touched no function bodies (module-level change in a multi-export file)');

  const entry: SymbolEntry = {
    ids,
    ecosystem: 'npm',
    package: pkg,
    symbols: [...symbols.keys()].sort(),
    source: 'derived',
    confidence: 'derived',
    references: used,
    note: internalOnly ? 'Some changed functions had no public caller in their file; coverage may be partial.' : undefined,
    evidence: {
      commits: used,
      files: [...files],
      changedFunctions: changed.size ? [...changed] : moduleLevel ? ['<module scope>'] : [],
      resolvedVia: Object.fromEntries(symbols),
      repoMatch,
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
