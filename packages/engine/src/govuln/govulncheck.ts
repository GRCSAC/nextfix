import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { findOnPath } from '../inventory/container.ts';

export type GoVerdictLevel = 'called' | 'imported' | 'required';

const LEVEL_RANK: Record<GoVerdictLevel, number> = { required: 0, imported: 1, called: 2 };

export interface GoTraceFrame {
  module: string;
  version?: string;
  package?: string;
  function?: string;
  receiver?: string;
  position?: { filename: string; line: number; column: number };
}

/** What govulncheck found for one advisory, at the deepest level any finding reached. */
export interface GoVerdict {
  level: GoVerdictLevel;
  /** The call stacks of the `called` findings (vulnerable symbol first, project entry function last). */
  trace: GoTraceFrame[][];
  /** Module path the first finding names (`stdlib` for the standard library). */
  module: string;
  /** Level reached per affected module: one advisory can cover several (net/http and golang.org/x/net). */
  byModule: Record<string, GoVerdictLevel>;
  /** Vulnerable packages the build imports, per module. */
  packages: Record<string, string[]>;
  fixedVersion?: string;
}

/** Vulnerable symbols of one advisory, by package path, from the OSV entries govulncheck emits. */
export interface GoVulnSymbols {
  /** OSV `affected[].package.name`: the module path, or `stdlib`. */
  modules: string[];
  /** Vulnerable packages with their symbols (`Func` or `Type.Method`), each under the module it belongs to. */
  packages: { module: string; path: string; symbols: string[] }[];
}

export interface GovulncheckResult {
  symbols: Map<string, GoVulnSymbols>;
  verdicts: Map<string, GoVerdict>;
  /** Every id govulncheck's advisories go by (GO-, GHSA-, CVE-) -> the GO- id the maps are keyed on. */
  aliases: Map<string, string>;
  /** Toolchain govulncheck analysed with, without the `go` prefix (`1.22.3`). */
  goVersion?: string;
  /** Set when govulncheck is missing or failed; the maps are then empty. */
  error?: string;
}

export interface GovulncheckOptions {
  /** Explicit binary; otherwise `NEXTFIX_GOVULNCHECK`, then the PATH. */
  binary?: string;
  /** PATH to search (tests); defaults to the process environment. */
  pathEnv?: string;
  /** Kill govulncheck after this long (default 10 minutes). */
  timeoutMs?: number;
}

export function findGovulncheck(opts: Pick<GovulncheckOptions, 'binary' | 'pathEnv'> = {}): string | undefined {
  const explicit = opts.binary ?? process.env.NEXTFIX_GOVULNCHECK;
  if (explicit) return existsSync(explicit) ? explicit : findOnPath(explicit, opts.pathEnv);
  return findOnPath('govulncheck', opts.pathEnv);
}

/** Runs `govulncheck -json ./...` in the project and parses what it streams; never throws. */
export async function runGovulncheck(projectDir: string, opts: GovulncheckOptions = {}): Promise<GovulncheckResult> {
  const binary = findGovulncheck(opts);
  if (!binary) return { symbols: new Map(), verdicts: new Map(), aliases: new Map(), error: 'govulncheck is not installed (go install golang.org/x/vuln/cmd/govulncheck@latest); Go reachability falls back to the inventory' };
  const shell = /\.(cmd|bat)$/i.test(binary);
  const run = new Promise<{ ok: boolean; out: string; err: string }>((res) => {
    execFile(binary, ['-json', './...'], { cwd: projectDir, shell, maxBuffer: 1024 * 1024 * 1024, timeout: opts.timeoutMs ?? 10 * 60_000, windowsHide: true }, (error, stdout, stderr) => {
      res({ ok: !error, out: String(stdout), err: String(stderr).trim() || (error ? `exit code ${(error as { code?: unknown }).code ?? '?'}` : '') });
    });
  });
  const r = await run;
  if (!r.ok) {
    // govulncheck exits 3 when it finds vulnerabilities and still writes its full output; anything
    // else (a build failure, a missing toolchain) ends with no findings and the reason on stderr.
    const parsed = parseGovulncheckJson(r.out);
    if (parsed.verdicts.size || parsed.symbols.size) return parsed;
    return { ...parsed, error: `govulncheck failed: ${lastLines(r.err || r.out)}` };
  }
  return parseGovulncheckJson(r.out);
}

function lastLines(text: string, n = 3): string {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(-n)
    .join(' · ');
}

interface OsvEntry {
  id?: string;
  aliases?: string[];
  affected?: { package?: { name?: string; ecosystem?: string }; ecosystem_specific?: { imports?: { path?: string; symbols?: string[] }[] } }[];
}

interface FindingEntry {
  osv?: string;
  fixed_version?: string;
  trace?: GoTraceFrame[];
}

/** Parses the stream of top-level JSON objects (`config`, `progress`, `osv`, `finding`, …) govulncheck writes. */
export function parseGovulncheckJson(text: string): GovulncheckResult {
  const symbols = new Map<string, GoVulnSymbols>();
  const verdicts = new Map<string, GoVerdict>();
  const aliases = new Map<string, string>();
  let goVersion: string | undefined;
  for (const obj of splitJsonObjects(text)) {
    if (obj.config && typeof obj.config === 'object') {
      const v = (obj.config as { go_version?: string }).go_version;
      if (v) goVersion = v.replace(/^go/, '');
    } else if (obj.osv && typeof obj.osv === 'object') {
      absorbOsv(symbols, aliases, obj.osv as OsvEntry);
    } else if (obj.finding && typeof obj.finding === 'object') {
      absorbFinding(verdicts, obj.finding as FindingEntry);
    }
  }
  return { symbols, verdicts, aliases, goVersion };
}

/** The GO- id govulncheck's maps are keyed on, for any of the advisory's ids. */
export function goIdFor(result: Pick<GovulncheckResult, 'aliases'>, ids: string[]): string | undefined {
  for (const id of ids) {
    const go = result.aliases.get(id);
    if (go) return go;
  }
  return undefined;
}

function absorbOsv(symbols: Map<string, GoVulnSymbols>, aliases: Map<string, string>, osv: OsvEntry): void {
  if (!osv.id) return;
  aliases.set(osv.id, osv.id);
  for (const a of osv.aliases ?? []) aliases.set(a, osv.id);
  const entry = symbols.get(osv.id) ?? { modules: [], packages: [] };
  for (const a of osv.affected ?? []) {
    if (a.package?.ecosystem && a.package.ecosystem !== 'Go') continue;
    const mod = a.package?.name;
    if (!mod) continue;
    if (!entry.modules.includes(mod)) entry.modules.push(mod);
    for (const imp of a.ecosystem_specific?.imports ?? []) {
      if (!imp.path) continue;
      let pkg = entry.packages.find((p) => p.module === mod && p.path === imp.path);
      if (!pkg) {
        pkg = { module: mod, path: imp.path, symbols: [] };
        entry.packages.push(pkg);
      }
      for (const s of imp.symbols ?? []) if (!pkg.symbols.includes(s)) pkg.symbols.push(s);
    }
  }
  symbols.set(osv.id, entry);
}

/** Maximum call stacks kept per advisory; the first few are what a reader looks at. */
const MAX_TRACES = 20;

function absorbFinding(verdicts: Map<string, GoVerdict>, f: FindingEntry): void {
  const first = f.trace?.[0];
  if (!f.osv || !first?.module) return;
  const level: GoVerdictLevel = first.function ? 'called' : first.package ? 'imported' : 'required';
  let cur = verdicts.get(f.osv);
  if (!cur) {
    cur = { level, trace: [], module: first.module, byModule: {}, packages: {}, fixedVersion: f.fixed_version };
    verdicts.set(f.osv, cur);
  }
  if (LEVEL_RANK[level] > LEVEL_RANK[cur.level]) cur.level = level;
  const have = cur.byModule[first.module];
  if (!have || LEVEL_RANK[level] > LEVEL_RANK[have]) cur.byModule[first.module] = level;
  if (first.package) {
    const pkgs = (cur.packages[first.module] ??= []);
    if (!pkgs.includes(first.package)) pkgs.push(first.package);
  }
  if (level === 'called' && cur.trace.length < MAX_TRACES) cur.trace.push(f.trace!);
  cur.fixedVersion ??= f.fixed_version;
}

/** Splits concatenated, pretty-printed JSON objects; a malformed object is skipped, not fatal. */
export function splitJsonObjects(text: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  let depth = 0;
  let start = -1;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0 && start >= 0) {
        try {
          const parsed = JSON.parse(text.slice(start, i + 1)) as unknown;
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) out.push(parsed as Record<string, unknown>);
        } catch {
          // a truncated or malformed object (govulncheck killed mid-write); the rest still counts
        }
        start = -1;
      } else if (depth < 0) depth = 0;
    }
  }
  return out;
}

/** The symbol name as the vulnerable-symbol data spells it: `Type.Method` or `Func`. */
export function frameSymbol(frame: GoTraceFrame): string {
  const recv = frame.receiver?.replace(/^\*/, '');
  return recv && frame.function ? `${recv}.${frame.function}` : frame.function ?? '';
}

/**
 * Where the project's own code makes the call: the last frame of a trace is the project
 * function and its position is the call it makes toward the vulnerable symbol.
 */
export function projectCallSite(trace: GoTraceFrame[]): { file: string; line: number; col: number; caller: string } | undefined {
  for (let i = trace.length - 1; i >= 0; i--) {
    const fr = trace[i]!;
    if (fr.position?.filename) return { file: fr.position.filename.replace(/\\/g, '/'), line: fr.position.line, col: fr.position.column, caller: frameSymbol(fr) };
  }
  return undefined;
}
