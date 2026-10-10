import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Optional per-project settings in `nextfix.config.json` at the project root. */
export interface ProjectConfig {
  /** Extra identifiers / call texts that count as auth guards, as regular expressions. */
  authGuards?: string[];
  /** Replace (not extend) the built-in auth-guard pattern. */
  authGuardsReplace?: boolean;
  /** Directory names (relative to the project) to skip during code analysis. */
  ignore?: string[];
  /** Routes that are known to be internal-only, e.g. ["GET /healthz"]; they are treated as authenticated. */
  internalRoutes?: string[];
  /** Container image reference(s) to inventory with syft, e.g. "ghcr.io/org/app:1.4". */
  image?: string | string[];
  /** SBOM file(s) to read instead of, or as well as, an image: CycloneDX JSON, SPDX JSON or a Grype report. */
  sbom?: string | string[];
  /** Path to the syft binary when it is not on the PATH. */
  syft?: string;
}

export function asList(v: string | string[] | undefined): string[] {
  return v === undefined ? [] : Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.trim()) : typeof v === 'string' && v.trim() ? [v] : [];
}

export function loadConfig(rootDir: string): ProjectConfig {
  const file = join(rootDir, 'nextfix.config.json');
  if (!existsSync(file)) return {};
  let cfg: unknown;
  try {
    cfg = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`nextfix.config.json is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  return validateConfig(cfg);
}

const STRING_LIST_KEYS: (keyof ProjectConfig)[] = ['authGuards', 'ignore', 'internalRoutes'];
const STRING_OR_LIST_KEYS: (keyof ProjectConfig)[] = ['image', 'sbom'];

/** Checks the shape of a config object and reports the first problem in plain words. */
export function validateConfig(cfg: unknown): ProjectConfig {
  if (cfg === null || typeof cfg !== 'object' || Array.isArray(cfg)) throw new Error('nextfix.config.json must contain a JSON object');
  const c = cfg as Record<string, unknown>;
  const isStringList = (v: unknown) => Array.isArray(v) && v.every((x) => typeof x === 'string');
  for (const k of STRING_LIST_KEYS) if (c[k] !== undefined && !isStringList(c[k])) throw new Error(`nextfix.config.json: "${k}" must be a list of strings`);
  for (const k of STRING_OR_LIST_KEYS) if (c[k] !== undefined && typeof c[k] !== 'string' && !isStringList(c[k])) throw new Error(`nextfix.config.json: "${k}" must be a string or a list of strings`);
  if (c.authGuardsReplace !== undefined && typeof c.authGuardsReplace !== 'boolean') throw new Error('nextfix.config.json: "authGuardsReplace" must be true or false');
  if (c.syft !== undefined && typeof c.syft !== 'string') throw new Error('nextfix.config.json: "syft" must be a string');
  const known = new Set<string>([...STRING_LIST_KEYS, ...STRING_OR_LIST_KEYS, 'authGuardsReplace', 'syft']);
  for (const k of Object.keys(c)) if (!known.has(k)) throw new Error(`nextfix.config.json: unknown setting "${k}" (known: ${[...known].join(', ')})`);
  return c as ProjectConfig;
}
