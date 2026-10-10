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
  try {
    const cfg = JSON.parse(readFileSync(file, 'utf8')) as ProjectConfig;
    return cfg && typeof cfg === 'object' ? cfg : {};
  } catch (err) {
    throw new Error(`nextfix.config.json is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
}
