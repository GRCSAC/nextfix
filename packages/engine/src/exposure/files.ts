import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

/*
 * The project files the deployment readers look at: configuration, manifests and
 * infrastructure definitions, found with a shallow walk that skips dependency and build
 * folders. Everything is read as text with a size cap; a file that cannot be read is skipped.
 */

export const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'dist', 'build', 'out', '.venv', 'venv', '__pycache__', '.next', '.nuxt', 'target', 'coverage', '.terraform', '.cache', 'tmp', 'temp', 'logs', 'bower_components', '.svelte-kit', '.turbo', 'site-packages']);
export const MAX_DEPTH = 5;
export const MAX_BYTES = 512 * 1024;

export interface ProjectFile {
  /** Relative to the project, with forward slashes. */
  rel: string;
  abs: string;
  name: string;
  /** Lowercase extension without the dot, or '' (dotfiles like `.env` report 'env'). */
  ext: string;
}

/** Files that may carry deployment information. Order is stable (depth first, names sorted). */
export function walkProject(rootDir: string, opts: { ignore?: string[]; maxDepth?: number } = {}): ProjectFile[] {
  const skip = new Set([...SKIP_DIRS, ...(opts.ignore ?? []).map((d) => d.replace(/[\\/]+$/, ''))]);
  const ignoredRel = new Set((opts.ignore ?? []).map((d) => d.replace(/\\/g, '/').replace(/\/+$/, '')));
  const out: ProjectFile[] = [];
  const walk = (dir: string, depth: number) => {
    let names: string[];
    try {
      names = readdirSync(dir).sort();
    } catch {
      return;
    }
    for (const name of names) {
      const abs = join(dir, name);
      const rel = relative(rootDir, abs).split(sep).join('/');
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (skip.has(name) || ignoredRel.has(rel) || (name.startsWith('.') && name !== '.github' && name !== '.platform')) continue;
        if (depth < (opts.maxDepth ?? MAX_DEPTH)) walk(abs, depth + 1);
        continue;
      }
      if (!st.isFile() || st.size > MAX_BYTES) continue;
      const dot = name.lastIndexOf('.');
      const ext = dot > 0 ? name.slice(dot + 1).toLowerCase() : name.startsWith('.') ? name.slice(1).split('.')[0]!.toLowerCase() : '';
      out.push({ rel, abs, name, ext });
    }
  };
  walk(rootDir, 0);
  return out;
}

export function readText(file: ProjectFile): string | undefined {
  try {
    return readFileSync(file.abs, 'utf8');
  } catch {
    return undefined;
  }
}

/** docker-compose.yml, compose.yaml, docker-compose.prod.yml, … */
export function isComposeFile(f: ProjectFile): boolean {
  return /^(docker-)?compose([.-][\w-]+)?\.ya?ml$/i.test(f.name);
}

const MANIFEST_DIRS = /(^|\/)(k8s|kube|kubernetes|deploy|deployment|deployments|manifests?|charts?|helm|infra|infrastructure|ops|cloud|cfn|cloudformation|templates|stacks?)(\/|$)/i;

/** YAML that may hold Kubernetes or CloudFormation documents: anything under a deployment-looking folder, or at the root. */
export function isManifestCandidate(f: ProjectFile): boolean {
  if (!/\.ya?ml$/i.test(f.name) || isComposeFile(f)) return false;
  if (/^\.github\//.test(f.rel)) return false;
  return !f.rel.includes('/') || MANIFEST_DIRS.test(f.rel);
}

export function isEnvFile(f: ProjectFile): boolean {
  return /^\.env(\.[\w.-]+)?$/i.test(f.name) && !/\.(ts|js)$/.test(f.name);
}

/** Configuration files worth scanning for service URLs. */
export function isConfigFile(f: ProjectFile): boolean {
  if (isEnvFile(f) || isComposeFile(f)) return false;
  if (/^(package|package-lock|tsconfig|jsconfig|composer|composer\.lock)\.json$/i.test(f.name)) return false;
  if (/\.(lock|min\.js|map)$/i.test(f.name)) return false;
  return /\.(json|ya?ml|toml|ini|cfg|conf|properties|env)$/i.test(f.name) || /^(Procfile|fly\.toml|app\.yaml|vercel\.json|netlify\.toml|render\.yaml|serverless\.ya?ml)$/i.test(f.name);
}
