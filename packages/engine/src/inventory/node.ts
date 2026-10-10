import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Component } from '../types.ts';
import { readNpmLock } from './npm-lock.ts';
import { readYarnLock } from './yarn-lock.ts';
import { parseYaml, readPnpmLock } from './pnpm-lock.ts';

/**
 * One entry point for Node projects: the root lockfile (package-lock.json, then yarn.lock,
 * then pnpm-lock.yaml) plus the lockfiles of any workspace that keeps its own, merged by purl.
 */

export const NODE_LOCKFILES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'] as const;
export type NodeLockfile = (typeof NODE_LOCKFILES)[number];

export interface NodeInventory {
  components: Component[];
  /** Lockfiles read, relative to the project root with forward slashes. */
  sources: string[];
  projectName?: string;
  projectVersion?: string;
}

/** The lockfile a directory would be inventoried from, in order of preference. */
export function findNodeLockfile(dir: string): NodeLockfile | undefined {
  return NODE_LOCKFILES.find((f) => existsSync(join(dir, f)));
}

/** True when the root or any workspace has a lockfile NextFix can read. */
export function hasNodeProject(rootDir: string): boolean {
  if (findNodeLockfile(rootDir)) return true;
  return listWorkspaceDirs(rootDir).some((ws) => findNodeLockfile(join(rootDir, ws)));
}

interface Manifest {
  name?: string;
  version?: string;
  workspaces?: string[] | { packages?: string[] };
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

function readManifest(dir: string): Manifest | undefined {
  const file = join(dir, 'package.json');
  if (!existsSync(file)) return undefined;
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as Manifest;
  } catch {
    return undefined;
  }
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function subdirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory() && !d.name.startsWith('.') && d.name !== 'node_modules')
      .map((d) => d.name);
  } catch {
    return [];
  }
}

/** Expands one workspace pattern (`packages/*`, `apps/**`, `tools/cli`) to directories under root. */
function expandPattern(rootDir: string, pattern: string): string[] {
  const segments = pattern.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '').split('/').filter(Boolean);
  let current = [''];
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i]!;
    const next: string[] = [];
    for (const rel of current) {
      const abs = rel ? join(rootDir, rel) : rootDir;
      if (seg === '**') {
        // Any depth, including none; the remaining segments continue from each directory.
        const all: string[] = [rel];
        const stackDirs = [rel];
        while (stackDirs.length) {
          const d = stackDirs.pop()!;
          for (const s of subdirs(d ? join(rootDir, d) : rootDir)) {
            const child = d ? `${d}/${s}` : s;
            all.push(child);
            stackDirs.push(child);
          }
        }
        next.push(...all);
      } else if (seg.includes('*')) {
        const re = new RegExp(`^${seg.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
        for (const s of subdirs(abs)) if (re.test(s)) next.push(rel ? `${rel}/${s}` : s);
      } else if (isDir(join(abs, seg))) next.push(rel ? `${rel}/${seg}` : seg);
    }
    current = next;
  }
  return current.filter((rel) => rel && existsSync(join(rootDir, rel, 'package.json')));
}

/** Workspace directories from package.json `workspaces` or pnpm-workspace.yaml `packages`, relative to the root. */
export function listWorkspaceDirs(rootDir: string): string[] {
  const patterns: string[] = [];
  const ws = readManifest(rootDir)?.workspaces;
  if (Array.isArray(ws)) patterns.push(...ws);
  else if (ws && Array.isArray(ws.packages)) patterns.push(...ws.packages);
  const pnpmWs = join(rootDir, 'pnpm-workspace.yaml');
  if (existsSync(pnpmWs)) {
    const parsed = parseYaml(readFileSync(pnpmWs, 'utf8'));
    if (Array.isArray(parsed.packages)) patterns.push(...parsed.packages.filter((p): p is string => typeof p === 'string'));
  }
  const dirs = new Set<string>();
  for (const p of patterns) {
    if (p.startsWith('!')) continue;
    for (const d of expandPattern(rootDir, p)) if (d !== '.') dirs.add(d);
  }
  return [...dirs].sort();
}

function readLockfile(dir: string, lockfile: NodeLockfile, workspaceDirs: string[]): { components: Component[]; projectName?: string; projectVersion?: string } {
  switch (lockfile) {
    case 'package-lock.json':
      return readNpmLock(dir);
    case 'yarn.lock':
      return readYarnLock(dir, { workspaceDirs });
    case 'pnpm-lock.yaml':
      return readPnpmLock(dir);
  }
}

function merge(byPurl: Map<string, Component>, c: Component, prefix: string) {
  const paths = (c.paths ?? [c.path]).map((p) => (prefix ? `${prefix}/${p}` : p));
  const existing = byPurl.get(c.purl);
  if (existing) {
    existing.dev = existing.dev && c.dev;
    existing.optional = existing.optional && c.optional;
    existing.direct = existing.direct || c.direct;
    existing.paths = [...(existing.paths ?? [existing.path]), ...paths];
    return;
  }
  byPurl.set(c.purl, { ...c, path: paths[0]!, paths: paths.length > 1 ? paths : undefined });
}

/**
 * Inventories a Node project. The root lockfile is read first (package-lock.json, then
 * yarn.lock, then pnpm-lock.yaml); workspaces that keep their own lockfile are read too and
 * merged by purl, with `paths` listing every location. Dependencies a workspace's own
 * package.json declares count as direct.
 */
export function readNodeInventory(rootDir: string): NodeInventory {
  const workspaceDirs = listWorkspaceDirs(rootDir);
  const rootLock = findNodeLockfile(rootDir);
  const byPurl = new Map<string, Component>();
  const sources: string[] = [];
  let projectName: string | undefined;
  let projectVersion: string | undefined;

  if (rootLock) {
    const inv = readLockfile(rootDir, rootLock, workspaceDirs);
    sources.push(rootLock);
    projectName = inv.projectName;
    projectVersion = inv.projectVersion;
    if (rootLock === 'package-lock.json' && workspaceDirs.length) {
      // package-lock.json only knows the root manifest's direct dependencies; a workspace's
      // own dependencies live hoisted at node_modules/<name> or under the workspace.
      for (const ws of workspaceDirs) {
        const m = readManifest(join(rootDir, ws));
        const declared = new Set(Object.keys({ ...(m?.dependencies ?? {}), ...(m?.devDependencies ?? {}), ...(m?.optionalDependencies ?? {}) }));
        for (const c of inv.components) {
          if (c.direct) continue;
          const installedAs = (p: string) => (p.startsWith(`${ws}/node_modules/`) ? p.slice(ws.length + '/node_modules/'.length) : p.startsWith('node_modules/') ? p.slice('node_modules/'.length) : undefined);
          if ((c.paths ?? [c.path]).some((p) => {
            const n = installedAs(p);
            return n !== undefined && !n.includes('node_modules/') && declared.has(n);
          })) c.direct = true;
        }
      }
    }
    for (const c of inv.components) merge(byPurl, c, '');
  }

  for (const ws of workspaceDirs) {
    const lock = findNodeLockfile(join(rootDir, ws));
    if (!lock) continue;
    const inv = readLockfile(join(rootDir, ws), lock, []);
    sources.push(`${ws}/${lock}`);
    for (const c of inv.components) merge(byPurl, c, ws);
  }

  if (!sources.length) throw new Error(`No package-lock.json, yarn.lock or pnpm-lock.yaml in ${rootDir}. Install with npm, yarn or pnpm there first.`);
  const manifest = readManifest(rootDir);
  const components = [...byPurl.values()];
  components.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { components, sources, projectName: projectName ?? manifest?.name, projectVersion: projectVersion ?? manifest?.version };
}
