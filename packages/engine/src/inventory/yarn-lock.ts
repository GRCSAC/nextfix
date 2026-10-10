import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import semver from 'semver';
import type { Component } from '../types.ts';
import { purlFor } from './npm-lock.ts';

/**
 * yarn.lock in both syntaxes: classic (`# yarn lockfile v1`, `version "1.2.3"`) and berry
 * (`__metadata:`, `version: 1.2.3`, `resolution: "name@npm:1.2.3"`). Both are an indented
 * list of entries keyed by one or more descriptors (`name@range`); the two differ only in the
 * leaf syntax, so one tolerant parser covers them.
 */

type Tree = { [key: string]: string | Tree };

interface Entry {
  /** The descriptors the entry is keyed by, e.g. `lodash@^4.17.0`. */
  descriptors: string[];
  /** Name the manifest asks for (an alias stays an alias). */
  installedAs: string;
  /** Name advisories are published for. */
  name: string;
  version: string;
  /** Berry only: `name@workspace:<path>` entries stand for workspace packages. */
  workspacePath?: string;
  fields: Tree;
}

export interface YarnInventory {
  components: Component[];
  /** 1 for the classic syntax, otherwise the berry `__metadata.version`. */
  lockfileVersion: number;
  projectName?: string;
  projectVersion?: string;
}

export interface YarnOptions {
  /**
   * Workspace directories (relative to the project) whose package.json dependencies also
   * count as direct. Berry lockfiles name their workspaces themselves; classic ones do not.
   */
  workspaceDirs?: string[];
}

interface Manifest {
  dir: string;
  name?: string;
  version?: string;
  prod: Record<string, string>;
  optional: Record<string, string>;
  dev: Record<string, string>;
}

function unquote(s: string): string {
  let out = s.trim();
  if (out.startsWith('"')) out = out.slice(1);
  if (out.endsWith('"')) out = out.slice(0, -1);
  return out;
}

/** `@scope/name@range` → name and range; the first `@` of a scoped name is not a separator. */
export function splitDescriptor(d: string): { name: string; range: string } {
  const at = d.startsWith('@') ? d.indexOf('@', 1) : d.indexOf('@');
  if (at < 0) return { name: d, range: '' };
  return { name: d.slice(0, at), range: d.slice(at + 1) };
}

function parseLeaf(content: string): [string, string] | undefined {
  if (content.startsWith('"')) {
    const close = content.indexOf('"', 1);
    if (close < 0) return undefined;
    return [content.slice(1, close), unquote(content.slice(close + 1).replace(/^\s*:?\s*/, ''))];
  }
  const m = /^([^\s"]+?):?\s+(.*)$/.exec(content);
  return m ? [m[1]!, unquote(m[2]!)] : undefined;
}

/** Parses either syntax into a tree: entry key → fields, nested blocks as nested trees. */
export function parseYarnLock(text: string): Tree {
  const root: Tree = {};
  const stack: { indent: number; node: Tree }[] = [{ indent: -1, node: root }];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\s+$/, '');
    const content = line.trimStart();
    if (!content || content.startsWith('#')) continue;
    const indent = line.length - content.length;
    while (stack.length > 1 && stack[stack.length - 1]!.indent >= indent) stack.pop();
    const parent = stack[stack.length - 1]!.node;
    if (content.endsWith(':')) {
      const key = content.slice(0, -1);
      const node: Tree = {};
      parent[key] = node;
      stack.push({ indent, node });
      continue;
    }
    const leaf = parseLeaf(content);
    if (leaf) parent[leaf[0]] = leaf[1];
  }
  return root;
}

function str(v: string | Tree | undefined): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function tree(v: string | Tree | undefined): Tree {
  return v && typeof v === 'object' ? v : {};
}

function toEntries(parsed: Tree): Entry[] {
  const entries: Entry[] = [];
  for (const [rawKey, fields] of Object.entries(parsed)) {
    if (rawKey === '__metadata' || typeof fields !== 'object') continue;
    const descriptors = rawKey.split(',').map(unquote).filter(Boolean);
    const version = str(fields.version);
    const first = splitDescriptor(descriptors[0] ?? '');
    const resolution = str(fields.resolution);
    let name = first.name;
    let workspacePath: string | undefined;
    if (resolution) {
      // Berry: the resolution names the real package (`string-width@npm:4.2.3` for an alias,
      // `fsevents@patch:fsevents@npm%3A2.3.2#…` for a patch, `app@workspace:.` for a workspace).
      const r = splitDescriptor(resolution);
      name = r.name;
      if (r.range.startsWith('workspace:')) workspacePath = r.range.slice('workspace:'.length);
    } else if (first.range.startsWith('npm:')) {
      // Classic alias: `string-width-cjs@npm:string-width@^4.2.0` installs string-width.
      name = splitDescriptor(first.range.slice(4)).name;
    }
    if (!version && !workspacePath) continue;
    entries.push({ descriptors, installedAs: first.name, name, version: version ?? '', workspacePath, fields });
  }
  return entries;
}

function readManifest(projectDir: string, dir: string): Manifest | undefined {
  const file = join(projectDir, dir, 'package.json');
  if (!existsSync(file)) return undefined;
  const pkg = JSON.parse(readFileSync(file, 'utf8')) as { name?: string; version?: string; dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string> };
  return { dir, name: pkg.name, version: pkg.version, prod: pkg.dependencies ?? {}, optional: pkg.optionalDependencies ?? {}, dev: pkg.devDependencies ?? {} };
}

function normalizeDir(dir: string): string {
  const d = dir.replace(/\\/g, '/').replace(/^\.\/+/, '').replace(/\/+$/, '');
  return d === '' ? '.' : d;
}

/** Reads yarn.lock (classic or berry) and returns every installed component. */
export function readYarnLock(projectDir: string, opts: YarnOptions = {}): YarnInventory {
  const lockPath = join(projectDir, 'yarn.lock');
  if (!existsSync(lockPath)) throw new Error(`No yarn.lock in ${projectDir}.`);
  const parsed = parseYarnLock(readFileSync(lockPath, 'utf8'));
  const berry = typeof parsed.__metadata === 'object';
  const lockfileVersion = berry ? parseInt(str(tree(parsed.__metadata).version) ?? '0', 10) || 0 : 1;
  const entries = toEntries(parsed);

  const byDescriptor = new Map<string, Entry>();
  const byName = new Map<string, Entry[]>();
  for (const e of entries) {
    for (const d of e.descriptors) byDescriptor.set(d, e);
    const list = byName.get(e.installedAs) ?? [];
    list.push(e);
    byName.set(e.installedAs, list);
  }

  const lookup = (name: string, range: string): Entry | undefined => {
    const direct = byDescriptor.get(`${name}@${range}`);
    if (direct) return direct;
    // Berry writes `npm:` in front of plain registry ranges.
    if (berry && !/^[a-z]+:/.test(range)) {
      const prefixed = byDescriptor.get(`${name}@npm:${range}`);
      if (prefixed) return prefixed;
    }
    const candidates = byName.get(name) ?? [];
    const plain = range.replace(/^npm:/, '');
    if (semver.validRange(plain)) {
      const match = candidates.filter((c) => semver.valid(c.version) && semver.satisfies(c.version, plain));
      if (match.length) return match.sort((a, b) => semver.rcompare(a.version, b.version))[0];
    }
    return candidates.length === 1 ? candidates[0] : undefined;
  };

  // Manifests: the root, the workspaces the caller names, and (berry) the workspaces the
  // lockfile names. Their dependencies are the roots of the dev / optional walk.
  const manifests = new Map<string, Manifest>();
  const want = new Set<string>(['.', ...(opts.workspaceDirs ?? []).map(normalizeDir), ...entries.filter((e) => e.workspacePath !== undefined).map((e) => normalizeDir(e.workspacePath!))]);
  for (const dir of want) {
    const m = readManifest(projectDir, dir);
    if (m) manifests.set(dir, m);
  }
  const root = manifests.get('.');
  const hasManifest = (e: Entry) => e.workspacePath !== undefined && manifests.has(normalizeDir(e.workspacePath));

  const edges = (e: Entry, followOptional: boolean): [string, string][] => {
    const out: [string, string][] = [];
    const meta = tree(e.fields.dependenciesMeta);
    for (const [n, r] of Object.entries(tree(e.fields.dependencies))) {
      if (typeof r !== 'string') continue;
      const optional = str(tree(meta[n]).optional) === 'true';
      if (optional && !followOptional) continue;
      out.push([n, r]);
    }
    if (followOptional) for (const [n, r] of Object.entries(tree(e.fields.optionalDependencies))) if (typeof r === 'string') out.push([n, r]);
    return out;
  };

  const walk = (roots: Entry[], followOptional: boolean): Set<Entry> => {
    const seen = new Set<Entry>();
    const queue = [...roots];
    while (queue.length) {
      const e = queue.pop()!;
      if (seen.has(e)) continue;
      seen.add(e);
      // A workspace whose manifest was read contributes its own roots; do not merge its dev
      // dependencies into whoever depends on it.
      if (hasManifest(e)) continue;
      for (const [n, r] of edges(e, followOptional)) {
        const dep = lookup(n, r);
        if (dep && !seen.has(dep)) queue.push(dep);
      }
    }
    return seen;
  };

  const resolveAll = (deps: Record<string, string>): Entry[] => Object.entries(deps).map(([n, r]) => lookup(n, r)).filter((e): e is Entry => !!e);
  const prodRoots: Entry[] = [];
  const optionalRoots: Entry[] = [];
  const devRoots: Entry[] = [];
  for (const m of manifests.values()) {
    prodRoots.push(...resolveAll(m.prod));
    optionalRoots.push(...resolveAll(m.optional));
    devRoots.push(...resolveAll(m.dev));
  }
  const direct = new Set<Entry>([...prodRoots, ...optionalRoots, ...devRoots]);
  // A berry workspace with no package.json to read is a root in its own right; its lockfile
  // entry merges dev and prod dependencies, so everything under it counts as prod.
  for (const e of entries) if (e.workspacePath !== undefined && !hasManifest(e)) prodRoots.push(e);
  const prodAll = walk([...prodRoots, ...optionalRoots], true);
  const devAll = walk(devRoots, true);
  const required = walk([...prodRoots, ...devRoots], false);

  // Several entries can stand for one name@version (an alias and the plain descriptor, an
  // npm entry and its patch); flags are folded onto the purl so an entry nothing resolves to
  // does not reset what the others established.
  const flags = new Map<string, { prod: boolean; dev: boolean; required: boolean; direct: boolean; paths: string[]; entry: Entry }>();
  for (const e of entries) {
    if (e.workspacePath !== undefined || !e.version) continue;
    const purl = purlFor(e.name, e.version);
    const f = flags.get(purl) ?? { prod: false, dev: false, required: false, direct: false, paths: [], entry: e };
    f.prod ||= prodAll.has(e);
    f.dev ||= devAll.has(e);
    f.required ||= required.has(e);
    f.direct ||= direct.has(e);
    f.paths.push(`yarn.lock:${e.descriptors[0]}`);
    flags.set(purl, f);
  }
  const components: Component[] = [];
  for (const [purl, f] of flags) {
    components.push({ ecosystem: 'npm', name: f.entry.name, version: f.entry.version, purl, dev: !f.prod && f.dev, optional: (f.prod || f.dev) && !f.required, direct: f.direct, path: f.paths[0]!, ...(f.paths.length > 1 ? { paths: f.paths } : {}) });
  }
  components.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { components, lockfileVersion, projectName: root?.name, projectVersion: root?.version };
}
