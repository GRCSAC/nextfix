import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Component } from '../types.ts';
import { purlFor } from './npm-lock.ts';

/**
 * pnpm-lock.yaml, lockfileVersion 5.x, 6.x and 9.x. The file is plain block YAML with flow
 * maps (`resolution: {integrity: …}`) and short sequences (`os: [darwin]`), so a small
 * subset parser is enough and avoids a dependency.
 */

export type Yaml = string | Yaml[] | { [key: string]: Yaml };
type YamlMap = { [key: string]: Yaml };

function unquoteScalar(s: string): string {
  const v = s.trim();
  if (v.length >= 2 && v.startsWith("'") && v.endsWith("'")) return v.slice(1, -1).replace(/''/g, "'");
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1).replace(/\\(["\\])/g, '$1');
  return v;
}

/** Splits `a: b, c: d` on commas that are not inside quotes or brackets. */
function splitFlow(s: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote = '';
  let cur = '';
  for (const ch of s) {
    if (quote) {
      cur += ch;
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === "'" || ch === '"') quote = ch;
    else if (ch === '{' || ch === '[') depth++;
    else if (ch === '}' || ch === ']') depth--;
    if (ch === ',' && depth === 0) {
      parts.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

function splitKeyValue(content: string): [string, string] | undefined {
  const q = content[0];
  if (q === "'" || q === '"') {
    let i = 1;
    while (i < content.length) {
      if (content[i] === q) {
        if (q === "'" && content[i + 1] === "'") {
          i += 2;
          continue;
        }
        break;
      }
      i++;
    }
    const rest = content.slice(i + 1).trimStart();
    if (!rest.startsWith(':')) return undefined;
    return [unquoteScalar(content.slice(0, i + 1)), rest.slice(1).trim()];
  }
  const idx = content.indexOf(': ');
  if (idx >= 0) return [content.slice(0, idx).trim(), content.slice(idx + 2).trim()];
  if (content.endsWith(':')) return [content.slice(0, -1).trim(), ''];
  return undefined;
}

function parseScalar(s: string): Yaml {
  const v = s.trim();
  if (v.startsWith('{') && v.endsWith('}')) {
    const out: YamlMap = {};
    for (const part of splitFlow(v.slice(1, -1))) {
      const kv = splitKeyValue(part);
      if (kv) out[kv[0]] = parseScalar(kv[1]);
    }
    return out;
  }
  if (v.startsWith('[') && v.endsWith(']')) return splitFlow(v.slice(1, -1)).map((p) => unquoteScalar(p));
  return unquoteScalar(v);
}

/** Block YAML subset: nested maps, scalar sequences, flow maps and sequences, quoted keys. */
export function parseYaml(text: string): YamlMap {
  const lines = text.split('\n').map((l) => l.replace(/\s+$/, ''));
  const meaningful = (l: string) => l.trim() !== '' && !l.trimStart().startsWith('#');
  const nextIsItem = (from: number, indent: number): boolean => {
    for (let j = from; j < lines.length; j++) {
      if (!meaningful(lines[j]!)) continue;
      const c = lines[j]!.trimStart();
      return lines[j]!.length - c.length >= indent && (c.startsWith('- ') || c === '-');
    }
    return false;
  };
  const root: YamlMap = {};
  const stack: { indent: number; node: Yaml }[] = [{ indent: -1, node: root }];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!meaningful(line)) continue;
    const content = line.trimStart();
    const indent = line.length - content.length;
    const isItem = content.startsWith('- ') || content === '-';
    while (stack.length > 1) {
      const top = stack[stack.length - 1]!;
      if (top.indent < indent) break;
      if (top.indent === indent && isItem && Array.isArray(top.node)) break;
      stack.pop();
    }
    const parent = stack[stack.length - 1]!.node;
    if (isItem) {
      if (Array.isArray(parent)) parent.push(parseScalar(content.slice(1)));
      continue;
    }
    if (Array.isArray(parent) || typeof parent === 'string') continue;
    const kv = splitKeyValue(content);
    if (!kv) continue;
    const [key, rest] = kv;
    if (rest === '') {
      const child: Yaml = nextIsItem(i + 1, indent) ? [] : {};
      parent[key] = child;
      stack.push({ indent, node: child });
    } else parent[key] = parseScalar(rest);
  }
  return root;
}

function map(v: Yaml | undefined): YamlMap {
  return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
}

function scalar(v: Yaml | undefined): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

export interface PnpmInventory {
  components: Component[];
  lockfileVersion: string;
  projectName?: string;
  projectVersion?: string;
}

/**
 * `/lodash@4.17.15` (v6), `lodash@4.17.15` (v9), `/lodash/4.17.15` (v5), with optional peer
 * suffixes `(react@18.2.0)` or `_react@18.2.0`. Returns undefined for tarball / git keys.
 */
export function parsePackageKey(key: string): { name: string; version: string } | undefined {
  const k = key.startsWith('/') ? key.slice(1) : key;
  if (k.includes('://') || /^(file:|git[+:]|github\.com\/|codeload\.)/.test(k)) return undefined;
  const at = k.startsWith('@') ? k.indexOf('@', 1) : k.indexOf('@');
  const scopeSlashes = k.startsWith('@') ? 1 : 0;
  let name: string;
  let version: string;
  if (at > 0 && k.slice(0, at).split('/').length - 1 === scopeSlashes) {
    name = k.slice(0, at);
    version = k.slice(at + 1);
  } else {
    // v5: `name/version` with peers after `_`; the `@` found above sits inside the peer suffix.
    const base = k.replace(/_.*$/, '');
    const slash = base.lastIndexOf('/');
    if (slash < 0) return undefined;
    name = base.slice(0, slash);
    version = base.slice(slash + 1);
  }
  version = version.replace(/[(_].*$/, '');
  if (!name || !version) return undefined;
  return { name, version };
}

/** Reads pnpm-lock.yaml and returns every installed component. */
export function readPnpmLock(projectDir: string): PnpmInventory {
  const lockPath = join(projectDir, 'pnpm-lock.yaml');
  if (!existsSync(lockPath)) throw new Error(`No pnpm-lock.yaml in ${projectDir}.`);
  const lock = parseYaml(readFileSync(lockPath, 'utf8'));
  const lockfileVersion = scalar(lock.lockfileVersion) ?? '0';
  const packages = map(lock.packages);
  // v9 keeps the dependency edges under `snapshots` (keyed with peer suffixes); earlier
  // versions keep them on the package entries themselves.
  const snapshots = lock.snapshots ? map(lock.snapshots) : packages;
  const importers: YamlMap = lock.importers ? map(lock.importers) : { '.': { dependencies: lock.dependencies ?? {}, devDependencies: lock.devDependencies ?? {}, optionalDependencies: lock.optionalDependencies ?? {} } };

  // A dependency is written as `name: <version-ish>`; the version-ish is a bare version, a
  // version with peer suffix, a full key for an alias (`/string-width@4.2.3`, `string-width@4.2.3`)
  // or `link:` for a workspace package.
  const resolveKey = (name: string, versionish: string): string | undefined => {
    if (/^(link|file|workspace):/.test(versionish)) return undefined;
    for (const candidate of [versionish, `/${versionish}`, `${name}@${versionish}`, `/${name}@${versionish}`, `/${name}/${versionish}`]) {
      if (candidate in snapshots || candidate in packages) return candidate;
    }
    return undefined;
  };
  const versionOf = (v: Yaml | undefined): string | undefined => (typeof v === 'string' ? v : scalar(map(v).version));

  const edges = (key: string, followOptional: boolean): string[] => {
    const entry = map(snapshots[key] ?? packages[key]);
    const out: string[] = [];
    const add = (block: Yaml | undefined) => {
      for (const [n, v] of Object.entries(map(block))) {
        const k = typeof v === 'string' ? resolveKey(n, v) : undefined;
        if (k) out.push(k);
      }
    };
    add(entry.dependencies);
    if (followOptional) add(entry.optionalDependencies);
    return out;
  };
  const walk = (roots: string[], followOptional: boolean): Set<string> => {
    const seen = new Set<string>();
    const queue = [...roots];
    while (queue.length) {
      const k = queue.pop()!;
      if (seen.has(k)) continue;
      seen.add(k);
      for (const dep of edges(k, followOptional)) if (!seen.has(dep)) queue.push(dep);
    }
    return seen;
  };

  const prodRoots: string[] = [];
  const optionalRoots: string[] = [];
  const devRoots: string[] = [];
  const directKeys = new Set<string>();
  for (const importer of Object.values(importers)) {
    const im = map(importer);
    const collect = (block: Yaml | undefined, into: string[]) => {
      for (const [n, v] of Object.entries(map(block))) {
        const ver = versionOf(v);
        const k = ver ? resolveKey(n, ver) : undefined;
        if (!k) continue;
        into.push(k);
        directKeys.add(k);
      }
    };
    collect(im.dependencies, prodRoots);
    collect(im.optionalDependencies, optionalRoots);
    collect(im.devDependencies, devRoots);
  }
  const prodAll = walk([...prodRoots, ...optionalRoots], true);
  const devAll = walk(devRoots, true);
  const required = walk([...prodRoots, ...devRoots], false);

  // Flags are computed on snapshot keys (one per peer combination) and folded onto the purl.
  const flags = new Map<string, { prod: boolean; dev: boolean; required: boolean; direct: boolean }>();
  const purlOfKey = (key: string): string | undefined => {
    const entry = map(packages[key] ?? snapshots[key]);
    const parsed = parsePackageKey(key);
    const name = scalar(entry.name) ?? parsed?.name;
    const version = scalar(entry.version) ?? parsed?.version;
    return name && version ? purlFor(name, version) : undefined;
  };
  for (const key of new Set([...Object.keys(snapshots), ...Object.keys(packages)])) {
    const purl = purlOfKey(key);
    if (!purl) continue;
    const f = flags.get(purl) ?? { prod: false, dev: false, required: false, direct: false };
    f.prod ||= prodAll.has(key);
    f.dev ||= devAll.has(key);
    f.required ||= required.has(key);
    f.direct ||= directKeys.has(key);
    flags.set(purl, f);
  }

  const byPurl = new Map<string, Component>();
  const source = Object.keys(packages).length ? packages : snapshots;
  for (const key of Object.keys(source)) {
    const purl = purlOfKey(key);
    if (!purl) continue;
    const entry = map(source[key]);
    const parsed = parsePackageKey(key);
    const name = scalar(entry.name) ?? parsed!.name;
    const version = scalar(entry.version) ?? parsed!.version;
    const f = flags.get(purl)!;
    const path = `pnpm-lock.yaml:${key}`;
    const existing = byPurl.get(purl);
    if (existing) {
      existing.paths = [...(existing.paths ?? [existing.path]), path];
      continue;
    }
    byPurl.set(purl, { ecosystem: 'npm', name, version, purl, dev: !f.prod && f.dev, optional: (f.prod || f.dev) && !f.required, direct: f.direct, path });
  }
  const components = [...byPurl.values()];
  components.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  const manifestPath = join(projectDir, 'package.json');
  const manifest = existsSync(manifestPath) ? (JSON.parse(readFileSync(manifestPath, 'utf8')) as { name?: string; version?: string }) : {};
  return { components, lockfileVersion, projectName: manifest.name, projectVersion: manifest.version };
}
