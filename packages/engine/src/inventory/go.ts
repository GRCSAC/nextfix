import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Component } from '../types.ts';

/** A `require` line of go.mod. */
export interface GoRequire {
  path: string;
  version: string;
  indirect: boolean;
}

/** A `replace` directive; `newVersion` is absent when the replacement is a directory. */
export interface GoReplace {
  oldPath: string;
  oldVersion?: string;
  newPath: string;
  newVersion?: string;
}

export interface GoModFile {
  module?: string;
  /** The `go` directive as written (`1.21`, `1.22.3`). */
  go?: string;
  /** The `toolchain` directive without its `go` prefix (`1.22.3`). */
  toolchain?: string;
  requires: GoRequire[];
  replaces: GoReplace[];
  excludes: { path: string; version: string }[];
}

export interface GoInventory {
  components: Component[];
  sources: string[];
  module?: string;
  /** Language/toolchain version the stdlib component was inventoried at (`1.22.3`). */
  goVersion?: string;
  /** Modules replaced by a directory: their registry version is not what runs, so they are not inventoried. */
  localReplacements: string[];
}

export function hasGoProject(projectDir: string): boolean {
  return existsSync(join(projectDir, 'go.mod'));
}

export function purlForGo(name: string, version: string): string {
  return `pkg:golang/${name}@${version}`;
}

/** Strips a trailing `// comment` from a go.mod line, outside of quotes, and reports whether it marked the line `indirect`. */
function stripComment(raw: string): { text: string; indirect: boolean } {
  let inStr = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === '"') inStr = !inStr;
    else if (!inStr && ch === '/' && raw[i + 1] === '/') {
      return { text: raw.slice(0, i).trim(), indirect: /^\/\/\s*indirect\b/.test(raw.slice(i)) };
    }
  }
  return { text: raw.trim(), indirect: false };
}

/** Splits a directive line into tokens; module paths may be quoted. */
function tokens(text: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|`([^`]*)`|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) out.push(m[1] ?? m[2] ?? m[3]!);
  return out;
}

/** Parses go.mod: module path, go/toolchain directives, require (with `// indirect`), replace and exclude. */
export function parseGoMod(text: string): GoModFile {
  const mod: GoModFile = { requires: [], replaces: [], excludes: [] };
  let block: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const { text: line, indirect } = stripComment(raw);
    if (!line) continue;
    if (block) {
      if (line === ')') {
        block = undefined;
        continue;
      }
      directive(mod, block, tokens(line), indirect);
      continue;
    }
    const toks = tokens(line);
    const verb = toks[0]!;
    if (toks[1] === '(') {
      block = verb;
      continue;
    }
    directive(mod, verb, toks.slice(1), indirect);
  }
  return mod;
}

function directive(mod: GoModFile, verb: string, args: string[], indirect: boolean): void {
  switch (verb) {
    case 'module':
      mod.module = args[0];
      break;
    case 'go':
      mod.go = args[0];
      break;
    case 'toolchain':
      mod.toolchain = args[0]?.replace(/^go/, '');
      break;
    case 'require':
      if (args[0] && args[1]) mod.requires.push({ path: args[0], version: args[1], indirect });
      break;
    case 'exclude':
      if (args[0] && args[1]) mod.excludes.push({ path: args[0], version: args[1] });
      break;
    case 'replace': {
      const arrow = args.indexOf('=>');
      if (arrow < 1 || arrow === args.length - 1) break;
      const left = args.slice(0, arrow);
      const right = args.slice(arrow + 1);
      mod.replaces.push({ oldPath: left[0]!, oldVersion: left[1], newPath: right[0]!, newVersion: right[1] });
      break;
    }
    default:
      // retract, godebug, tool, ignore: nothing to inventory
      break;
  }
}

/** Every `module version` pair in go.sum; the `/go.mod` hash lines are not components. */
export function parseGoSum(text: string): { path: string; version: string }[] {
  const out: { path: string; version: string }[] = [];
  const seen = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const [path, version] = line.split(/\s+/);
    if (!path || !version || version.endsWith('/go.mod')) continue;
    const key = `${path}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ path, version });
  }
  return out;
}

/** `1.21` → `1.21.0`; `1.22.3` stays; anything else is returned as written. */
export function fullGoVersion(v: string): string {
  const m = /^(\d+)\.(\d+)(?:\.(\d+))?(.*)$/.exec(v.replace(/^go/, ''));
  if (!m) return v;
  return `${m[1]}.${m[2]}.${m[3] ?? '0'}${m[4] ?? ''}`;
}

/** The replacement for a module@version, when go.mod has one (a version-specific replace wins over a path-only one). */
function replacementFor(mod: GoModFile, path: string, version: string): GoReplace | undefined {
  return mod.replaces.find((r) => r.oldPath === path && r.oldVersion === version) ?? mod.replaces.find((r) => r.oldPath === path && !r.oldVersion);
}

/**
 * Inventories a Go module from go.mod and go.sum. Versions keep their `v` (OSV queries strip it).
 * Modules go.mod requires are inventoried at that version only: minimal version selection makes it
 * the one that builds, so older lines left in go.sum for the same module are superseded. Modules
 * that appear only in go.sum are inventoried at every version listed, since nothing says which one
 * the build picks.
 */
export function readGoDeps(projectDir: string): GoInventory {
  const modText = readFileSync(join(projectDir, 'go.mod'), 'utf8');
  const mod = parseGoMod(modText);
  const sources = ['go.mod'];
  const byPurl = new Map<string, Component>();
  const localReplacements: string[] = [];
  const excluded = new Set(mod.excludes.map((e) => `${e.path}@${e.version}`));
  const add = (path: string, version: string, direct: boolean, source: string) => {
    if (excluded.has(`${path}@${version}`)) return;
    const purl = purlForGo(path, version);
    const existing = byPurl.get(purl);
    if (existing) {
      existing.direct = existing.direct || direct;
      return;
    }
    byPurl.set(purl, { ecosystem: 'Go', name: path, version, purl, dev: false, optional: false, direct, path: source });
  };
  // Resolves a module through `replace`; returns nothing when the replacement is a directory.
  const resolved = (path: string, version: string): { path: string; version: string } | undefined => {
    const r = replacementFor(mod, path, version);
    if (!r) return { path, version };
    if (!r.newVersion) {
      if (!localReplacements.includes(path)) localReplacements.push(path);
      return undefined;
    }
    return { path: r.newPath, version: r.newVersion };
  };

  const pinned = new Set<string>();
  for (const req of mod.requires) {
    pinned.add(req.path);
    const target = resolved(req.path, req.version);
    if (target) add(target.path, target.version, !req.indirect, 'go.mod');
  }

  const sumFile = join(projectDir, 'go.sum');
  if (existsSync(sumFile)) {
    sources.push('go.sum');
    for (const { path, version } of parseGoSum(readFileSync(sumFile, 'utf8'))) {
      if (pinned.has(path)) continue;
      // go.sum lists the replacement under its own path; the replaced path's lines are leftovers.
      if (mod.replaces.some((r) => r.oldPath === path)) continue;
      add(path, version, false, 'go.sum');
    }
  }

  const goVersion = mod.toolchain ? fullGoVersion(mod.toolchain) : mod.go ? fullGoVersion(mod.go) : undefined;
  if (goVersion) byPurl.set(purlForGo('stdlib', goVersion), { ecosystem: 'Go', name: 'stdlib', version: goVersion, purl: purlForGo('stdlib', goVersion), dev: false, optional: false, direct: true, path: 'go.mod' });

  const components = [...byPurl.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { components, sources, module: mod.module, goVersion, localReplacements };
}
