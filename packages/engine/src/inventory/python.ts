import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Component } from '../types.ts';

/** PEP 503 normalisation: case-insensitive, runs of `-_.` collapse to `-`. */
export function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

export function purlForPy(name: string, version: string): string {
  return `pkg:pypi/${normalizePyName(name)}@${version}`;
}

export interface PythonInventory {
  components: Component[];
  sources: string[];
}

/** Reads pinned Python dependencies from requirements files, Pipfile.lock, poetry.lock and uv.lock. */
export function readPythonDeps(projectDir: string): PythonInventory {
  const byPurl = new Map<string, Component>();
  const sources: string[] = [];
  const add = (name: string, version: string, dev: boolean, direct: boolean, source: string) => {
    const purl = purlForPy(name, version);
    const existing = byPurl.get(purl);
    if (existing) {
      existing.dev = existing.dev && dev;
      existing.direct = existing.direct || direct;
      return;
    }
    byPurl.set(purl, { ecosystem: 'PyPI', name: normalizePyName(name), version, purl, dev, optional: false, direct, path: source });
  };

  // Lockfiles first (they know transitive deps), then requirements files.
  const pipfileLock = join(projectDir, 'Pipfile.lock');
  if (existsSync(pipfileLock)) {
    sources.push('Pipfile.lock');
    const lock = JSON.parse(readFileSync(pipfileLock, 'utf8')) as { default?: Record<string, { version?: string }>; develop?: Record<string, { version?: string }> };
    for (const [section, dev] of [['default', false], ['develop', true]] as const) {
      for (const [name, info] of Object.entries(lock[section] ?? {})) {
        const v = info.version?.replace(/^==/, '');
        if (v) add(name, v, dev, true, 'Pipfile.lock');
      }
    }
  }
  for (const lockName of ['poetry.lock', 'uv.lock']) {
    const file = join(projectDir, lockName);
    if (!existsSync(file)) continue;
    sources.push(lockName);
    for (const pkg of tomlPackages(readFileSync(file, 'utf8'))) add(pkg.name, pkg.version, pkg.dev, false, lockName);
  }
  for (const name of readdirSync(projectDir)) {
    if (!/^(requirements[\w.-]*\.txt|[\w.-]*requirements\.txt)$/i.test(name)) continue;
    sources.push(name);
    const dev = /dev|test|lint/i.test(name);
    for (const line of readFileSync(join(projectDir, name), 'utf8').split(/\r?\n/)) {
      const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+*-]+)/.exec(line.split('#')[0] ?? '');
      if (m) add(m[1]!, m[2]!, dev, true, name);
    }
  }
  const components = [...byPurl.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { components, sources };
}

/** Minimal reader for the `[[package]]` tables of poetry.lock and uv.lock. */
function tomlPackages(text: string): { name: string; version: string; dev: boolean }[] {
  const out: { name: string; version: string; dev: boolean }[] = [];
  let cur: { name?: string; version?: string; dev: boolean } | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '[[package]]') {
      if (cur?.name && cur.version) out.push({ name: cur.name, version: cur.version, dev: cur.dev });
      cur = { dev: false };
      continue;
    }
    if (!cur) continue;
    if (/^\[/.test(line) && line !== '[[package]]') {
      // A sub-table such as [package.dependencies] or [package.extras]; stays within the package.
      if (/^\[package\.(dev-dependencies|dev_dependencies)\]/.test(line)) cur.dev = true;
      continue;
    }
    const m = /^(name|version|category)\s*=\s*"([^"]*)"/.exec(line);
    if (!m) continue;
    if (m[1] === 'name') cur.name = m[2];
    else if (m[1] === 'version') cur.version = m[2];
    else if (m[1] === 'category' && m[2] === 'dev') cur.dev = true;
  }
  if (cur?.name && cur.version) out.push({ name: cur.name, version: cur.version, dev: cur.dev });
  return out;
}

export function hasPythonProject(projectDir: string): boolean {
  if (['Pipfile.lock', 'poetry.lock', 'uv.lock'].some((f) => existsSync(join(projectDir, f)))) return true;
  return readdirSync(projectDir).some((n) => /^(requirements[\w.-]*\.txt|[\w.-]*requirements\.txt)$/i.test(n));
}
