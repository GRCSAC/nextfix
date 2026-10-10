import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Component } from '../types.ts';

interface LockPackage {
  version?: string;
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  name?: string;
}

interface LockFile {
  name?: string;
  version?: string;
  lockfileVersion?: number;
  packages?: Record<string, LockPackage>;
}

export interface NpmInventory {
  components: Component[];
  lockfileVersion: number;
  projectName?: string;
  projectVersion?: string;
}

export function purlFor(name: string, version: string): string {
  // pkg:npm/%40scope/name@version per the purl spec.
  const encoded = name.startsWith('@') ? '%40' + name.slice(1) : name;
  return `pkg:npm/${encoded}@${version}`;
}

/** Reads package-lock.json (v2/v3) and returns every installed component. */
export function readNpmLock(projectDir: string): NpmInventory {
  const lockPath = join(projectDir, 'package-lock.json');
  if (!existsSync(lockPath)) {
    throw new Error(`No package-lock.json in ${projectDir}. Run \`npm install --package-lock-only\` there first.`);
  }
  const lock = JSON.parse(readFileSync(lockPath, 'utf8')) as LockFile;
  if (!lock.packages) {
    throw new Error('package-lock.json is lockfileVersion 1; run `npm install` with npm 7+ to upgrade it.');
  }
  const root = lock.packages[''] ?? {};
  const directNames = new Set([
    ...Object.keys(root.dependencies ?? {}),
    ...Object.keys(root.devDependencies ?? {}),
  ]);

  // One component per name@version: the same package installed at several lockfile paths is
  // one thing to fix. It is "dev" only if every copy is dev, "direct" if any copy is.
  const byPurl = new Map<string, Component>();
  for (const [key, pkg] of Object.entries(lock.packages)) {
    if (key === '' || !pkg.version) continue;
    const marker = 'node_modules/';
    const idx = key.lastIndexOf(marker);
    if (idx < 0) continue; // workspace link, not a dependency
    const installedAs = key.slice(idx + marker.length);
    // `"foo": "npm:bar@1"` installs bar under the name foo; advisories are published for bar.
    const name = pkg.name && pkg.name !== installedAs ? pkg.name : installedAs;
    const nested = key.slice(0, idx).includes(marker);
    const purl = purlFor(name, pkg.version);
    const existing = byPurl.get(purl);
    if (existing) {
      existing.dev = existing.dev && !!pkg.dev;
      existing.optional = existing.optional && !!pkg.optional;
      existing.direct = existing.direct || (!nested && directNames.has(installedAs));
      existing.paths = [...(existing.paths ?? [existing.path]), key];
      continue;
    }
    byPurl.set(purl, {
      ecosystem: 'npm',
      name,
      version: pkg.version,
      purl,
      dev: !!pkg.dev,
      optional: !!pkg.optional,
      direct: !nested && directNames.has(installedAs),
      path: key,
    });
  }
  const components = [...byPurl.values()];
  components.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return {
    components,
    lockfileVersion: lock.lockfileVersion ?? 0,
    projectName: lock.name ?? root.name,
    projectVersion: lock.version ?? root.version,
  };
}
