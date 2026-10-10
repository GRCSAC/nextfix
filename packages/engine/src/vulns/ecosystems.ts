import semver from 'semver';
import type { Ecosystem } from '../types.ts';
import { comparePep440, validPep440 } from './pep440.ts';
import { compareDistroVersion } from './distro-version.ts';

export type VersionFamily = 'semver' | 'pep440' | 'distro' | 'none';

/** How versions are ordered in an ecosystem, which decides how "lowest fixed version above mine" is found. */
export function versionFamily(eco: Ecosystem): VersionFamily {
  if (eco === 'npm' || eco === 'Go' || eco === 'crates.io' || eco === 'Hex' || eco === 'Pub') return 'semver';
  if (eco === 'PyPI') return 'pep440';
  if (isDistro(eco)) return 'distro';
  return 'none';
}

/** Distribution ecosystems: OS packages inside container images. */
export function isDistro(eco: Ecosystem): boolean {
  return /^(Debian|Ubuntu|Alpine|Wolfi|Chainguard|Red Hat|AlmaLinux|Rocky Linux)/.test(eco);
}

/**
 * Ecosystems OSV can answer for. `generic` (binaries, unknown SBOM types) is listed but never
 * queried, and so is Alpine without a release: OSV only has per-release Alpine data, and an
 * empty answer would read as "clean".
 */
export function osvQueryable(eco: Ecosystem): boolean {
  return eco !== 'generic' && eco !== 'Alpine';
}

/** Version string as OSV stores it for the ecosystem (Go without the `v`). */
export function osvVersion(eco: Ecosystem, version: string): string {
  return eco === 'Go' ? version.replace(/^v/, '') : version;
}

/** `true` when `v` is a well-formed version for the ecosystem. */
export function validVersion(eco: Ecosystem, v: string): boolean {
  switch (versionFamily(eco)) {
    case 'semver':
      return semver.valid(v.replace(/^v/, '')) !== null;
    case 'pep440':
      return validPep440(v);
    case 'distro':
      return v.length > 0;
    default:
      return v.length > 0;
  }
}

/** Compares two versions of the ecosystem: negative, zero or positive. */
export function compareVersions(eco: Ecosystem, a: string, b: string): number {
  switch (versionFamily(eco)) {
    case 'semver':
      return semver.compare(a.replace(/^v/, ''), b.replace(/^v/, ''));
    case 'pep440':
      return comparePep440(a, b);
    case 'distro':
      return compareDistroVersion(a, b);
    default:
      return a === b ? 0 : a < b ? -1 : 1;
  }
}
